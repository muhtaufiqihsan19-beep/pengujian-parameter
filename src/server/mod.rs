//! The network side: accept connections, run TLS 1.3 with client certificates (mTLS),
//! check the client name against the allowlist, hand requests to the API router, and
//! shut down gracefully. `tls.rs` builds the rustls configuration.

pub mod tls;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use crate::api::AppState;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
const ACCEPT_BACKOFF: Duration = Duration::from_secs(1);

pub struct MtlsSettings {
    pub acceptor: TlsAcceptor,
    pub allowed_clients: Arc<Vec<String>>,
    pub max_connections: usize,
    pub grace: Duration,
}

pub async fn serve_mtls(
    listener: TcpListener,
    app: axum::Router,
    state: Arc<AppState>,
    settings: MtlsSettings,
) -> Result<(), String> {
    let graceful = GracefulShutdown::new();
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let slots = Arc::new(Semaphore::new(settings.max_connections));

    let mut builder = ConnBuilder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);
    builder.http2().timer(TokioTimer::new());
    let builder = Arc::new(builder);

    loop {
        let permit = tokio::select! {
            _ = &mut shutdown => break,
            p = slots.clone().acquire_owned() => match p {
                Ok(p) => p,
                Err(_) => break,
            },
        };
        let (tcp, peer) = tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => match accepted {
                Ok(v) => v,
                Err(e) if is_connection_error(&e) => continue,
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed, backing off");
                    tokio::select! {
                        _ = &mut shutdown => break,
                        _ = tokio::time::sleep(ACCEPT_BACKOFF) => continue,
                    }
                }
            },
        };
        let watcher = graceful.watcher();
        let acceptor = settings.acceptor.clone();
        let allowed = settings.allowed_clients.clone();
        let (app, builder) = (app.clone(), builder.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    tracing::warn!(%peer, error = %e, "TLS handshake failed");
                    return;
                }
                Err(_) => {
                    tracing::warn!(%peer, "TLS handshake timed out");
                    return;
                }
            };
            let permitted = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first())
                .is_some_and(|c| tls::san_allowed(c.as_ref(), &allowed));
            if !permitted {
                tracing::warn!(%peer, security_event = true, "mTLS client not in KS_ALLOWED_CLIENTS");
                return;
            }
            let conn = builder
                .serve_connection(TokioIo::new(tls), TowerToHyperService::new(app))
                .into_owned();
            if let Err(e) = watcher.watch(conn).await {
                tracing::debug!(%peer, error = %e, "connection closed with error");
            }
        });
    }

    state.start_draining();
    drop(listener);
    tracing::info!(
        open_connections = graceful.count(),
        grace_secs = settings.grace.as_secs(),
        "shutdown: no longer accepting connections, waiting for in-flight requests"
    );
    tokio::select! {
        _ = graceful.shutdown() => tracing::info!("all connections finished, exiting"),
        _ = tokio::time::sleep(settings.grace) => {
            tracing::warn!(grace_secs = settings.grace.as_secs(), "shutdown grace period expired, dropping remaining connections");
        }
    }
    Ok(())
}

pub async fn serve_plain(
    listener: TcpListener,
    app: axum::Router,
    state: Arc<AppState>,
) -> Result<(), String> {
    let local: SocketAddr = listener.local_addr().map_err(|e| e.to_string())?;
    if !local.ip().is_loopback() {
        return Err(
            "dev mode without TLS only listens on loopback (KS_LISTEN=127.0.0.1:8443)".into(),
        );
    }
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            state.start_draining();
        })
        .await
        .map_err(|e| e.to_string())
}

fn is_connection_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        e.kind(),
        ConnectionRefused | ConnectionAborted | ConnectionReset
    )
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut s) = signal(SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}
