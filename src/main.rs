//! Entry point: read the configuration, pick the backends, build the service, serve.

use std::process::ExitCode;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing_subscriber::EnvFilter;

use crypto_service::api::{self, AppState};
use crypto_service::backends::{
    InsecureDevSealer, InsecureDevSigner, KeyCustody, OpenBaoTransit, Signer, SoftwareKeyCustody,
    TransitGrantKeys, TransitSigner,
};
use crypto_service::config::Config;
use crypto_service::crypto::{self, eks1};
use crypto_service::server::{self, MtlsSettings, tls};
use crypto_service::service::Service;
use crypto_service::service::grant::GrantVerifier;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "stopped");
            ExitCode::FAILURE
        }
    }
}

/// The swappable parts, chosen here and nowhere else. To add an HSM, implement
/// `KeyCustody` (and `Signer` if the HSM signs) in `src/backends/` and add a branch here.
struct Backends {
    custody: Arc<dyn KeyCustody>,
    signer: Arc<dyn Signer>,
    /// The OpenBao client, when there is one (also used for the grant issuer keys).
    transit: Option<OpenBaoTransit>,
}

fn backends(cfg: &Config) -> Result<Backends, String> {
    match &cfg.openbao_addr {
        None if cfg.dev => {
            tracing::warn!(
                "DEV MODE: in-memory KEK and signing key, position keys are lost on restart"
            );
            let sealer = InsecureDevSealer::new().map_err(|e| e.to_string())?;
            let signer = InsecureDevSigner::new().map_err(|e| e.to_string())?;
            Ok(Backends {
                custody: Arc::new(SoftwareKeyCustody::new(Arc::new(sealer))),
                signer: Arc::new(signer),
                transit: None,
            })
        }
        None => Err("OPENBAO_ADDR is required outside dev mode".into()),
        Some(addr) => {
            let transit = OpenBaoTransit {
                addr: addr.clone(),
                mount: cfg.openbao_mount.clone(),
                key_name: cfg.openbao_kek_name.clone(),
                namespace: cfg.openbao_namespace.clone(),
                token_file: cfg.openbao_token_file.clone(),
                http: OpenBaoTransit::http_client(
                    cfg.openbao_ca.as_deref(),
                    addr.starts_with("https://"),
                )
                .map_err(|e| e.to_string())?,
            };
            let signer = TransitSigner::new(transit.with_key(&cfg.openbao_signing_key_name));
            Ok(Backends {
                custody: Arc::new(SoftwareKeyCustody::new(Arc::new(transit.clone()))),
                signer: Arc::new(signer),
                transit: Some(transit),
            })
        }
    }
}

fn grant_verifier(cfg: &Config, transit: Option<&OpenBaoTransit>) -> Result<GrantVerifier, String> {
    let mut verifier = match &cfg.grant_public_keys {
        Some(path) => GrantVerifier::from_pem_file(path, cfg.grant_max_ttl)?,
        None => GrantVerifier::new(Vec::new(), cfg.grant_max_ttl),
    };
    match (&cfg.openbao_grant_key_name, transit) {
        (Some(name), Some(t)) => {
            verifier = verifier.with_source(Arc::new(TransitGrantKeys::new(t.with_key(name))));
        }
        (Some(_), None) => return Err("OPENBAO_GRANT_KEY_NAME needs OPENBAO_ADDR".into()),
        (None, _) => {}
    }
    if !verifier.is_configured() {
        tracing::warn!(
            "neither KS_GRANT_PUBLIC_KEYS nor OPENBAO_GRANT_KEY_NAME is set: every decrypt \
             and disposition is refused"
        );
    }
    Ok(verifier)
}

async fn run() -> Result<(), String> {
    let cfg = Config::from_env()?;
    let fips = crypto::primitives::fips_mode();
    if cfg!(feature = "fips") && !fips {
        return Err("built with the fips feature, but AWS-LC is not in FIPS mode".into());
    }

    let default_suite = cfg.default_suite.as_deref().unwrap_or(crypto::COMPOSITE_V2);
    let registry = crypto::registry(default_suite).map_err(|e| {
        let available: Vec<_> = crypto::suites::all().iter().map(|s| s.id()).collect();
        format!("KS_DEFAULT_SUITE: {e} (available: {available:?})")
    })?;
    let suite_ids = registry.ids();
    let Backends {
        custody,
        signer,
        transit,
    } = backends(&cfg)?;
    let service = Service {
        registry,
        custody,
        signer,
        grants: grant_verifier(&cfg, transit.as_ref())?,
        max_plaintext: cfg.max_document_bytes,
        chunk_size: eks1::DEFAULT_CHUNK_SIZE,
    };
    let state = Arc::new(
        AppState::new(service).with_limits(cfg.max_concurrent_requests, cfg.request_timeout),
    );
    let app = api::router(state.clone(), cfg.max_body_bytes);

    let health = TcpListener::bind(&cfg.health_listen)
        .await
        .map_err(|e| format!("{}: {e}", cfg.health_listen))?;
    let health_app = api::health_router(state.clone());
    tokio::spawn(async move {
        if let Err(e) = axum::serve(health, health_app).await {
            tracing::error!(error = %e, "health server stopped");
        }
    });

    let listener = TcpListener::bind(&cfg.listen)
        .await
        .map_err(|e| format!("{}: {e}", cfg.listen))?;
    let mtls = match (&cfg.tls_cert, &cfg.tls_key, &cfg.tls_client_ca) {
        (Some(cert), Some(key), Some(ca)) => Some(tls::server_config(
            cert,
            key,
            ca,
            cfg.tls_client_crl.as_deref(),
            cfg.tls_require_pq,
        )?),
        _ => None,
    };
    if mtls.is_some() && !cfg.tls_require_pq {
        tracing::warn!(
            "KS_TLS_REQUIRE_PQ=0: classical-only TLS clients are accepted, and documents they \
             send or receive are not protected against harvest now, decrypt later"
        );
    }
    tracing::info!(
        listen = %cfg.listen, health = %cfg.health_listen, default_suite,
        suites = ?suite_ids, tls = mtls.is_some(), tls_require_pq = cfg.tls_require_pq,
        fips, "crypto-service started"
    );

    match mtls {
        Some(tls_cfg) => {
            let settings = MtlsSettings {
                acceptor: TlsAcceptor::from(Arc::new(tls_cfg)),
                allowed_clients: Arc::new(cfg.allowed_clients.clone()),
                max_connections: cfg.max_connections,
                grace: cfg.shutdown_grace,
            };
            server::serve_mtls(listener, app, state, settings).await
        }
        None if cfg.dev => server::serve_plain(listener, app, state).await,
        None => {
            Err("KS_TLS_CERT, KS_TLS_KEY and KS_TLS_CLIENT_CA are required outside dev mode".into())
        }
    }
}
