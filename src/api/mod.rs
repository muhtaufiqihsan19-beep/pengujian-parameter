//! HTTP API: one file per endpoint group, matching the tags in `docs/openapi.yaml`.
//! Handlers only parse JSON, call [`Service`] and shape the response; no crypto here.
//!
//! | File | Endpoints |
//! |---|---|
//! | `keys.rs` | `GET /suites`, `POST /keys` |
//! | `documents.rs` | `POST /documents/encrypt`, `POST /documents/decrypt` |
//! | `text.rs` | `POST /text/encrypt`, `POST /text/decrypt` |
//! | `dispositions.rs` | `POST /dispositions` |
//! | `health.rs` | `GET /healthz`, `GET /readyz` (separate listener) |
//! | `middleware.rs` | request slots, timeout, security headers, access log |
//! | `error.rs` | service errors to HTTP status and `{"error": ...}` |

mod dispositions;
mod documents;
mod error;
mod health;
mod keys;
mod middleware;
#[cfg(test)]
mod tests;
mod text;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware::{from_fn, from_fn_with_state};
use axum::routing::{get, post};
use tokio::sync::Semaphore;

pub use error::ApiError;

use crate::service::Service;

const READY_TTL: Duration = Duration::from_secs(5);
pub const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 8;
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// The main API routes.
pub fn router(state: Arc<AppState>, max_body: usize) -> Router {
    Router::new()
        .route("/suites", get(keys::suites))
        .route("/keys", post(keys::create_key))
        .route("/documents/encrypt", post(documents::encrypt))
        .route("/documents/decrypt", post(documents::decrypt))
        .route("/text/encrypt", post(text::encrypt))
        .route("/text/decrypt", post(text::decrypt))
        .route("/dispositions", post(dispositions::create))
        .layer(DefaultBodyLimit::max(max_body))
        .layer(from_fn_with_state(
            state.clone(),
            middleware::limit_requests,
        ))
        .layer(from_fn(middleware::headers_and_access_log))
        .with_state(state)
}

/// Liveness and readiness, served on their own plain-HTTP listener for the orchestrator.
pub fn health_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(health::healthz))
        .route("/readyz", get(health::readyz))
        .with_state(state)
}

/// What every handler can reach: the service, plus request limits and readiness state.
pub struct AppState {
    pub service: Service,
    draining: AtomicBool,
    ready_cache: tokio::sync::Mutex<Option<(Instant, bool)>>,
    inflight: Semaphore,
    request_timeout: Duration,
}

impl AppState {
    pub fn new(service: Service) -> Self {
        Self {
            service,
            draining: AtomicBool::new(false),
            ready_cache: tokio::sync::Mutex::new(None),
            inflight: Semaphore::new(DEFAULT_MAX_CONCURRENT_REQUESTS),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        }
    }

    pub fn with_limits(mut self, max_concurrent: usize, timeout: Duration) -> Self {
        self.inflight = Semaphore::new(max_concurrent);
        self.request_timeout = timeout;
        self
    }

    /// Called on shutdown: `/readyz` turns 503 so no new traffic is routed here.
    pub fn start_draining(&self) {
        self.draining.store(true, Ordering::SeqCst);
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::SeqCst)
    }

    /// [`Service::backends_ready`], cached for a few seconds so probes do not load the KMS.
    pub async fn backends_ready(&self) -> bool {
        let mut cache = self.ready_cache.lock().await;
        if let Some((at, ok)) = *cache
            && at.elapsed() < READY_TTL
        {
            return ok;
        }
        let ok = self.service.backends_ready().await;
        *cache = Some((Instant::now(), ok));
        ok
    }
}
