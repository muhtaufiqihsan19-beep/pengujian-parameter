//! `GET /healthz` (the process is up) and `GET /readyz` (it can serve: not shutting down,
//! key custody and signer reachable).

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;

use super::AppState;

pub async fn healthz() -> StatusCode {
    StatusCode::NO_CONTENT
}

pub async fn readyz(State(st): State<Arc<AppState>>) -> StatusCode {
    if !st.is_draining() && st.backends_ready().await {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}
