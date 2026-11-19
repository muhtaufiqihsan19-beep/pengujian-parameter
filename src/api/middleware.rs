//! Layers around every API request.

use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use super::{ApiError, AppState};
use crate::crypto::primitives::random;

/// A bounded number of requests at a time, each with a deadline (body upload included).
pub async fn limit_requests(State(st): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let deadline = tokio::time::Instant::now() + st.request_timeout;
    let Ok(Ok(_permit)) = tokio::time::timeout_at(deadline, st.inflight.acquire()).await else {
        tracing::warn!("all request slots busy");
        return ApiError(StatusCode::SERVICE_UNAVAILABLE, "overloaded").into_response();
    };
    match tokio::time::timeout_at(deadline, next.run(req)).await {
        Ok(resp) => resp,
        Err(_) => {
            tracing::warn!(
                timeout_secs = st.request_timeout.as_secs(),
                "request timed out"
            );
            ApiError(StatusCode::REQUEST_TIMEOUT, "request_timeout").into_response()
        }
    }
}

pub(super) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[usize::from(b >> 4)] as char);
        s.push(DIGITS[usize::from(b & 0x0f)] as char);
    }
    s
}

/// `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, an `x-request-id`
/// (the caller's, or a random one) and one access log line per request.
pub async fn headers_and_access_log(req: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() <= 64)
        .map(str::to_string)
        .unwrap_or_else(|| hex(&random::bytes::<8>().unwrap_or_default()));
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if let Ok(v) = HeaderValue::from_str(&request_id) {
        h.insert("x-request-id", v);
    }
    tracing::info!(
        %request_id, %method, %path,
        status = resp.status().as_u16(),
        duration_ms = start.elapsed().as_millis() as u64,
        "request"
    );
    resp
}
