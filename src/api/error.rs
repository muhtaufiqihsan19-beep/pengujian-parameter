//! Service errors to HTTP status codes and `{"error": "<code>"}` bodies, plus JSON helpers.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::service::ServiceError;

pub struct ApiError(pub StatusCode, pub &'static str);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

impl From<ServiceError> for ApiError {
    fn from(e: ServiceError) -> Self {
        match e {
            ServiceError::BadRequest(reason) => {
                tracing::warn!(%reason, "request rejected");
                ApiError(StatusCode::BAD_REQUEST, "bad_request")
            }
            ServiceError::TooLarge => ApiError(StatusCode::PAYLOAD_TOO_LARGE, "document_too_large"),
            ServiceError::Open => {
                tracing::warn!(security_event = true, "document or key could not be opened");
                ApiError(StatusCode::UNPROCESSABLE_ENTITY, "open_failed")
            }
            ServiceError::Forbidden(reason) => {
                tracing::warn!(security_event = true, %reason, "access denied");
                ApiError(StatusCode::FORBIDDEN, "access_denied")
            }
            ServiceError::Untrusted(reason) => {
                tracing::warn!(security_event = true, %reason, "untrusted public key");
                ApiError(StatusCode::UNPROCESSABLE_ENTITY, "untrusted_key")
            }
            ServiceError::Internal(reason) => {
                tracing::error!(%reason, "internal error");
                ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal")
            }
        }
    }
}

pub fn parse<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|e| {
        tracing::warn!(kind = ?e.classify(), line = e.line(), column = e.column(), "invalid JSON");
        ApiError(StatusCode::BAD_REQUEST, "invalid_json")
    })
}

pub fn json_response<T: Serialize>(status: StatusCode, v: &T) -> Result<Response, ApiError> {
    let body = serde_json::to_vec(v)
        .map_err(|e| ApiError::from(ServiceError::Internal(format!("serialize response: {e}"))))?;
    Ok((
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        body,
    )
        .into_response())
}
