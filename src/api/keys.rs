//! `GET /suites` and `POST /keys`.

use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use serde::{Deserialize, Serialize};

use super::AppState;
use super::error::{ApiError, json_response, parse};
use crate::crypto::eks1;
use crate::service::b64;

/// Which suites exist, which one new keys get, and the content algorithm.
pub async fn suites(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let reg = &st.service.registry;
    Json(serde_json::json!({
        "default": reg.default_suite().id(),
        "available": reg.ids(),
        "content_alg": eks1::CONTENT_ALG,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateKeyRequest {
    position_code: String,
    key_version: u32,
    #[serde(default)]
    suite_id: Option<String>,
}

#[derive(Serialize)]
struct CreateKeyResponse {
    position_code: String,
    key_version: u32,
    suite_id: String,
    #[serde(with = "b64")]
    public_key: Vec<u8>,
    private_key_blob: String,
}

/// A new key pair for one position and key version.
pub async fn create_key(
    State(st): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let req: CreateKeyRequest = parse(&body)?;
    let key = st
        .service
        .create_key(&req.position_code, req.key_version, req.suite_id.as_deref())
        .await?;
    json_response(
        StatusCode::CREATED,
        &CreateKeyResponse {
            position_code: key.identity.position_code,
            key_version: key.identity.key_version,
            suite_id: key.identity.suite_id,
            public_key: key.public_key,
            private_key_blob: key.private_key_blob,
        },
    )
}
