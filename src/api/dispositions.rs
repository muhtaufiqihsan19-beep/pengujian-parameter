//! `POST /dispositions`: give target positions access to a document version.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use serde::{Deserialize, Serialize};

use super::AppState;
use super::error::{ApiError, json_response, parse};
use crate::service::{KeyHolder, Recipient, WrappedKey, cpu};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DispositionRequest {
    document_id: String,
    version: u32,
    source: KeyHolder,
    targets: Vec<Recipient>,
    grant: String,
}

#[derive(Serialize)]
struct DispositionResponse {
    wrapped_keys: Vec<WrappedKey>,
}

pub async fn create(State(st): State<Arc<AppState>>, body: Bytes) -> Result<Response, ApiError> {
    let req: DispositionRequest = cpu(|| parse(&body))?;
    drop(body);
    let wrapped_keys = st
        .service
        .rewrap(
            &req.document_id,
            req.version,
            &req.source,
            &req.targets,
            &req.grant,
        )
        .await?;
    json_response(StatusCode::OK, &DispositionResponse { wrapped_keys })
}
