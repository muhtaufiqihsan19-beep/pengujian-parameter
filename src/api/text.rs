//! `POST /text/encrypt` and `POST /text/decrypt`: like the document endpoints, but the
//! content is a UTF-8 string in the JSON instead of base64.

use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::AppState;
use super::documents::{DecryptRequest, encrypt_response};
use super::error::{ApiError, parse};
use crate::service::{Recipient, ServiceError, cpu};

fn secret_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EncryptTextRequest {
    document_id: String,
    version: u32,
    #[serde(deserialize_with = "secret_string")]
    text: Zeroizing<String>,
    recipients: Vec<Recipient>,
}

pub async fn encrypt(State(st): State<Arc<AppState>>, body: Bytes) -> Result<Response, ApiError> {
    let body = Zeroizing::new(Vec::from(body));
    let req: EncryptTextRequest = cpu(|| parse(&body))?;
    drop(body);
    let enc = st
        .service
        .encrypt(
            &req.document_id,
            req.version,
            req.text.as_bytes(),
            &req.recipients,
        )
        .await?;
    encrypt_response(req.document_id, req.version, enc)
}

#[derive(Serialize)]
struct DecryptTextResponse<'a> {
    document_id: &'a str,
    version: u32,
    text: &'a str,
}

/// The JSON response is built in a zeroized buffer, since it holds the plaintext.
pub async fn decrypt(State(st): State<Arc<AppState>>, body: Bytes) -> Result<Response, ApiError> {
    let req: DecryptRequest = cpu(|| parse(&body))?;
    drop(body);
    let text = st
        .service
        .decrypt_text(
            &req.document_id,
            req.version,
            &req.key,
            req.ciphertext,
            &req.grant,
        )
        .await?;
    let mut json = Zeroizing::new(Vec::with_capacity(text.len() * 6 + 128));
    let resp = DecryptTextResponse {
        document_id: &req.document_id,
        version: req.version,
        text: &text,
    };
    serde_json::to_writer(&mut *json, &resp)
        .map_err(|e| ServiceError::Internal(format!("serialize response: {e}")))?;
    Ok((
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        Body::from(Bytes::from_owner(json)),
    )
        .into_response())
}
