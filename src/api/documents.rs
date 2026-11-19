//! `POST /documents/encrypt` and `POST /documents/decrypt` (binary content as base64).
//! The request and response shapes here are shared with `text.rs`.

use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::AppState;
use super::error::{ApiError, json_response, parse};
use crate::crypto::eks1;
use crate::service::{Encrypted, KeyHolder, Recipient, WrappedKey, b64, cpu};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EncryptDocumentRequest {
    document_id: String,
    version: u32,
    #[serde(deserialize_with = "b64::deserialize_secret")]
    plaintext: Zeroizing<Vec<u8>>,
    recipients: Vec<Recipient>,
}

#[derive(Serialize)]
struct EncryptResponse {
    document_id: String,
    version: u32,
    content_alg: &'static str,
    #[serde(with = "b64")]
    ciphertext: Vec<u8>,
    wrapped_keys: Vec<WrappedKey>,
}

/// Body of both decrypt endpoints.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DecryptRequest {
    pub document_id: String,
    pub version: u32,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
    pub key: KeyHolder,
    pub grant: String,
}

pub async fn encrypt(State(st): State<Arc<AppState>>, body: Bytes) -> Result<Response, ApiError> {
    let body = Zeroizing::new(Vec::from(body));
    let req: EncryptDocumentRequest = cpu(|| parse(&body))?;
    drop(body);
    let enc = st
        .service
        .encrypt(
            &req.document_id,
            req.version,
            &req.plaintext,
            &req.recipients,
        )
        .await?;
    encrypt_response(req.document_id, req.version, enc)
}

/// The response of both encrypt endpoints.
pub(super) fn encrypt_response(
    document_id: String,
    version: u32,
    enc: Encrypted,
) -> Result<Response, ApiError> {
    cpu(|| {
        json_response(
            StatusCode::OK,
            &EncryptResponse {
                document_id,
                version,
                content_alg: eks1::CONTENT_ALG,
                ciphertext: enc.ciphertext,
                wrapped_keys: enc.wrapped_keys,
            },
        )
    })
}

/// Returns the plaintext as `application/octet-stream`.
pub async fn decrypt(State(st): State<Arc<AppState>>, body: Bytes) -> Result<Response, ApiError> {
    let req: DecryptRequest = cpu(|| parse(&body))?;
    drop(body);
    let plain = st
        .service
        .decrypt(
            &req.document_id,
            req.version,
            &req.key,
            req.ciphertext,
            &req.grant,
        )
        .await?;
    Ok((
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        )],
        Body::from(Bytes::from_owner(plain)),
    )
        .into_response())
}
