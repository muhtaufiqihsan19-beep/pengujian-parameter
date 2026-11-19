//! Types shared by the flows and the HTTP API (they are part of the JSON contract in
//! `docs/openapi.yaml`). Binary fields are base64 in JSON.

use serde::{Deserialize, Serialize};

/// A position that should be able to open a document: its signed public key (PKS1).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recipient {
    pub position_code: String,
    pub key_version: u32,
    pub suite_id: String,
    #[serde(with = "super::b64")]
    pub public_key: Vec<u8>,
}

/// The DEK of one document version, wrapped for one position key.
#[derive(Debug, Clone, Serialize)]
pub struct WrappedKey {
    pub position_code: String,
    pub key_version: u32,
    pub suite_id: String,
    #[serde(with = "super::b64")]
    pub wrapped_key: Vec<u8>,
}

/// A position that wants to open a document: its wrapped DEK and its private key blob.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyHolder {
    pub position_code: String,
    pub key_version: u32,
    pub suite_id: String,
    #[serde(with = "super::b64")]
    pub wrapped_key: Vec<u8>,
    pub private_key_blob: String,
}

/// Result of an encryption: the CTS1 ciphertext and one wrapped DEK per recipient.
pub struct Encrypted {
    pub ciphertext: Vec<u8>,
    pub wrapped_keys: Vec<WrappedKey>,
}
