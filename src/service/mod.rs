//! Business flows (use cases), one file per flow. No HTTP here and no algorithm detail:
//! the flows combine the crypto suites, the backends and the grant check.
//!
//! | File | What it does |
//! |---|---|
//! | `keys.rs` | create a position key; check that a public key was issued by this service |
//! | `encrypt.rs` | encrypt a document or text for its recipients |
//! | `decrypt.rs` | decrypt with a holder's key, after checking the grant |
//! | `disposition.rs` | give more positions access to a document (rewrap its DEK) |
//! | `dek.rs` | wrap the DEK for each recipient, unwrap it for a key holder |
//! | `checks.rs` | input checks, and the grant check with its audit log |
//! | `grant.rs` | the grant token: format, verification, test issuer |
//! | `types.rs`, `b64.rs` | request and response types shared with the API |

pub mod b64;
mod checks;
mod decrypt;
mod dek;
mod disposition;
mod encrypt;
pub mod grant;
mod keys;
mod types;

#[cfg(test)]
pub(crate) mod tests;

use std::sync::Arc;

use thiserror::Error;

use crate::backends::{BackendError, KeyCustody, Signer};
use crate::crypto::Registry;
use grant::GrantVerifier;

pub use checks::MAX_RECIPIENTS;
pub use keys::GeneratedKey;
pub use types::{Encrypted, KeyHolder, Recipient, WrappedKey};

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("document or key could not be opened")]
    Open,
    #[error("document exceeds the size limit")]
    TooLarge,
    #[error("access denied: {0}")]
    Forbidden(String),
    #[error("untrusted public key: {0}")]
    Untrusted(String),
    #[error("internal error: {0}")]
    Internal(String),
}

/// The service and everything it depends on. `main.rs` builds it; the API calls it.
pub struct Service {
    /// Key-wrap suites by id, and the default for new keys.
    pub registry: Registry,
    /// Generates position keys and opens DEKs (software today, an HSM later).
    pub custody: Arc<dyn KeyCustody>,
    /// Signs public keys (PKS1) and ciphertexts (CTS1).
    pub signer: Arc<dyn Signer>,
    /// Checks the grant on every decrypt and disposition.
    pub grants: GrantVerifier,
    pub max_plaintext: usize,
    pub chunk_size: u32,
}

/// Runs CPU-heavy work (large documents) without stalling other requests on the runtime.
pub fn cpu<R>(f: impl FnOnce() -> R) -> R {
    use tokio::runtime::{Handle, RuntimeFlavor};
    match Handle::try_current() {
        Ok(h) if h.runtime_flavor() == RuntimeFlavor::MultiThread => tokio::task::block_in_place(f),
        _ => f(),
    }
}

/// A backend failure seen by a caller: a blob or wrapped key that does not open is the
/// caller's problem (422); an unreachable or misconfigured backend is ours (500).
fn backend_error(e: BackendError) -> ServiceError {
    match e {
        BackendError::Rejected { status: 400, .. }
        | BackendError::BadBlob
        | BackendError::Mismatch
        | BackendError::Crypto(_) => ServiceError::Open,
        other => ServiceError::Internal(other.to_string()),
    }
}

impl Service {
    /// For `/readyz`: the key custody and the signer both work end to end.
    pub async fn backends_ready(&self) -> bool {
        let custody = self.custody.ready().await;
        let signer = match self.signer.sign(b"readyz").await {
            Ok(signature) => self
                .signer
                .verify(b"readyz", &signature)
                .await
                .unwrap_or(false),
            Err(_) => false,
        };
        custody && signer
    }
}
