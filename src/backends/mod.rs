//! Everything that can be swapped without touching the rest of the service.
//!
//! Three contracts (traits) and the implementations available today:
//!
//! | Contract | Job | Implementations |
//! |---|---|---|
//! | [`KeyCustody`] | generate position key pairs, keep the private keys, open DEKs | [`SoftwareKeyCustody`]: keys generated in this process, private key sealed by a [`Sealer`] |
//! | [`Sealer`] | encrypt a secret at rest, decrypt it again | [`OpenBaoTransit`] (production), [`InsecureDevSealer`] (dev) |
//! | [`Signer`] | sign and verify public keys (PKS1) and ciphertexts (CTS1) | [`TransitSigner`] (production), [`InsecureDevSigner`] (dev) |
//! | [`GrantKeySource`] | public keys of the grant issuer kept outside this service | [`TransitGrantKeys`] (an OpenBao Transit `mldsa-65` key that E-Office signs with) |
//!
//! `main.rs` picks the implementations from the configuration. To use an HSM, add one
//! file here that implements [`KeyCustody`] (and [`Signer`] if the HSM also signs), then
//! one branch in `main.rs`; see `docs/ARCHITECTURE.md`.

mod dev;
mod openbao;
mod software_custody;

use std::future::Future;
use std::pin::Pin;

use thiserror::Error;
use zeroize::Zeroizing;

use crate::crypto::{Context, CryptoError, KeyIdentity, Suite};

pub use dev::{InsecureDevSealer, InsecureDevSigner};
pub use openbao::{OpenBaoTransit, TransitGrantKeys, TransitSigner};
pub use software_custody::SoftwareKeyCustody;

/// The future every contract method returns. Boxed so the traits can be used as
/// `Arc<dyn KeyCustody>` and friends, which is what lets `main.rs` choose at startup.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("cannot read the backend credentials")]
    Token,
    #[error("cannot reach the backend: {0}")]
    Transport(String),
    #[error("backend rejected the request (HTTP {status}): {errors:?}")]
    Rejected { status: u16, errors: Vec<String> },
    #[error("invalid backend response")]
    BadResponse,
    #[error("invalid blob")]
    BadBlob,
    #[error("backend configuration: {0}")]
    Config(String),
    #[error("private key blob does not belong to this key")]
    Mismatch,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// What [`KeyCustody::create`] hands back to E-Office.
pub struct CreatedKey {
    /// The raw public key, in the suite's layout (the caller signs it).
    pub public_key: Vec<u8>,
    /// Opaque to E-Office: stored per position and key version, sent back to open DEKs.
    /// For [`SoftwareKeyCustody`] it is the sealed private key; for an HSM it would be a
    /// key handle.
    pub private_key_blob: String,
}

/// Who generates position key pairs and holds the private keys.
///
/// An HSM implementation generates the ML-KEM-768 and X25519 key pairs inside the HSM,
/// builds the public key with [`Suite::public_key_from_parts`] and returns a key handle as
/// the blob. To open a DEK it wraps the handle in a [`crate::crypto::suites::PrivateKeyOps`]
/// and calls [`Suite::unwrap_with`], so the private key never leaves the HSM.
pub trait KeyCustody: Send + Sync {
    /// Generates a key pair for `id` with `suite` and keeps the private half.
    fn create<'a>(
        &'a self,
        suite: &'a dyn Suite,
        id: &'a KeyIdentity,
    ) -> BoxFuture<'a, Result<CreatedKey, BackendError>>;

    /// Opens a DEK that `suite` wrapped for `id` under `ctx`, using the private key behind
    /// `private_key_blob`. Fails with [`BackendError::Mismatch`] if the blob belongs to
    /// another position or key version.
    fn unwrap_dek<'a>(
        &'a self,
        suite: &'a dyn Suite,
        id: &'a KeyIdentity,
        private_key_blob: &'a str,
        wrapped: &'a [u8],
        ctx: &'a Context,
    ) -> BoxFuture<'a, Result<Zeroizing<Vec<u8>>, BackendError>>;

    /// For `/readyz`: true if a full round trip through the custody works right now.
    fn ready(&self) -> BoxFuture<'_, bool>;
}

/// Encrypts small secrets (sealed private keys) with a key this service never sees.
pub trait Sealer: Send + Sync {
    fn seal<'a>(&'a self, plaintext: &'a [u8]) -> BoxFuture<'a, Result<String, BackendError>>;
    fn unseal<'a>(
        &'a self,
        blob: &'a str,
    ) -> BoxFuture<'a, Result<Zeroizing<Vec<u8>>, BackendError>>;
}

/// Signs what this service issues (public keys, ciphertexts) and checks it on the way back.
pub trait Signer: Send + Sync {
    fn sign<'a>(&'a self, message: &'a [u8]) -> BoxFuture<'a, Result<String, BackendError>>;
    /// `Ok(false)` for a wrong or foreign signature; `Err` only if the check could not run.
    fn verify<'a>(
        &'a self,
        message: &'a [u8],
        signature: &'a str,
    ) -> BoxFuture<'a, Result<bool, BackendError>>;
}

/// Public keys (raw ML-DSA-65) of a grant issuer whose private key lives elsewhere, so the
/// service follows its rotations without a restart.
pub trait GrantKeySource: Send + Sync {
    /// Every version's public key. Cached; `refresh` asks for a reload, which the source may
    /// rate-limit.
    fn grant_keys(&self, refresh: bool) -> BoxFuture<'_, Result<Vec<Vec<u8>>, BackendError>>;
}
