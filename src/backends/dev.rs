//! In-memory [`Sealer`] and [`Signer`] for local development (`KS_DEV=true` without
//! OpenBao). Their keys are random per process, so every position key and signature is
//! lost on restart. Never use them in production.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use zeroize::Zeroizing;

use super::{BackendError, BoxFuture, Sealer, Signer};
use crate::crypto::primitives::aes::{self, Aes256Gcm};
use crate::crypto::primitives::mldsa::{self, SigningKey};
use crate::crypto::primitives::random;

const PREFIX: &str = "dev:v1:";
const NONCE_LEN: usize = aes::NONCE_LEN;

/// AES-256-GCM under a random in-memory key. Blob: `dev:v1:` + base64(nonce || ct || tag).
pub struct InsecureDevSealer {
    key: Aes256Gcm,
}

impl InsecureDevSealer {
    pub fn new() -> Result<Self, BackendError> {
        let k = random::dek().map_err(|_| BackendError::Config("RNG".into()))?;
        let key = Aes256Gcm::new(&k[..]).map_err(|_| BackendError::Config("KEK".into()))?;
        Ok(Self { key })
    }

    fn seal_now(&self, plaintext: &[u8]) -> Result<String, BackendError> {
        let nonce = random::bytes::<NONCE_LEN>().map_err(|_| BackendError::BadBlob)?;
        let mut buf = plaintext.to_vec();
        self.key
            .seal_append_tag(nonce, PREFIX.as_bytes(), &mut buf)
            .map_err(|_| BackendError::BadBlob)?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&buf);
        Ok(format!("{PREFIX}{}", B64.encode(out)))
    }

    fn unseal_now(&self, blob: &str) -> Result<Zeroizing<Vec<u8>>, BackendError> {
        let raw = blob
            .strip_prefix(PREFIX)
            .and_then(|s| B64.decode(s).ok())
            .filter(|r| r.len() >= NONCE_LEN)
            .ok_or(BackendError::BadBlob)?;
        let (nonce, ct) = raw.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| BackendError::BadBlob)?;
        let mut buf = Zeroizing::new(ct.to_vec());
        let n = self
            .key
            .open(nonce, PREFIX.as_bytes(), &mut buf)
            .map_err(|_| BackendError::BadBlob)?
            .len();
        buf.truncate(n);
        Ok(buf)
    }
}

impl Sealer for InsecureDevSealer {
    fn seal<'a>(&'a self, plaintext: &'a [u8]) -> BoxFuture<'a, Result<String, BackendError>> {
        Box::pin(std::future::ready(self.seal_now(plaintext)))
    }

    fn unseal<'a>(
        &'a self,
        blob: &'a str,
    ) -> BoxFuture<'a, Result<Zeroizing<Vec<u8>>, BackendError>> {
        Box::pin(std::future::ready(self.unseal_now(blob)))
    }
}

/// ML-DSA-65 under a random in-memory key. Signature: `dev:v1:` + base64(signature).
pub struct InsecureDevSigner {
    key: SigningKey,
    public_key: Vec<u8>,
}

const SIGNATURE_PREFIX: &str = "dev:v1:";

impl InsecureDevSigner {
    pub fn new() -> Result<Self, BackendError> {
        let key = SigningKey::generate().map_err(|_| BackendError::Config("signing key".into()))?;
        let public_key = key.public_key();
        Ok(Self { key, public_key })
    }

    fn sign_now(&self, message: &[u8]) -> Result<String, BackendError> {
        let sig = self
            .key
            .sign(message)
            .map_err(|_| BackendError::Config("signing key".into()))?;
        Ok(format!("{SIGNATURE_PREFIX}{}", B64.encode(sig)))
    }

    fn verify_now(&self, message: &[u8], signature: &str) -> bool {
        signature
            .strip_prefix(SIGNATURE_PREFIX)
            .and_then(|s| B64.decode(s).ok())
            .is_some_and(|sig| mldsa::verify(&self.public_key, message, &sig))
    }
}

impl Signer for InsecureDevSigner {
    fn sign<'a>(&'a self, message: &'a [u8]) -> BoxFuture<'a, Result<String, BackendError>> {
        Box::pin(std::future::ready(self.sign_now(message)))
    }

    fn verify<'a>(
        &'a self,
        message: &'a [u8],
        signature: &'a str,
    ) -> BoxFuture<'a, Result<bool, BackendError>> {
        Box::pin(std::future::ready(Ok(self.verify_now(message, signature))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn signer_round_trip_and_isolation() {
        let a = InsecureDevSigner::new().unwrap();
        let b = InsecureDevSigner::new().unwrap();
        let sig = a.sign(b"message").await.unwrap();
        assert!(a.verify(b"message", &sig).await.unwrap());
        assert!(!a.verify(b"other", &sig).await.unwrap());
        assert!(!b.verify(b"message", &sig).await.unwrap());
        assert!(!a.verify(b"message", "vault:v1:AAAA").await.unwrap());
    }

    #[tokio::test]
    async fn round_trip_and_isolation() {
        let a = InsecureDevSealer::new().unwrap();
        let b = InsecureDevSealer::new().unwrap();
        let blob = a.seal(b"secret").await.unwrap();
        assert_eq!(&a.unseal(&blob).await.unwrap()[..], b"secret");
        assert!(b.unseal(&blob).await.is_err(), "another KEK must fail");
    }
}
