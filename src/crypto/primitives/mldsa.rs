//! ML-DSA-65 signatures (FIPS 204), pure mode with an empty context: the same as OpenBao
//! Transit `mldsa-65` keys and OpenSSL 3.5 `pkeyutl -sign -rawin`.

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::signature::{
    KeyPair as _, ML_DSA_65, ML_DSA_65_SIGNING, PqdsaKeyPair, UnparsedPublicKey,
};

use super::Unspecified;

pub const PUBLIC_KEY_LEN: usize = 1952;
pub const SIGNATURE_LEN: usize = 3309;

/// True if `signature` is a valid ML-DSA-65 signature of `message` under the raw
/// `public_key` (1952 bytes, as OpenBao's `transit/keys` returns it).
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    public_key.len() == PUBLIC_KEY_LEN
        && signature.len() == SIGNATURE_LEN
        && UnparsedPublicKey::new(&ML_DSA_65, public_key)
            .verify(message, signature)
            .is_ok()
}

/// An in-memory signing key. Production signatures come from OpenBao Transit; this key is
/// for the dev signer, the Rust grant issuer and tests.
pub struct SigningKey(PqdsaKeyPair);

impl SigningKey {
    pub fn generate() -> Result<Self, Unspecified> {
        PqdsaKeyPair::generate(&ML_DSA_65_SIGNING)
            .map(Self)
            .map_err(|_| Unspecified)
    }

    /// The raw public key (1952 bytes).
    pub fn public_key(&self) -> Vec<u8> {
        self.0.public_key().as_ref().to_vec()
    }

    /// The public key as an X.509 SubjectPublicKeyInfo (RFC 9881), for PEM files.
    pub fn public_key_spki(&self) -> Result<Vec<u8>, Unspecified> {
        self.0
            .public_key()
            .as_der()
            .map(|d| d.as_ref().to_vec())
            .map_err(|_| Unspecified)
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Unspecified> {
        let mut sig = vec![0u8; SIGNATURE_LEN];
        let n = self.0.sign(message, &mut sig).map_err(|_| Unspecified)?;
        sig.truncate(n);
        Ok(sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_and_sizes() {
        let k = SigningKey::generate().unwrap();
        let pk = k.public_key();
        let sig = k.sign(b"message").unwrap();
        assert_eq!((pk.len(), sig.len()), (PUBLIC_KEY_LEN, SIGNATURE_LEN));
        assert!(verify(&pk, b"message", &sig));
        assert!(!verify(&pk, b"other", &sig));
        assert!(!verify(&pk[1..], b"message", &sig), "raw key only");
        assert!(
            !verify(&k.public_key_spki().unwrap(), b"message", &sig),
            "raw key only"
        );
        let other = SigningKey::generate().unwrap().public_key();
        assert!(!verify(&other, b"message", &sig));
    }
}
