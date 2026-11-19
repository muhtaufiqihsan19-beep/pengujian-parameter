//! Cryptographic primitives: one file per algorithm.
//!
//! This folder is the only code that calls `aws-lc-rs` directly
//! (`scripts/check-crypto-deps.sh` enforces it). Suites, EKS1, the backends and grant
//! verification compose these functions, so an audit of "which algorithm, which library"
//! starts and ends here, and the known-answer tests in `tests/kat.rs` run against these
//! wrappers rather than against the library.
//!
//! | File | Algorithm | Used for |
//! |---|---|---|
//! | `aes.rs` | AES-256-GCM, AES-256-KW (RFC 3394) | EKS1 chunks, dev sealer; v2 key wrap |
//! | `mlkem.rs` | ML-KEM-768 (FIPS 203) | post-quantum half of suite v2 |
//! | `x25519.rs` | X25519 (RFC 7748) | classical half of suite v2 |
//! | `hkdf.rs` | HKDF-SHA256 (RFC 5869) | KEK derivation in suite v2 |
//! | `hash.rs` | SHA-256, SHA3-256 (FIPS 180-4, FIPS 202) | signed messages, EKS1 AAD, v2 combiner |
//! | `mldsa.rs` | ML-DSA-65 (FIPS 204) | service signatures (PKS1, CTS1), grants |
//! | `ed25519.rs` | Ed25519 (RFC 8032) | grants from an Ed25519 issuer key, still accepted |
//! | `random.rs` | AWS-LC DRBG | DEKs, nonces, request ids |

pub mod aes;
pub mod ed25519;
pub mod hash;
pub mod hkdf;
pub mod mldsa;
pub mod mlkem;
pub mod random;
pub mod x25519;

/// Whether AWS-LC runs as its FIPS 140-3 validated module, with the power-on self-tests
/// passed. Only true in a build with the `fips` feature (`aws-lc-fips-sys`).
pub fn fips_mode() -> bool {
    aws_lc_rs::try_fips_mode().is_ok()
}

/// A primitive failed. Like `aws-lc-rs`' own error it carries no detail, so callers map it
/// to an error that fits their context (bad input, failed unwrap, internal).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("cryptographic operation failed")]
pub struct Unspecified;

#[cfg(test)]
mod tests {
    #[test]
    fn fips_mode_matches_the_build() {
        assert_eq!(super::fips_mode(), cfg!(feature = "fips"));
    }
}
