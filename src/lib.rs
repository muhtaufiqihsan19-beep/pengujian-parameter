#![forbid(unsafe_code)]
//! Crypto Service for E-Office. Layers, each using only the ones below it:
//!
//! ```text
//! server   network, TLS 1.3 / mTLS
//! api      HTTP endpoints (JSON in, JSON out)
//! service  business flows: keys, encrypt, decrypt, disposition, grants
//! backends swappable parts: key custody, sealer, signer (OpenBao, dev, later HSM)
//! crypto   primitives (aws-lc-rs), key-wrap suites, EKS1 and other formats
//! ```
//!
//! `main.rs` reads [`config`], picks the backends and wires everything together.
//! See `docs/ARCHITECTURE.md` for the full map.

pub mod api;
pub mod backends;
pub mod config;
pub mod crypto;
pub mod server;
pub mod service;
