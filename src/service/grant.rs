//! Access grants: short-lived tokens, signed by E-Office, that allow one decrypt or one
//! disposition for one document version and one position key.
//!
//! Token: `base64url(claims JSON) . base64url(signature over the first part)`. The
//! signature is ML-DSA-65 (FIPS 204, pure, empty context) or, for issuers that have not
//! moved yet, Ed25519. [`GrantVerifier`] checks it against the configured issuer keys
//! (`KS_GRANT_PUBLIC_KEYS`, X.509 SubjectPublicKeyInfo PEM; the key type decides the
//! algorithm), the lifetime, and that every claim matches the request. [`GrantIssuer`]
//! makes tokens for tests.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as B64URL};
use rustls::pki_types::SubjectPublicKeyInfoDer;
use rustls::pki_types::pem::PemObject;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::backends::GrantKeySource;
use crate::crypto::primitives::{ed25519, mldsa};

const MAX_TOKEN_LEN: usize = 16 << 10;
const CLOCK_SKEW_SECS: u64 = 60;
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
/// SubjectPublicKeyInfo header for id-ml-dsa-65 (2.16.840.1.101.3.4.3.18, RFC 9881).
const MLDSA65_SPKI_PREFIX: [u8; 22] = [
    0x30, 0x82, 0x07, 0xb2, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03,
    0x12, 0x03, 0x82, 0x07, 0xa1, 0x00,
];

/// A grant issuer's public key. The type decides the signature algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerKey {
    /// Raw ML-DSA-65 public key (1952 bytes).
    MlDsa65(Vec<u8>),
    Ed25519([u8; 32]),
}

impl IssuerKey {
    /// From a DER SubjectPublicKeyInfo; `None` for any other key type.
    pub fn from_spki(der: &[u8]) -> Option<Self> {
        if let Some(raw) = der.strip_prefix(&MLDSA65_SPKI_PREFIX[..]) {
            return (raw.len() == mldsa::PUBLIC_KEY_LEN).then(|| Self::MlDsa65(raw.to_vec()));
        }
        der.strip_prefix(&ED25519_SPKI_PREFIX[..])
            .and_then(|k| <[u8; 32]>::try_from(k).ok())
            .map(Self::Ed25519)
    }

    pub fn to_spki(&self) -> Vec<u8> {
        let (prefix, raw): (&[u8], &[u8]) = match self {
            Self::MlDsa65(k) => (&MLDSA65_SPKI_PREFIX, k),
            Self::Ed25519(k) => (&ED25519_SPKI_PREFIX, k),
        };
        [prefix, raw].concat()
    }

    pub fn to_pem(&self) -> String {
        let b64 = STANDARD.encode(self.to_spki());
        let lines: Vec<&str> = b64
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).expect("base64 is ASCII"))
            .collect();
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            lines.join("\n")
        )
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        match self {
            Self::MlDsa65(k) => mldsa::verify(k, message, signature),
            Self::Ed25519(k) => ed25519::verify(k, message, signature),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Decrypt,
    Dispose,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    pub sub: String,
    pub action: Action,
    pub document_id: String,
    pub version: u32,
    pub position_code: String,
    pub key_version: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<String>,
    pub iat: u64,
    pub exp: u64,
}

pub struct Requested<'a> {
    pub action: Action,
    pub document_id: &'a str,
    pub version: u32,
    pub position_code: &'a str,
    pub key_version: u32,
    pub targets: Vec<&'a str>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GrantError {
    #[error("no grant issuer key is configured")]
    NotConfigured,
    #[error("malformed grant")]
    Malformed,
    #[error("invalid grant signature")]
    Signature,
    #[error("grant expired or not yet valid")]
    Expired,
    #[error("grant lifetime exceeds the maximum")]
    TooLong,
    #[error("grant does not match the request: {0}")]
    Mismatch(&'static str),
    #[error("grant issuer keys unavailable: {0}")]
    KeysUnavailable(String),
}

pub struct GrantVerifier {
    issuer_keys: Vec<IssuerKey>,
    /// ML-DSA-65 issuer keys read from OpenBao Transit (`OPENBAO_GRANT_KEY_NAME`).
    source: Option<Arc<dyn GrantKeySource>>,
    max_ttl_secs: u64,
}

impl GrantVerifier {
    pub fn new(issuer_keys: Vec<IssuerKey>, max_ttl: Duration) -> Self {
        Self {
            issuer_keys,
            source: None,
            max_ttl_secs: max_ttl.as_secs(),
        }
    }

    /// Also accepts grants signed by the Transit key behind `source`.
    pub fn with_source(mut self, source: Arc<dyn GrantKeySource>) -> Self {
        self.source = Some(source);
        self
    }

    pub fn disabled() -> Self {
        Self::new(Vec::new(), Duration::ZERO)
    }

    pub fn from_pem_file(path: &Path, max_ttl: Duration) -> Result<Self, String> {
        let err = |e: &dyn std::fmt::Display| format!("{}: {e}", path.display());
        let mut keys = Vec::new();
        for spki in SubjectPublicKeyInfoDer::pem_file_iter(path).map_err(|e| err(&e))? {
            let spki = spki.map_err(|e| err(&e))?;
            let key = IssuerKey::from_spki(spki.as_ref())
                .ok_or_else(|| err(&"not an ML-DSA-65 or Ed25519 public key"))?;
            keys.push(key);
        }
        if keys.is_empty() {
            return Err(err(&"no public key found"));
        }
        Ok(Self::new(keys, max_ttl))
    }

    pub fn is_configured(&self) -> bool {
        !self.issuer_keys.is_empty() || self.source.is_some()
    }

    /// Checks `token` against the keys from `KS_GRANT_PUBLIC_KEYS` only.
    pub fn verify(&self, token: &str, want: &Requested, now: u64) -> Result<Claims, GrantError> {
        let (payload, signature) = self.split(token)?;
        if !self
            .issuer_keys
            .iter()
            .any(|k| k.verify(payload.as_bytes(), &signature))
        {
            return Err(GrantError::Signature);
        }
        self.claims(payload, want, now)
    }

    /// Like [`Self::verify`], and also against the Transit issuer keys, reloaded once if
    /// none of the cached ones fits (the issuer may have rotated).
    pub async fn verify_with_source(
        &self,
        token: &str,
        want: &Requested<'_>,
        now: u64,
    ) -> Result<Claims, GrantError> {
        let result = self.verify(token, want, now);
        let Some(source) = &self.source else {
            return result;
        };
        if result != Err(GrantError::Signature) {
            return result;
        }
        let (payload, signature) = self.split(token)?;
        for refresh in [false, true] {
            let keys = source
                .grant_keys(refresh)
                .await
                .map_err(|e| GrantError::KeysUnavailable(e.to_string()))?;
            if keys
                .iter()
                .any(|k| mldsa::verify(k, payload.as_bytes(), &signature))
            {
                return self.claims(payload, want, now);
            }
        }
        Err(GrantError::Signature)
    }

    fn split<'t>(&self, token: &'t str) -> Result<(&'t str, Vec<u8>), GrantError> {
        if !self.is_configured() {
            return Err(GrantError::NotConfigured);
        }
        if token.len() > MAX_TOKEN_LEN {
            return Err(GrantError::Malformed);
        }
        let (payload, signature) = token.split_once('.').ok_or(GrantError::Malformed)?;
        let signature = B64URL
            .decode(signature)
            .map_err(|_| GrantError::Malformed)?;
        Ok((payload, signature))
    }

    /// The claims of a token whose signature is already checked.
    fn claims(&self, payload: &str, want: &Requested, now: u64) -> Result<Claims, GrantError> {
        let json = B64URL.decode(payload).map_err(|_| GrantError::Malformed)?;
        let claims: Claims = serde_json::from_slice(&json).map_err(|_| GrantError::Malformed)?;

        if claims.exp <= claims.iat {
            return Err(GrantError::Malformed);
        }
        if claims.exp - claims.iat > self.max_ttl_secs {
            return Err(GrantError::TooLong);
        }
        if now + CLOCK_SKEW_SECS < claims.iat || now >= claims.exp {
            return Err(GrantError::Expired);
        }
        check_matches(&claims, want)?;
        Ok(claims)
    }
}

fn check_matches(c: &Claims, want: &Requested) -> Result<(), GrantError> {
    use GrantError::Mismatch;
    if c.action != want.action {
        return Err(Mismatch("action"));
    }
    if c.document_id != want.document_id || c.version != want.version {
        return Err(Mismatch("document"));
    }
    if c.position_code != want.position_code || c.key_version != want.key_version {
        return Err(Mismatch("position"));
    }
    let mut granted: Vec<&str> = c.targets.iter().map(String::as_str).collect();
    granted.sort_unstable();
    let before = granted.len();
    granted.dedup();
    let mut requested = want.targets.clone();
    requested.sort_unstable();
    if granted.len() != before || granted != requested {
        return Err(Mismatch("targets"));
    }
    Ok(())
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

enum IssuerSigningKey {
    MlDsa65(mldsa::SigningKey),
    Ed25519(ed25519::SigningKey),
}

/// Makes grants with an in-memory key, for tests. E-Office signs its grants itself
/// (OpenBao Transit `mldsa-65` in production).
pub struct GrantIssuer {
    key: IssuerSigningKey,
}

impl GrantIssuer {
    /// An ML-DSA-65 issuer.
    pub fn generate() -> Result<Self, String> {
        mldsa::SigningKey::generate()
            .map(|k| Self {
                key: IssuerSigningKey::MlDsa65(k),
            })
            .map_err(|e| e.to_string())
    }

    /// An Ed25519 issuer, the older key type that is still accepted.
    pub fn generate_ed25519() -> Result<Self, String> {
        ed25519::SigningKey::generate()
            .map(|k| Self {
                key: IssuerSigningKey::Ed25519(k),
            })
            .map_err(|e| e.to_string())
    }

    pub fn public_key(&self) -> IssuerKey {
        match &self.key {
            IssuerSigningKey::MlDsa65(k) => IssuerKey::MlDsa65(k.public_key()),
            IssuerSigningKey::Ed25519(k) => IssuerKey::Ed25519(k.public_key()),
        }
    }

    pub fn public_key_pem(&self) -> String {
        self.public_key().to_pem()
    }

    fn sign_bytes(&self, message: &[u8]) -> Vec<u8> {
        match &self.key {
            IssuerSigningKey::MlDsa65(k) => k.sign(message).expect("ML-DSA signing"),
            IssuerSigningKey::Ed25519(k) => k.sign(message).to_vec(),
        }
    }

    pub fn sign(&self, claims: &Claims) -> String {
        let payload = B64URL.encode(serde_json::to_vec(claims).expect("claims serialize"));
        let signature = self.sign_bytes(payload.as_bytes());
        format!("{payload}.{}", B64URL.encode(signature))
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use std::sync::OnceLock;

    use super::*;

    pub(crate) const TTL: Duration = Duration::from_secs(300);

    pub(crate) fn issuer() -> &'static GrantIssuer {
        static ISSUER: OnceLock<GrantIssuer> = OnceLock::new();
        ISSUER.get_or_init(|| GrantIssuer::generate().unwrap())
    }

    pub(crate) fn verifier() -> GrantVerifier {
        GrantVerifier::new(vec![issuer().public_key()], TTL)
    }

    pub(crate) fn claims(
        action: Action,
        document_id: &str,
        version: u32,
        position: &str,
    ) -> Claims {
        let now = now_unix();
        Claims {
            sub: "user-1".into(),
            action,
            document_id: document_id.into(),
            version,
            position_code: position.into(),
            key_version: 1,
            targets: Vec::new(),
            iat: now,
            exp: now + 120,
        }
    }

    pub(crate) fn decrypt_grant(document_id: &str, version: u32, position: &str) -> String {
        issuer().sign(&claims(Action::Decrypt, document_id, version, position))
    }

    pub(crate) fn dispose_grant(
        document_id: &str,
        version: u32,
        position: &str,
        targets: &[&str],
    ) -> String {
        let mut c = claims(Action::Dispose, document_id, version, position);
        c.targets = targets.iter().map(|t| t.to_string()).collect();
        issuer().sign(&c)
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    fn requested(action: Action, targets: Vec<&'static str>) -> Requested<'static> {
        Requested {
            action,
            document_id: "DOC-1",
            version: 2,
            position_code: "HEAD-OF-BUREAU",
            key_version: 1,
            targets,
        }
    }

    fn base() -> Claims {
        claims(Action::Decrypt, "DOC-1", 2, "HEAD-OF-BUREAU")
    }

    fn verify(token: &str, want: &Requested) -> Result<Claims, GrantError> {
        verifier().verify(token, want, now_unix())
    }

    #[test]
    fn valid_grant_accepted() {
        let got = verify(&issuer().sign(&base()), &requested(Action::Decrypt, vec![])).unwrap();
        assert_eq!(got, base());
    }

    #[test]
    fn each_field_must_match() {
        let want = requested(Action::Decrypt, vec![]);
        type Mutation = (&'static str, fn(&mut Claims));
        let cases: [Mutation; 5] = [
            ("action", |c| c.action = Action::Dispose),
            ("document", |c| c.document_id = "DOC-2".into()),
            ("document", |c| c.version = 3),
            ("position", |c| c.position_code = "STAFF".into()),
            ("position", |c| c.key_version = 2),
        ];
        for (field, mutate) in cases {
            let mut c = base();
            mutate(&mut c);
            assert_eq!(
                verify(&issuer().sign(&c), &want),
                Err(GrantError::Mismatch(field))
            );
        }
    }

    #[test]
    fn disposition_targets_compared_as_exact_set() {
        let mut c = base();
        c.action = Action::Dispose;
        c.targets = vec!["B".into(), "A".into()];
        let token = issuer().sign(&c);
        assert!(verify(&token, &requested(Action::Dispose, vec!["A", "B"])).is_ok());
        for targets in [vec!["A"], vec!["A", "B", "C"], vec!["A", "X"], vec![]] {
            assert_eq!(
                verify(&token, &requested(Action::Dispose, targets)),
                Err(GrantError::Mismatch("targets"))
            );
        }
        c.targets = vec!["A".into(), "A".into()];
        assert_eq!(
            verify(&issuer().sign(&c), &requested(Action::Dispose, vec!["A"])),
            Err(GrantError::Mismatch("targets"))
        );
    }

    #[test]
    fn signature_and_issuer_checked() {
        let want = requested(Action::Decrypt, vec![]);
        let other = GrantIssuer::generate().unwrap();
        assert_eq!(
            verify(&other.sign(&base()), &want),
            Err(GrantError::Signature)
        );

        let token = issuer().sign(&base());
        let mut forged = base();
        forged.position_code = "ADMIN-STAFF".into();
        let forged_payload = issuer().sign(&forged);
        let (payload, _) = forged_payload.split_once('.').unwrap();
        let (_, signature) = token.split_once('.').unwrap();
        assert_eq!(
            verify(&format!("{payload}.{signature}"), &want),
            Err(GrantError::Signature)
        );

        let rotated = GrantVerifier::new(vec![other.public_key(), issuer().public_key()], TTL);
        assert!(rotated.verify(&token, &want, now_unix()).is_ok());
    }

    #[test]
    fn lifetime_enforced() {
        let want = requested(Action::Decrypt, vec![]);
        let now = now_unix();
        let at = |iat: u64, exp: u64| {
            let mut c = base();
            (c.iat, c.exp) = (iat, exp);
            issuer().sign(&c)
        };
        assert_eq!(
            verify(&at(now - 200, now - 1), &want),
            Err(GrantError::Expired)
        );
        assert_eq!(
            verify(&at(now + 600, now + 700), &want),
            Err(GrantError::Expired)
        );
        assert_eq!(verify(&at(now, now + 301), &want), Err(GrantError::TooLong));
        assert_eq!(verify(&at(now, now), &want), Err(GrantError::Malformed));
        assert!(
            verify(&at(now + 30, now + 100), &want).is_ok(),
            "small clock skew is tolerated"
        );
    }

    #[test]
    fn malformed_and_unconfigured() {
        let want = requested(Action::Decrypt, vec![]);
        for token in ["", "abc", "a.b", &"x".repeat(MAX_TOKEN_LEN + 1)] {
            assert!(verify(token, &want).is_err(), "{token:.10}");
        }
        let payload = B64URL.encode(br#"{"sub":"u","extra":1}"#);
        let sig = B64URL.encode(issuer().sign_bytes(payload.as_bytes()));
        assert_eq!(
            verify(&format!("{payload}.{sig}"), &want),
            Err(GrantError::Malformed)
        );

        let token = issuer().sign(&base());
        assert_eq!(
            GrantVerifier::disabled().verify(&token, &want, now_unix()),
            Err(GrantError::NotConfigured)
        );
    }

    #[test]
    fn pem_round_trip() {
        let dir = std::env::temp_dir().join(format!(
            "ks-grant-{}",
            now_unix() ^ u64::from(std::process::id())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("issuers.pem");
        let other = GrantIssuer::generate_ed25519().unwrap();
        std::fs::write(&path, issuer().public_key_pem() + &other.public_key_pem()).unwrap();
        let v = GrantVerifier::from_pem_file(&path, TTL).unwrap();
        assert_eq!(
            v.issuer_keys,
            vec![issuer().public_key(), other.public_key()]
        );

        std::fs::write(&path, "").unwrap();
        assert!(GrantVerifier::from_pem_file(&path, TTL).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mldsa_spki_matches_the_library() {
        let k = mldsa::SigningKey::generate().unwrap();
        let spki = k.public_key_spki().unwrap();
        assert_eq!(
            IssuerKey::from_spki(&spki),
            Some(IssuerKey::MlDsa65(k.public_key()))
        );
        assert_eq!(IssuerKey::MlDsa65(k.public_key()).to_spki(), spki);
        assert_eq!(IssuerKey::from_spki(&spki[..spki.len() - 1]), None);
    }

    #[test]
    fn ed25519_issuers_still_accepted_and_types_do_not_cross() {
        let want = requested(Action::Decrypt, vec![]);
        let ed = GrantIssuer::generate_ed25519().unwrap();
        let both = GrantVerifier::new(vec![issuer().public_key(), ed.public_key()], TTL);
        assert!(both.verify(&ed.sign(&base()), &want, now_unix()).is_ok());
        assert!(
            both.verify(&issuer().sign(&base()), &want, now_unix())
                .is_ok()
        );

        let mldsa_only = verifier();
        assert_eq!(
            mldsa_only.verify(&ed.sign(&base()), &want, now_unix()),
            Err(GrantError::Signature)
        );
        let ed_only = GrantVerifier::new(vec![ed.public_key()], TTL);
        assert_eq!(
            ed_only.verify(&issuer().sign(&base()), &want, now_unix()),
            Err(GrantError::Signature)
        );
    }

    #[test]
    fn other_key_types_rejected_in_pem() {
        let dir = std::env::temp_dir().join(format!(
            "ks-grant-p256-{}",
            now_unix() ^ u64::from(std::process::id())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("issuers.pem");
        // An ECDSA P-256 public key.
        std::fs::write(
            &path,
            "-----BEGIN PUBLIC KEY-----\n\
             MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9\n\
             q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==\n\
             -----END PUBLIC KEY-----\n",
        )
        .unwrap();
        let err = GrantVerifier::from_pem_file(&path, TTL).err().unwrap();
        assert!(err.contains("ML-DSA-65"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    struct FakeSource {
        cached: Vec<Vec<u8>>,
        reloaded: Option<Vec<Vec<u8>>>,
        calls: std::sync::Mutex<Vec<bool>>,
    }

    impl GrantKeySource for FakeSource {
        fn grant_keys(
            &self,
            refresh: bool,
        ) -> crate::backends::BoxFuture<'_, Result<Vec<Vec<u8>>, crate::backends::BackendError>>
        {
            self.calls.lock().unwrap().push(refresh);
            let r = match (&self.reloaded, refresh) {
                (None, true) => Err(crate::backends::BackendError::Transport("down".into())),
                (Some(k), true) => Ok(k.clone()),
                (_, false) => Ok(self.cached.clone()),
            };
            Box::pin(std::future::ready(r))
        }
    }

    fn mldsa_raw(i: &GrantIssuer) -> Vec<u8> {
        match i.public_key() {
            IssuerKey::MlDsa65(k) => k,
            IssuerKey::Ed25519(_) => unreachable!(),
        }
    }

    #[tokio::test]
    async fn transit_issuer_keys_and_rotation() {
        let want = requested(Action::Decrypt, vec![]);
        let old = GrantIssuer::generate().unwrap();
        let new = GrantIssuer::generate().unwrap();
        let source = Arc::new(FakeSource {
            cached: vec![mldsa_raw(&old)],
            reloaded: Some(vec![mldsa_raw(&new), mldsa_raw(&old)]),
            calls: Default::default(),
        });
        let v = GrantVerifier::new(Vec::new(), TTL).with_source(source.clone());
        assert!(v.is_configured());

        assert!(
            v.verify_with_source(&old.sign(&base()), &want, now_unix())
                .await
                .is_ok()
        );
        assert_eq!(*source.calls.lock().unwrap(), vec![false]);

        assert!(
            v.verify_with_source(&new.sign(&base()), &want, now_unix())
                .await
                .is_ok()
        );
        assert_eq!(*source.calls.lock().unwrap(), vec![false, false, true]);

        let stranger = GrantIssuer::generate().unwrap();
        assert_eq!(
            v.verify_with_source(&stranger.sign(&base()), &want, now_unix())
                .await,
            Err(GrantError::Signature)
        );

        let mut wrong = base();
        wrong.position_code = "ADMIN-STAFF".into();
        assert_eq!(
            v.verify_with_source(&old.sign(&wrong), &want, now_unix())
                .await,
            Err(GrantError::Mismatch("position"))
        );
    }

    #[tokio::test]
    async fn static_keys_need_no_source_call_and_source_errors_surface() {
        let want = requested(Action::Decrypt, vec![]);
        let source = Arc::new(FakeSource {
            cached: Vec::new(),
            reloaded: None,
            calls: Default::default(),
        });
        let v = verifier().with_source(source.clone());
        assert!(
            v.verify_with_source(&issuer().sign(&base()), &want, now_unix())
                .await
                .is_ok()
        );
        assert!(source.calls.lock().unwrap().is_empty());

        let stranger = GrantIssuer::generate().unwrap();
        assert!(matches!(
            v.verify_with_source(&stranger.sign(&base()), &want, now_unix())
                .await,
            Err(GrantError::KeysUnavailable(_))
        ));
    }
}
