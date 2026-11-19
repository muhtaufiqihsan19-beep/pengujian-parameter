//! OpenBao Transit adapter, the production backend.
//!
//! - [`OpenBaoTransit`] is a [`Sealer`]: `transit/encrypt` and `transit/decrypt` with the
//!   `jabatan-kek` key (AES-256-GCM inside OpenBao; the key never leaves it).
//! - [`TransitSigner`] is a [`Signer`]: `transit/sign` with an ML-DSA-65 key (`mldsa-65`),
//!   and local verification against the public keys from `transit/keys` (cached).
//! - [`TransitGrantKeys`] is a [`GrantKeySource`]: the public keys of the `mldsa-65` key
//!   E-Office signs grants with. This service may only read them, never sign.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use bytes::Bytes;
use reqwest::Method;
use reqwest::header::{CONTENT_TYPE, HeaderValue};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use super::{BackendError, BoxFuture, GrantKeySource, Sealer, Signer};
use crate::crypto::primitives::mldsa;

const KEY_REFRESH_INTERVAL: Duration = Duration::from_secs(10);
/// The only Transit key type the signer accepts (`transit/keys` field `type`).
pub const SIGNING_KEY_TYPE: &str = "mldsa-65";

#[derive(Clone)]
pub struct OpenBaoTransit {
    pub addr: String,
    pub mount: String,
    pub key_name: String,
    pub namespace: Option<String>,
    pub token_file: PathBuf,
    pub http: reqwest::Client,
}

#[derive(Deserialize, Default)]
struct TransitData {
    #[serde(default)]
    ciphertext: String,
    #[serde(default)]
    plaintext: String,
    #[serde(default)]
    signature: String,
}

impl Drop for TransitData {
    fn drop(&mut self) {
        self.plaintext.zeroize();
    }
}

#[derive(Deserialize, Default)]
struct TransitResponse {
    #[serde(default)]
    data: Option<TransitData>,
    #[serde(default)]
    errors: Vec<String>,
}

#[derive(Deserialize)]
struct KeyInfo {
    #[serde(default)]
    public_key: String,
}

#[derive(Deserialize)]
struct KeysData {
    #[serde(rename = "type", default)]
    key_type: String,
    keys: BTreeMap<String, KeyInfo>,
}

#[derive(Deserialize)]
struct KeysResponse {
    data: KeysData,
}

#[derive(Serialize, Default)]
struct TransitRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    plaintext: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ciphertext: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    input: Option<&'a str>,
}

impl TransitRequest<'_> {
    fn encoded_len(&self) -> usize {
        [self.plaintext, self.ciphertext, self.input]
            .iter()
            .flatten()
            .map(|v| v.len())
            .sum::<usize>()
            + 64
    }
}

impl OpenBaoTransit {
    pub fn http_client(
        ca_pem_file: Option<&Path>,
        https_only: bool,
    ) -> Result<reqwest::Client, BackendError> {
        use rustls::pki_types::CertificateDer;
        use rustls::pki_types::pem::PemObject;

        let config_err =
            |e: &dyn std::fmt::Display| BackendError::Config(format!("OpenBao CA: {e}"));
        let mut roots = rustls::RootCertStore::empty();
        if let Some(path) = ca_pem_file {
            for cert in CertificateDer::pem_file_iter(path).map_err(|e| config_err(&e))? {
                roots
                    .add(cert.map_err(|e| config_err(&e))?)
                    .map_err(|e| config_err(&e))?;
            }
        }
        let tls = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
        reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .redirect(reqwest::redirect::Policy::none())
            .https_only(https_only)
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| BackendError::Config(e.to_string()))
    }

    pub fn with_key(&self, key_name: &str) -> Self {
        Self {
            key_name: key_name.to_string(),
            ..self.clone()
        }
    }

    async fn send(
        &self,
        method: Method,
        op: &str,
        body: Option<&TransitRequest<'_>>,
    ) -> Result<Zeroizing<Vec<u8>>, BackendError> {
        let token = Zeroizing::new(
            tokio::fs::read_to_string(&self.token_file)
                .await
                .map_err(|_| BackendError::Token)?,
        );
        let mut token_header =
            HeaderValue::from_str(token.trim()).map_err(|_| BackendError::Token)?;
        token_header.set_sensitive(true);

        let url = format!(
            "{}/v1/{}/{}/{}",
            self.addr.trim_end_matches('/'),
            self.mount,
            op,
            self.key_name
        );
        let mut req = self
            .http
            .request(method, url)
            .header("X-Vault-Token", token_header);
        if let Some(body) = body {
            let mut json = Zeroizing::new(Vec::with_capacity(body.encoded_len()));
            serde_json::to_writer(&mut *json, body)
                .map_err(|e| BackendError::Config(e.to_string()))?;
            req = req
                .header(CONTENT_TYPE, "application/json")
                .body(Bytes::from_owner(json));
        }
        if let Some(ns) = &self.namespace {
            req = req.header("X-Vault-Namespace", ns);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;
        let status = resp.status().as_u16();
        let raw = Zeroizing::new(Vec::from(
            resp.bytes()
                .await
                .map_err(|e| BackendError::Transport(e.to_string()))?,
        ));
        if status != 200 {
            let errors = serde_json::from_slice::<TransitResponse>(&raw)
                .map(|mut r| std::mem::take(&mut r.errors))
                .unwrap_or_default();
            return Err(BackendError::Rejected { status, errors });
        }
        Ok(raw)
    }

    async fn call(&self, op: &str, body: &TransitRequest<'_>) -> Result<TransitData, BackendError> {
        let raw = self.send(Method::POST, op, Some(body)).await?;
        let mut parsed: TransitResponse =
            serde_json::from_slice(&raw).map_err(|_| BackendError::BadResponse)?;
        parsed.data.take().ok_or(BackendError::BadResponse)
    }

    /// `transit/encrypt`: returns the `vault:vN:...` ciphertext.
    pub async fn encrypt(&self, plaintext: &[u8]) -> Result<String, BackendError> {
        let encoded = Zeroizing::new(B64.encode(plaintext));
        let request = TransitRequest {
            plaintext: Some(&encoded),
            ..Default::default()
        };
        let mut data = self.call("encrypt", &request).await?;
        if data.ciphertext.is_empty() {
            return Err(BackendError::BadResponse);
        }
        Ok(std::mem::take(&mut data.ciphertext))
    }

    /// `transit/decrypt`.
    pub async fn decrypt(&self, blob: &str) -> Result<Zeroizing<Vec<u8>>, BackendError> {
        let request = TransitRequest {
            ciphertext: Some(blob),
            ..Default::default()
        };
        let mut data = self.call("decrypt", &request).await?;
        let encoded = Zeroizing::new(std::mem::take(&mut data.plaintext));
        B64.decode(encoded.as_bytes())
            .map(Zeroizing::new)
            .map_err(|_| BackendError::BadResponse)
    }

    /// `transit/sign`: returns the `vault:vN:...` signature.
    pub async fn sign(&self, message: &[u8]) -> Result<String, BackendError> {
        let input = B64.encode(message);
        let request = TransitRequest {
            input: Some(&input),
            ..Default::default()
        };
        let mut data = self.call("sign", &request).await?;
        if !data.signature.starts_with("vault:v") {
            return Err(BackendError::BadResponse);
        }
        Ok(std::mem::take(&mut data.signature))
    }

    /// `transit/keys`: every version's raw ML-DSA-65 public key. Fails if the key is of
    /// another type, so a key created with the wrong type shows up as a clear error.
    pub async fn public_keys(&self) -> Result<HashMap<u32, Vec<u8>>, BackendError> {
        let raw = self.send(Method::GET, "keys", None).await?;
        let parsed: KeysResponse =
            serde_json::from_slice(&raw).map_err(|_| BackendError::BadResponse)?;
        if parsed.data.key_type != SIGNING_KEY_TYPE {
            return Err(BackendError::Config(format!(
                "Transit key {} is of type {:?}, expected {SIGNING_KEY_TYPE}",
                self.key_name, parsed.data.key_type
            )));
        }
        parsed
            .data
            .keys
            .into_iter()
            .map(|(version, info)| {
                let version = version
                    .parse::<u32>()
                    .map_err(|_| BackendError::BadResponse)?;
                let key = B64
                    .decode(info.public_key)
                    .ok()
                    .filter(|k| k.len() == mldsa::PUBLIC_KEY_LEN)
                    .ok_or(BackendError::BadResponse)?;
                Ok((version, key))
            })
            .collect()
    }
}

impl Sealer for OpenBaoTransit {
    fn seal<'a>(&'a self, plaintext: &'a [u8]) -> BoxFuture<'a, Result<String, BackendError>> {
        Box::pin(self.encrypt(plaintext))
    }

    fn unseal<'a>(
        &'a self,
        blob: &'a str,
    ) -> BoxFuture<'a, Result<Zeroizing<Vec<u8>>, BackendError>> {
        Box::pin(self.decrypt(blob))
    }
}

type KeyCache = (HashMap<u32, Vec<u8>>, Option<Instant>);

pub struct TransitSigner {
    transit: OpenBaoTransit,
    keys: tokio::sync::Mutex<KeyCache>,
}

impl TransitSigner {
    pub fn new(transit: OpenBaoTransit) -> Self {
        Self {
            transit,
            keys: tokio::sync::Mutex::new((HashMap::new(), None)),
        }
    }

    async fn verify_locally(&self, message: &[u8], signature: &str) -> Result<bool, BackendError> {
        let parsed = signature
            .strip_prefix("vault:v")
            .and_then(|rest| rest.split_once(':'))
            .and_then(|(version, sig)| Some((version.parse::<u32>().ok()?, B64.decode(sig).ok()?)));
        let Some((version, sig)) = parsed else {
            return Ok(false);
        };
        let Some(key) = self.public_key(version).await? else {
            return Ok(false);
        };
        Ok(mldsa::verify(&key, message, &sig))
    }

    async fn public_key(&self, version: u32) -> Result<Option<Vec<u8>>, BackendError> {
        let mut cache = self.keys.lock().await;
        if let Some(key) = cache.0.get(&version) {
            return Ok(Some(key.clone()));
        }
        if cache
            .1
            .is_some_and(|at| at.elapsed() < KEY_REFRESH_INTERVAL)
        {
            return Ok(None);
        }
        let keys = self.transit.public_keys().await?;
        *cache = (keys, Some(Instant::now()));
        Ok(cache.0.get(&version).cloned())
    }
}

/// After this long the grant keys are read again even if every grant verified, so a version
/// trimmed in OpenBao (a compromised grant key) stops being accepted.
const GRANT_KEYS_MAX_AGE: Duration = Duration::from_secs(300);

/// Public keys of the grant issuer's Transit key, read with `transit/keys` and cached.
pub struct TransitGrantKeys {
    transit: OpenBaoTransit,
    cache: tokio::sync::Mutex<(Vec<Vec<u8>>, Option<Instant>)>,
}

impl TransitGrantKeys {
    pub fn new(transit: OpenBaoTransit) -> Self {
        Self {
            transit,
            cache: tokio::sync::Mutex::new((Vec::new(), None)),
        }
    }

    async fn keys(&self, refresh: bool) -> Result<Vec<Vec<u8>>, BackendError> {
        let mut cache = self.cache.lock().await;
        let age = cache.1.map(|at| at.elapsed());
        let stale = age.is_none_or(|a| a >= GRANT_KEYS_MAX_AGE);
        let recent = age.is_some_and(|a| a < KEY_REFRESH_INTERVAL);
        if stale || (refresh && !recent) {
            let mut keys: Vec<(u32, Vec<u8>)> =
                self.transit.public_keys().await?.into_iter().collect();
            keys.sort_by_key(|k| std::cmp::Reverse(k.0));
            *cache = (
                keys.into_iter().map(|(_, k)| k).collect(),
                Some(Instant::now()),
            );
        }
        Ok(cache.0.clone())
    }
}

impl GrantKeySource for TransitGrantKeys {
    fn grant_keys(&self, refresh: bool) -> BoxFuture<'_, Result<Vec<Vec<u8>>, BackendError>> {
        Box::pin(self.keys(refresh))
    }
}

impl Signer for TransitSigner {
    fn sign<'a>(&'a self, message: &'a [u8]) -> BoxFuture<'a, Result<String, BackendError>> {
        Box::pin(self.transit.sign(message))
    }

    fn verify<'a>(
        &'a self,
        message: &'a [u8],
        signature: &'a str,
    ) -> BoxFuture<'a, Result<bool, BackendError>> {
        Box::pin(self.verify_locally(message, signature))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::primitives::{mldsa::SigningKey, random};
    use axum::{Json, Router, http::HeaderMap, http::StatusCode, routing::post};
    use serde_json::{Value, json};

    async fn fake_transit(token: &'static str) -> String {
        let authorized = move |h: &HeaderMap| {
            h.get("X-Vault-Token").and_then(|v| v.to_str().ok()) == Some(token)
        };
        let denied = || {
            (
                StatusCode::FORBIDDEN,
                Json(json!({"errors": ["permission denied"]})),
            )
        };
        let app = Router::new()
            .route(
                "/v1/transit/encrypt/jabatan-kek",
                post(move |h: HeaderMap, Json(b): Json<Value>| async move {
                    if !authorized(&h) {
                        return denied();
                    }
                    let pt: String = b["plaintext"]
                        .as_str()
                        .unwrap_or_default()
                        .chars()
                        .rev()
                        .collect();
                    (
                        StatusCode::OK,
                        Json(json!({"data": {"ciphertext": format!("vault:v1:{pt}")}})),
                    )
                }),
            )
            .route(
                "/v1/transit/decrypt/jabatan-kek",
                post(move |h: HeaderMap, Json(b): Json<Value>| async move {
                    if !authorized(&h) {
                        return denied();
                    }
                    let ct = b["ciphertext"].as_str().unwrap_or_default();
                    let Some(pt) = ct.strip_prefix("vault:v1:") else {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(json!({"errors": ["invalid ciphertext"]})),
                        );
                    };
                    let pt: String = pt.chars().rev().collect();
                    (StatusCode::OK, Json(json!({"data": {"plaintext": pt}})))
                }),
            )
            .route(
                "/v1/redirect/encrypt/jabatan-kek",
                post(|| async {
                    (
                        StatusCode::TEMPORARY_REDIRECT,
                        [("location", "/v1/transit/encrypt/jabatan-kek")],
                    )
                }),
            )
            .route(
                "/v1/broken/encrypt/jabatan-kek",
                post(|| async { (StatusCode::SERVICE_UNAVAILABLE, "upstream down") }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    struct TokenFile(PathBuf);

    impl Drop for TokenFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn token_file(content: &str) -> TokenFile {
        let mut r = [0u8; 8];
        random::fill(&mut r).unwrap();
        let path = std::env::temp_dir().join(format!("ks-token-{}", u64::from_be_bytes(r)));
        std::fs::write(&path, content).unwrap();
        TokenFile(path)
    }

    fn transit(addr: String, token: &TokenFile, mount: &str) -> OpenBaoTransit {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        OpenBaoTransit {
            addr,
            mount: mount.into(),
            key_name: "jabatan-kek".into(),
            namespace: None,
            token_file: token.0.clone(),
            http: OpenBaoTransit::http_client(None, false).unwrap(),
        }
    }

    #[tokio::test]
    async fn round_trip() {
        let addr = fake_transit("s.token").await;
        let tf = token_file("s.token\n");
        let t = transit(addr, &tf, "transit");
        let blob = t.seal(b"secret").await.unwrap();
        assert!(blob.starts_with("vault:v1:"));
        assert_eq!(&t.unseal(&blob).await.unwrap()[..], b"secret");
    }

    #[tokio::test]
    async fn wrong_token_is_403() {
        let addr = fake_transit("s.right").await;
        let tf = token_file("s.wrong");
        let t = transit(addr, &tf, "transit");
        assert!(matches!(
            t.seal(b"x").await,
            Err(BackendError::Rejected { status: 403, .. })
        ));
    }

    #[tokio::test]
    async fn bad_blob_is_400_and_escaped() {
        let addr = fake_transit("s.token").await;
        let tf = token_file("s.token");
        let t = transit(addr, &tf, "transit");
        assert!(matches!(
            t.unseal("x\",\"context\":\"y").await,
            Err(BackendError::Rejected { status: 400, .. })
        ));
    }

    #[tokio::test]
    async fn redirects_not_followed() {
        let addr = fake_transit("s.token").await;
        let tf = token_file("s.token");
        let t = transit(addr, &tf, "redirect");
        assert!(matches!(
            t.seal(b"private key").await,
            Err(BackendError::Rejected { status: 307, .. })
        ));
    }

    #[tokio::test]
    async fn non_json_error_keeps_status() {
        let addr = fake_transit("s.token").await;
        let tf = token_file("s.token");
        let t = transit(addr, &tf, "broken");
        assert!(matches!(
            t.seal(b"x").await,
            Err(BackendError::Rejected { status: 503, .. })
        ));
    }

    #[test]
    fn https_only_rejects_plain_http() {
        let tf = token_file("s.token");
        let mut t = transit("http://127.0.0.1:1".into(), &tf, "transit");
        t.http = OpenBaoTransit::http_client(None, true).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert!(matches!(
            rt.block_on(t.seal(b"x")),
            Err(BackendError::Transport(_))
        ));
    }

    async fn fake_signing_transit(
        key_fetches: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        key_type: &'static str,
    ) -> String {
        use axum::routing::get;
        use std::sync::atomic::Ordering;

        let key = std::sync::Arc::new(SigningKey::generate().unwrap());
        let public = B64.encode(key.public_key());
        let app = Router::new()
            .route(
                "/v1/transit/sign/signing-key",
                post(move |Json(b): Json<Value>| {
                    let key = key.clone();
                    async move {
                        let input = B64.decode(b["input"].as_str().unwrap()).unwrap();
                        let sig = B64.encode(key.sign(&input).unwrap());
                        Json(json!({"data": {"signature": format!("vault:v1:{sig}"), "key_version": 1}}))
                    }
                }),
            )
            .route(
                "/v1/transit/keys/signing-key",
                get(move || {
                    key_fetches.fetch_add(1, Ordering::SeqCst);
                    let public = public.clone();
                    async move { Json(json!({"data": {"type": key_type, "keys": {"1": {"public_key": public, "name": key_type}}}})) }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn transit_signer_sign_and_verify() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let fetches = std::sync::Arc::new(AtomicUsize::new(0));
        let addr = fake_signing_transit(fetches.clone(), SIGNING_KEY_TYPE).await;
        let tf = token_file("s.token");
        let signer = TransitSigner::new(transit(addr, &tf, "transit").with_key("signing-key"));

        let sig = signer.sign(b"message").await.unwrap();
        assert!(sig.starts_with("vault:v1:"));
        assert!(signer.verify(b"message", &sig).await.unwrap());
        assert!(!signer.verify(b"other", &sig).await.unwrap());
        for bad in [
            "",
            "vault:v1:",
            "vault:vX:AAAA",
            "dev:v1:AAAA",
            "vault:v1:!!!",
        ] {
            assert!(!signer.verify(b"message", bad).await.unwrap(), "{bad:?}");
        }
        let unknown_version = sig.replacen("vault:v1:", "vault:v9:", 1);
        for _ in 0..20 {
            assert!(!signer.verify(b"message", &unknown_version).await.unwrap());
        }
        assert_eq!(
            fetches.load(Ordering::SeqCst),
            1,
            "public keys fetched once and cached"
        );
    }

    #[tokio::test]
    async fn transit_signer_refuses_other_key_types() {
        let fetches = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let addr = fake_signing_transit(fetches, "ed25519").await;
        let tf = token_file("s.token");
        let signer = TransitSigner::new(transit(addr, &tf, "transit").with_key("signing-key"));
        let sig = signer.sign(b"message").await.unwrap();
        match signer.verify(b"message", &sig).await {
            Err(BackendError::Config(e)) => assert!(e.contains("mldsa-65"), "{e}"),
            other => panic!("expected a configuration error, got {other:?}"),
        }
    }

    /// Signatures and `transit/keys` output made by OpenBao's own Transit code (sdk v2,
    /// `keysutil`, key type `mldsa-65`); see tests/vectors/openbao/.
    #[tokio::test]
    async fn verifies_signatures_made_by_openbao() {
        use axum::routing::get;

        let v: Value = serde_json::from_str(include_str!(
            "../../tests/vectors/openbao/mldsa65-transit.json"
        ))
        .unwrap();
        let body = json!({"data": {"type": v["type"], "keys": v["public_keys"].as_object().unwrap()
            .iter()
            .map(|(k, pk)| (k.clone(), json!({"public_key": pk})))
            .collect::<serde_json::Map<_, _>>()}});
        let app = Router::new().route(
            "/v1/transit/keys/crypto-service-signing",
            get(move || {
                let body = body.clone();
                async move { Json(body) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let tf = token_file("s.token");
        let signer = TransitSigner::new(
            transit(format!("http://{addr}"), &tf, "transit").with_key("crypto-service-signing"),
        );
        let sigs = v["signatures"].as_array().unwrap();
        assert_eq!(sigs.len(), 4);
        for e in sigs {
            let msg = B64.decode(e["message_b64"].as_str().unwrap()).unwrap();
            let sig = e["signature"].as_str().unwrap();
            assert!(signer.verify(&msg, sig).await.unwrap(), "{sig:.20}");
            assert!(!signer.verify(b"tampered", sig).await.unwrap());
            let other_version = if sig.starts_with("vault:v1:") {
                sig.replacen("vault:v1:", "vault:v2:", 1)
            } else {
                sig.replacen("vault:v2:", "vault:v1:", 1)
            };
            assert!(!signer.verify(&msg, &other_version).await.unwrap());
        }
    }

    #[tokio::test]
    async fn transit_grant_keys_cached_and_reloaded_at_most_every_interval() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let fetches = std::sync::Arc::new(AtomicUsize::new(0));
        let addr = fake_signing_transit(fetches.clone(), SIGNING_KEY_TYPE).await;
        let tf = token_file("s.token");
        let keys = TransitGrantKeys::new(transit(addr, &tf, "transit").with_key("signing-key"));
        let first = keys.grant_keys(false).await.unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].len(), mldsa::PUBLIC_KEY_LEN);
        for refresh in [false, true, true] {
            assert_eq!(keys.grant_keys(refresh).await.unwrap(), first);
        }
        assert_eq!(fetches.load(Ordering::SeqCst), 1, "reload rate-limited");
    }
}
