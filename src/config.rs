use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: String,
    pub health_listen: String,
    pub dev: bool,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub tls_client_ca: Option<PathBuf>,
    pub tls_client_crl: Option<PathBuf>,
    pub tls_require_pq: bool,
    pub allowed_clients: Vec<String>,
    pub default_suite: Option<String>,
    pub max_body_bytes: usize,
    pub max_document_bytes: usize,
    pub shutdown_grace: Duration,
    pub max_connections: usize,
    pub max_concurrent_requests: usize,
    pub request_timeout: Duration,
    pub grant_public_keys: Option<PathBuf>,
    pub grant_max_ttl: Duration,
    pub openbao_addr: Option<String>,
    pub openbao_ca: Option<PathBuf>,
    pub openbao_token_file: PathBuf,
    pub openbao_mount: String,
    pub openbao_kek_name: String,
    pub openbao_signing_key_name: String,
    /// Transit `mldsa-65` key E-Office signs grants with; the service only reads its public
    /// keys.
    pub openbao_grant_key_name: Option<String>,
    pub openbao_namespace: Option<String>,
}

struct Env<'a>(&'a dyn Fn(&str) -> Option<String>);

impl Env<'_> {
    fn var(&self, key: &str) -> Option<String> {
        (self.0)(key).filter(|v| !v.trim().is_empty())
    }

    fn path(&self, key: &str) -> Option<PathBuf> {
        self.var(key).map(PathBuf::from)
    }

    fn flag(&self, key: &str) -> bool {
        self.var(key).as_deref() == Some("1")
    }

    fn bounded(
        &self,
        key: &str,
        default: u64,
        min: u64,
        max: u64,
        unit: &str,
    ) -> Result<u64, String> {
        match self.var(key) {
            None => Ok(default),
            Some(v) => v
                .parse::<u64>()
                .ok()
                .filter(|n| (min..=max).contains(n))
                .ok_or_else(|| format!("{key} must be a number in {min}..{max} ({unit})")),
        }
    }

    fn megabytes(&self, key: &str, default: u64) -> Result<usize, String> {
        self.bounded(key, default, 1, 512, "MB")
            .map(|n| (n as usize) << 20)
    }

    fn seconds(&self, key: &str, default: u64) -> Result<Duration, String> {
        self.bounded(key, default, 1, 300, "seconds")
            .map(Duration::from_secs)
    }
}

fn is_loopback(listen: &str) -> bool {
    listen
        .parse::<SocketAddr>()
        .is_ok_and(|a| a.ip().is_loopback())
}

fn required_body_bytes(max_document: usize) -> usize {
    const JSON_SLACK: usize = 1 << 20;
    // CTS1 prefix with an ML-DSA-65 signature (about 4.4 KB as text) plus the EKS1 header.
    const HEADER_MAX: usize = 8 << 10;
    let ciphertext = max_document + max_document.div_ceil(1 << 20) * 16 + HEADER_MAX;
    ciphertext.div_ceil(3) * 4 + JSON_SLACK
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(&|k| env::var(k).ok())
    }

    pub fn from_lookup(lookup: &dyn Fn(&str) -> Option<String>) -> Result<Self, String> {
        let e = Env(lookup);
        let c = Config {
            listen: e.var("KS_LISTEN").unwrap_or_else(|| "0.0.0.0:8443".into()),
            health_listen: e
                .var("KS_HEALTH_LISTEN")
                .unwrap_or_else(|| "0.0.0.0:8080".into()),
            dev: e.flag("KS_DEV"),
            tls_cert: e.path("KS_TLS_CERT"),
            tls_key: e.path("KS_TLS_KEY"),
            tls_client_ca: e.path("KS_TLS_CLIENT_CA"),
            tls_client_crl: e.path("KS_TLS_CLIENT_CRL"),
            // On unless explicitly "0": documents cross this TLS link in clear, so a
            // classical-only handshake would undo the post-quantum key wrap.
            tls_require_pq: e.var("KS_TLS_REQUIRE_PQ").as_deref() != Some("0"),
            allowed_clients: e
                .var("KS_ALLOWED_CLIENTS")
                .map(|v| {
                    v.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            default_suite: e.var("KS_DEFAULT_SUITE"),
            max_body_bytes: e.megabytes("KS_MAX_BODY_MB", 64)?,
            max_document_bytes: e.megabytes("KS_MAX_DOCUMENT_MB", 40)?,
            shutdown_grace: e.seconds("KS_SHUTDOWN_GRACE_SECS", 20)?,
            max_connections: e.bounded("KS_MAX_CONNECTIONS", 1024, 1, 65_535, "connections")?
                as usize,
            max_concurrent_requests: e.bounded(
                "KS_MAX_CONCURRENT_REQUESTS",
                8,
                1,
                1024,
                "requests",
            )? as usize,
            request_timeout: e.seconds("KS_REQUEST_TIMEOUT_SECS", 60)?,
            grant_public_keys: e.path("KS_GRANT_PUBLIC_KEYS"),
            grant_max_ttl: Duration::from_secs(e.bounded(
                "KS_GRANT_MAX_TTL_SECS",
                300,
                1,
                3600,
                "seconds",
            )?),
            openbao_addr: e.var("OPENBAO_ADDR"),
            openbao_ca: e.path("OPENBAO_CACERT"),
            openbao_token_file: e
                .path("OPENBAO_TOKEN_FILE")
                .unwrap_or_else(|| PathBuf::from("/vault/secrets/token")),
            openbao_mount: e
                .var("OPENBAO_TRANSIT_MOUNT")
                .unwrap_or_else(|| "transit".into()),
            openbao_kek_name: e
                .var("OPENBAO_KEK_NAME")
                .unwrap_or_else(|| "jabatan-kek".into()),
            openbao_signing_key_name: e
                .var("OPENBAO_SIGNING_KEY_NAME")
                .unwrap_or_else(|| "crypto-service-signing".into()),
            openbao_grant_key_name: e.var("OPENBAO_GRANT_KEY_NAME"),
            openbao_namespace: e.var("OPENBAO_NAMESPACE"),
        };
        c.validate()?;
        Ok(c)
    }

    fn validate(&self) -> Result<(), String> {
        let need = required_body_bytes(self.max_document_bytes);
        if self.max_body_bytes < need {
            return Err(format!(
                "KS_MAX_BODY_MB is too small for KS_MAX_DOCUMENT_MB={}: needs about {} MB",
                self.max_document_bytes >> 20,
                need.div_ceil(1 << 20)
            ));
        }

        if self.dev {
            if self.openbao_addr.is_none() && !is_loopback(&self.listen) {
                return Err(format!(
                    "KS_DEV=1 without OPENBAO_ADDR uses an in-memory KEK and only listens on \
                     loopback (KS_LISTEN={} is not loopback)",
                    self.listen
                ));
            }
            return Ok(());
        }

        let required = [
            ("KS_TLS_CERT", self.tls_cert.is_some()),
            ("KS_TLS_KEY", self.tls_key.is_some()),
            ("KS_TLS_CLIENT_CA", self.tls_client_ca.is_some()),
            ("KS_ALLOWED_CLIENTS", !self.allowed_clients.is_empty()),
            ("KS_DEFAULT_SUITE", self.default_suite.is_some()),
            (
                "KS_GRANT_PUBLIC_KEYS or OPENBAO_GRANT_KEY_NAME",
                self.grant_public_keys.is_some() || self.openbao_grant_key_name.is_some(),
            ),
            ("OPENBAO_ADDR", self.openbao_addr.is_some()),
            ("OPENBAO_CACERT", self.openbao_ca.is_some()),
        ];
        let missing: Vec<_> = required
            .iter()
            .filter(|(_, ok)| !ok)
            .map(|(k, _)| *k)
            .collect();
        if !missing.is_empty() {
            return Err(format!("missing required settings: {}", missing.join(", ")));
        }
        if !self
            .openbao_addr
            .as_deref()
            .unwrap_or_default()
            .starts_with("https://")
        {
            return Err("OPENBAO_ADDR must be https".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn load(vars: &[(&str, &str)]) -> Result<Config, String> {
        let m: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::from_lookup(&|k| m.get(k).cloned())
    }

    const DEV: [(&str, &str); 2] = [("KS_DEV", "1"), ("KS_LISTEN", "127.0.0.1:8443")];

    fn dev_with(extra: &[(&'static str, &'static str)]) -> Result<Config, String> {
        let mut v = DEV.to_vec();
        v.extend_from_slice(extra);
        load(&v)
    }

    #[test]
    fn dev_memory_kek_only_on_loopback() {
        assert!(dev_with(&[]).is_ok());
        assert!(load(&[("KS_DEV", "1"), ("KS_LISTEN", "[::1]:8443")]).is_ok());
        let err = load(&[("KS_DEV", "1")]).unwrap_err();
        assert!(err.contains("loopback"), "{err}");
        assert!(load(&[("KS_DEV", "1"), ("KS_LISTEN", "10.0.0.5:8443")]).is_err());
        assert!(
            load(&[
                ("KS_DEV", "1"),
                ("KS_LISTEN", "0.0.0.0:8443"),
                ("OPENBAO_ADDR", "https://openbao:8200"),
            ])
            .is_ok()
        );
    }

    #[test]
    fn pq_tls_is_on_unless_turned_off() {
        assert!(dev_with(&[]).unwrap().tls_require_pq);
        assert!(
            dev_with(&[("KS_TLS_REQUIRE_PQ", "1")])
                .unwrap()
                .tls_require_pq
        );
        assert!(
            dev_with(&[("KS_TLS_REQUIRE_PQ", "yes")])
                .unwrap()
                .tls_require_pq
        );
        assert!(
            !dev_with(&[("KS_TLS_REQUIRE_PQ", "0")])
                .unwrap()
                .tls_require_pq
        );
    }

    #[test]
    fn production_requires_settings() {
        let err = load(&[]).unwrap_err();
        assert!(
            err.contains("KS_TLS_CERT") && err.contains("KS_GRANT_PUBLIC_KEYS"),
            "{err}"
        );
    }

    #[test]
    fn body_limit_must_fit_document() {
        assert!(dev_with(&[]).is_ok(), "defaults 64/40 must be consistent");
        let err = dev_with(&[("KS_MAX_DOCUMENT_MB", "60")]).unwrap_err();
        assert!(err.contains("KS_MAX_BODY_MB"), "{err}");
        assert!(dev_with(&[("KS_MAX_DOCUMENT_MB", "60"), ("KS_MAX_BODY_MB", "84")]).is_ok());
    }

    #[test]
    fn required_body_covers_real_requests() {
        for doc in [1usize, 4096, 1 << 20, 40 << 20] {
            let ct = doc + doc.div_ceil(1 << 20) * 16 + 1100 + 4500;
            assert!(required_body_bytes(doc) > ct.div_ceil(3) * 4);
        }
    }
}
