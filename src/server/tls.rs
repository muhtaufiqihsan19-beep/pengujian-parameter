//! rustls server configuration: TLS 1.3 only, post-quantum key exchange preferred (or
//! required), client certificates checked against the client CA and an optional CRL,
//! and the server certificate reloaded when its files change.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use rustls::RootCertStore;
use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs as provider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
use rustls::server::danger::ClientCertVerifier;
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use x509_parser::extensions::GeneralName;

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    CertificateDer::pem_file_iter(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{}: {e}", path.display()))
}

const CERT_CHECK_INTERVAL: Duration = Duration::from_secs(60);

fn load_certified_key(
    cert: &Path,
    key: &Path,
    provider: &CryptoProvider,
) -> Result<CertifiedKey, String> {
    let certs = load_certs(cert)?;
    let key = PrivateKeyDer::from_pem_file(key).map_err(|e| format!("{}: {e}", key.display()))?;
    CertifiedKey::from_der(certs, key, provider).map_err(|e| format!("server certificate: {e}"))
}

fn modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

#[derive(Debug)]
struct CertState {
    key: Arc<CertifiedKey>,
    stamp: (Option<SystemTime>, Option<SystemTime>),
    checked: Instant,
}

#[derive(Debug)]
pub struct ReloadingCert {
    cert: PathBuf,
    key: PathBuf,
    provider: Arc<CryptoProvider>,
    interval: Duration,
    state: Mutex<CertState>,
}

impl ReloadingCert {
    pub fn new(
        cert: &Path,
        key: &Path,
        provider: Arc<CryptoProvider>,
        interval: Duration,
    ) -> Result<Self, String> {
        let stamp = (modified(cert), modified(key));
        let certified = load_certified_key(cert, key, &provider)?;
        Ok(Self {
            cert: cert.to_path_buf(),
            key: key.to_path_buf(),
            provider,
            interval,
            state: Mutex::new(CertState {
                key: Arc::new(certified),
                stamp,
                checked: Instant::now(),
            }),
        })
    }

    pub fn current(&self) -> Arc<CertifiedKey> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.checked.elapsed() >= self.interval {
            state.checked = Instant::now();
            let stamp = (modified(&self.cert), modified(&self.key));
            if stamp != state.stamp {
                match load_certified_key(&self.cert, &self.key, &self.provider) {
                    Ok(certified) => {
                        state.key = Arc::new(certified);
                        state.stamp = stamp;
                        tracing::info!("server certificate reloaded");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "server certificate reload failed, keeping the current one")
                    }
                }
            }
        }
        state.key.clone()
    }
}

impl ResolvesServerCert for ReloadingCert {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current())
    }
}

pub fn client_verifier(
    client_ca: &Path,
    client_crl: Option<&Path>,
    crypto: Arc<CryptoProvider>,
) -> Result<Arc<dyn ClientCertVerifier>, String> {
    let mut roots = RootCertStore::empty();
    for c in load_certs(client_ca)? {
        roots.add(c).map_err(|e| format!("client CA: {e}"))?;
    }
    let mut builder = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), crypto);
    if let Some(path) = client_crl {
        let crls = CertificateRevocationListDer::pem_file_iter(path)
            .map_err(|e| format!("{}: {e}", path.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if crls.is_empty() {
            return Err(format!("{}: no CRL found", path.display()));
        }
        builder = builder.with_crls(crls);
    }
    builder.build().map_err(|e| format!("client verifier: {e}"))
}

pub fn server_config(
    cert: &Path,
    key: &Path,
    client_ca: &Path,
    client_crl: Option<&Path>,
    require_pq: bool,
) -> Result<rustls::ServerConfig, String> {
    let mut crypto = provider::default_provider();
    if require_pq {
        crypto.kx_groups = vec![provider::kx_group::X25519MLKEM768];
    }
    let crypto = Arc::new(crypto);
    let verifier = client_verifier(client_ca, client_crl, crypto.clone())?;

    let resolver = ReloadingCert::new(cert, key, crypto.clone(), CERT_CHECK_INTERVAL)?;

    let mut cfg = rustls::ServerConfig::builder_with_provider(crypto)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(resolver));
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(cfg)
}

pub fn san_allowed(cert_der: &[u8], allowed: &[String]) -> bool {
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(cert_der) else {
        return false;
    };
    let Ok(Some(san)) = cert.subject_alternative_name() else {
        return false;
    };
    san.value.general_names.iter().any(|name| match name {
        GeneralName::DNSName(d) => allowed.iter().any(|a| a == d),
        GeneralName::URI(u) => allowed.iter().any(|a| a == u),
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CertificateRevocationListParams, CertifiedIssuer,
        DnType, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose, RevokedCertParams, SerialNumber,
        date_time_ymd,
    };
    use rustls::pki_types::UnixTime;

    struct TempDir(std::path::PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn client(issuer: &CertifiedIssuer<'static, KeyPair>, serial: u64) -> CertificateDer<'static> {
        let mut p = CertificateParams::new(vec!["key-service-api.keyservice.svc".into()]).unwrap();
        p.serial_number = Some(SerialNumber::from(serial));
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        p.signed_by(&KeyPair::generate().unwrap(), issuer)
            .unwrap()
            .der()
            .clone()
    }

    #[test]
    fn revoked_client_rejected_with_crl() {
        let _ = provider::default_provider().install_default();
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.distinguished_name
            .push(DnType::CommonName, "crl-test-ca");
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = CertifiedIssuer::self_signed(ca, KeyPair::generate().unwrap()).unwrap();
        let (good, revoked) = (client(&ca, 1001), client(&ca, 1002));

        let crl = CertificateRevocationListParams {
            this_update: date_time_ymd(2020, 1, 1),
            next_update: date_time_ymd(2099, 1, 1),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: vec![RevokedCertParams {
                serial_number: SerialNumber::from(1002u64),
                revocation_time: date_time_ymd(2021, 1, 1),
                reason_code: None,
                invalidity_date: None,
            }],
            key_identifier_method: KeyIdMethod::Sha256,
        }
        .signed_by(&ca)
        .unwrap();

        let mut r = [0u8; 8];
        crate::crypto::primitives::random::fill(&mut r).unwrap();
        let dir = TempDir(std::env::temp_dir().join(format!("ks-crl-{}", u64::from_be_bytes(r))));
        std::fs::create_dir_all(&dir.0).unwrap();
        let (ca_path, crl_path) = (dir.0.join("ca.crt"), dir.0.join("ca.crl"));
        std::fs::write(&ca_path, ca.pem()).unwrap();
        std::fs::write(&crl_path, crl.pem().unwrap()).unwrap();

        let crypto = Arc::new(provider::default_provider());
        let now = UnixTime::now();
        let without = client_verifier(&ca_path, None, crypto.clone()).unwrap();
        assert!(without.verify_client_cert(&revoked, &[], now).is_ok());

        let with = client_verifier(&ca_path, Some(&crl_path), crypto.clone()).unwrap();
        assert!(with.verify_client_cert(&good, &[], now).is_ok());
        assert!(with.verify_client_cert(&revoked, &[], now).is_err());

        std::fs::write(&crl_path, "").unwrap();
        assert!(client_verifier(&ca_path, Some(&crl_path), crypto).is_err());
    }

    fn write_server_cert(dir: &std::path::Path, ca: &CertifiedIssuer<'static, KeyPair>) -> Vec<u8> {
        let mut p = CertificateParams::new(vec!["crypto-service".into()]).unwrap();
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let key = KeyPair::generate().unwrap();
        let cert = p.signed_by(&key, ca).unwrap();
        std::fs::write(dir.join("tls.crt"), cert.pem()).unwrap();
        std::fs::write(dir.join("tls.key"), key.serialize_pem()).unwrap();
        cert.der().to_vec()
    }

    #[test]
    fn server_certificate_reloads_when_files_change() {
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(ca, KeyPair::generate().unwrap()).unwrap();
        let mut r = [0u8; 8];
        crate::crypto::primitives::random::fill(&mut r).unwrap();
        let dir =
            TempDir(std::env::temp_dir().join(format!("ks-reload-{}", u64::from_be_bytes(r))));
        std::fs::create_dir_all(&dir.0).unwrap();
        let (cert, key) = (dir.0.join("tls.crt"), dir.0.join("tls.key"));

        let first = write_server_cert(&dir.0, &ca);
        let provider = Arc::new(provider::default_provider());
        let reloading = ReloadingCert::new(&cert, &key, provider, Duration::ZERO).unwrap();
        assert_eq!(
            reloading.current().end_entity_cert().unwrap().as_ref(),
            &first[..]
        );

        std::thread::sleep(Duration::from_millis(20));
        let second = write_server_cert(&dir.0, &ca);
        assert_eq!(
            reloading.current().end_entity_cert().unwrap().as_ref(),
            &second[..]
        );

        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(&key, "not a key").unwrap();
        assert_eq!(
            reloading.current().end_entity_cert().unwrap().as_ref(),
            &second[..],
            "a broken update keeps the current certificate"
        );
        let other = KeyPair::generate().unwrap();
        std::fs::write(&key, other.serialize_pem()).unwrap();
        assert_eq!(
            reloading.current().end_entity_cert().unwrap().as_ref(),
            &second[..],
            "a key that does not match the certificate is not loaded"
        );
    }
}
