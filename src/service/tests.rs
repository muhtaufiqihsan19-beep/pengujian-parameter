//! Tests of the flows, with the dev backends and suite v2.

use std::collections::HashMap;
use std::sync::Arc;

use zeroize::Zeroizing;

use super::grant::testing::{self as grant_testing, decrypt_grant, dispose_grant};
use super::*;
use crate::backends::{InsecureDevSealer, InsecureDevSigner, SoftwareKeyCustody};
use crate::crypto::formats::{self, CIPHERTEXT_MAGIC, PUBLIC_KEY_MAGIC};
use crate::crypto::primitives::random;
use crate::crypto::{self, COMPOSITE_V2, CryptoError, MAX_ID_LEN};

pub(crate) const POSITIONS: [&str; 5] = [
    "STAFF",
    "TEAM-LEAD",
    "HEAD-OF-SECTION",
    "HEAD-OF-BUREAU",
    "ADMIN-STAFF",
];

/// A service on the dev backends: suite v2, 1 MiB limit, 4 KiB chunks.
pub(crate) fn service() -> Service {
    Service {
        registry: crypto::registry(COMPOSITE_V2).unwrap(),
        custody: Arc::new(SoftwareKeyCustody::new(Arc::new(
            InsecureDevSealer::new().unwrap(),
        ))),
        signer: Arc::new(InsecureDevSigner::new().unwrap()),
        grants: grant_testing::verifier(),
        max_plaintext: 1 << 20,
        chunk_size: 4096,
    }
}

pub(crate) async fn setup() -> (Service, HashMap<&'static str, GeneratedKey>) {
    let service = service();
    let mut generated = HashMap::new();
    for code in POSITIONS {
        generated.insert(code, service.create_key(code, 1, None).await.unwrap());
    }
    (service, generated)
}

pub(crate) fn recipient(g: &GeneratedKey) -> Recipient {
    Recipient {
        position_code: g.identity.position_code.clone(),
        key_version: g.identity.key_version,
        suite_id: g.identity.suite_id.clone(),
        public_key: g.public_key.clone(),
    }
}

pub(crate) fn holder(g: &GeneratedKey, wrapped: &[WrappedKey]) -> KeyHolder {
    let key = wrapped
        .iter()
        .find(|w| w.position_code == g.identity.position_code)
        .unwrap_or(&wrapped[0]);
    KeyHolder {
        position_code: g.identity.position_code.clone(),
        key_version: g.identity.key_version,
        suite_id: key.suite_id.clone(),
        wrapped_key: key.wrapped_key.clone(),
        private_key_blob: g.private_key_blob.clone(),
    }
}

pub(crate) async fn open(
    s: &Service,
    document_id: &str,
    version: u32,
    h: &KeyHolder,
    ciphertext: Vec<u8>,
) -> Result<Zeroizing<Vec<u8>>, ServiceError> {
    let grant = decrypt_grant(document_id, version, &h.position_code);
    s.decrypt(document_id, version, h, ciphertext, &grant).await
}

pub(crate) async fn dispose(
    s: &Service,
    document_id: &str,
    version: u32,
    source: &KeyHolder,
    targets: &[Recipient],
) -> Result<Vec<WrappedKey>, ServiceError> {
    let codes: Vec<_> = targets.iter().map(|t| t.position_code.as_str()).collect();
    let grant = dispose_grant(document_id, version, &source.position_code, &codes);
    s.rewrap(document_id, version, source, targets, &grant)
        .await
}

#[tokio::test]
async fn only_recipients_can_decrypt() {
    let (s, k) = setup().await;
    let mut pdf = vec![0u8; 10_000];
    random::fill(&mut pdf).unwrap();
    let enc = s
        .encrypt(
            "DOC-1",
            1,
            &pdf,
            &[recipient(&k["STAFF"]), recipient(&k["TEAM-LEAD"])],
        )
        .await
        .unwrap();
    for code in ["STAFF", "TEAM-LEAD"] {
        let h = holder(&k[code], &enc.wrapped_keys);
        let got = open(&s, "DOC-1", 1, &h, enc.ciphertext.clone())
            .await
            .unwrap();
        assert_eq!(&got[..], &pdf[..], "{code}");
    }
    let outsider = holder(&k["ADMIN-STAFF"], &enc.wrapped_keys);
    assert!(matches!(
        open(&s, "DOC-1", 1, &outsider, enc.ciphertext.clone()).await,
        Err(ServiceError::Open)
    ));
}

#[tokio::test]
async fn wrong_document_or_version() {
    let (s, k) = setup().await;
    let enc = s
        .encrypt("DOC-1", 1, b"x", &[recipient(&k["HEAD-OF-BUREAU"])])
        .await
        .unwrap();
    let h = holder(&k["HEAD-OF-BUREAU"], &enc.wrapped_keys);
    assert!(
        open(&s, "DOC-2", 1, &h, enc.ciphertext.clone())
            .await
            .is_err()
    );
    assert!(
        open(&s, "DOC-1", 2, &h, enc.ciphertext.clone())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn new_version_new_dek() {
    let (s, k) = setup().await;
    let chain: Vec<_> = POSITIONS[..4].iter().map(|c| recipient(&k[c])).collect();
    let v1 = s.encrypt("DOC-9", 1, b"draft", &chain).await.unwrap();
    let v2 = s
        .encrypt("DOC-9", 2, b"draft + signature", &chain)
        .await
        .unwrap();
    let old = holder(&k["HEAD-OF-BUREAU"], &v1.wrapped_keys);
    assert!(
        open(&s, "DOC-9", 2, &old, v2.ciphertext.clone())
            .await
            .is_err()
    );
    let new = holder(&k["HEAD-OF-BUREAU"], &v2.wrapped_keys);
    let got = open(&s, "DOC-9", 2, &new, v2.ciphertext).await.unwrap();
    assert_eq!(&got[..], b"draft + signature");
}

#[tokio::test]
async fn rewrap_for_disposition() {
    let (s, k) = setup().await;
    let enc = s
        .encrypt(
            "DOC-5",
            3,
            b"incoming letter",
            &[recipient(&k["HEAD-OF-BUREAU"])],
        )
        .await
        .unwrap();
    let source = holder(&k["HEAD-OF-BUREAU"], &enc.wrapped_keys);
    let added = dispose(&s, "DOC-5", 3, &source, &[recipient(&k["HEAD-OF-SECTION"])])
        .await
        .unwrap();
    let target = holder(&k["HEAD-OF-SECTION"], &added);
    let got = open(&s, "DOC-5", 3, &target, enc.ciphertext.clone())
        .await
        .unwrap();
    assert_eq!(&got[..], b"incoming letter");

    let outsider = holder(&k["ADMIN-STAFF"], &enc.wrapped_keys);
    assert!(
        dispose(&s, "DOC-5", 3, &outsider, &[recipient(&k["STAFF"])])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn encrypt_validation() {
    let (s, k) = setup().await;
    let r = recipient(&k["HEAD-OF-BUREAU"]);
    let bad_request =
        |res: Result<Encrypted, ServiceError>| matches!(res, Err(ServiceError::BadRequest(_)));
    assert!(bad_request(s.encrypt("DOC-1", 1, b"", &[]).await));
    assert!(bad_request(
        s.encrypt("DOC-1", 1, b"", &[r.clone(), r.clone()]).await
    ));
    assert!(bad_request(
        s.encrypt(
            &"D".repeat(MAX_ID_LEN + 1),
            1,
            b"",
            std::slice::from_ref(&r)
        )
        .await
    ));
    assert!(bad_request(
        s.encrypt("DOC-1", 1, b"x", &vec![r.clone(); MAX_RECIPIENTS + 1])
            .await
    ));
    let mut unknown = r.clone();
    unknown.suite_id = "RSA-OAEP".into();
    assert!(bad_request(s.encrypt("DOC-1", 1, b"", &[unknown]).await));
    assert!(matches!(
        s.encrypt(
            "DOC-1",
            1,
            &vec![0u8; (1 << 20) + 1],
            std::slice::from_ref(&r)
        )
        .await,
        Err(ServiceError::TooLarge)
    ));
    assert!(
        s.encrypt("DOC-1", 1, &vec![0u8; 1 << 20], &[r])
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn cheap_checks_run_before_kms() {
    let (mut s, k) = setup().await;
    let enc = s
        .encrypt(
            "DOC-1",
            1,
            &vec![7u8; 3 * 4096],
            &[recipient(&k["HEAD-OF-BUREAU"])],
        )
        .await
        .unwrap();
    let mut h = holder(&k["HEAD-OF-BUREAU"], &enc.wrapped_keys);
    h.private_key_blob = "broken".into();
    assert!(matches!(
        open(&s, "", 1, &h, enc.ciphertext.clone()).await,
        Err(ServiceError::BadRequest(_))
    ));
    let t = recipient(&k["HEAD-OF-SECTION"]);
    for targets in [vec![], vec![t.clone(), t.clone()]] {
        assert!(matches!(
            dispose(&s, "DOC-1", 1, &h, &targets).await,
            Err(ServiceError::BadRequest(_))
        ));
    }
    s.max_plaintext = 3 * 4096 - 1;
    assert!(matches!(
        open(&s, "DOC-1", 1, &h, enc.ciphertext).await,
        Err(ServiceError::TooLarge)
    ));
}

#[tokio::test]
async fn grant_required_and_bound_to_request() {
    let (s, k) = setup().await;
    let enc = s
        .encrypt("DOC-1", 1, b"memo", &[recipient(&k["HEAD-OF-BUREAU"])])
        .await
        .unwrap();
    let h = holder(&k["HEAD-OF-BUREAU"], &enc.wrapped_keys);
    let ct = || enc.ciphertext.clone();
    let forbidden =
        |r: Result<Zeroizing<Vec<u8>>, ServiceError>| matches!(r, Err(ServiceError::Forbidden(_)));

    assert!(forbidden(s.decrypt("DOC-1", 1, &h, ct(), "").await));
    for g in [
        decrypt_grant("DOC-2", 1, "HEAD-OF-BUREAU"),
        decrypt_grant("DOC-1", 2, "HEAD-OF-BUREAU"),
        decrypt_grant("DOC-1", 1, "STAFF"),
        dispose_grant("DOC-1", 1, "HEAD-OF-BUREAU", &[]),
    ] {
        assert!(forbidden(s.decrypt("DOC-1", 1, &h, ct(), &g).await));
    }
    let ok = decrypt_grant("DOC-1", 1, "HEAD-OF-BUREAU");
    assert_eq!(
        &s.decrypt("DOC-1", 1, &h, ct(), &ok).await.unwrap()[..],
        b"memo"
    );

    let section = recipient(&k["HEAD-OF-SECTION"]);
    let staff = recipient(&k["STAFF"]);
    let only_section = dispose_grant("DOC-1", 1, "HEAD-OF-BUREAU", &["HEAD-OF-SECTION"]);
    let res = s
        .rewrap("DOC-1", 1, &h, &[section.clone(), staff], &only_section)
        .await;
    assert!(matches!(res, Err(ServiceError::Forbidden(_))));
    assert!(
        s.rewrap("DOC-1", 1, &h, &[section], &only_section)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn text_round_trip_and_binary_rejected() {
    let (s, k) = setup().await;
    let r = [recipient(&k["STAFF"])];
    let text = "Rahasia: rapat pukul 09.00 — ruang 3 ✓";
    let enc = s.encrypt("NOTE-1", 1, text.as_bytes(), &r).await.unwrap();
    let h = holder(&k["STAFF"], &enc.wrapped_keys);
    let grant = decrypt_grant("NOTE-1", 1, "STAFF");
    let got = s
        .decrypt_text("NOTE-1", 1, &h, enc.ciphertext, &grant)
        .await
        .unwrap();
    assert_eq!(got.as_str(), text);

    let bin = s.encrypt("NOTE-2", 1, &[0xff, 0xfe], &r).await.unwrap();
    let h = holder(&k["STAFF"], &bin.wrapped_keys);
    let grant = decrypt_grant("NOTE-2", 1, "STAFF");
    assert!(matches!(
        s.decrypt_text("NOTE-2", 1, &h, bin.ciphertext, &grant)
            .await,
        Err(ServiceError::BadRequest(_))
    ));
}

#[tokio::test]
async fn untrusted_public_keys_rejected() {
    let (s, k) = setup().await;
    let mut swapped = recipient(&k["HEAD-OF-BUREAU"]);
    swapped.public_key = k["ADMIN-STAFF"].public_key.clone();
    let mut raw = recipient(&k["HEAD-OF-BUREAU"]);
    raw.public_key = formats::open_envelope(PUBLIC_KEY_MAGIC, &raw.public_key)
        .unwrap()
        .body
        .to_vec();
    let mut wrong_version = recipient(&k["HEAD-OF-BUREAU"]);
    wrong_version.key_version = 7;
    for r in [swapped, raw, wrong_version] {
        assert!(matches!(
            s.encrypt("DOC-1", 1, b"x", &[r]).await,
            Err(ServiceError::Untrusted(_))
        ));
    }
}

#[tokio::test]
async fn disposition_cannot_redirect_to_foreign_key() {
    let (s, k) = setup().await;
    let enc = s
        .encrypt("DOC-1", 1, b"secret", &[recipient(&k["HEAD-OF-BUREAU"])])
        .await
        .unwrap();
    let source = holder(&k["HEAD-OF-BUREAU"], &enc.wrapped_keys);
    let mut evil = recipient(&k["HEAD-OF-SECTION"]);
    evil.public_key = <crate::crypto::CompositeV2 as crate::crypto::Suite>::generate_key_pair(
        &crate::crypto::CompositeV2,
    )
    .unwrap()
    .public_key;
    let res = dispose(&s, "DOC-1", 1, &source, &[evil]).await;
    assert!(matches!(res, Err(ServiceError::Untrusted(_))));
}

#[tokio::test]
async fn forged_or_swapped_ciphertext_rejected() {
    let (s, k) = setup().await;
    let r = [recipient(&k["HEAD-OF-BUREAU"])];
    let enc = s.encrypt("DOC-1", 1, b"real", &r).await.unwrap();
    let h = holder(&k["HEAD-OF-BUREAU"], &enc.wrapped_keys);
    let body = formats::open_envelope(CIPHERTEXT_MAGIC, &enc.ciphertext).unwrap();
    let content = body.body.to_vec();

    assert!(
        open(&s, "DOC-1", 1, &h, content.clone()).await.is_err(),
        "unsigned EKS1"
    );
    let forged = formats::seal_envelope(CIPHERTEXT_MAGIC, "dev:v1:AAAA", &content);
    assert!(matches!(
        open(&s, "DOC-1", 1, &h, forged).await,
        Err(ServiceError::Open)
    ));
    let other = s.encrypt("DOC-1", 1, b"other", &r).await.unwrap();
    let other_sig = formats::open_envelope(CIPHERTEXT_MAGIC, &other.ciphertext)
        .unwrap()
        .signature
        .to_string();
    let swapped = formats::seal_envelope(CIPHERTEXT_MAGIC, &other_sig, &content);
    assert!(matches!(
        open(&s, "DOC-1", 1, &h, swapped).await,
        Err(ServiceError::Open)
    ));
    assert_eq!(
        &open(&s, "DOC-1", 1, &h, enc.ciphertext).await.unwrap()[..],
        b"real"
    );
}

#[test]
fn backend_error_classification() {
    let rejected = |status| BackendError::Rejected {
        status,
        errors: vec![],
    };
    for e in [
        rejected(400),
        BackendError::BadBlob,
        BackendError::Mismatch,
        BackendError::Crypto(CryptoError::Unwrap),
    ] {
        assert!(matches!(backend_error(e), ServiceError::Open));
    }
    for e in [
        rejected(403),
        rejected(307),
        rejected(503),
        BackendError::Token,
        BackendError::Transport("x".into()),
        BackendError::BadResponse,
    ] {
        assert!(matches!(backend_error(e), ServiceError::Internal(_)));
    }
}

#[tokio::test]
async fn removed_suite_v1_rejected() {
    // Suite v1 was removed before any production data existed: its id is unknown now.
    const V1: &str = "X25519-MLKEM768-HKDFSHA256-AES256GCM-v1";
    let (s, k) = setup().await;
    assert!(matches!(
        s.create_key("STAFF", 2, Some(V1)).await,
        Err(ServiceError::BadRequest(_))
    ));
    let mut v1_recipient = recipient(&k["STAFF"]);
    v1_recipient.suite_id = V1.into();
    assert!(
        s.encrypt("DOC-V1", 1, b"memo", &[v1_recipient])
            .await
            .is_err()
    );

    let enc = s
        .encrypt("DOC-V1", 1, b"memo", &[recipient(&k["STAFF"])])
        .await
        .unwrap();
    let mut wrong = holder(&k["STAFF"], &enc.wrapped_keys);
    wrong.suite_id = V1.into();
    assert!(
        open(&s, "DOC-V1", 1, &wrong, enc.ciphertext.clone())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn create_key_validation() {
    let s = service();
    let bad_request =
        |r: Result<GeneratedKey, ServiceError>| matches!(r, Err(ServiceError::BadRequest(_)));
    assert!(bad_request(s.create_key("", 1, None).await));
    assert!(bad_request(s.create_key("STAFF", 0, None).await));
    assert!(bad_request(
        s.create_key(&"P".repeat(MAX_ID_LEN + 1), 1, None).await
    ));
    assert!(bad_request(
        s.create_key("STAFF", 1, Some("RSA-OAEP")).await
    ));
    let g = s.create_key("STAFF", 1, Some("")).await.unwrap();
    assert_eq!(
        g.identity.suite_id, COMPOSITE_V2,
        "empty suite_id means the default"
    );
    let raw = s
        .trusted_public_key(COMPOSITE_V2, "STAFF", 1, &g.public_key)
        .await
        .unwrap();
    assert_eq!(raw.len(), crypto::suites::composite_v2::PUBLIC_KEY_LEN);
}

#[tokio::test]
async fn public_key_signature_binds_identity() {
    let s = service();
    let g = s.create_key("HEAD-OF-BUREAU", 1, None).await.unwrap();
    let trusted = |code: &'static str, version: u32, key: Vec<u8>| {
        let s = &s;
        async move {
            s.trusted_public_key(COMPOSITE_V2, code, version, &key)
                .await
        }
    };
    assert!(
        trusted("HEAD-OF-BUREAU", 1, g.public_key.clone())
            .await
            .is_ok()
    );
    for (code, version) in [("ADMIN-STAFF", 1), ("HEAD-OF-BUREAU", 2)] {
        assert!(matches!(
            trusted(code, version, g.public_key.clone()).await,
            Err(ServiceError::Untrusted(_))
        ));
    }
    let raw = formats::open_envelope(PUBLIC_KEY_MAGIC, &g.public_key)
        .unwrap()
        .body
        .to_vec();
    assert!(
        trusted("HEAD-OF-BUREAU", 1, raw.clone()).await.is_err(),
        "unsigned raw key"
    );
    let mut swapped = g.public_key.clone();
    let last = swapped.len() - 1;
    swapped[last] ^= 1;
    assert!(
        trusted("HEAD-OF-BUREAU", 1, swapped).await.is_err(),
        "key bytes changed"
    );
    assert!(
        service()
            .trusted_public_key(COMPOSITE_V2, "HEAD-OF-BUREAU", 1, &g.public_key)
            .await
            .is_err(),
        "signed by another service"
    );
}

#[tokio::test]
async fn backends_ready_with_dev_backends() {
    assert!(service().backends_ready().await);
}
