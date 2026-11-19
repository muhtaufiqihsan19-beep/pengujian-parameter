use std::sync::atomic::AtomicUsize;

use axum::Json;
use axum::body::{Body, Bytes};
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use http_body_util::BodyExt;
use serde::Deserialize;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::middleware::hex;
use super::*;
use crate::backends::{OpenBaoTransit, SoftwareKeyCustody};
use crate::service::b64;
use crate::service::grant::testing::{decrypt_grant, dispose_grant};

fn state() -> AppState {
    AppState::new(crate::service::tests::service())
}

fn app() -> Router {
    router(Arc::new(state()), 4 << 20)
}

async fn call(app: &Router, path: &str, body: Value) -> (StatusCode, Vec<u8>) {
    let req = axum::http::Request::post(path)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, body)
}

async fn get(app: Router, path: &str) -> axum::response::Response {
    let req = axum::http::Request::get(path).body(Body::empty()).unwrap();
    app.oneshot(req).await.unwrap()
}

async fn create_key(app: &Router, code: &str) -> Value {
    let (s, b) = call(
        app,
        "/keys",
        json!({"position_code": code, "key_version": 1}),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    serde_json::from_slice(&b).unwrap()
}

fn recipient(k: &Value) -> Value {
    json!({"position_code": k["position_code"], "key_version": 1,
           "suite_id": k["suite_id"], "public_key": k["public_key"]})
}

fn holder(k: &Value, wrapped_key: &Value) -> Value {
    json!({"position_code": k["position_code"], "key_version": 1, "suite_id": k["suite_id"],
           "wrapped_key": wrapped_key, "private_key_blob": k["private_key_blob"]})
}

#[tokio::test]
async fn end_to_end() {
    let app = app();
    let bureau = create_key(&app, "HEAD-OF-BUREAU").await;
    let section = create_key(&app, "HEAD-OF-SECTION").await;
    let admin = create_key(&app, "ADMIN-STAFF").await;
    let pdf = b"%PDF-1.7 top secret memo";

    let (s, b) = call(
        &app,
        "/documents/encrypt",
        json!({
            "document_id": "DOC-77", "version": 1, "plaintext": B64.encode(pdf),
            "recipients": [recipient(&bureau)],
        }),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let enc: Value = serde_json::from_slice(&b).unwrap();
    let ct = B64.decode(enc["ciphertext"].as_str().unwrap()).unwrap();
    assert!(
        !ct.windows(10).any(|w| w == b"top secret"),
        "plaintext leaked"
    );
    let wk = &enc["wrapped_keys"][0]["wrapped_key"];

    let decrypt = |key: Value| {
        let grant = decrypt_grant("DOC-77", 1, key["position_code"].as_str().unwrap());
        json!({"document_id": "DOC-77", "version": 1, "ciphertext": enc["ciphertext"],
               "key": key, "grant": grant})
    };
    let (s, b) = call(&app, "/documents/decrypt", decrypt(holder(&bureau, wk))).await;
    assert_eq!((s, b.as_slice()), (StatusCode::OK, &pdf[..]));

    let (s, _) = call(&app, "/documents/decrypt", decrypt(holder(&admin, wk))).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);

    let (s, b) = call(
        &app,
        "/dispositions",
        json!({
            "document_id": "DOC-77", "version": 1, "source": holder(&bureau, wk),
            "targets": [recipient(&section)],
            "grant": dispose_grant("DOC-77", 1, "HEAD-OF-BUREAU", &["HEAD-OF-SECTION"]),
        }),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let disp: Value = serde_json::from_slice(&b).unwrap();
    let section_key = holder(&section, &disp["wrapped_keys"][0]["wrapped_key"]);
    let (s, b) = call(&app, "/documents/decrypt", decrypt(section_key)).await;
    assert_eq!((s, b.as_slice()), (StatusCode::OK, &pdf[..]));
}

#[tokio::test]
async fn text_end_to_end() {
    let app = app();
    let staff = create_key(&app, "STAFF").await;
    let text = "Nomor rekening: 123-456 — \"rahasia\" ✓";
    let (s, b) = call(
        &app,
        "/text/encrypt",
        json!({
            "document_id": "NOTE-1", "version": 1, "text": text, "recipients": [recipient(&staff)],
        }),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let enc: Value = serde_json::from_slice(&b).unwrap();
    let (s, b) = call(
        &app,
        "/text/decrypt",
        json!({
            "document_id": "NOTE-1", "version": 1, "ciphertext": enc["ciphertext"],
            "key": holder(&staff, &enc["wrapped_keys"][0]["wrapped_key"]),
            "grant": decrypt_grant("NOTE-1", 1, "STAFF"),
        }),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let got: Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(
        got,
        json!({"document_id": "NOTE-1", "version": 1, "text": text})
    );
}

#[tokio::test]
async fn decrypt_without_matching_grant_is_403() {
    let app = app();
    let bureau = create_key(&app, "HEAD-OF-BUREAU").await;
    let (_, b) = call(
        &app,
        "/documents/encrypt",
        json!({
            "document_id": "DOC-1", "version": 1, "plaintext": B64.encode(b"memo"),
            "recipients": [recipient(&bureau)],
        }),
    )
    .await;
    let enc: Value = serde_json::from_slice(&b).unwrap();
    let key = holder(&bureau, &enc["wrapped_keys"][0]["wrapped_key"]);
    for grant in [
        String::new(),
        decrypt_grant("DOC-1", 1, "ADMIN-STAFF"),
        dispose_grant("DOC-1", 1, "HEAD-OF-BUREAU", &[]),
    ] {
        let (s, b) = call(
            &app,
            "/documents/decrypt",
            json!({
                "document_id": "DOC-1", "version": 1, "ciphertext": enc["ciphertext"],
                "key": key, "grant": grant,
            }),
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(
            serde_json::from_slice::<Value>(&b).unwrap()["error"],
            "access_denied"
        );
    }
    let (s, _) = call(
        &app,
        "/documents/decrypt",
        json!({
            "document_id": "DOC-1", "version": 1, "ciphertext": enc["ciphertext"], "key": key,
        }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn bad_input() {
    let app = app();
    let (s, _) = call(
        &app,
        "/documents/encrypt",
        json!({"document_id": "D", "version": 1, "unknown": true}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let (s, _) = call(
        &app,
        "/keys",
        json!({"position_code": "X", "key_version": 1, "suite_id": "RSA"}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let (s, _) = call(&app, "/documents/encrypt", json!({
        "document_id": "D", "version": 1, "plaintext": "",
        "recipients": [{"position_code": "X", "key_version": 1, "suite_id": "S", "public_key": "", "extra": 1}],
    }))
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "unknown recipient field");

    let big = B64.encode(vec![0u8; 5 << 20]);
    let (s, _) = call(
        &app,
        "/documents/encrypt",
        json!({
            "document_id": "D", "version": 1, "plaintext": big, "recipients": [],
        }),
    )
    .await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn readyz_caches_kms_probe() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let fake = Router::new().route(
        "/v1/transit/{op}/jabatan-kek",
        post(move |Json(b): Json<Value>| {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                match b["plaintext"].as_str() {
                    Some(pt) => Json(json!({"data": {"ciphertext": format!("vault:v1:{pt}")}})),
                    None => {
                        let ct = b["ciphertext"].as_str().unwrap_or_default();
                        Json(json!({"data": {"plaintext": ct.trim_start_matches("vault:v1:")}}))
                    }
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, fake).await.unwrap() });

    let token = std::env::temp_dir().join(format!("ks-readyz-{}", addr.port()));
    std::fs::write(&token, "s.token").unwrap();
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut service = crate::service::tests::service();
    service.custody = Arc::new(SoftwareKeyCustody::new(Arc::new(OpenBaoTransit {
        addr: format!("http://{addr}"),
        mount: "transit".into(),
        key_name: "jabatan-kek".into(),
        namespace: None,
        token_file: token.clone(),
        http: OpenBaoTransit::http_client(None, false).unwrap(),
    })));
    let state = Arc::new(AppState::new(service));
    let health = health_router(state.clone());
    for _ in 0..20 {
        assert_eq!(
            get(health.clone(), "/readyz").await.status(),
            StatusCode::NO_CONTENT
        );
    }
    let _ = std::fs::remove_file(&token);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "one seal + unseal for 20 probes"
    );

    state.start_draining();
    assert_eq!(
        get(health, "/readyz").await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "draining must not call the KMS"
    );
}

#[tokio::test]
async fn overloaded_when_no_slot() {
    let st = Arc::new(state().with_limits(1, Duration::from_millis(50)));
    let app = router(st.clone(), 4 << 20);
    let held = st.inflight.acquire().await.unwrap();
    assert_eq!(
        get(app.clone(), "/suites").await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    drop(held);
    assert_eq!(get(app, "/suites").await.status(), StatusCode::OK);
}

#[tokio::test]
async fn stalled_body_times_out() {
    struct Pending;
    impl futures_core::Stream for Pending {
        type Item = Result<Bytes, std::io::Error>;
        fn poll_next(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            std::task::Poll::Pending
        }
    }
    let app = router(
        Arc::new(state().with_limits(4, Duration::from_millis(50))),
        4 << 20,
    );
    let req = axum::http::Request::post("/documents/encrypt")
        .header("content-type", "application/json")
        .body(Body::from_stream(Pending))
        .unwrap();
    assert_eq!(
        app.oneshot(req).await.unwrap().status(),
        StatusCode::REQUEST_TIMEOUT
    );
}

#[test]
fn b64_decodes_escaped_and_borrowed_strings() {
    #[derive(Deserialize)]
    struct T {
        #[serde(with = "b64")]
        v: Vec<u8>,
    }
    assert_eq!(
        serde_json::from_str::<T>(r#"{"v":"\/w=="}"#).unwrap().v,
        [0xff]
    );
    assert_eq!(
        serde_json::from_str::<T>(r#"{"v":"/w=="}"#).unwrap().v,
        [0xff]
    );
    assert!(serde_json::from_str::<T>(r#"{"v":"!!"}"#).is_err());
    assert!(serde_json::from_str::<T>(r#"{"v":5}"#).is_err());
}

#[test]
fn hex_request_id() {
    assert_eq!(hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
}

#[tokio::test]
async fn security_headers() {
    let resp = get(app(), "/suites").await;
    assert_eq!(resp.headers()["cache-control"], "no-store");
    assert!(resp.headers().contains_key("x-request-id"));
}
