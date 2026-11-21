//! Secrets must never reach error messages or debug output.

mod common;

use common::{FakeTransport, api, ok};
use megaquarry_core::adapters::http::ReqwestTransport;
use megaquarry_core::api::{ApiConfig, MegaApi, RetryPolicy};
use megaquarry_core::session::{self, Credentials};
use serde_json::json;

#[tokio::test]
async fn failed_logins_never_set_a_session_id() {
    for reply in [
        r#"[{"k":"AAAAAAAAAAAAAAAAAAAAAA"}]"#,
        r#"[{"privk":"x","csid":"y"}]"#,
        r#"[{"k":"AAAAAAAAAAAAAAAAAAAAAA","keys":"z","privk":"AAAAAAAAAAAAAAAAAAAAAA","csid":"AAA"}]"#,
        r#"[{"k":"AAAA","privk":"AAAA","csid":"AAAA"}]"#,
    ] {
        let api = api(FakeTransport::with(vec![ok(reply)]));
        let creds = Credentials {
            email: "e@x.y".into(),
            password_aes: [1; 16],
            user_hash: "uh".into(),
        };
        let r = session::login_with_credentials(&api, &creds, Some("1")).await;
        assert!(r.is_err(), "{reply}");
        assert_eq!(api.session_id(), None);
    }
}

#[test]
fn debug_output_hides_key_material() {
    let creds = Credentials {
        email: "e@x.y".into(),
        password_aes: [0xAB; 16],
        user_hash: "USERHASHSECRET".into(),
    };
    let s = format!("{creds:?} {creds:#?}");
    assert!(!s.contains("171") && !s.contains("ab") && !s.contains("USERHASHSECRET"));
}

#[tokio::test]
async fn network_errors_do_not_include_the_session_id() {
    // A local server that accepts and immediately drops each connection,
    // so the request fails deterministically with a reqwest error.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            drop(socket);
        }
    });
    let api = MegaApi::new(
        ReqwestTransport::new().unwrap(),
        ApiConfig {
            api_url: format!("http://{addr}"),
            retry: RetryPolicy {
                max_retries: 0,
                ..RetryPolicy::default()
            },
            ..ApiConfig::default()
        },
    );
    api.set_session_id(Some("SECRETSESSIONID".into()));
    let err = api.call(json!({"a": "ug"})).await.unwrap_err();
    let login_err = megaquarry_core::session::LoginError::from(err.clone());
    assert!(!login_err.to_string().contains("SECRETSESSIONID"));
    assert!(
        !err.to_string().contains("SECRETSESSIONID"),
        "sid leaked in error text"
    );
}
