mod common;

use std::time::Duration;

use common::{FakeTransport, api, ok, status};
use megaquarry_core::api::{ApiError, ErrorCode, HttpResponse, TransportError, hashcash};
use serde_json::json;

#[tokio::test]
async fn sends_command_batch_with_sequence_id_and_app_key() {
    let api = api(FakeTransport::with(vec![ok(r#"[{"v":2}]"#), ok("[0]")]));
    let reply = api
        .call(json!({"a": "us0", "user": "a@b.c"}))
        .await
        .unwrap();
    assert_eq!(reply, json!({"v": 2}));
    api.call(json!({"a": "x"})).await.unwrap();

    let requests = api.transport().requests();
    let first = &requests[0];
    assert!(first.url.starts_with("https://g.api.mega.co.nz/cs?id="));
    assert!(first.url.contains("&ak=BdARkQSQ"));
    assert!(!first.url.contains("sid="));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&first.body).unwrap(),
        json!([{"a": "us0", "user": "a@b.c"}])
    );

    let id = |url: &str| -> u64 {
        url.split("id=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap()
            .parse()
            .unwrap()
    };
    assert_eq!(id(&requests[1].url), id(&first.url) + 1);
}

#[tokio::test]
async fn adds_session_id_and_extra_query_parameters() {
    let api = api(FakeTransport::with(vec![ok("[1]")]));
    api.set_session_id(Some("SID123".into()));
    api.call_with_query(json!({"a": "f"}), &[("n", "FOLDER")])
        .await
        .unwrap();
    let url = &api.transport().requests()[0].url;
    assert!(url.contains("&sid=SID123"), "{url}");
    assert!(url.ends_with("&n=FOLDER"), "{url}");
}

#[tokio::test]
async fn maps_whole_body_and_per_command_errors() {
    let api = api(FakeTransport::with(vec![
        ok("-9"),
        ok("[-11]"),
        ok("[-14]"),
    ]));
    assert_eq!(
        api.call(json!({"a": "g"})).await,
        Err(ApiError::Mega(ErrorCode::NotFound))
    );
    assert_eq!(
        api.call(json!({"a": "g"})).await,
        Err(ApiError::Mega(ErrorCode::AccessDenied))
    );
    let err = api.call(json!({"a": "g"})).await.unwrap_err();
    assert_eq!(err, ApiError::Mega(ErrorCode::Key));
    assert_eq!(err.to_string(), "MEGA error -14 (EKEY): decryption failed");
}

#[tokio::test(start_paused = true)]
async fn retries_transient_failures_with_backoff() {
    let api = api(FakeTransport::with(vec![
        status(500, ""),
        ok(""),
        ok("-3"),
        ok(r#"[{"ok":true}]"#),
    ]));
    let started = tokio::time::Instant::now();
    assert_eq!(
        api.call(json!({"a": "x"})).await.unwrap(),
        json!({"ok": true})
    );
    // Backoff 1 + 2 + 4 seconds.
    assert_eq!(started.elapsed(), Duration::from_secs(7));
    let requests = api.transport().requests();
    assert_eq!(requests.len(), 4);
    // Retries reuse the same sequence id.
    assert!(requests.iter().all(|r| r.url == requests[0].url));
}

#[tokio::test(start_paused = true)]
async fn gives_up_after_the_retry_limit() {
    let api = api(FakeTransport::with(vec![
        ok("-3"),
        ok("-3"),
        ok("-3"),
        ok("-3"),
    ]));
    assert_eq!(
        api.call(json!({"a": "x"})).await,
        Err(ApiError::Mega(ErrorCode::Again))
    );
    assert_eq!(api.transport().requests().len(), 4);
}

#[tokio::test(start_paused = true)]
async fn retries_network_errors_but_not_other_http_statuses() {
    let api = api(FakeTransport::with(vec![
        Err(TransportError("connection reset".into())),
        ok("[1]"),
        status(404, ""),
    ]));
    assert_eq!(api.call(json!({"a": "x"})).await.unwrap(), json!(1));
    assert_eq!(api.call(json!({"a": "x"})).await, Err(ApiError::Http(404)));
}

#[tokio::test]
async fn answers_hashcash_challenges() {
    let challenge =
        "1:255:1700000000:ZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo-QkZKT";
    let api = api(FakeTransport::with(vec![
        Ok(HttpResponse {
            status: 402,
            headers: vec![("X-Hashcash".into(), challenge.into())],
            body: vec![],
        }),
        ok("[0]"),
    ]));
    assert_eq!(api.call(json!({"a": "x"})).await.unwrap(), json!(0));

    let retry = &api.transport().requests()[1];
    let answer = retry
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("X-Hashcash"))
        .map(|(_, v)| v.clone())
        .expect("hashcash header");
    assert!(hashcash::verify(challenge, &answer));
}

#[test]
fn hashcash_verifies_reference_solution_and_rejects_others() {
    let challenge =
        "1:192:1700000000:ZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo-QkZKT";
    let solution = "1:ZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo-QkZKT:AAAAGA";
    assert!(hashcash::verify(challenge, solution));
    assert!(!hashcash::verify(
        challenge,
        "1:ZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo-QkZKT:AAAAAA"
    ));
    let solved = hashcash::solve(challenge).unwrap();
    assert!(hashcash::verify(challenge, &solved));
}

#[test]
fn hashcash_rejects_malformed_challenges() {
    for bad in ["", "2:1:1:abc", "1:300:1:abc", "1:1:1:short"] {
        assert!(hashcash::solve(bad).is_err(), "{bad}");
    }
}

#[test]
fn error_codes_round_trip_through_their_numbers() {
    for code in -30..=-1 {
        assert_eq!(ErrorCode::from_code(code).code(), code);
    }
    assert_eq!(ErrorCode::from_code(-17), ErrorCode::OverQuota);
    assert_eq!(ErrorCode::from_code(-26), ErrorCode::MfaRequired);
    assert_eq!(ErrorCode::from_code(-99), ErrorCode::Unknown(-99));
}

#[tokio::test]
async fn percent_encodes_query_values() {
    let api = api(FakeTransport::with(vec![ok("[1]")]));
    api.call_with_query(json!({"a": "f"}), &[("n", "a b&c=d")])
        .await
        .unwrap();
    assert!(
        api.transport().requests()[0]
            .url
            .ends_with("&n=a%20b%26c%3Dd")
    );
}

#[tokio::test(start_paused = true)]
async fn reports_the_last_http_status_once_retries_run_out() {
    let api = api(FakeTransport::with(vec![
        status(500, ""),
        status(503, ""),
        status(500, ""),
        status(500, ""),
    ]));
    assert_eq!(api.call(json!({"a": "x"})).await, Err(ApiError::Http(500)));
}

#[tokio::test]
async fn rejects_replies_that_are_not_json() {
    let api = api(FakeTransport::with(vec![ok("<html>oops</html>")]));
    assert!(matches!(
        api.call(json!({"a": "x"})).await,
        Err(ApiError::InvalidResponse(_))
    ));
}

#[tokio::test(start_paused = true)]
async fn stops_retrying_at_the_overall_deadline() {
    let transport = FakeTransport::with((0..30).map(|_| ok("-3")).collect());
    let api = megaquarry_core::api::MegaApi::new(
        transport,
        megaquarry_core::api::ApiConfig {
            deadline: Some(Duration::from_secs(10)),
            ..Default::default()
        },
    );
    let started = tokio::time::Instant::now();
    assert_eq!(
        api.call(json!({"a": "x"})).await,
        Err(ApiError::Mega(ErrorCode::Again))
    );
    // Attempts at t = 0, 1, 3 and 7 s; the next 8 s backoff would pass 10 s.
    assert_eq!(api.transport().requests().len(), 4);
    assert_eq!(started.elapsed(), Duration::from_secs(7));
}

#[tokio::test]
async fn gives_up_after_repeated_hashcash_challenges() {
    let challenge =
        "1:255:1700000000:ZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo-QkZKT";
    let challenged = || {
        Ok(HttpResponse {
            status: 402,
            headers: vec![("X-Hashcash".into(), challenge.into())],
            body: vec![],
        })
    };
    let api = api(FakeTransport::with((0..6).map(|_| challenged()).collect()));
    assert!(matches!(
        api.call(json!({"a": "x"})).await,
        Err(ApiError::Hashcash(_))
    ));
}

/// A transport whose requests never complete (a server trickling forever).
struct StalledTransport;

impl megaquarry_core::api::ApiTransport for StalledTransport {
    async fn post(
        &self,
        _request: megaquarry_core::api::HttpRequest,
    ) -> Result<HttpResponse, TransportError> {
        std::future::pending().await
    }
}

#[tokio::test(start_paused = true)]
async fn the_deadline_also_bounds_an_attempt_in_flight() {
    let api = megaquarry_core::api::MegaApi::new(
        StalledTransport,
        megaquarry_core::api::ApiConfig {
            deadline: Some(Duration::from_secs(10)),
            ..Default::default()
        },
    );
    let started = tokio::time::Instant::now();
    assert!(matches!(
        api.call(json!({"a": "x"})).await,
        Err(ApiError::Transport(_))
    ));
    assert_eq!(started.elapsed(), Duration::from_secs(10));
}
