//! The gluetun control adapter and the reqwest transports' rotation hooks,
//! against local HTTP servers.

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use common::gluetun::FakeGluetun;
use megaquarry_core::adapters::gluetun::GluetunControl;
use megaquarry_core::adapters::http::ReqwestDownloadTransport;
use megaquarry_core::download::{ChunkBody, DownloadTransport};
use megaquarry_core::egress::{RotationOptions, Rotator, VpnControl, VpnStatus};
use megaquarry_core::store::Store;

const KEY: &str = "s3cret-api-key";

#[tokio::test]
async fn reads_status_and_ip_and_reconnects_with_the_key_in_a_header() {
    let fake = FakeGluetun::start(KEY, "1.1.1.1", &["2.2.2.2"]);
    let control = GluetunControl::new(&fake.base, KEY.into()).unwrap();

    assert_eq!(control.status().await.unwrap(), VpnStatus::Running);
    assert_eq!(
        control.public_ip().await.unwrap().as_deref(),
        Some("1.1.1.1")
    );
    control.set_running(false).await.unwrap();
    assert_eq!(control.status().await.unwrap(), VpnStatus::Stopped);
    assert_eq!(control.public_ip().await.unwrap(), None, "empty while down");
    control.set_running(true).await.unwrap();
    assert_eq!(
        control.public_ip().await.unwrap().as_deref(),
        Some("2.2.2.2")
    );

    let requests = fake.requests();
    assert_eq!(requests.len(), 7);
    assert!(requests.iter().all(|(_, _, authorized)| *authorized));
    assert!(
        requests.iter().all(|(_, target, _)| !target.contains('?')),
        "the key never goes in the URL: {requests:?}"
    );
}

#[tokio::test]
async fn starting_while_running_is_a_harmless_no_op() {
    let fake = FakeGluetun::start(KEY, "1.1.1.1", &["2.2.2.2"]);
    let control = GluetunControl::new(&fake.base, KEY.into()).unwrap();

    control.set_running(true).await.unwrap();

    assert_eq!(
        control.public_ip().await.unwrap().as_deref(),
        Some("1.1.1.1")
    );
}

#[tokio::test]
async fn the_auth_guard_tells_a_protected_server_from_an_open_one() {
    let fake = FakeGluetun::start(KEY, "1.1.1.1", &[]);
    let control = GluetunControl::new(&fake.base, KEY.into()).unwrap();

    assert!(control.requires_auth().await.unwrap());
    let (_, _, authorized) = fake.requests()[0].clone();
    assert!(!authorized, "the guard sends no key");

    fake.state.lock().unwrap().open = true;
    assert!(!control.requires_auth().await.unwrap());
}

#[tokio::test]
async fn a_wrong_key_is_reported_without_revealing_it() {
    let fake = FakeGluetun::start(KEY, "1.1.1.1", &[]);
    let wrong = "wrong-key-value";
    let control = GluetunControl::new(&fake.base, wrong.into()).unwrap();

    let error = control.status().await.unwrap_err();

    assert!(error.0.contains("401"), "{error}");
    assert!(!error.0.contains(wrong), "{error}");
    assert!(!format!("{control:?}").contains(wrong));
}

#[tokio::test]
async fn an_unreachable_control_is_an_error() {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let control = GluetunControl::new(&format!("http://127.0.0.1:{port}"), KEY.into()).unwrap();

    assert!(control.status().await.is_err());
}

#[test]
fn only_http_control_urls_are_accepted() {
    assert!(GluetunControl::new("ftp://127.0.0.1:8000", KEY.into()).is_err());
    assert!(GluetunControl::new("127.0.0.1:8000", KEY.into()).is_err());
    assert!(GluetunControl::new("http://127.0.0.1:8000/", KEY.into()).is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rotator_over_gluetun_moves_to_a_new_exit_ip() {
    let fake = FakeGluetun::start(KEY, "1.1.1.1", &["2.2.2.2"]);
    let control = GluetunControl::new(&fake.base, KEY.into()).unwrap();
    let store = Arc::new(Store::open_in_memory().unwrap());
    let rotator = Rotator::new(
        control,
        store.clone(),
        RotationOptions {
            poll_interval: Duration::from_millis(10),
            reconnect_timeout: Duration::from_secs(5),
            ..RotationOptions::default()
        },
    );

    rotator
        .rotate(0, Some(Duration::from_secs(600)))
        .await
        .unwrap();

    assert_eq!(fake.state.lock().unwrap().ip, "2.2.2.2");
    assert!(
        store
            .ip_cooling_until("1.1.1.1", std::time::SystemTime::now())
            .unwrap()
            .is_some()
    );
}

/// A storage server answering every request with a 509 and MEGA's wait.
fn quota_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(
                b"HTTP/1.1 509 Bandwidth Limit Exceeded\r\nX-MEGA-Time-Left: 1234\r\nContent-Length: 0\r\n\r\n",
            );
        }
    });
    base
}

#[tokio::test]
async fn chunk_bodies_expose_headers_and_connections_can_be_reset() {
    let base = quota_server();
    let transport = ReqwestDownloadTransport::new().unwrap();

    let (status, body) = transport.get(&format!("{base}/dl/0-10")).await.unwrap();
    assert_eq!(status, 509);
    assert_eq!(body.header("x-mega-time-left").as_deref(), Some("1234"));

    transport.reset_connections();
    let (status, _) = transport.get(&format!("{base}/dl/0-10")).await.unwrap();
    assert_eq!(status, 509, "requests still work after a reset");
}
