//! Regression probes from the independent verification of MegaRunner.
mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{FakeTransport, api, ok};
use megaquarry_core::api::{RetryPolicy, TransportError};
use megaquarry_core::crypto::FileKey;
use megaquarry_core::download::{ChunkBody, DownloadOptions, DownloadTransport, Downloader};
use megaquarry_core::link::MegaLink;
use megaquarry_core::queue::{JobContext, JobOutcome, JobProgress, MegaRunner, TransferRunner};
use megaquarry_core::session::{Credentials, Session};
use megaquarry_core::store::{QueueKind, Store};
use megaquarry_core::upload::{UploadCheckpoint, UploadOptions, UploadTransport, Uploader};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

struct NoBody;
impl ChunkBody for NoBody {
    async fn next_piece(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        Ok(None)
    }
}
struct NoDownloads;
impl DownloadTransport for NoDownloads {
    type Body = NoBody;
    async fn get(&self, _url: &str) -> Result<(u16, NoBody), TransportError> {
        Ok((500, NoBody))
    }
}

/// Every chunk reply is the fixed (status, body), after `delay` ms per POST.
struct Sink {
    status: u16,
    body: &'static str,
    delay: u64,
    posts: Mutex<usize>,
}
impl UploadTransport for Sink {
    async fn post(&self, _url: &str, _b: Vec<u8>) -> Result<(u16, Vec<u8>), TransportError> {
        tokio::time::sleep(Duration::from_millis(self.delay)).await;
        *self.posts.lock().unwrap() += 1;
        Ok((self.status, self.body.as_bytes().to_vec()))
    }
}

fn session() -> Session {
    Session {
        sid: "SID".into(),
        master_key: [9; 16],
        user_handle: "U".into(),
        credentials: Credentials {
            email: "e@x.y".into(),
            password_aes: [1; 16],
            user_hash: "uh".into(),
        },
    }
}

fn retry() -> RetryPolicy {
    RetryPolicy {
        max_retries: 1,
        base: Duration::from_millis(1),
        cap: Duration::from_millis(2),
    }
}

fn runner(
    store: &Arc<Store>,
    replies: Vec<&str>,
    sink: Sink,
    session: Option<Session>,
) -> MegaRunner<FakeTransport, NoDownloads, Sink> {
    MegaRunner::new(
        Arc::new(api(FakeTransport::with(
            replies.into_iter().map(ok).collect(),
        ))),
        session,
        store.clone(),
        Downloader::new(
            Arc::new(NoDownloads),
            None,
            DownloadOptions {
                workers: 1,
                retry: retry(),
                ..DownloadOptions::default()
            },
        ),
        Uploader::new(
            Arc::new(sink),
            None,
            UploadOptions {
                workers: 1,
                retry: retry(),
            },
        ),
        false,
    )
}

fn ctx(id: i64) -> JobContext {
    JobContext {
        id,
        cancel: CancellationToken::new(),
        progress: Arc::new(JobProgress::default()),
    }
}

fn sink(status: u16, body: &'static str, delay: u64) -> Sink {
    Sink {
        status,
        body,
        delay,
        posts: Mutex::new(0),
    }
}

fn upload_entry(store: &Store, dir: &tempfile::TempDir, size: usize) -> (i64, Value) {
    let path = dir.path().join("u.bin");
    std::fs::write(&path, vec![7u8; size]).unwrap();
    let payload = json!({"path": path.display().to_string(), "parent": "P", "keep": "me"});
    (store.enqueue(QueueKind::Upload, &payload).unwrap(), payload)
}

fn retry_of(o: &JobOutcome) -> Option<Option<Duration>> {
    match o {
        JobOutcome::Failed { retry_after, .. } => Some(*retry_after),
        _ => None,
    }
}

#[tokio::test]
async fn r1_upload_error_classes() {
    let cases: Vec<(u16, &'static str, Option<Duration>)> = vec![
        (200, "-17", Some(Duration::from_secs(60))),
        (200, "-4", Some(Duration::from_secs(60))),
        (200, "-11", None),
        (500, "", Some(Duration::from_secs(3))),
        (509, "", Some(Duration::from_secs(60))), // L24 lists HTTP 509 as quota
    ];
    for (status, body, want) in cases {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let dir = tempfile::tempdir().unwrap();
        let (id, payload) = upload_entry(&store, &dir, 1000);
        let r = runner(
            &store,
            vec![r#"[{"p": "http://ul/a"}]"#],
            sink(status, body, 0),
            Some(session()),
        );
        let o = r.run(QueueKind::Upload, payload, ctx(id)).await;
        let got = retry_of(&o);
        assert_eq!(got, Some(want), "status {status} body {body:?}: {o:?}");
        let stored = store.entry(id).unwrap().unwrap().payload;
        assert_eq!(stored["keep"], json!("me"));
        assert!(
            UploadCheckpoint::from_json(&stored["checkpoint"]).is_some(),
            "checkpoint kept on failure"
        );
    }
}

#[tokio::test]
async fn r2_no_token_clears_checkpoint_and_api_errors() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    let dir = tempfile::tempdir().unwrap();
    let (id, payload) = upload_entry(&store, &dir, 1000);
    let r = runner(
        &store,
        vec![r#"[{"p": "http://ul/a"}]"#],
        sink(200, "", 0),
        Some(session()),
    );
    let o = r.run(QueueKind::Upload, payload, ctx(id)).await;
    assert_eq!(retry_of(&o), Some(Some(Duration::from_secs(3))), "{o:?}");
    assert!(
        store
            .entry(id)
            .unwrap()
            .unwrap()
            .payload
            .get("checkpoint")
            .is_none()
    );

    // `u` failing with -3 (transient API) → 3 s; -9 → permanent.
    for (reply, want) in [("-3", Some(Duration::from_secs(3))), ("-9", None)] {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let (id, payload) = upload_entry(&store, &dir, 10);
        let replies = vec![reply; 8];
        let r = runner(&store, replies, sink(200, "TOK", 0), Some(session()));
        let o = r.run(QueueKind::Upload, payload, ctx(id)).await;
        assert_eq!(retry_of(&o), Some(want), "{reply}: {o:?}");
    }
}

#[tokio::test]
async fn r3_payload_validation_is_permanent() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    let key = FileKey::from_bytes(&[3u8; 32]).unwrap();
    let file = MegaLink::File {
        handle: "H".into(),
        key,
    }
    .to_url();
    let downloads = [
        json!({"link": file, "name": "n", "size": 1}),
        json!({"link": file, "name": "n", "size": 1, "destination": ""}),
        json!({"link": "https://mega.nz/folder/AAAA#BBBBBBBBBBBBBBBBBBBBBB", "destination": "/x"}),
        json!({"link": "garbage", "destination": "/x"}),
        json!({"destination": "/x"}),
    ];
    let r = runner(&store, vec![], sink(200, "", 0), Some(session()));
    for p in downloads {
        let o = r.run(QueueKind::Download, p.clone(), ctx(1)).await;
        assert_eq!(retry_of(&o), Some(None), "{p}: {o:?}");
    }
    for p in [json!({"path": "/x"}), json!({"parent": "P"}), json!({})] {
        let o = r.run(QueueKind::Upload, p.clone(), ctx(1)).await;
        assert_eq!(retry_of(&o), Some(None), "{p}: {o:?}");
    }
    let o = runner(&store, vec![], sink(200, "", 0), None)
        .run(
            QueueKind::Upload,
            json!({"path": "/x", "parent": "P"}),
            ctx(1),
        )
        .await;
    assert_eq!(retry_of(&o), Some(None));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r4_checkpoint_saved_during_run_and_ticker_stops() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    let dir = tempfile::tempdir().unwrap();
    let (id, payload) = upload_entry(&store, &dir, 900 * 1024); // 4 chunks
    let r = Arc::new(runner(
        &store,
        vec![r#"[{"p": "http://ul/a"}]"#, r#"[{"f":[{"h":"N"}]}]"#],
        sink(200, "", 200),
        Some(session()),
    ));
    let job = {
        let r = r.clone();
        tokio::spawn(async move { r.run(QueueKind::Upload, payload, ctx(id)).await })
    };
    tokio::time::sleep(Duration::from_millis(600)).await;
    let mid = store.entry(id).unwrap().unwrap().payload;
    let cp =
        UploadCheckpoint::from_json(&mid["checkpoint"]).expect("checkpoint saved while running");
    assert!(
        !cp.done.is_empty() && cp.done.len() < 4,
        "{:?}",
        cp.done.keys()
    );
    let o = job.await.unwrap();
    assert!(matches!(o, JobOutcome::Failed { .. }), "{o:?}"); // no token: NoCompletionToken
    // After the job, nothing writes the entry again.
    let mut p = store.entry(id).unwrap().unwrap().payload;
    p["marker"] = json!(1);
    p.as_object_mut().unwrap().remove("checkpoint");
    store.update_entry(id, &p).unwrap();
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(
        store.entry(id).unwrap().unwrap().payload,
        p,
        "ticker still writing"
    );
}
