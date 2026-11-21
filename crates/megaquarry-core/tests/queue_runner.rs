mod common;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{FakeTransport, api, ok};
use megaquarry_core::api::{RetryPolicy, TransportError};
use megaquarry_core::chunk::meta_mac_of;
use megaquarry_core::crypto::{FileKey, ctr_apply};
use megaquarry_core::download::{ChunkBody, DownloadOptions, DownloadTransport, Downloader};
use megaquarry_core::link::MegaLink;
use megaquarry_core::queue::{JobContext, JobOutcome, JobProgress, MegaRunner, TransferRunner};
use megaquarry_core::session::{Credentials, Session};
use megaquarry_core::store::{QueueKind, Store};
use megaquarry_core::upload::{UploadCheckpoint, UploadOptions, UploadTransport, Uploader};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

const KIB: usize = 1024;

struct Body(Option<Vec<u8>>);

impl ChunkBody for Body {
    async fn next_piece(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        Ok(self.0.take())
    }
}

/// Serves one encrypted file at any base URL.
struct Storage {
    ciphertext: Vec<u8>,
}

impl DownloadTransport for Storage {
    type Body = Body;

    async fn get(&self, url: &str) -> Result<(u16, Body), TransportError> {
        let range = url.rsplit('/').next().unwrap();
        let (start, end) = match range.split_once('-') {
            Some((s, e)) => (s.parse::<usize>().unwrap(), e.parse::<usize>().unwrap() + 1),
            None => (range.parse().unwrap(), self.ciphertext.len()),
        };
        Ok((200, Body(Some(self.ciphertext[start..end].to_vec()))))
    }
}

/// Accepts upload chunks slowly; answers a token once complete.
#[derive(Default)]
struct UploadSink {
    size: u64,
    received: Mutex<BTreeMap<u64, usize>>,
}

impl UploadTransport for UploadSink {
    async fn post(&self, url: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>), TransportError> {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let offset: u64 = url.rsplit('/').next().unwrap().parse().unwrap();
        let mut received = self.received.lock().unwrap();
        received.insert(offset, body.len());
        let total: u64 = received.values().map(|n| *n as u64).sum();
        Ok((
            200,
            if total >= self.size {
                b"TOKEN".to_vec()
            } else {
                vec![]
            },
        ))
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
        max_retries: 2,
        base: Duration::from_millis(1),
        cap: Duration::from_millis(2),
    }
}

struct Fixture {
    store: Arc<Store>,
    dir: tempfile::TempDir,
    plain: Vec<u8>,
    key: FileKey,
}

fn fixture(size: usize) -> (Fixture, Storage) {
    let plain: Vec<u8> = (0..size).map(|i| (i % 199) as u8).collect();
    let (aes_key, nonce) = ([4u8; 16], [6u8; 8]);
    let key = FileKey::pack(&aes_key, &nonce, &meta_mac_of(&aes_key, &nonce, &plain));
    let mut ciphertext = plain.clone();
    ctr_apply(&aes_key, &nonce, 0, &mut ciphertext);
    (
        Fixture {
            store: Arc::new(Store::open_in_memory().unwrap()),
            dir: tempfile::tempdir().unwrap(),
            plain,
            key,
        },
        Storage { ciphertext },
    )
}

fn runner(
    fx: &Fixture,
    api_replies: Vec<&str>,
    storage: Storage,
    sink: UploadSink,
    session: Option<Session>,
) -> MegaRunner<FakeTransport, Storage, UploadSink> {
    MegaRunner::new(
        Arc::new(api(FakeTransport::with(
            api_replies.into_iter().map(ok).collect(),
        ))),
        session,
        fx.store.clone(),
        Downloader::new(
            Arc::new(storage),
            None,
            DownloadOptions {
                workers: 2,
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
        true,
    )
}

fn ctx(id: i64) -> JobContext {
    JobContext {
        id,
        cancel: CancellationToken::new(),
        progress: Arc::new(JobProgress::default()),
    }
}

fn download_payload(fx: &Fixture) -> Value {
    json!({
        "link": MegaLink::File { handle: "H".into(), key: fx.key.clone() }.to_url(),
        "name": "movie.mkv",
        "size": fx.plain.len(),
        "destination": fx.dir.path().join("movie.mkv").display().to_string(),
    })
}

#[tokio::test]
async fn runs_a_download_entry() {
    let (fx, storage) = fixture(700 * KIB);
    let runner = runner(
        &fx,
        vec![r#"[{"g": "http://dl/x", "s": 1}]"#],
        storage,
        UploadSink::default(),
        None,
    );
    let context = ctx(1);
    let outcome = runner
        .run(QueueKind::Download, download_payload(&fx), context.clone())
        .await;
    assert!(
        matches!(&outcome, JobOutcome::Done { summary } if summary.contains("movie.mkv")),
        "{outcome:?}"
    );
    assert_eq!(
        std::fs::read(fx.dir.path().join("movie.mkv")).unwrap(),
        fx.plain
    );
    assert_eq!(context.progress.done(), fx.plain.len() as u64);
}

#[tokio::test]
async fn classifies_download_failures() {
    let (fx, storage) = fixture(10);
    let blocked = runner(
        &fx,
        vec!["[{\"e\": -16}]"],
        storage,
        UploadSink::default(),
        None,
    );
    assert_eq!(
        blocked.run(QueueKind::Download, download_payload(&fx), ctx(1)).await,
        JobOutcome::Failed {
            error: "could not get a download URL: MEGA error -16 (EBLOCKED): blocked (account suspended or link taken down)".into(),
            retry_after: None,
        }
    );

    let (fx, storage) = fixture(10);
    let quota = runner(&fx, vec!["[-17]"], storage, UploadSink::default(), None);
    assert!(matches!(
        quota.run(QueueKind::Download, download_payload(&fx), ctx(1)).await,
        JobOutcome::Failed { retry_after: Some(d), .. } if d == Duration::from_secs(60)
    ));

    let (fx, storage) = fixture(10);
    let bad = runner(&fx, vec![], storage, UploadSink::default(), None);
    assert!(matches!(
        bad.run(QueueKind::Download, json!({"link": "nope"}), ctx(1))
            .await,
        JobOutcome::Failed {
            retry_after: None,
            ..
        }
    ));
}

#[tokio::test]
async fn uploads_need_an_account() {
    let (fx, storage) = fixture(10);
    let runner = runner(&fx, vec![], storage, UploadSink::default(), None);
    assert!(matches!(
        runner
            .run(QueueKind::Upload, json!({"path": "/tmp/x", "parent": "P"}), ctx(1))
            .await,
        JobOutcome::Failed { retry_after: None, error } if error.contains("log in")
    ));
}

#[tokio::test]
async fn persists_the_upload_checkpoint_when_cancelled() {
    let (fx, storage) = fixture(10);
    let path = fx.dir.path().join("big.bin");
    std::fs::write(&path, vec![1u8; 3584 * KIB + 2 * 1024 * KIB]).unwrap();
    let payload = json!({"path": path.display().to_string(), "parent": "P"});
    let id = fx.store.enqueue(QueueKind::Upload, &payload).unwrap();
    let sink = UploadSink {
        size: std::fs::metadata(&path).unwrap().len(),
        ..UploadSink::default()
    };
    let runner = runner(
        &fx,
        vec![r#"[{"p": "http://ul/z"}]"#],
        storage,
        sink,
        Some(session()),
    );
    let context = ctx(id);
    {
        // Cancel as soon as a confirmed chunk is in the stored checkpoint.
        let (cancel, store) = (context.cancel.clone(), fx.store.clone());
        tokio::spawn(async move {
            loop {
                let payload = store.entry(id).unwrap().unwrap().payload;
                let confirmed = UploadCheckpoint::from_json(&payload["checkpoint"])
                    .is_some_and(|c| !c.done.is_empty());
                if confirmed {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            cancel.cancel();
        });
    }
    assert_eq!(
        runner.run(QueueKind::Upload, payload, context).await,
        JobOutcome::Cancelled
    );
    let stored = fx.store.entry(id).unwrap().unwrap().payload;
    let checkpoint = UploadCheckpoint::from_json(&stored["checkpoint"]).expect("checkpoint saved");
    assert_eq!(checkpoint.url, "http://ul/z");
    assert!(!checkpoint.done.is_empty());
}

#[tokio::test]
async fn finished_uploads_report_their_public_link() {
    let (fx, storage) = fixture(10);
    let path = fx.dir.path().join("doc.txt");
    std::fs::write(&path, b"hello").unwrap();
    let payload = json!({"path": path.display().to_string(), "parent": "P"});
    let id = fx.store.enqueue(QueueKind::Upload, &payload).unwrap();
    let runner = runner(
        &fx,
        vec![
            r#"[{"p": "http://ul/a"}]"#,
            r#"[{"f": [{"h": "NODE"}]}]"#,
            r#"["PUBLIC"]"#,
        ],
        storage,
        UploadSink {
            size: 5,
            ..UploadSink::default()
        },
        Some(session()),
    );
    let outcome = runner.run(QueueKind::Upload, payload, ctx(id)).await;
    assert!(
        matches!(&outcome, JobOutcome::Done { summary } if summary.contains("doc.txt") && summary.contains("https://mega.nz/file/PUBLIC#")),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn invalid_entries_do_not_leak_link_keys_in_errors() {
    let (fx, storage) = fixture(10);
    let runner = runner(&fx, vec![], storage, UploadSink::default(), None);
    let mut payload = download_payload(&fx);
    payload.as_object_mut().unwrap().remove("destination");
    let JobOutcome::Failed { error, .. } = runner.run(QueueKind::Download, payload, ctx(1)).await
    else {
        panic!("expected a failure");
    };
    let key = megaquarry_core::crypto::b64url_encode(&fx.key.to_bytes());
    assert!(!error.contains(&key), "{error}");
}
