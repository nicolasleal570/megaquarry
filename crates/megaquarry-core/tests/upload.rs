mod common;

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{FakeTransport, api, ok};
use megaquarry_core::api::{RetryPolicy, TransportError};
use megaquarry_core::chunk::meta_mac_of;
use megaquarry_core::crypto::{
    Attributes, FileKey, b64url_decode, ctr_apply, decrypt_attributes, ecb_decrypt,
};
use megaquarry_core::link::MegaLink;
use megaquarry_core::session::{Credentials, Session};
use megaquarry_core::upload::{
    self, UploadError, UploadOptions, UploadProgress, UploadTransport, Uploader,
};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

const KIB: usize = 1024;
const MASTER: [u8; 16] = [0x33; 16];

fn session() -> Session {
    Session {
        sid: "SID".into(),
        master_key: MASTER,
        user_handle: "U".into(),
        credentials: Credentials {
            email: "e@x.y".into(),
            password_aes: [1; 16],
            user_hash: "uh".into(),
        },
    }
}

/// Collects uploaded ciphertext by offset; answers the completion token on
/// the POST that completes the file.
struct FakeStorage {
    size: u64,
    received: Mutex<BTreeMap<u64, Vec<u8>>>,
    faults: Mutex<HashMap<u64, Vec<u16>>>,
    negative: Mutex<Option<(u64, &'static str)>>,
    posts: Mutex<Vec<String>>,
}

impl FakeStorage {
    fn new(size: u64) -> Arc<Self> {
        Arc::new(Self {
            size,
            received: Mutex::default(),
            faults: Mutex::default(),
            negative: Mutex::default(),
            posts: Mutex::default(),
        })
    }

    fn ciphertext(&self) -> Vec<u8> {
        self.received
            .lock()
            .unwrap()
            .values()
            .flatten()
            .copied()
            .collect()
    }
}

impl UploadTransport for FakeStorage {
    async fn post(&self, url: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>), TransportError> {
        // A little latency so cancellation tests do not race an instant server.
        tokio::time::sleep(Duration::from_millis(3)).await;
        self.posts.lock().unwrap().push(url.to_owned());
        let offset: u64 = url.rsplit('/').next().unwrap().parse().unwrap();
        if let Some(code) = self
            .faults
            .lock()
            .unwrap()
            .get_mut(&offset)
            .and_then(|f| (!f.is_empty()).then(|| f.remove(0)))
        {
            return Ok((code, vec![]));
        }
        if let Some((at, body)) = *self.negative.lock().unwrap() {
            if at == offset {
                return Ok((200, body.as_bytes().to_vec()));
            }
        }
        let mut received = self.received.lock().unwrap();
        received.insert(offset, body);
        let total: u64 = received.values().map(|b| b.len() as u64).sum();
        Ok((
            200,
            if total >= self.size {
                b"COMPLETIONTOKEN".to_vec()
            } else {
                vec![]
            },
        ))
    }
}

fn options(workers: usize) -> UploadOptions {
    UploadOptions {
        workers,
        retry: RetryPolicy {
            max_retries: 3,
            base: Duration::from_millis(1),
            cap: Duration::from_millis(2),
        },
    }
}

fn write_file(dir: &tempfile::TempDir, size: usize) -> (std::path::PathBuf, Vec<u8>) {
    let data: Vec<u8> = (0..size).map(|i| (i * 13 % 241) as u8).collect();
    let path = dir.path().join("photo.jpg");
    std::fs::write(&path, &data).unwrap();
    (path, data)
}

/// The node key wrapped in the `p` command, unwrapped with the master key.
fn node_key_of(body: &Value) -> FileKey {
    let wrapped = b64url_decode(body[0]["n"][0]["k"].as_str().unwrap()).unwrap();
    FileKey::from_bytes(&ecb_decrypt(&MASTER, &wrapped).unwrap()).unwrap()
}

#[tokio::test]
async fn uploads_an_encrypted_file_and_registers_the_node() {
    let dir = tempfile::tempdir().unwrap();
    let (path, data) = write_file(&dir, 5 * 1024 * KIB + 123);
    let storage = FakeStorage::new(data.len() as u64);
    let api = api(FakeTransport::with(vec![
        ok(r#"[{"p": "http://storage.example/ul/abc"}]"#),
        ok(r#"[{"f": [{"h": "NEWHANDLE", "t": 0}]}]"#),
    ]));
    let uploader = Uploader::new(storage.clone(), None, options(4));
    let progress = Arc::new(UploadProgress::default());
    let uploaded = uploader
        .run(
            &api,
            &session(),
            &path,
            "PARENT",
            progress.clone(),
            CancellationToken::new(),
        )
        .await
        .unwrap();

    assert_eq!(uploaded.handle, "NEWHANDLE");
    assert_eq!(progress.done(), data.len() as u64);
    let bodies = api.transport().bodies();
    assert_eq!(bodies[0], json!([{"a": "u", "s": data.len()}]));
    let finish = &bodies[1];
    assert_eq!(finish[0]["a"], json!("p"));
    assert_eq!(finish[0]["t"], json!("PARENT"));
    assert_eq!(finish[0]["n"][0]["h"], json!("COMPLETIONTOKEN"));
    assert_eq!(finish[0]["n"][0]["t"], json!(0));

    // The storage holds the file encrypted with the registered node key,
    // and the key's meta-MAC matches the plaintext.
    let key = node_key_of(finish);
    assert_eq!(uploaded.key, key);
    let mut plain = storage.ciphertext();
    assert_ne!(plain, data);
    ctr_apply(&key.aes_key(), &key.nonce(), 0, &mut plain);
    assert_eq!(plain, data);
    assert_eq!(
        meta_mac_of(&key.aes_key(), &key.nonce(), &data),
        key.meta_mac()
    );

    let attrs = b64url_decode(finish[0]["n"][0]["a"].as_str().unwrap()).unwrap();
    assert_eq!(
        decrypt_attributes(&attrs, &key.aes_key()).unwrap().name(),
        Some("photo.jpg")
    );

    // Chunks go to `url/offset`.
    let posts = storage.posts.lock().unwrap().clone();
    assert!(posts.contains(&"http://storage.example/ul/abc/0".to_string()));
    assert!(posts.contains(&format!("http://storage.example/ul/abc/{}", 128 * KIB)));
}

#[tokio::test]
async fn uploads_an_empty_file_with_one_empty_post() {
    let dir = tempfile::tempdir().unwrap();
    let (path, _) = write_file(&dir, 0);
    let storage = FakeStorage::new(0);
    let api = api(FakeTransport::with(vec![
        ok(r#"[{"p": "http://s/ul/e"}]"#),
        ok(r#"[{"f": [{"h": "H0"}]}]"#),
    ]));
    let uploaded = Uploader::new(storage.clone(), None, options(2))
        .run(
            &api,
            &session(),
            &path,
            "P",
            Arc::default(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(uploaded.handle, "H0");
    assert_eq!(
        storage.posts.lock().unwrap().as_slice(),
        ["http://s/ul/e/0"]
    );
}

#[tokio::test]
async fn retries_failed_chunks_and_stops_on_server_errors() {
    let dir = tempfile::tempdir().unwrap();
    let (path, data) = write_file(&dir, 600 * KIB);

    let storage = FakeStorage::new(data.len() as u64);
    storage
        .faults
        .lock()
        .unwrap()
        .insert(128 * KIB as u64, vec![500, 503]);
    let api_ok = api(FakeTransport::with(vec![
        ok(r#"[{"p": "http://s/ul/r"}]"#),
        ok(r#"[{"f": [{"h": "H"}]}]"#),
    ]));
    Uploader::new(storage.clone(), None, options(2))
        .run(
            &api_ok,
            &session(),
            &path,
            "P",
            Arc::default(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let faulted = format!("/{}", 128 * KIB);
    let retries = storage
        .posts
        .lock()
        .unwrap()
        .iter()
        .filter(|p| p.ends_with(&faulted))
        .count();
    assert_eq!(retries, 3, "two failures, then success");
    let key = node_key_of(&api_ok.transport().bodies()[1]);
    let mut plain = storage.ciphertext();
    ctr_apply(&key.aes_key(), &key.nonce(), 0, &mut plain);
    assert_eq!(plain, data);

    let storage = FakeStorage::new(data.len() as u64);
    *storage.negative.lock().unwrap() = Some((0, "-4"));
    let api_bad = api(FakeTransport::with(vec![ok(r#"[{"p": "http://s/ul/n"}]"#)]));
    let result = Uploader::new(storage, None, options(2))
        .run(
            &api_bad,
            &session(),
            &path,
            "P",
            Arc::default(),
            CancellationToken::new(),
        )
        .await;
    assert!(
        matches!(
            result,
            Err(UploadError::Rejected(
                megaquarry_core::api::ErrorCode::RateLimit
            ))
        ),
        "{result:?}"
    );
}

#[tokio::test]
async fn resumes_from_confirmed_chunks() {
    let dir = tempfile::tempdir().unwrap();
    let (path, data) = write_file(&dir, 1024 * KIB);
    let storage = FakeStorage::new(data.len() as u64);

    // First run cancelled after it started; keep its checkpoint.
    let progress = Arc::new(UploadProgress::default());
    let api1 = api(FakeTransport::with(vec![ok(r#"[{"p": "http://s/ul/z"}]"#)]));
    let cancel = CancellationToken::new();
    {
        let progress = progress.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            while progress.done() < 384 * KIB as u64 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            cancel.cancel();
        });
    }
    let first = Uploader::new(storage.clone(), None, options(1))
        .run(&api1, &session(), &path, "P", progress.clone(), cancel)
        .await;
    assert!(matches!(first, Err(UploadError::Cancelled)), "{first:?}");
    let checkpoint = progress.checkpoint().expect("upload URL and key are known");
    assert!(!checkpoint.done.is_empty());
    let posts_before = storage.posts.lock().unwrap().len();

    // Second run resumes: no new `u` call, only the missing chunks are sent.
    let api2 = api(FakeTransport::with(vec![ok(
        r#"[{"f": [{"h": "RESUMED"}]}]"#,
    )]));
    let resumed = Arc::new(UploadProgress::resuming(checkpoint.clone()));
    let uploaded = Uploader::new(storage.clone(), None, options(2))
        .run(
            &api2,
            &session(),
            &path,
            "P",
            resumed,
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(uploaded.handle, "RESUMED");
    let new_posts = &storage.posts.lock().unwrap()[posts_before..];
    for offset in checkpoint.done.keys() {
        assert!(!new_posts.iter().any(|p| p.ends_with(&format!("/{offset}"))));
    }
    let key = node_key_of(&api2.transport().bodies()[0]);
    let mut plain = storage.ciphertext();
    ctr_apply(&key.aes_key(), &key.nonce(), 0, &mut plain);
    assert_eq!(plain, data);
    assert_eq!(
        meta_mac_of(&key.aes_key(), &key.nonce(), &data),
        key.meta_mac()
    );
}

#[tokio::test]
async fn exports_public_links_and_creates_folders() {
    let api = api(FakeTransport::with(vec![
        ok(r#"["PUBHANDLE"]"#),
        ok(r#"[{"f": [{"h": "DIRHANDLE", "t": 1}]}]"#),
        ok(
            r#"[{"f": [{"h": "ROOT", "t": 2}, {"h": "INBOX", "t": 3}, {"h": "X", "t": 0, "p": "ROOT"}]}]"#,
        ),
    ]));
    let key = FileKey::pack(&[1; 16], &[2; 8], &[3; 8]);
    let link = upload::export_link(&api, "NODE", &key).await.unwrap();
    assert_eq!(
        link,
        MegaLink::File {
            handle: "PUBHANDLE".into(),
            key: key.clone()
        }
    );
    assert_eq!(
        api.transport().bodies()[0],
        json!([{"a": "l", "n": "NODE"}])
    );

    let folder = upload::create_folder(&api, &session(), "PARENT", "Holidays")
        .await
        .unwrap();
    assert_eq!(folder, "DIRHANDLE");
    let body = &api.transport().bodies()[1][0];
    assert_eq!(body["a"], json!("p"));
    assert_eq!(body["t"], json!("PARENT"));
    assert_eq!(body["n"][0]["t"], json!(1));
    let folder_key: [u8; 16] = ecb_decrypt(
        &MASTER,
        &b64url_decode(body["n"][0]["k"].as_str().unwrap()).unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let attrs = b64url_decode(body["n"][0]["a"].as_str().unwrap()).unwrap();
    assert_eq!(
        decrypt_attributes(&attrs, &folder_key).unwrap(),
        Attributes::with_name("Holidays")
    );

    assert_eq!(upload::root_handle(&api).await.unwrap(), "ROOT");
    assert_eq!(api.transport().bodies()[2], json!([{"a": "f", "c": 1}]));
}

#[test]
fn checkpoints_round_trip_through_json() {
    let checkpoint = upload::UploadCheckpoint {
        url: "http://s/ul/x".into(),
        aes_key: [4; 16],
        nonce: [5; 8],
        done: BTreeMap::from([(0, [6; 16]), (131072, [7; 16])]),
        completion_token: Some("TOKEN".into()),
        file_size: 1,
        file_mtime: 2,
    };
    let value = checkpoint.to_json();
    assert_eq!(
        upload::UploadCheckpoint::from_json(&value),
        Some(checkpoint)
    );
    assert_eq!(
        upload::UploadCheckpoint::from_json(&json!({"url": "x"})),
        None
    );
}

#[tokio::test]
async fn retries_temporary_storage_errors() {
    let dir = tempfile::tempdir().unwrap();
    let (path, data) = write_file(&dir, 200 * KIB);
    let storage = FakeStorage::new(data.len() as u64);
    *storage.negative.lock().unwrap() = Some((0, "-3"));
    {
        // Clear the EAGAIN after the first answer.
        let storage = storage.clone();
        tokio::spawn(async move {
            while storage.posts.lock().unwrap().is_empty() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            *storage.negative.lock().unwrap() = None;
        });
    }
    let api = api(FakeTransport::with(vec![
        ok(r#"[{"p": "http://s/ul/t"}]"#),
        ok(r#"[{"f": [{"h": "H"}]}]"#),
    ]));
    let uploaded = Uploader::new(storage.clone(), None, options(1))
        .run(
            &api,
            &session(),
            &path,
            "P",
            Arc::default(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(uploaded.handle, "H");
    let posts = storage.posts.lock().unwrap();
    assert!(posts.iter().filter(|p| p.ends_with("/0")).count() >= 2);
}

#[tokio::test]
async fn a_changed_file_restarts_instead_of_resuming() {
    let dir = tempfile::tempdir().unwrap();
    let (path, data) = write_file(&dir, 300 * KIB);
    let stale = upload::UploadCheckpoint {
        url: "http://s/ul/old".into(),
        aes_key: [1; 16],
        nonce: [2; 8],
        done: BTreeMap::from([(0, [3; 16])]),
        completion_token: None,
        file_size: 123,
        file_mtime: 0,
    };
    let storage = FakeStorage::new(data.len() as u64);
    let api = api(FakeTransport::with(vec![
        ok(r#"[{"p": "http://s/ul/new"}]"#),
        ok(r#"[{"f": [{"h": "H"}]}]"#),
    ]));
    let progress = Arc::new(UploadProgress::resuming(stale));
    Uploader::new(storage.clone(), None, options(2))
        .run(
            &api,
            &session(),
            &path,
            "P",
            progress,
            CancellationToken::new(),
        )
        .await
        .unwrap();
    // A new upload URL was requested and every chunk went to it.
    assert_eq!(api.transport().bodies()[0][0]["a"], json!("u"));
    let posts = storage.posts.lock().unwrap();
    assert!(posts.iter().all(|p| p.starts_with("http://s/ul/new/")));
    assert!(posts.iter().any(|p| p.ends_with("/0")));
}
