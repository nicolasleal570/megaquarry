//! Regression probes from the independent verification of uploads
//! (reference crypto, completion tokens, resume, retries, checkpoints).
mod common;

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use common::{FakeTransport, api, ok};
use megaquarry_core::api::{ErrorCode, RetryPolicy, TransportError};
use megaquarry_core::crypto::{FileKey, b64url_decode, ecb_decrypt};
use megaquarry_core::session::{Credentials, Session};
use megaquarry_core::upload::{
    UploadCheckpoint, UploadError, UploadOptions, UploadProgress, UploadTransport, Uploader,
};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

const KIB: u64 = 1024;
const MASTER: [u8; 16] = [0x5a; 16];

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

fn opts(workers: usize, retries: u32) -> UploadOptions {
    UploadOptions {
        workers,
        retry: RetryPolicy {
            max_retries: retries,
            base: Duration::from_millis(1),
            cap: Duration::from_millis(2),
        },
    }
}

// ---------- independent reference crypto (not using crate code) ----------
fn enc(key: &[u8; 16], block: [u8; 16]) -> [u8; 16] {
    let c = Aes128::new(GenericArray::from_slice(key));
    let mut b = GenericArray::from(block);
    c.encrypt_block(&mut b);
    b.into()
}

fn ref_ctr(key: &[u8; 16], nonce: &[u8; 8], data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    for (i, block) in out.chunks_mut(16).enumerate() {
        let mut ctr = [0u8; 16];
        ctr[..8].copy_from_slice(nonce);
        ctr[8..].copy_from_slice(&(i as u64).to_be_bytes());
        let ks = enc(key, ctr);
        for (b, k) in block.iter_mut().zip(ks) {
            *b ^= k;
        }
    }
    out
}

/// Chunk boundaries per protocol-and-crypto.md: 128K*i for i in 1..=7, then 1 MiB.
fn ref_bounds(size: u64) -> Vec<(u64, u64)> {
    let mut v = vec![];
    let mut off = 0;
    let mut i = 1;
    loop {
        let len = if i <= 7 { i * 128 * KIB } else { 1024 * KIB };
        if off >= size {
            break;
        }
        v.push((off, len.min(size - off)));
        off += len;
        i += 1;
    }
    if size == 0 {
        v.push((0, 0));
    }
    v
}

fn ref_meta_mac(key: &[u8; 16], nonce: &[u8; 8], data: &[u8]) -> [u8; 8] {
    let mut fm = [0u8; 16];
    for (off, len) in ref_bounds(data.len() as u64) {
        let mut cm = [0u8; 16];
        cm[..8].copy_from_slice(nonce);
        cm[8..].copy_from_slice(nonce);
        for blk in data[off as usize..(off + len) as usize].chunks(16) {
            let mut b = [0u8; 16];
            b[..blk.len()].copy_from_slice(blk);
            for i in 0..16 {
                cm[i] ^= b[i];
            }
            cm = enc(key, cm);
        }
        for i in 0..16 {
            fm[i] ^= cm[i];
        }
        fm = enc(key, fm);
    }
    let mut mm = [0u8; 8];
    for i in 0..4 {
        mm[i] = fm[i] ^ fm[i + 4];
        mm[i + 4] = fm[i + 8] ^ fm[i + 12];
    }
    mm
}

// ---------- scriptable storage ----------
#[derive(Default)]
struct Probe {
    size: u64,
    /// Offset whose reply carries the token (None: the one completing the file).
    token_on: Option<u64>,
    block_on: Option<u64>,
    negative: Option<(u64, &'static str)>,
    faults: Mutex<HashMap<u64, Vec<u16>>>,
    received: Mutex<BTreeMap<u64, Vec<u8>>>,
    posts: Mutex<Vec<u64>>,
}

impl UploadTransport for Probe {
    async fn post(&self, url: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>), TransportError> {
        let offset: u64 = url.rsplit('/').next().unwrap().parse().unwrap();
        self.posts.lock().unwrap().push(offset);
        if self.block_on == Some(offset) {
            std::future::pending::<()>().await;
        }
        if let Some(code) = self
            .faults
            .lock()
            .unwrap()
            .get_mut(&offset)
            .and_then(|f| (!f.is_empty()).then(|| f.remove(0)))
        {
            return Ok((code, vec![]));
        }
        if let Some((at, body)) = self.negative {
            if at == offset {
                return Ok((200, body.as_bytes().to_vec()));
            }
        }
        let mut r = self.received.lock().unwrap();
        r.insert(offset, body);
        let total: u64 = r.values().map(|b| b.len() as u64).sum();
        let token = match self.token_on {
            Some(at) => at == offset,
            None => total >= self.size,
        };
        Ok((200, if token { b"TOK123".to_vec() } else { vec![] }))
    }
}

fn file(dir: &tempfile::TempDir, size: usize) -> (std::path::PathBuf, Vec<u8>) {
    let data: Vec<u8> = (0..size).map(|i| ((i * 7919) % 251) as u8).collect();
    let p = dir.path().join("f.bin");
    std::fs::write(&p, &data).unwrap();
    (p, data)
}

fn node_key(body: &Value) -> FileKey {
    let wrapped = b64url_decode(body[0]["n"][0]["k"].as_str().unwrap()).unwrap();
    FileKey::from_bytes(&ecb_decrypt(&MASTER, &wrapped).unwrap()).unwrap()
}

fn check_against_reference(key: &FileKey, storage: &Probe, data: &[u8]) {
    let raw = key.to_bytes();
    let (aes, nonce) = (key.aes_key(), key.nonce());
    // Node key packing: [k0^k4, k1^k5, k2^mm0, k3^mm1, k4, k5, mm0, mm1]
    let mm = ref_meta_mac(&aes, &nonce, data);
    assert_eq!(&raw[24..32], &mm, "meta-MAC differs from the reference");
    for i in 0..16 {
        let tail = [nonce.as_slice(), mm.as_slice()].concat();
        assert_eq!(raw[i], aes[i] ^ tail[i], "packing byte {i}");
    }
    // Each chunk's ciphertext equals the reference CTR stream at its offset.
    let whole = ref_ctr(&aes, &nonce, data);
    let r = storage.received.lock().unwrap();
    for (off, len) in ref_bounds(data.len() as u64) {
        let got = r.get(&off).unwrap_or_else(|| panic!("no chunk at {off}"));
        assert_eq!(
            got.as_slice(),
            &whole[off as usize..(off + len) as usize],
            "chunk {off}"
        );
    }
    assert_eq!(r.len(), ref_bounds(data.len() as u64).len());
}

#[tokio::test]
async fn p1_reference_crypto_many_sizes() {
    for size in [
        1usize,
        15,
        16,
        17,
        128 * 1024,
        128 * 1024 + 1,
        3584 * 1024,
        3584 * 1024 + 1,
        5 * 1024 * 1024 + 7,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (path, data) = file(&dir, size);
        let storage = Arc::new(Probe {
            size: size as u64,
            ..Probe::default()
        });
        let api = api(FakeTransport::with(vec![
            ok(r#"[{"p": "http://s/ul"}]"#),
            ok(r#"[{"f": [{"h": "N"}]}]"#),
        ]));
        let up = Uploader::new(storage.clone(), None, opts(5, 1))
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
        let b = api.transport().bodies();
        let key = node_key(&b[1]);
        assert_eq!(key, up.key);
        check_against_reference(&key, &storage, &data);
    }
}

#[tokio::test]
async fn p2_token_on_a_chunk_other_than_the_last() {
    for workers in [1, 4] {
        let dir = tempfile::tempdir().unwrap();
        let (path, data) = file(&dir, 2 * 1024 * 1024);
        let storage = Arc::new(Probe {
            size: data.len() as u64,
            token_on: Some(0),
            ..Probe::default()
        });
        let api = api(FakeTransport::with(vec![
            ok(r#"[{"p": "http://s/ul"}]"#),
            ok(r#"[{"f": [{"h": "N"}]}]"#),
        ]));
        Uploader::new(storage.clone(), None, opts(workers, 1))
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
        let b = api.transport().bodies();
        assert_eq!(b[1][0]["n"][0]["h"], json!("TOK123"), "workers={workers}");
    }
}

#[tokio::test]
async fn p3_token_from_an_earlier_run_sends_no_chunks() {
    let dir = tempfile::tempdir().unwrap();
    let (path, data) = file(&dir, 300 * 1024);
    // First run: complete everything but fail the `p` command.
    let storage = Arc::new(Probe {
        size: data.len() as u64,
        ..Probe::default()
    });
    let api1 = api(FakeTransport::with(vec![
        ok(r#"[{"p": "http://s/ul"}]"#),
        ok("[-11]"),
    ]));
    let progress = Arc::new(UploadProgress::default());
    let err = Uploader::new(storage.clone(), None, opts(2, 1))
        .run(
            &api1,
            &session(),
            &path,
            "P",
            progress.clone(),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, UploadError::Api(_)), "{err:?}");
    let cp = progress.checkpoint().unwrap();
    assert_eq!(cp.completion_token.as_deref(), Some("TOK123"));
    // Round trip through JSON as the queue would.
    let cp = UploadCheckpoint::from_json(&cp.to_json()).unwrap();
    let posts_before = storage.posts.lock().unwrap().len();
    let api2 = api(FakeTransport::with(vec![ok(r#"[{"f": [{"h": "N2"}]}]"#)]));
    let up = Uploader::new(storage.clone(), None, opts(2, 1))
        .run(
            &api2,
            &session(),
            &path,
            "P",
            Arc::new(UploadProgress::resuming(cp)),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(up.handle, "N2");
    assert_eq!(
        storage.posts.lock().unwrap().len(),
        posts_before,
        "no chunk re-sent"
    );
    let b = api2.transport().bodies();
    assert_eq!(b.len(), 1, "no `u` on resume");
    assert_eq!(b[0][0]["n"][0]["h"], json!("TOK123"));
    check_against_reference(&node_key(&b[0]), &storage, &data);
}

#[tokio::test]
async fn p4_cancel_mid_chunk_then_resume_only_unconfirmed() {
    let dir = tempfile::tempdir().unwrap();
    let size = 3584 * 1024 + 1024 * 1024 + 99;
    let (path, data) = file(&dir, size);
    let blocked = 1280 * KIB; // chunk 5
    let storage = Arc::new(Probe {
        size: size as u64,
        block_on: Some(blocked),
        ..Probe::default()
    });
    let api1 = api(FakeTransport::with(vec![ok(r#"[{"p": "http://s/ul"}]"#)]));
    let progress = Arc::new(UploadProgress::default());
    let cancel = CancellationToken::new();
    {
        let c = cancel.clone();
        let st = storage.clone();
        tokio::spawn(async move {
            while !st.posts.lock().unwrap().contains(&blocked) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            c.cancel();
        });
    }
    let err = tokio::time::timeout(
        Duration::from_secs(5),
        Uploader::new(storage.clone(), None, opts(1, 1)).run(
            &api1,
            &session(),
            &path,
            "P",
            progress.clone(),
            cancel,
        ),
    )
    .await
    .expect("cancel must stop a blocked POST")
    .unwrap_err();
    assert_eq!(err, UploadError::Cancelled);
    let cp = progress.checkpoint().unwrap();
    assert!(!cp.done.contains_key(&blocked));
    let confirmed: Vec<u64> = cp.done.keys().copied().collect();
    assert_eq!(confirmed, vec![0, 128 * KIB, 384 * KIB, 768 * KIB]);
    let cp = UploadCheckpoint::from_json(&cp.to_json()).unwrap();

    // Resume with a fresh storage view keeping earlier chunks.
    let storage2 = Arc::new(Probe {
        size: size as u64,
        ..Probe::default()
    });
    *storage2.received.lock().unwrap() = storage.received.lock().unwrap().clone();
    let api2 = api(FakeTransport::with(vec![ok(r#"[{"f": [{"h": "N"}]}]"#)]));
    Uploader::new(storage2.clone(), None, opts(3, 1))
        .run(
            &api2,
            &session(),
            &path,
            "P",
            Arc::new(UploadProgress::resuming(cp)),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let mut posts = storage2.posts.lock().unwrap().clone();
    posts.sort();
    assert_eq!(
        posts,
        vec![1280 * KIB, 1920 * KIB, 2688 * KIB, 3584 * KIB, 4608 * KIB]
    );
    check_against_reference(&node_key(&api2.transport().bodies()[0]), &storage2, &data);
}

#[tokio::test]
async fn p5_negative_reply_and_retries() {
    let dir = tempfile::tempdir().unwrap();
    let (path, data) = file(&dir, 600 * 1024);
    // -17 on chunk 2 → Rejected(OverQuota), no retry.
    let storage = Arc::new(Probe {
        size: data.len() as u64,
        negative: Some((128 * KIB, "-17")),
        ..Probe::default()
    });
    let api1 = api(FakeTransport::with(vec![ok(r#"[{"p": "http://s/ul"}]"#)]));
    let err = Uploader::new(storage.clone(), None, opts(1, 5))
        .run(
            &api1,
            &session(),
            &path,
            "P",
            Arc::default(),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(err, UploadError::Rejected(ErrorCode::OverQuota));
    assert_eq!(
        storage
            .posts
            .lock()
            .unwrap()
            .iter()
            .filter(|o| **o == 128 * KIB)
            .count(),
        1
    );

    // 3 x HTTP 500 with max_retries 3 → succeeds; 4 → ChunkFailed.
    for (n, ok_expected) in [(3usize, true), (4, false)] {
        let storage = Arc::new(Probe {
            size: data.len() as u64,
            ..Probe::default()
        });
        storage.faults.lock().unwrap().insert(0, vec![500; n]);
        let api1 = api(FakeTransport::with(vec![
            ok(r#"[{"p": "http://s/ul"}]"#),
            ok(r#"[{"f": [{"h": "N"}]}]"#),
        ]));
        let r = Uploader::new(storage.clone(), None, opts(2, 3))
            .run(
                &api1,
                &session(),
                &path,
                "P",
                Arc::default(),
                CancellationToken::new(),
            )
            .await;
        assert_eq!(r.is_ok(), ok_expected, "{n}: {r:?}");
        if !ok_expected {
            assert!(
                matches!(r, Err(UploadError::ChunkFailed { offset: 0, .. })),
                "{r:?}"
            );
        }
    }
}

#[test]
fn p6_checkpoint_json_round_trip_and_rejects() {
    let mut done = BTreeMap::new();
    done.insert(0u64, [1u8; 16]);
    done.insert(5_000_000_000u64, [2u8; 16]);
    for token in [None, Some("T".to_string())] {
        let cp = UploadCheckpoint {
            url: "http://x/y".into(),
            aes_key: [3; 16],
            nonce: [4; 8],
            done: done.clone(),
            completion_token: token,
            file_size: 7,
            file_mtime: 8,
        };
        let text = serde_json::to_string(&cp.to_json()).unwrap();
        let back = UploadCheckpoint::from_json(&serde_json::from_str(&text).unwrap()).unwrap();
        assert_eq!(back, cp);
    }
    assert!(UploadCheckpoint::from_json(&json!({"url":"u","key":"AAAA","done":{}})).is_none());
    assert!(UploadCheckpoint::from_json(&json!(null)).is_none());
}

#[tokio::test]
async fn p7_empty_file() {
    let dir = tempfile::tempdir().unwrap();
    let (path, data) = file(&dir, 0);
    let storage = Arc::new(Probe {
        size: 0,
        ..Probe::default()
    });
    let api1 = api(FakeTransport::with(vec![
        ok(r#"[{"p": "http://s/ul"}]"#),
        ok(r#"[{"f": [{"h": "N"}]}]"#),
    ]));
    Uploader::new(storage.clone(), None, opts(3, 1))
        .run(
            &api1,
            &session(),
            &path,
            "P",
            Arc::default(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(*storage.posts.lock().unwrap(), vec![0]);
    let key = node_key(&api1.transport().bodies()[1]);
    // Reference per protocol-and-crypto.md: empty file → one (empty) chunk.
    assert_eq!(
        &key.to_bytes()[24..],
        &ref_meta_mac(&key.aes_key(), &key.nonce(), &data)
    );
}
