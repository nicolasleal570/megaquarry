//! Regression probes from the independent verification of the download
//! engine (resume across plans, cancellation, failures, boundaries, limits).

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use megaquarry_core::api::{RetryPolicy, TransportError};
use megaquarry_core::chunk::meta_mac_of;
use megaquarry_core::crypto::{FileKey, ctr_apply};
use megaquarry_core::download::{
    ChunkBody, DownloadError, DownloadOptions, DownloadTransport, Downloader, Progress, UrlSource,
};
use megaquarry_core::link::MegaLink;
use megaquarry_core::public::RemoteFile;
use megaquarry_core::throttle::RateLimiter;
use tokio_util::sync::CancellationToken;

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;

#[derive(Default)]
struct Behaviour {
    /// Always fail (HTTP 500) requests whose start offset is in this set.
    always_fail: HashSet<u64>,
    /// Never answer requests whose start offset is in this set.
    hang: HashSet<u64>,
    /// Delay (ms) by start offset.
    delay_ms: std::collections::HashMap<u64, u64>,
    /// Pseudo-random jitter per request.
    jitter: bool,
    /// Cancel this token after N requests.
    cancel_after: Option<(usize, CancellationToken)>,
    /// Create this file on first request.
    create_on_first: Option<PathBuf>,
}

struct Server {
    ciphertext: Vec<u8>,
    b: Mutex<Behaviour>,
    requests: AtomicUsize,
    inflight: Arc<AtomicUsize>,
    seed: AtomicU32,
}

struct Body {
    pieces: Vec<Vec<u8>>,
    inflight: Arc<AtomicUsize>,
}
impl Drop for Body {
    fn drop(&mut self) {
        self.inflight.fetch_sub(1, Ordering::SeqCst);
    }
}
impl ChunkBody for Body {
    async fn next_piece(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        Ok(if self.pieces.is_empty() {
            None
        } else {
            Some(self.pieces.remove(0))
        })
    }
}

impl DownloadTransport for Server {
    type Body = Body;
    async fn get(&self, url: &str) -> Result<(u16, Body), TransportError> {
        let n = self.requests.fetch_add(1, Ordering::SeqCst) + 1;
        let range = url.rsplit_once('/').unwrap().1;
        let (start, end) = match range.split_once('-') {
            Some((s, e)) => (s.parse::<u64>().unwrap(), e.parse::<u64>().unwrap() + 1),
            None => (range.parse().unwrap(), self.ciphertext.len() as u64),
        };
        let (fail, hang, delay, jitter) = {
            let mut b = self.b.lock().unwrap();
            if let Some((k, tok)) = &b.cancel_after {
                if n >= *k {
                    tok.cancel();
                }
            }
            if let Some(p) = b.create_on_first.take() {
                std::fs::write(p, b"user file").unwrap();
            }
            (
                b.always_fail.contains(&start),
                b.hang.contains(&start),
                b.delay_ms.get(&start).copied(),
                b.jitter,
            )
        };
        if hang {
            std::future::pending::<()>().await;
        }
        if let Some(ms) = delay {
            tokio::time::sleep(Duration::from_millis(ms)).await;
        }
        if jitter {
            let s = self.seed.fetch_add(2654435761, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_micros((s % 3000) as u64)).await;
        }
        self.inflight.fetch_add(1, Ordering::SeqCst);
        let inflight = self.inflight.clone();
        if fail {
            return Ok((
                500,
                Body {
                    pieces: vec![],
                    inflight,
                },
            ));
        }
        let data = &self.ciphertext[start as usize..end as usize];
        Ok((
            200,
            Body {
                pieces: data.chunks(64 * KIB).map(<[u8]>::to_vec).collect(),
                inflight,
            },
        ))
    }
}

struct Urls(AtomicU32);
impl UrlSource for Urls {
    async fn fresh_url(&self) -> Result<String, DownloadError> {
        Ok(format!(
            "http://fake/dl/{}",
            self.0.fetch_add(1, Ordering::SeqCst)
        ))
    }
}

struct Fx {
    plain: Vec<u8>,
    server: Arc<Server>,
    file: RemoteFile,
    dir: tempfile::TempDir,
}
impl Fx {
    fn dest(&self) -> PathBuf {
        self.dir.path().join("out/file.bin")
    }
    fn temp(&self) -> PathBuf {
        self.dir.path().join("out/file.bin.mctemp")
    }
}

fn fx(size: usize) -> Fx {
    let plain: Vec<u8> = (0..size)
        .map(|i| (i * 7 % 251) as u8 ^ (i >> 13) as u8)
        .collect();
    let aes_key = [0x5a; 16];
    let nonce = [0x17; 8];
    let mac = meta_mac_of(&aes_key, &nonce, &plain);
    let key = FileKey::pack(&aes_key, &nonce, &mac);
    let mut ciphertext = plain.clone();
    ctr_apply(&aes_key, &nonce, 0, &mut ciphertext);
    Fx {
        plain,
        server: Arc::new(Server {
            ciphertext,
            b: Mutex::default(),
            requests: AtomicUsize::new(0),
            inflight: Arc::new(AtomicUsize::new(0)),
            seed: AtomicU32::new(7),
        }),
        file: RemoteFile {
            name: "file.bin".into(),
            size: size as u64,
            key: key.clone(),
            link: MegaLink::File {
                handle: "H".into(),
                key,
            },
        },
        dir: tempfile::tempdir().unwrap(),
    }
}

fn opts(workers: usize, multiplier: u64) -> DownloadOptions {
    DownloadOptions {
        workers,
        chunk_multiplier: multiplier,
        verify: true,
        retry: RetryPolicy {
            max_retries: 3,
            base: Duration::from_millis(1),
            cap: Duration::from_millis(2),
        },
    }
}

async fn go(
    f: &Fx,
    o: DownloadOptions,
    limiter: Option<Arc<RateLimiter>>,
    cancel: CancellationToken,
) -> (Result<PathBuf, DownloadError>, Arc<Progress>) {
    let d = Downloader::new(f.server.clone(), limiter, o);
    let p = Arc::new(Progress::default());
    let r = tokio::time::timeout(
        Duration::from_secs(30),
        d.run(
            &f.file,
            &f.dest(),
            Arc::new(Urls(AtomicU32::new(0))),
            p.clone(),
            cancel,
        ),
    )
    .await
    .expect("download hung");
    (r, p)
}

fn seed_temp(f: &Fx, len: usize) {
    std::fs::create_dir_all(f.dir.path().join("out")).unwrap();
    std::fs::write(f.temp(), &f.plain[..len]).unwrap();
}

// 1. Resume across a different worker count (chunk plan changes).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resume_multi_then_mono() {
    let f = fx(3584 * KIB + 25 * MIB + 77);
    seed_temp(&f, 3584 * KIB + 21 * MIB + 5);
    let (r, p) = go(&f, opts(1, 20), None, CancellationToken::new()).await;
    assert_eq!(std::fs::read(r.unwrap()).unwrap(), f.plain);
    assert_eq!(p.done(), f.plain.len() as u64);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resume_mono_then_multi() {
    let f = fx(3584 * KIB + 25 * MIB + 77);
    seed_temp(&f, 3584 * KIB + 5 * MIB);
    let (r, p) = go(&f, opts(6, 20), None, CancellationToken::new()).await;
    assert_eq!(std::fs::read(r.unwrap()).unwrap(), f.plain);
    assert_eq!(p.done(), f.plain.len() as u64);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resume_with_complete_and_oversized_temp() {
    let f = fx(500 * KIB);
    seed_temp(&f, 500 * KIB);
    let (r, _) = go(&f, opts(3, 1), None, CancellationToken::new()).await;
    assert_eq!(std::fs::read(r.unwrap()).unwrap(), f.plain);
    assert_eq!(f.server.requests.load(Ordering::SeqCst), 0);

    let g = fx(500 * KIB);
    seed_temp(&g, 500 * KIB);
    let mut extra = std::fs::read(g.temp()).unwrap();
    extra.extend_from_slice(b"garbage");
    std::fs::write(g.temp(), extra).unwrap();
    let (r, _) = go(&g, opts(3, 1), None, CancellationToken::new()).await;
    assert_eq!(std::fs::read(r.unwrap()).unwrap(), g.plain);
}

// 2. Cancel mid-download from the transport after N requests, plus a hanging chunk.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_mid_download_keeps_valid_prefix() {
    let f = fx(3584 * KIB + 6 * MIB);
    let cancel = CancellationToken::new();
    {
        let mut b = f.server.b.lock().unwrap();
        b.cancel_after = Some((5, cancel.clone()));
        b.hang.insert(3584 * KIB as u64 + MIB as u64); // chunk 9 never answers
    }
    let (r, p) = go(&f, opts(4, 1), None, cancel).await;
    assert_eq!(r, Err(DownloadError::Cancelled));
    let temp = std::fs::read(f.temp()).unwrap();
    assert_eq!(temp, f.plain[..temp.len()]);
    assert_eq!(p.done(), temp.len() as u64);
    assert!(!f.dest().exists());
    tokio::time::sleep(Duration::from_millis(100)).await;
    let n = f.server.requests.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        n,
        f.server.requests.load(Ordering::SeqCst),
        "requests after run returned"
    );
    // Resume completes.
    f.server.b.lock().unwrap().hang.clear();
    f.server.b.lock().unwrap().cancel_after = None;
    let (r, p) = go(&f, opts(4, 1), None, CancellationToken::new()).await;
    assert_eq!(std::fs::read(r.unwrap()).unwrap(), f.plain);
    assert_eq!(p.done(), f.plain.len() as u64);
}

// 3. One chunk always fails while the others succeed: no hang, prefix kept, no stray work.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_chunk_always_fails() {
    let f = fx(3584 * KIB + 10 * MIB);
    f.server
        .b
        .lock()
        .unwrap()
        .always_fail
        .insert(128 * KIB as u64); // chunk 2
    let (r, p) = go(&f, opts(4, 1), None, CancellationToken::new()).await;
    assert!(
        matches!(r, Err(DownloadError::ChunkFailed { offset, .. }) if offset == 128 * KIB as u64),
        "{r:?}"
    );
    let temp = std::fs::read(f.temp()).unwrap();
    assert!(temp.len() <= 128 * KIB);
    assert_eq!(temp, f.plain[..temp.len()]);
    assert_eq!(p.done(), temp.len() as u64);
    let n = f.server.requests.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        n,
        f.server.requests.load(Ordering::SeqCst),
        "requests after run returned"
    );
    assert_eq!(f.server.inflight.load(Ordering::SeqCst), 0);
    f.server.b.lock().unwrap().always_fail.clear();
    let (r, _) = go(&f, opts(4, 1), None, CancellationToken::new()).await;
    assert_eq!(std::fs::read(r.unwrap()).unwrap(), f.plain);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failing_chunk_with_a_hanging_chunk_returns() {
    let f = fx(3584 * KIB + 4 * MIB);
    {
        let mut b = f.server.b.lock().unwrap();
        b.always_fail.insert(128 * KIB as u64);
        b.hang.insert(384 * KIB as u64);
    }
    let (r, _) = go(&f, opts(4, 1), None, CancellationToken::new()).await;
    assert!(matches!(r, Err(DownloadError::ChunkFailed { .. })), "{r:?}");
}

struct PanicServer;
impl DownloadTransport for PanicServer {
    type Body = Body;
    async fn get(&self, _url: &str) -> Result<(u16, Body), TransportError> {
        panic!("transport bug")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn panicking_transport_is_an_error_not_a_hang() {
    let f = fx(600 * KIB);
    let d = Downloader::new(Arc::new(PanicServer), None, opts(3, 1));
    let r = tokio::time::timeout(
        Duration::from_secs(10),
        d.run(
            &f.file,
            &f.dest(),
            Arc::new(Urls(AtomicU32::new(0))),
            Arc::new(Progress::default()),
            CancellationToken::new(),
        ),
    )
    .await
    .expect("hung");
    assert!(matches!(r, Err(DownloadError::Io(_))), "{r:?}");
    assert!(f.temp().exists());
}

struct BadUrls;
impl UrlSource for BadUrls {
    async fn fresh_url(&self) -> Result<String, DownloadError> {
        Err(DownloadError::Url(
            megaquarry_core::public::PublicError::BadKey,
        ))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn url_failure_is_reported() {
    let f = fx(600 * KIB);
    let d = Downloader::new(f.server.clone(), None, opts(3, 1));
    let r = tokio::time::timeout(
        Duration::from_secs(10),
        d.run(
            &f.file,
            &f.dest(),
            Arc::new(BadUrls),
            Arc::new(Progress::default()),
            CancellationToken::new(),
        ),
    )
    .await
    .expect("hung");
    assert!(matches!(r, Err(DownloadError::Url(_))), "{r:?}");
}

// 4. Very small and boundary sizes, mono and multi.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn boundary_sizes() {
    for size in [
        1,
        15,
        16,
        17,
        128 * KIB - 1,
        128 * KIB,
        128 * KIB + 1,
        384 * KIB,
        3584 * KIB,
        3584 * KIB + 1,
        3584 * KIB + MIB,
        3584 * KIB + 20 * MIB + 1,
    ] {
        for workers in [1, 2, 6] {
            let f = fx(size);
            let (r, p) = go(&f, opts(workers, 20), None, CancellationToken::new()).await;
            assert_eq!(
                std::fs::read(r.unwrap()).unwrap(),
                f.plain,
                "size {size} workers {workers}"
            );
            assert_eq!(p.done(), size as u64);
            assert!(!f.temp().exists());
        }
    }
}

// 5. Out-of-order stress with a slow first chunk (permits exhausted).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_first_chunk_with_exhausted_permits() {
    let f = fx(3584 * KIB + 30 * MIB);
    f.server.b.lock().unwrap().delay_ms.insert(0, 300);
    let (r, _) = go(&f, opts(3, 1), None, CancellationToken::new()).await;
    assert_eq!(std::fs::read(r.unwrap()).unwrap(), f.plain);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jitter_stress_loop() {
    for i in 0..6 {
        let f = fx(3584 * KIB + 12 * MIB + i * 4099);
        f.server.b.lock().unwrap().jitter = true;
        let workers = 1 + (i % 9);
        let (r, p) = go(
            &f,
            opts(workers, 1 + (i as u64 % 3)),
            None,
            CancellationToken::new(),
        )
        .await;
        assert_eq!(std::fs::read(r.unwrap()).unwrap(), f.plain, "iteration {i}");
        assert_eq!(p.done(), f.plain.len() as u64);
    }
}

// Concurrent downloads sharing one limiter, real time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn downloads_respect_shared_limiter() {
    let limiter = Arc::new(RateLimiter::new(512 * KIB as u64));
    let a = fx(768 * KIB);
    let b = fx(768 * KIB);
    let started = std::time::Instant::now();
    let (ra, rb) = tokio::join!(
        go(
            &a,
            opts(3, 1),
            Some(limiter.clone()),
            CancellationToken::new()
        ),
        go(
            &b,
            opts(3, 1),
            Some(limiter.clone()),
            CancellationToken::new()
        ),
    );
    ra.0.unwrap();
    rb.0.unwrap();
    // 1536 KiB at 512 KiB/s with a 1 s burst -> at least 2 s. Only the lower
    // bound is asserted: wall-clock upper bounds are flaky on loaded hosts and
    // the paused-clock test in download_engine.rs pins the exact rate.
    let e = started.elapsed();
    assert!(e >= Duration::from_millis(1900), "{e:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn destination_created_mid_download_is_not_overwritten() {
    let f = fx(300 * KIB);
    std::fs::create_dir_all(f.dir.path().join("out")).unwrap();
    f.server.b.lock().unwrap().create_on_first = Some(f.dest());
    let (r, _) = go(&f, opts(2, 1), None, CancellationToken::new()).await;
    assert_eq!(r, Err(DownloadError::DestinationExists(f.dest())));
    assert_eq!(std::fs::read(f.dest()).unwrap(), b"user file");
    // The verified download stays in the temp file for the user to resolve.
    assert_eq!(std::fs::read(f.temp()).unwrap(), f.plain);
}
