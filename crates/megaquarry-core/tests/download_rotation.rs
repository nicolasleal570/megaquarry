//! The download engine with an exit IP rotation: quota hits rotate and the
//! download carries on instead of failing.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use megaquarry_core::api::{ApiError, ErrorCode, RetryPolicy, TransportError};
use megaquarry_core::chunk::meta_mac_of;
use megaquarry_core::crypto::{FileKey, ctr_apply};
use megaquarry_core::download::{
    ChunkBody, DownloadError, DownloadOptions, DownloadTransport, Downloader, Progress, UrlSource,
};
use megaquarry_core::egress::{
    BoxFuture, ControlError, QuotaRotation, RotateError, RotationOptions, Rotator, VpnControl,
    VpnStatus,
};
use megaquarry_core::link::MegaLink;
use megaquarry_core::public::{PublicError, RemoteFile};
use megaquarry_core::store::Store;
use tokio_util::sync::CancellationToken;

const KIB: usize = 1024;

#[derive(Clone, Copy)]
enum Fault {
    /// A network error after this long (a connection cut by a rotation).
    NetworkAfter(Duration),
    /// HTTP 509 after this long, whatever the quota state.
    QuotaAfter(Duration),
}

/// Serves one encrypted file; answers 509 to everything while `quota` is set.
struct FakeServer {
    ciphertext: Vec<u8>,
    quota: AtomicBool,
    time_left: Option<&'static str>,
    faults: Mutex<HashMap<u64, Vec<Fault>>>,
    requests: Mutex<Vec<String>>,
    resets: AtomicU32,
}

struct Body {
    pieces: Vec<Vec<u8>>,
    headers: Vec<(&'static str, String)>,
}

impl ChunkBody for Body {
    async fn next_piece(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        Ok(if self.pieces.is_empty() {
            None
        } else {
            Some(self.pieces.remove(0))
        })
    }

    fn header(&self, name: &str) -> Option<String> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }
}

impl DownloadTransport for FakeServer {
    type Body = Body;

    async fn get(&self, url: &str) -> Result<(u16, Body), TransportError> {
        self.requests.lock().unwrap().push(url.to_owned());
        let (_, range) = url.rsplit_once('/').unwrap();
        let (start, end) = match range.split_once('-') {
            Some((s, e)) => (s.parse::<u64>().unwrap(), e.parse::<u64>().unwrap() + 1),
            None => (range.parse().unwrap(), self.ciphertext.len() as u64),
        };
        let fault = self
            .faults
            .lock()
            .unwrap()
            .get_mut(&start)
            .and_then(|f| (!f.is_empty()).then(|| f.remove(0)));
        let quota = match fault {
            Some(Fault::NetworkAfter(delay)) => {
                tokio::time::sleep(delay).await;
                return Err(TransportError("connection reset".into()));
            }
            Some(Fault::QuotaAfter(delay)) => {
                tokio::time::sleep(delay).await;
                true
            }
            None => self.quota.load(Ordering::SeqCst),
        };
        if quota {
            let headers = self
                .time_left
                .map(|t| vec![("X-MEGA-Time-Left", t.to_owned())])
                .unwrap_or_default();
            return Ok((
                509,
                Body {
                    pieces: vec![],
                    headers,
                },
            ));
        }
        let data = self.ciphertext[start as usize..end as usize].to_vec();
        Ok((
            200,
            Body {
                pieces: vec![data],
                headers: vec![],
            },
        ))
    }

    fn reset_connections(&self) {
        self.resets.fetch_add(1, Ordering::SeqCst);
    }
}

/// Hands out a new URL each time; the first `over_quota` requests fail
/// with the API's `OverQuota`.
struct FakeUrls {
    count: AtomicU32,
    over_quota: Mutex<u32>,
    resets: AtomicU32,
}

impl FakeUrls {
    fn new(over_quota: u32) -> Arc<Self> {
        Arc::new(Self {
            count: AtomicU32::new(0),
            over_quota: Mutex::new(over_quota),
            resets: AtomicU32::new(0),
        })
    }
}

impl UrlSource for FakeUrls {
    async fn fresh_url(&self) -> Result<String, DownloadError> {
        let over_quota = {
            let mut left = self.over_quota.lock().unwrap();
            let hit = *left > 0;
            *left = left.saturating_sub(1);
            hit
        };
        if over_quota {
            return Err(DownloadError::Url(PublicError::Api(ApiError::Mega(
                ErrorCode::OverQuota,
            ))));
        }
        Ok(format!(
            "http://fake/dl/{}",
            self.count.fetch_add(1, Ordering::SeqCst)
        ))
    }

    fn reset_connections(&self) {
        self.resets.fetch_add(1, Ordering::SeqCst);
    }
}

/// A rotation that clears the server's quota; `results` scripts the
/// outcome of each real rotation (default `Ok`), `delay` how long it takes.
struct FakeRotation {
    server: Arc<FakeServer>,
    generation: AtomicU64,
    busy: tokio::sync::Mutex<()>,
    results: Mutex<VecDeque<Result<(), RotateError>>>,
    delay: Duration,
    calls: Mutex<Vec<(u64, Option<Duration>)>>,
    last: Mutex<Result<(), RotateError>>,
}

impl FakeRotation {
    fn new(server: &Arc<FakeServer>, results: Vec<Result<(), RotateError>>) -> Arc<Self> {
        Arc::new(Self {
            server: server.clone(),
            generation: AtomicU64::new(0),
            busy: tokio::sync::Mutex::new(()),
            results: Mutex::new(results.into()),
            delay: Duration::from_secs(2),
            calls: Mutex::default(),
            last: Mutex::new(Ok(())),
        })
    }

    fn calls(&self) -> Vec<(u64, Option<Duration>)> {
        self.calls.lock().unwrap().clone()
    }
}

impl QuotaRotation for FakeRotation {
    fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    fn rotate(
        &self,
        seen: u64,
        time_left: Option<Duration>,
    ) -> BoxFuture<'_, Result<(), RotateError>> {
        Box::pin(async move {
            let _busy = self.busy.lock().await;
            if self.generation() != seen {
                return self.last.lock().unwrap().clone();
            }
            self.calls.lock().unwrap().push((seen, time_left));
            tokio::time::sleep(self.delay).await;
            let result = self.results.lock().unwrap().pop_front().unwrap_or(Ok(()));
            if result.is_ok() {
                self.server.quota.store(false, Ordering::SeqCst);
            }
            *self.last.lock().unwrap() = result.clone();
            self.generation.fetch_add(1, Ordering::SeqCst);
            result
        })
    }

    fn wait_ready(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            drop(self.busy.lock().await);
        })
    }

    fn tunnel_up(&self) -> BoxFuture<'_, bool> {
        Box::pin(async { true })
    }
}

struct Fixture {
    plain: Vec<u8>,
    server: Arc<FakeServer>,
    file: RemoteFile,
    dir: tempfile::TempDir,
}

fn fixture(size: usize, quota: bool, time_left: Option<&'static str>) -> Fixture {
    let plain: Vec<u8> = (0..size).map(|i| (i * 13 % 251) as u8).collect();
    let aes_key = [0x3c; 16];
    let nonce = [0x42; 8];
    let mac = meta_mac_of(&aes_key, &nonce, &plain);
    let key = FileKey::pack(&aes_key, &nonce, &mac);
    let mut ciphertext = plain.clone();
    ctr_apply(&aes_key, &nonce, 0, &mut ciphertext);
    Fixture {
        plain,
        server: Arc::new(FakeServer {
            ciphertext,
            quota: AtomicBool::new(quota),
            time_left,
            faults: Mutex::default(),
            requests: Mutex::default(),
            resets: AtomicU32::new(0),
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

/// Few chunk retries, so any attempt spent on quota would fail the download.
fn options(workers: usize) -> DownloadOptions {
    DownloadOptions {
        workers,
        chunk_multiplier: 1,
        verify: true,
        retry: RetryPolicy {
            max_retries: 1,
            base: Duration::from_millis(1),
            cap: Duration::from_millis(2),
        },
    }
}

async fn run(
    fx: &Fixture,
    workers: usize,
    rotation: Option<Arc<FakeRotation>>,
    urls: Arc<FakeUrls>,
) -> Result<std::path::PathBuf, DownloadError> {
    let mut downloader = Downloader::new(fx.server.clone(), None, options(workers));
    if let Some(rotation) = rotation {
        downloader = downloader.with_rotation(rotation);
    }
    downloader
        .run(
            &fx.file,
            &fx.dir.path().join("file.bin"),
            urls,
            Arc::new(Progress::default()),
            CancellationToken::new(),
        )
        .await
}

#[tokio::test(start_paused = true)]
async fn a_quota_hit_rotates_once_and_the_download_finishes() {
    let fx = fixture(1024 * KIB, true, Some("300"));
    let rotation = FakeRotation::new(&fx.server, vec![]);
    let urls = FakeUrls::new(0);

    let path = run(&fx, 4, Some(rotation.clone()), urls.clone())
        .await
        .unwrap();

    assert_eq!(std::fs::read(path).unwrap(), fx.plain);
    assert_eq!(rotation.calls(), [(0, Some(Duration::from_secs(300)))]);
    // A fresh URL and fresh connections after the rotation.
    assert_eq!(urls.count.load(Ordering::SeqCst), 2);
    assert!(
        fx.server
            .requests
            .lock()
            .unwrap()
            .iter()
            .rev()
            .take(1)
            .all(|r| r.starts_with("http://fake/dl/1/"))
    );
    assert_eq!(fx.server.resets.load(Ordering::SeqCst), 1);
    assert_eq!(urls.resets.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn a_509_without_megas_wait_passes_no_time_left() {
    let fx = fixture(256 * KIB, true, None);
    let rotation = FakeRotation::new(&fx.server, vec![]);

    run(&fx, 1, Some(rotation.clone()), FakeUrls::new(0))
        .await
        .unwrap();

    assert_eq!(rotation.calls(), [(0, None)]);
}

#[tokio::test(start_paused = true)]
async fn a_failed_rotation_waits_a_minute_and_tries_again_without_failing() {
    let fx = fixture(256 * KIB, true, Some("60"));
    let rotation = FakeRotation::new(
        &fx.server,
        vec![
            Err(RotateError::Exhausted),
            Err(RotateError::Unavailable("connection refused".into())),
        ],
    );
    let started = tokio::time::Instant::now();

    let path = run(&fx, 1, Some(rotation.clone()), FakeUrls::new(0))
        .await
        .unwrap();

    assert_eq!(std::fs::read(path).unwrap(), fx.plain);
    assert_eq!(rotation.calls().len(), 3);
    assert!(
        started.elapsed() >= Duration::from_secs(120),
        "two 60 s waits"
    );
}

#[tokio::test(start_paused = true)]
async fn an_api_over_quota_for_the_url_also_rotates() {
    let fx = fixture(256 * KIB, false, None);
    let rotation = FakeRotation::new(&fx.server, vec![]);

    let path = run(&fx, 1, Some(rotation.clone()), FakeUrls::new(1))
        .await
        .unwrap();

    assert_eq!(std::fs::read(path).unwrap(), fx.plain);
    assert_eq!(rotation.calls(), [(0, None)]);
}

#[tokio::test(start_paused = true)]
async fn connections_cut_by_a_rotation_do_not_use_chunk_attempts() {
    let fx = fixture(512 * KIB, false, None);
    // Both first requests start together. Chunk 1 hits the quota after
    // 100 ms and rotates (2 s); chunk 2 loses its connection at 500 ms, in
    // the middle of that rotation, and once more afterwards. With one retry
    // allowed, it only finishes if the first loss is not counted.
    fx.server.faults.lock().unwrap().extend([
        (0, vec![Fault::QuotaAfter(Duration::from_millis(100))]),
        (
            128 * KIB as u64,
            vec![
                Fault::NetworkAfter(Duration::from_millis(500)),
                Fault::NetworkAfter(Duration::from_millis(500)),
            ],
        ),
    ]);
    let rotation = FakeRotation::new(&fx.server, vec![]);

    let path = run(&fx, 2, Some(rotation.clone()), FakeUrls::new(0))
        .await
        .unwrap();

    assert_eq!(std::fs::read(path).unwrap(), fx.plain);
}

#[tokio::test(start_paused = true)]
async fn without_a_rotation_a_509_still_fails_the_chunk() {
    let fx = fixture(256 * KIB, true, Some("300"));

    let result = run(&fx, 1, None, FakeUrls::new(0)).await;

    assert!(
        matches!(
            result,
            Err(DownloadError::ChunkFailed {
                status: Some(509),
                ..
            })
        ),
        "{result:?}"
    );
    assert_eq!(fx.server.resets.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn without_a_rotation_an_api_over_quota_still_fails() {
    let fx = fixture(256 * KIB, false, None);

    let result = run(&fx, 1, None, FakeUrls::new(1)).await;

    assert_eq!(
        result,
        Err(DownloadError::Url(PublicError::Api(ApiError::Mega(
            ErrorCode::OverQuota
        ))))
    );
}

// Regression tests from the independent verification (B1).

/// A VPN whose every reconnect lands on the same, cooling exit IP.
struct StuckVpn {
    reconnects: AtomicU32,
}

impl VpnControl for StuckVpn {
    async fn status(&self) -> Result<VpnStatus, ControlError> {
        Ok(VpnStatus::Running)
    }

    async fn set_running(&self, running: bool) -> Result<(), ControlError> {
        if running {
            self.reconnects.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }

    async fn public_ip(&self) -> Result<Option<String>, ControlError> {
        Ok(Some("9.9.9.9".into()))
    }
}

#[tokio::test(start_paused = true)]
async fn after_a_failed_rotation_every_worker_waits_a_minute() {
    let fx = fixture(1024 * KIB, true, Some("300"));
    let vpn = Arc::new(StuckVpn {
        reconnects: AtomicU32::new(0),
    });
    let rotator = Rotator::new(
        vpn.clone(),
        Arc::new(Store::open_in_memory().unwrap()),
        RotationOptions::default(),
    );
    let downloader =
        Downloader::new(fx.server.clone(), None, options(4)).with_rotation(Arc::new(rotator));

    let _ = tokio::time::timeout(
        Duration::from_secs(59),
        downloader.run(
            &fx.file,
            &fx.dir.path().join("file.bin"),
            FakeUrls::new(0),
            Arc::new(Progress::default()),
            CancellationToken::new(),
        ),
    )
    .await;

    // One rotation of 5 reconnects, then a quiet minute for every worker.
    assert_eq!(vpn.reconnects.load(Ordering::SeqCst), 5);
}

/// A rotation that ends `Unavailable` with the tunnel left down: requests
/// fail with network errors until it is back.
struct DownRotation {
    inner: Arc<FakeRotation>,
    server: Arc<FakeServer>,
    offsets: Vec<u64>,
    failed_once: AtomicBool,
}

impl QuotaRotation for DownRotation {
    fn generation(&self) -> u64 {
        self.inner.generation()
    }

    fn rotate(&self, seen: u64, _: Option<Duration>) -> BoxFuture<'_, Result<(), RotateError>> {
        Box::pin(async move {
            let _busy = self.inner.busy.lock().await;
            if self.inner.generation() != seen {
                return Ok(());
            }
            self.inner.calls.lock().unwrap().push((seen, None));
            tokio::time::sleep(Duration::from_secs(2)).await;
            self.server.quota.store(false, Ordering::SeqCst);
            self.inner.generation.fetch_add(1, Ordering::SeqCst);
            if self.failed_once.swap(true, Ordering::SeqCst) {
                return Ok(());
            }
            let mut faults = self.server.faults.lock().unwrap();
            for offset in &self.offsets {
                faults.insert(
                    *offset,
                    vec![Fault::NetworkAfter(Duration::from_millis(1)); 3],
                );
            }
            Err(RotateError::Unavailable(
                "the VPN tunnel was not up within 90 s".into(),
            ))
        })
    }

    fn wait_ready(&self) -> BoxFuture<'_, ()> {
        self.inner.wait_ready()
    }

    /// Down while any scripted network error is left.
    fn tunnel_up(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            let up = self
                .server
                .faults
                .lock()
                .unwrap()
                .values()
                .all(|f| f.is_empty());
            if !up {
                // The tunnel comes back a little later.
                for faults in self.server.faults.lock().unwrap().values_mut() {
                    faults.pop();
                }
            }
            up
        })
    }
}

#[tokio::test(start_paused = true)]
async fn network_errors_while_the_tunnel_is_down_do_not_fail_the_download() {
    let fx = fixture(1024 * KIB, true, None);
    let plan = megaquarry_core::chunk::ChunkPlan::new(1024 * KIB as u64, 1);
    let rotation = Arc::new(DownRotation {
        inner: FakeRotation::new(&fx.server, vec![]),
        server: fx.server.clone(),
        offsets: (1..=plan.count())
            .map(|i| plan.chunk(i).unwrap().offset)
            .collect(),
        failed_once: AtomicBool::new(false),
    });
    let downloader = Downloader::new(fx.server.clone(), None, options(4)).with_rotation(rotation);

    let result = downloader
        .run(
            &fx.file,
            &fx.dir.path().join("file.bin"),
            FakeUrls::new(0),
            Arc::new(Progress::default()),
            CancellationToken::new(),
        )
        .await;

    assert_eq!(std::fs::read(result.unwrap()).unwrap(), fx.plain);
}
