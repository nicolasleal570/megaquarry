use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU32, Ordering};
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

/// Serves one encrypted file at `http://fake/dl/<n>/<start>[-<end>]`.
struct FakeServer {
    ciphertext: Vec<u8>,
    expired: Mutex<HashSet<String>>,
    /// Scripted failures by chunk start offset, consumed once each.
    faults: Mutex<HashMap<u64, Vec<Fault>>>,
    requests: Mutex<Vec<String>>,
}

#[derive(Clone, Copy)]
enum Fault {
    Status(u16),
    Truncate,
    Network,
}

struct Body(Vec<Vec<u8>>);

impl ChunkBody for Body {
    async fn next_piece(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        Ok(if self.0.is_empty() {
            None
        } else {
            Some(self.0.remove(0))
        })
    }
}

impl DownloadTransport for FakeServer {
    type Body = Body;

    async fn get(&self, url: &str) -> Result<(u16, Body), TransportError> {
        self.requests.lock().unwrap().push(url.to_owned());
        let (base, range) = url.rsplit_once('/').unwrap();
        if self.expired.lock().unwrap().contains(base) {
            return Ok((403, Body(vec![])));
        }
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
        let data = self.ciphertext[start as usize..end as usize].to_vec();
        match fault {
            Some(Fault::Status(code)) => Ok((code, Body(vec![]))),
            Some(Fault::Network) => Err(TransportError("reset".into())),
            Some(Fault::Truncate) => Ok((200, Body(vec![data[..data.len() / 2].to_vec()]))),
            None => Ok((
                200,
                Body(data.chunks(64 * KIB).map(<[u8]>::to_vec).collect()),
            )),
        }
    }
}

/// Hands out a new URL generation each time it is asked.
struct FakeUrls(AtomicU32);

impl UrlSource for FakeUrls {
    async fn fresh_url(&self) -> Result<String, DownloadError> {
        Ok(format!(
            "http://fake/dl/{}",
            self.0.fetch_add(1, Ordering::SeqCst)
        ))
    }
}

struct Fixture {
    plain: Vec<u8>,
    server: Arc<FakeServer>,
    file: RemoteFile,
    dir: tempfile::TempDir,
}

fn fixture(size: usize, corrupt_mac: bool) -> Fixture {
    let plain: Vec<u8> = (0..size).map(|i| (i * 7 % 251) as u8).collect();
    let aes_key = [0x5a; 16];
    let nonce = [0x17; 8];
    let mut mac = meta_mac_of(&aes_key, &nonce, &plain);
    if corrupt_mac {
        mac[0] ^= 1;
    }
    let key = FileKey::pack(&aes_key, &nonce, &mac);
    let mut ciphertext = plain.clone();
    ctr_apply(&aes_key, &nonce, 0, &mut ciphertext);
    Fixture {
        plain,
        server: Arc::new(FakeServer {
            ciphertext,
            expired: Mutex::default(),
            faults: Mutex::default(),
            requests: Mutex::default(),
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

fn options(workers: usize, multiplier: u64) -> DownloadOptions {
    DownloadOptions {
        workers,
        chunk_multiplier: multiplier,
        verify: true,
        retry: RetryPolicy {
            max_retries: 4,
            base: Duration::from_millis(1),
            cap: Duration::from_millis(2),
        },
    }
}

async fn run(
    fx: &Fixture,
    opts: DownloadOptions,
) -> (Result<std::path::PathBuf, DownloadError>, Arc<Progress>) {
    let downloader = Downloader::new(fx.server.clone(), None, opts);
    let progress = Arc::new(Progress::default());
    let result = downloader
        .run(
            &fx.file,
            &fx.dir.path().join("out/file.bin"),
            Arc::new(FakeUrls(AtomicU32::new(0))),
            progress.clone(),
            CancellationToken::new(),
        )
        .await;
    (result, progress)
}

#[tokio::test]
async fn downloads_and_decrypts_with_parallel_workers() {
    let fx = fixture(5 * 1024 * KIB + 333, false);
    let (result, progress) = run(&fx, options(4, 1)).await;
    let path = result.unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), fx.plain);
    assert!(!fx.dir.path().join("out/file.bin.mctemp").exists());
    assert_eq!(progress.done(), fx.plain.len() as u64);
    assert_eq!(progress.total(), fx.plain.len() as u64);
    // Chunks 1..=7 plus two 1 MiB chunks; the last URL has no end.
    let requests = fx.server.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 9);
    assert!(requests.iter().any(|r| r.ends_with("/0-131071")));
    assert!(
        requests
            .iter()
            .any(|r| r.ends_with(&format!("/{}", 3584 * KIB + 1024 * KIB)))
    );
}

#[tokio::test]
async fn large_chunk_multiplier_reduces_requests() {
    let fx = fixture(6 * 1024 * KIB, false);
    let (result, _) = run(&fx, options(3, 20)).await;
    assert_eq!(std::fs::read(result.unwrap()).unwrap(), fx.plain);
    assert_eq!(fx.server.requests.lock().unwrap().len(), 8);
}

#[tokio::test]
async fn retries_failed_chunks_and_refreshes_expired_urls() {
    let fx = fixture(1024 * KIB, false);
    fx.server
        .expired
        .lock()
        .unwrap()
        .insert("http://fake/dl/0".into());
    fx.server.faults.lock().unwrap().extend([
        (128 * KIB as u64, vec![Fault::Status(500), Fault::Truncate]),
        (384 * KIB as u64, vec![Fault::Network, Fault::Status(509)]),
    ]);
    let (result, progress) = run(&fx, options(2, 1)).await;
    assert_eq!(std::fs::read(result.unwrap()).unwrap(), fx.plain);
    assert_eq!(progress.done(), fx.plain.len() as u64);
    let requests = fx.server.requests.lock().unwrap().clone();
    assert!(requests.iter().any(|r| r.starts_with("http://fake/dl/1/")));
}

#[tokio::test]
async fn gives_up_on_a_chunk_after_the_retry_limit() {
    let fx = fixture(300 * KIB, false);
    fx.server
        .faults
        .lock()
        .unwrap()
        .insert(0, vec![Fault::Status(500); 10]);
    let (result, _) = run(&fx, options(2, 1)).await;
    assert!(
        matches!(result, Err(DownloadError::ChunkFailed { offset: 0, .. })),
        "{result:?}"
    );
    // Partial progress is kept for a later resume.
    assert!(fx.dir.path().join("out/file.bin.mctemp").exists());
    assert!(!fx.dir.path().join("out/file.bin").exists());
}

#[tokio::test]
async fn resumes_from_the_completed_prefix_of_the_temp_file() {
    let fx = fixture(1024 * KIB, false);
    let out = fx.dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    // Chunks 1 and 2 (384 KiB) are complete, chunk 3 is half written.
    std::fs::write(out.join("file.bin.mctemp"), &fx.plain[..(384 + 100) * KIB]).unwrap();

    let (result, _) = run(&fx, options(2, 1)).await;
    assert_eq!(std::fs::read(result.unwrap()).unwrap(), fx.plain);
    let requests = fx.server.requests.lock().unwrap().clone();
    assert!(!requests.iter().any(|r| r.ends_with("/0-131071")));
    assert!(
        requests
            .iter()
            .any(|r| r.contains(&format!("/{}-", 384 * KIB)))
    );
}

#[tokio::test]
async fn deletes_files_that_fail_the_integrity_check() {
    let fx = fixture(200 * KIB, true);
    let (result, _) = run(&fx, options(2, 1)).await;
    assert_eq!(result, Err(DownloadError::Corrupted));
    assert!(!fx.dir.path().join("out/file.bin").exists());
    assert!(!fx.dir.path().join("out/file.bin.mctemp").exists());
}

#[tokio::test]
async fn skips_verification_when_disabled() {
    let fx = fixture(200 * KIB, true);
    let opts = DownloadOptions {
        verify: false,
        ..options(2, 1)
    };
    let (result, _) = run(&fx, opts).await;
    assert_eq!(std::fs::read(result.unwrap()).unwrap(), fx.plain);
}

#[tokio::test]
async fn creates_empty_files_without_requests() {
    let fx = fixture(0, false);
    let (result, _) = run(&fx, options(2, 1)).await;
    assert_eq!(std::fs::read(result.unwrap()).unwrap(), Vec::<u8>::new());
    assert!(fx.server.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn refuses_to_overwrite_an_existing_file() {
    let fx = fixture(10, false);
    let dest = fx.dir.path().join("out/file.bin");
    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
    std::fs::write(&dest, b"keep").unwrap();
    let (result, _) = run(&fx, options(1, 1)).await;
    assert_eq!(result, Err(DownloadError::DestinationExists(dest.clone())));
    assert_eq!(std::fs::read(&dest).unwrap(), b"keep");
}

#[tokio::test]
async fn cancellation_keeps_the_temp_file() {
    let fx = fixture(1024 * KIB, false);
    let downloader = Downloader::new(fx.server.clone(), None, options(2, 1));
    let cancel = CancellationToken::new();
    cancel.cancel();
    let result = downloader
        .run(
            &fx.file,
            &fx.dir.path().join("out/file.bin"),
            Arc::new(FakeUrls(AtomicU32::new(0))),
            Arc::new(Progress::default()),
            cancel,
        )
        .await;
    assert_eq!(result, Err(DownloadError::Cancelled));
    assert!(fx.dir.path().join("out/file.bin.mctemp").exists());
}

#[tokio::test(start_paused = true)]
async fn rate_limiter_enforces_the_average_rate() {
    let limiter = RateLimiter::new(100 * KIB as u64);
    let started = tokio::time::Instant::now();
    for _ in 0..5 {
        limiter.acquire(100 * KIB as u64).await;
    }
    // The first second is a burst allowance; four more seconds of debt.
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_secs(4) && elapsed < Duration::from_secs(5),
        "{elapsed:?}"
    );
}
