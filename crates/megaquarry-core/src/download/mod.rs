//! Chunked, parallel, resumable file downloads.
//!
//! Workers fetch chunks (`url/start-end`) in parallel and decrypt them with
//! AES-CTR; a single writer appends them in order to `<name>.mctemp`, so the
//! temp file is always a valid plaintext prefix and resuming only needs its
//! length. The finished file is optionally checked against the meta-MAC and
//! then renamed into place.

mod transport;
mod verify;

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

pub use transport::{ApiUrlSource, ChunkBody, DownloadTransport, UrlSource};

use crate::api::{ApiError, ErrorCode, RetryPolicy};
use crate::chunk::{Chunk, ChunkPlan, DOWNLOAD_CHUNK_MULTIPLIER, MAC_CHUNK_MULTIPLIER, chunk_url};
use crate::crypto::ctr_apply;
use crate::egress::QuotaRotation;
use crate::public::{PublicError, RemoteFile};
use crate::throttle::RateLimiter;

/// Suffix of the in-progress file next to the destination.
pub const TEMP_SUFFIX: &str = ".mctemp";

/// Wait before trying again when a rotation could not give a usable exit IP
/// (the rotator also starts no new rotation for this long after a failure).
pub const QUOTA_WAIT: Duration = Duration::from_secs(60);

/// Header with MEGA's wait, in seconds, on an HTTP 509.
const TIME_LEFT_HEADER: &str = "X-MEGA-Time-Left";

/// Download tuning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadOptions {
    /// Parallel connections (1..=20, default 6).
    pub workers: usize,
    /// Chunk size multiplier after the seventh chunk (20 → 20 MiB chunks).
    pub chunk_multiplier: u64,
    /// Check the meta-MAC before moving the file into place.
    pub verify: bool,
    /// Per-chunk retry schedule; `max_retries` bounds attempts per chunk.
    pub retry: RetryPolicy,
}

impl Default for DownloadOptions {
    fn default() -> Self {
        Self {
            workers: 6,
            chunk_multiplier: DOWNLOAD_CHUNK_MULTIPLIER,
            verify: true,
            retry: RetryPolicy::default(),
        }
    }
}

/// Why a download stopped.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DownloadError {
    #[error("destination already exists: {}", .0.display())]
    DestinationExists(PathBuf),
    #[error("could not get a download URL: {0}")]
    Url(#[from] PublicError),
    /// `status` is the last HTTP status received, if any.
    #[error("chunk at offset {offset} failed: {reason}")]
    ChunkFailed {
        offset: u64,
        reason: String,
        status: Option<u16>,
    },
    #[error("file is damaged: the integrity check (MAC) failed; it was deleted")]
    Corrupted,
    #[error("download cancelled")]
    Cancelled,
    #[error("I/O error: {0}")]
    Io(String),
}

impl From<std::io::Error> for DownloadError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

/// Live byte counters of one download, safe to read from other tasks.
#[derive(Debug, Default)]
pub struct Progress {
    total: AtomicU64,
    done: AtomicU64,
}

impl Progress {
    /// Bytes written so far (including resumed bytes).
    pub fn done(&self) -> u64 {
        self.done.load(Ordering::Relaxed)
    }

    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }
}

/// The temp file used while downloading to `destination`.
pub fn temp_path(destination: &Path) -> PathBuf {
    let mut name = destination.as_os_str().to_owned();
    name.push(TEMP_SUFFIX);
    PathBuf::from(name)
}

/// Runs downloads over a transport, sharing an optional speed limit.
pub struct Downloader<T> {
    transport: Arc<T>,
    limiter: Option<Arc<RateLimiter>>,
    options: DownloadOptions,
    rotation: Option<Arc<dyn QuotaRotation>>,
}

/// The current download URL, refreshed when MEGA reports it expired.
struct UrlCache<U> {
    source: Arc<U>,
    current: Mutex<Option<(u64, String)>>,
    generation: AtomicU64,
}

impl<U: UrlSource> UrlCache<U> {
    async fn get(&self) -> Result<(u64, String), DownloadError> {
        let mut current = self.current.lock().await;
        if let Some(url) = current.as_ref() {
            return Ok(url.clone());
        }
        let url = self.source.fresh_url().await?;
        let generation = self.generation.fetch_add(1, Ordering::Relaxed);
        *current = Some((generation, url.clone()));
        Ok((generation, url))
    }

    /// Drops `generation` unless another worker already replaced it.
    async fn invalidate(&self, generation: u64) {
        let mut current = self.current.lock().await;
        if current.as_ref().is_some_and(|(g, _)| *g == generation) {
            *current = None;
        }
    }
}

struct Shared<T, U> {
    transport: Arc<T>,
    limiter: Option<Arc<RateLimiter>>,
    urls: UrlCache<U>,
    plan: ChunkPlan,
    file: RemoteFile,
    retry: RetryPolicy,
    queue: std::sync::Mutex<VecDeque<u64>>,
    progress: Arc<Progress>,
    cancel: CancellationToken,
    rotation: Option<Arc<dyn QuotaRotation>>,
    /// Rotation generation the connections and URL were last refreshed for.
    synced: AtomicU64,
}

impl<T: DownloadTransport> Downloader<T> {
    pub fn new(
        transport: Arc<T>,
        limiter: Option<Arc<RateLimiter>>,
        options: DownloadOptions,
    ) -> Self {
        Self {
            transport,
            limiter,
            options,
            rotation: None,
        }
    }

    /// Rotates the exit IP on quota hits instead of failing: downloads wait
    /// and carry on.
    pub fn with_rotation(mut self, rotation: Arc<dyn QuotaRotation>) -> Self {
        self.rotation = Some(rotation);
        self
    }

    pub fn options(&self) -> &DownloadOptions {
        &self.options
    }

    /// Downloads `file` to `destination`, resuming from an existing temp file.
    ///
    /// On failure or cancellation the temp file is kept so a later run can
    /// resume; only a failed integrity check deletes it.
    pub async fn run<U: UrlSource>(
        &self,
        file: &RemoteFile,
        destination: &Path,
        urls: Arc<U>,
        progress: Arc<Progress>,
        cancel: CancellationToken,
    ) -> Result<PathBuf, DownloadError> {
        if tokio::fs::try_exists(destination).await? {
            return Err(DownloadError::DestinationExists(destination.to_owned()));
        }
        if let Some(parent) = destination.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let temp = temp_path(destination);
        let mut out = tokio::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&temp)
            .await?;

        let multiplier = if self.options.workers <= 1 {
            MAC_CHUNK_MULTIPLIER
        } else {
            self.options.chunk_multiplier
        };
        let plan = ChunkPlan::new(file.size, multiplier);
        let existing = out.metadata().await?.len().min(file.size);
        let completed = plan.completed_chunks(existing);
        let resume_at = plan.chunk(completed).map_or(0, |c| c.end());
        out.set_len(resume_at).await?;
        out.seek(std::io::SeekFrom::Start(resume_at)).await?;
        progress.total.store(file.size, Ordering::Relaxed);
        progress.done.store(resume_at, Ordering::Relaxed);

        if cancel.is_cancelled() {
            return Err(DownloadError::Cancelled);
        }

        if resume_at < file.size {
            let shared = Arc::new(Shared {
                transport: self.transport.clone(),
                limiter: self.limiter.clone(),
                urls: UrlCache {
                    source: urls,
                    current: Mutex::new(None),
                    generation: AtomicU64::new(0),
                },
                plan,
                file: file.clone(),
                retry: self.options.retry,
                queue: std::sync::Mutex::new((completed + 1..=plan.count()).collect()),
                progress: progress.clone(),
                cancel: cancel.child_token(),
                synced: AtomicU64::new(self.rotation.as_ref().map_or(0, |r| r.generation())),
                rotation: self.rotation.clone(),
            });
            write_chunks(shared, out, completed + 1, self.options.workers.max(1)).await?;
        } else {
            out.sync_all().await?;
        }

        if self.options.verify {
            let key = file.key.clone();
            let path = temp.clone();
            let mac = tokio::task::spawn_blocking(move || verify::meta_mac_of_file(&path, &key))
                .await
                .map_err(|e| DownloadError::Io(e.to_string()))??;
            if mac != file.key.meta_mac() {
                tokio::fs::remove_file(&temp).await?;
                return Err(DownloadError::Corrupted);
            }
        }
        move_into_place(&temp, destination).await?;
        Ok(destination.to_owned())
    }
}

/// Moves the finished temp file to `destination` without ever replacing a
/// file that appeared there meanwhile (a plain rename would overwrite it).
/// On conflict the verified temp file is kept.
async fn move_into_place(temp: &Path, destination: &Path) -> Result<(), DownloadError> {
    match tokio::fs::hard_link(temp, destination).await {
        Ok(()) => Ok(tokio::fs::remove_file(temp).await?),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(DownloadError::DestinationExists(destination.to_owned()))
        }
        // Filesystems without hard links: best-effort check, then rename.
        Err(_) => {
            if tokio::fs::try_exists(destination).await? {
                return Err(DownloadError::DestinationExists(destination.to_owned()));
            }
            Ok(tokio::fs::rename(temp, destination).await?)
        }
    }
}

/// Spawns the workers and appends their chunks in order until the end.
async fn write_chunks<T: DownloadTransport, U: UrlSource>(
    shared: Arc<Shared<T, U>>,
    mut out: tokio::fs::File,
    first_id: u64,
    workers: usize,
) -> Result<(), DownloadError> {
    // Each chunk holds a permit from fetch until written, bounding memory to
    // `2 * workers` chunks even when one slow chunk blocks the writer.
    let permits = Arc::new(Semaphore::new(workers * 2));
    let (tx, mut rx) = mpsc::channel::<(Chunk, Vec<u8>, OwnedSemaphorePermit)>(workers * 2);
    let mut tasks = JoinSet::new();
    for _ in 0..workers {
        tasks.spawn(worker(shared.clone(), permits.clone(), tx.clone()));
    }
    drop(tx);

    let last_id = shared.plan.count();
    let mut next_id = first_id;
    let mut pending: BTreeMap<u64, (Vec<u8>, OwnedSemaphorePermit)> = BTreeMap::new();
    let mut failure: Option<DownloadError> = None;

    while next_id <= last_id {
        tokio::select! {
            received = rx.recv() => match received {
                Some((chunk, data, permit)) => {
                    pending.insert(chunk.id, (data, permit));
                    while let Some((data, _permit)) = pending.remove(&next_id) {
                        out.write_all(&data).await?;
                        shared.progress.done.fetch_add(data.len() as u64, Ordering::Relaxed);
                        next_id += 1;
                    }
                }
                None => break, // every worker exited
            },
            Some(joined) = tasks.join_next(), if failure.is_none() => {
                match joined {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => failure = Some(e),
                    Err(e) => failure = Some(DownloadError::Io(e.to_string())),
                }
                if failure.is_some() {
                    shared.cancel.cancel();
                }
            }
        }
    }
    out.flush().await?;
    out.sync_all().await?;
    shared.cancel.cancel();
    // A worker that panicked closes its sender, so the loop above can end
    // before seeing the panic: collect it here so it is not mistaken for a
    // cancellation.
    while let Some(joined) = tasks.join_next().await {
        if failure.is_none() {
            match joined {
                Ok(Ok(())) => {}
                Ok(Err(e)) => failure = Some(e),
                Err(e) => failure = Some(DownloadError::Io(format!("worker failed: {e}"))),
            }
        }
    }

    if next_id > last_id {
        Ok(())
    } else {
        Err(failure.unwrap_or(DownloadError::Cancelled))
    }
}

async fn worker<T: DownloadTransport, U: UrlSource>(
    shared: Arc<Shared<T, U>>,
    permits: Arc<Semaphore>,
    tx: mpsc::Sender<(Chunk, Vec<u8>, OwnedSemaphorePermit)>,
) -> Result<(), DownloadError> {
    loop {
        let permit = tokio::select! {
            permit = permits.clone().acquire_owned() => permit.expect("semaphore is never closed"),
            () = shared.cancel.cancelled() => return Ok(()),
        };
        let Some(id) = shared.queue.lock().expect("lock").pop_front() else {
            return Ok(());
        };
        let chunk = shared.plan.chunk(id).expect("queued ids are in the plan");
        let data = tokio::select! {
            data = fetch_with_retries(&shared, &chunk) => data?,
            () = shared.cancel.cancelled() => return Ok(()),
        };
        if tx.send((chunk, data, permit)).await.is_err() {
            return Ok(());
        }
    }
}

async fn fetch_with_retries<T: DownloadTransport, U: UrlSource>(
    shared: &Shared<T, U>,
    chunk: &Chunk,
) -> Result<Vec<u8>, DownloadError> {
    let mut attempt = 0;
    loop {
        let seen = match &shared.rotation {
            Some(rotation) => Some(sync_rotation(shared, rotation.as_ref()).await),
            None => None,
        };
        let (generation, base) = match shared.urls.get().await {
            Ok(url) => url,
            Err(e) if is_api_over_quota(&e) && seen.is_some() => {
                on_quota(shared, seen, None).await;
                continue;
            }
            Err(e) if is_api_unreachable(&e) && vpn_down(shared, seen).await => continue,
            Err(e) => return Err(e),
        };
        let url = chunk_url(&base, chunk, &shared.plan);
        let (reason, status, immediate) = match fetch_once(shared, &url, chunk).await {
            Ok(mut data) => {
                let key = shared.file.key.clone();
                let offset = chunk.offset;
                return tokio::task::spawn_blocking(move || {
                    ctr_apply(&key.aes_key(), &key.nonce(), offset, &mut data);
                    data
                })
                .await
                .map_err(|e| DownloadError::Io(e.to_string()));
            }
            // An expired URL is retried at once with a fresh one.
            Err(FetchError::Expired) => {
                shared.urls.invalidate(generation).await;
                (
                    "download URL expired (HTTP 403)".to_owned(),
                    Some(403),
                    true,
                )
            }
            Err(FetchError::Quota(time_left)) if seen.is_some() => {
                on_quota(shared, seen, time_left).await;
                continue;
            }
            Err(FetchError::Quota(_)) => (
                "transfer quota exceeded (HTTP 509)".to_owned(),
                Some(509),
                false,
            ),
            // A connection cut by a rotation, or lost while the tunnel is
            // down, is not this chunk's fault.
            Err(FetchError::Retry(_, None)) if vpn_down(shared, seen).await => continue,
            Err(FetchError::Retry(reason, status)) => (reason, status, false),
        };
        if attempt >= shared.retry.max_retries {
            return Err(DownloadError::ChunkFailed {
                offset: chunk.offset,
                reason,
                status,
            });
        }
        if !immediate {
            tokio::time::sleep(shared.retry.delay(attempt)).await;
        }
        attempt += 1;
    }
}

/// Waits for a rotation in progress and, the first time a worker sees a new
/// generation, drops pooled connections and the download URL, which belong to
/// the old exit IP. Returns the generation the next request runs under.
async fn sync_rotation<T: DownloadTransport, U: UrlSource>(
    shared: &Shared<T, U>,
    rotation: &dyn QuotaRotation,
) -> u64 {
    rotation.wait_ready().await;
    let generation = rotation.generation();
    // Checked under the URL lock, so no worker can read the old URL between
    // another worker noticing the new generation and dropping that URL.
    let mut current = shared.urls.current.lock().await;
    if shared.synced.fetch_max(generation, Ordering::SeqCst) < generation {
        shared.transport.reset_connections();
        shared.urls.source.reset_connections();
        *current = None;
    }
    generation
}

/// After a network error with a rotation configured: true (once it has
/// waited) when the error belongs to the VPN rather than to the download,
/// because a rotation replaced the tunnel since the request started, or the
/// tunnel is down, in which case it waits [`QUOTA_WAIT`] first.
async fn vpn_down<T: DownloadTransport, U: UrlSource>(
    shared: &Shared<T, U>,
    seen: Option<u64>,
) -> bool {
    let (Some(rotation), Some(seen)) = (&shared.rotation, seen) else {
        return false;
    };
    rotation.wait_ready().await;
    if rotation.generation() != seen {
        return true;
    }
    if rotation.tunnel_up().await {
        return false;
    }
    tokio::time::sleep(QUOTA_WAIT).await;
    true
}

/// Rotates the exit IP; when that gives no usable IP, waits before the next
/// try. Quota hits never use chunk retry attempts, so downloads keep waiting
/// instead of failing.
async fn on_quota<T: DownloadTransport, U: UrlSource>(
    shared: &Shared<T, U>,
    seen: Option<u64>,
    time_left: Option<Duration>,
) {
    let (Some(rotation), Some(seen)) = (&shared.rotation, seen) else {
        return;
    };
    if rotation.rotate(seen, time_left).await.is_err() {
        tokio::time::sleep(QUOTA_WAIT).await;
    }
}

/// The API could not be reached at all (no HTTP answer).
fn is_api_unreachable(error: &DownloadError) -> bool {
    matches!(
        error,
        DownloadError::Url(PublicError::Api(ApiError::Transport(_)))
    )
}

fn is_api_over_quota(error: &DownloadError) -> bool {
    matches!(
        error,
        DownloadError::Url(PublicError::Api(ApiError::Mega(ErrorCode::OverQuota)))
    )
}

enum FetchError {
    Expired,
    /// HTTP 509, with MEGA's wait when it sent one.
    Quota(Option<Duration>),
    /// Reason and HTTP status (when the server answered).
    Retry(String, Option<u16>),
}

async fn fetch_once<T: DownloadTransport, U: UrlSource>(
    shared: &Shared<T, U>,
    url: &str,
    chunk: &Chunk,
) -> Result<Vec<u8>, FetchError> {
    let (status, mut body) = shared
        .transport
        .get(url)
        .await
        .map_err(|e| FetchError::Retry(format!("network error: {e}"), None))?;
    match status {
        200 => {}
        403 => return Err(FetchError::Expired),
        509 => {
            let time_left = body
                .header(TIME_LEFT_HEADER)
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map(Duration::from_secs);
            return Err(FetchError::Quota(time_left));
        }
        other => return Err(FetchError::Retry(format!("HTTP {other}"), Some(other))),
    }
    let mut data = Vec::with_capacity(chunk.size as usize);
    while let Some(piece) = body
        .next_piece()
        .await
        .map_err(|e| FetchError::Retry(format!("network error: {e}"), None))?
    {
        if let Some(limiter) = &shared.limiter {
            limiter.acquire(piece.len() as u64).await;
        }
        data.extend_from_slice(&piece);
        if data.len() as u64 > chunk.size {
            break;
        }
    }
    if data.len() as u64 == chunk.size {
        Ok(data)
    } else {
        Err(FetchError::Retry(
            format!("expected {} bytes, got {}", chunk.size, data.len()),
            Some(200),
        ))
    }
}
