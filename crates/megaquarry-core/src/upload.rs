//! Chunked, parallel, resumable uploads and remote folder creation.
//!
//! The file is split with the 1 MiB MAC geometry; each chunk is encrypted
//! with AES-CTR at its offset and POSTed to `upload_url/offset` (the MEGA SDK
//! form). The storage server answers the POST that completes the file with
//! a completion token, which the `p` command turns into a node.

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::io::SeekFrom;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::api::{ApiError, ApiTransport, ErrorCode, MegaApi, RetryPolicy, TransportError};
use crate::chunk::{Chunk, ChunkPlan, MAC_CHUNK_MULTIPLIER, MacAccumulator};
use crate::crypto::{
    AesKey, Attributes, FileKey, Nonce, b64url_decode, b64url_encode, ctr_apply, ecb_encrypt,
    encrypt_attributes,
};
use crate::link::MegaLink;
use crate::session::Session;
use crate::throttle::RateLimiter;

/// Port: POSTs encrypted chunks to MEGA storage servers.
pub trait UploadTransport: Send + Sync + 'static {
    /// Returns the HTTP status and the response body.
    fn post(
        &self,
        url: &str,
        body: Vec<u8>,
    ) -> impl Future<Output = Result<(u16, Vec<u8>), TransportError>> + Send;
}

/// Upload tuning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadOptions {
    /// Parallel connections (default 6).
    pub workers: usize,
    /// Per-chunk retry schedule.
    pub retry: RetryPolicy,
}

impl Default for UploadOptions {
    fn default() -> Self {
        Self {
            workers: 6,
            retry: RetryPolicy::default(),
        }
    }
}

/// Why an upload stopped.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UploadError {
    #[error("not a regular file: {0}")]
    NotAFile(String),
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error("the storage server rejected the upload: {0}")]
    Rejected(ErrorCode),
    /// `status` is the last HTTP status received, if any.
    #[error("chunk at offset {offset} failed: {reason}")]
    ChunkFailed {
        offset: u64,
        reason: String,
        status: Option<u16>,
    },
    #[error("the storage server sent no completion token")]
    NoCompletionToken,
    #[error("unexpected reply: {0}")]
    Malformed(String),
    #[error("upload cancelled")]
    Cancelled,
    #[error("I/O error: {0}")]
    Io(String),
}

impl From<std::io::Error> for UploadError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

/// What is needed to resume an upload: its URL, key and confirmed chunks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadCheckpoint {
    pub url: String,
    pub aes_key: AesKey,
    pub nonce: Nonce,
    /// Chunk MAC of every chunk the server confirmed, by chunk offset.
    pub done: BTreeMap<u64, [u8; 16]>,
    pub completion_token: Option<String>,
    /// Size and modification time (seconds) of the file when the upload
    /// started; a resume of a changed file starts over instead.
    pub file_size: u64,
    pub file_mtime: u64,
}

impl UploadCheckpoint {
    /// JSON form for the persisted queue.
    pub fn to_json(&self) -> Value {
        let done: serde_json::Map<String, Value> = self
            .done
            .iter()
            .map(|(offset, mac)| (offset.to_string(), json!(b64url_encode(mac))))
            .collect();
        json!({
            "url": self.url,
            "key": b64url_encode(&[self.aes_key.as_slice(), self.nonce.as_slice()].concat()),
            "done": done,
            "token": self.completion_token,
            "size": self.file_size,
            "mtime": self.file_mtime,
        })
    }

    pub fn from_json(value: &Value) -> Option<Self> {
        let key = b64url_decode(value["key"].as_str()?).ok()?;
        if key.len() != 24 {
            return None;
        }
        let mut done = BTreeMap::new();
        for (offset, mac) in value["done"].as_object()? {
            let mac: [u8; 16] = b64url_decode(mac.as_str()?).ok()?.try_into().ok()?;
            done.insert(offset.parse().ok()?, mac);
        }
        Some(Self {
            url: value["url"].as_str()?.to_owned(),
            aes_key: key[..16].try_into().ok()?,
            nonce: key[16..].try_into().ok()?,
            done,
            completion_token: value["token"].as_str().map(str::to_owned),
            file_size: value["size"].as_u64()?,
            file_mtime: value["mtime"].as_u64()?,
        })
    }
}

/// Live counters and the resumable state of one upload.
#[derive(Debug, Default)]
pub struct UploadProgress {
    total: AtomicU64,
    done: AtomicU64,
    state: Mutex<Option<UploadCheckpoint>>,
}

impl UploadProgress {
    /// Progress that continues a previous upload.
    pub fn resuming(checkpoint: UploadCheckpoint) -> Self {
        Self {
            state: Mutex::new(Some(checkpoint)),
            ..Self::default()
        }
    }

    pub fn done(&self) -> u64 {
        self.done.load(Ordering::Relaxed)
    }

    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    /// The current resumable state, once the upload URL is known.
    pub fn checkpoint(&self) -> Option<UploadCheckpoint> {
        self.state.lock().expect("lock").clone()
    }

    fn update(&self, f: impl FnOnce(&mut UploadCheckpoint)) {
        if let Some(state) = self.state.lock().expect("lock").as_mut() {
            f(state);
        }
    }
}

/// A finished upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uploaded {
    pub handle: String,
    pub name: String,
    pub key: FileKey,
}

/// Runs uploads over a transport, sharing an optional speed limit.
pub struct Uploader<T> {
    transport: Arc<T>,
    limiter: Option<Arc<RateLimiter>>,
    options: UploadOptions,
}

struct Shared<T> {
    transport: Arc<T>,
    limiter: Option<Arc<RateLimiter>>,
    retry: RetryPolicy,
    url: String,
    aes_key: AesKey,
    nonce: Nonce,
    path: std::path::PathBuf,
    queue: Mutex<VecDeque<Chunk>>,
    progress: Arc<UploadProgress>,
    cancel: CancellationToken,
}

impl<T: UploadTransport> Uploader<T> {
    pub fn new(
        transport: Arc<T>,
        limiter: Option<Arc<RateLimiter>>,
        options: UploadOptions,
    ) -> Self {
        Self {
            transport,
            limiter,
            options,
        }
    }

    /// Uploads `path` into the remote folder `parent`.
    ///
    /// When `progress` holds a checkpoint, the upload resumes with its URL
    /// and key and skips confirmed chunks. On failure or cancellation the
    /// checkpoint stays available through `progress`.
    pub async fn run<A: ApiTransport>(
        &self,
        api: &MegaApi<A>,
        session: &Session,
        path: &Path,
        parent: &str,
        progress: Arc<UploadProgress>,
        cancel: CancellationToken,
    ) -> Result<Uploaded, UploadError> {
        let metadata = tokio::fs::metadata(path).await?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .filter(|_| metadata.is_file())
            .ok_or_else(|| UploadError::NotAFile(path.display().to_string()))?;
        let size = metadata.len();
        let mtime = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs());

        // A checkpoint of a file that changed since is useless: start over.
        let stale = progress
            .checkpoint()
            .is_some_and(|c| c.file_size != size || c.file_mtime != mtime);
        if stale {
            *progress.state.lock().expect("lock") = None;
        }
        if progress.checkpoint().is_none() {
            let reply = api.call(json!({"a": "u", "s": size})).await?;
            let url = reply["p"]
                .as_str()
                .ok_or_else(|| UploadError::Malformed(format!("no upload URL in {reply}")))?;
            let key: [u8; 24] = rand::random();
            *progress.state.lock().expect("lock") = Some(UploadCheckpoint {
                url: url.to_owned(),
                aes_key: key[..16].try_into().expect("16 bytes"),
                nonce: key[16..].try_into().expect("8 bytes"),
                done: BTreeMap::new(),
                completion_token: None,
                file_size: size,
                file_mtime: mtime,
            });
        }
        let checkpoint = progress.checkpoint().expect("set above");
        let plan = ChunkPlan::new(size, MAC_CHUNK_MULTIPLIER);
        let pending: VecDeque<Chunk> = plan
            .iter()
            .filter(|c| !checkpoint.done.contains_key(&c.offset))
            .collect();
        progress.total.store(size, Ordering::Relaxed);
        progress.done.store(
            plan.iter()
                .filter(|c| checkpoint.done.contains_key(&c.offset))
                .map(|c| c.size)
                .sum(),
            Ordering::Relaxed,
        );

        let shared = Arc::new(Shared {
            transport: self.transport.clone(),
            limiter: self.limiter.clone(),
            retry: self.options.retry,
            url: checkpoint.url.clone(),
            aes_key: checkpoint.aes_key,
            nonce: checkpoint.nonce,
            path: path.to_owned(),
            queue: Mutex::new(pending),
            progress: progress.clone(),
            cancel: cancel.child_token(),
        });
        let mut tasks = JoinSet::new();
        for _ in 0..self.options.workers.max(1) {
            tasks.spawn(worker(shared.clone()));
        }
        let mut failure = None;
        while let Some(joined) = tasks.join_next().await {
            let result =
                joined.unwrap_or_else(|e| Err(UploadError::Io(format!("worker failed: {e}"))));
            if let (Err(e), None) = (result, &failure) {
                failure = Some(e);
                shared.cancel.cancel();
            }
        }
        if let Some(e) = failure {
            return Err(e);
        }
        if cancel.is_cancelled() {
            return Err(UploadError::Cancelled);
        }

        let checkpoint = progress.checkpoint().expect("set above");
        let token = checkpoint
            .completion_token
            .clone()
            .ok_or(UploadError::NoCompletionToken)?;
        let mut mac = MacAccumulator::new(checkpoint.aes_key, checkpoint.nonce);
        for chunk in plan.iter() {
            let chunk_mac = checkpoint.done.get(&chunk.offset).ok_or_else(|| {
                UploadError::Malformed(format!("chunk at {} was never confirmed", chunk.offset))
            })?;
            mac.absorb(chunk_mac);
        }
        let key = FileKey::pack(&checkpoint.aes_key, &checkpoint.nonce, &mac.meta_mac());
        let handle = put_node(
            api,
            session,
            parent,
            &token,
            0,
            &name,
            &key.to_bytes(),
            &key.aes_key(),
        )
        .await?;
        Ok(Uploaded { handle, name, key })
    }
}

async fn worker<T: UploadTransport>(shared: Arc<Shared<T>>) -> Result<(), UploadError> {
    let mut file = tokio::fs::File::open(&shared.path).await?;
    loop {
        if shared.cancel.is_cancelled() {
            return Ok(());
        }
        let Some(chunk) = shared.queue.lock().expect("lock").pop_front() else {
            return Ok(());
        };
        let mut plain = vec![0u8; chunk.size as usize];
        file.seek(SeekFrom::Start(chunk.offset)).await?;
        file.read_exact(&mut plain).await?;

        let (aes_key, nonce, offset) = (shared.aes_key, shared.nonce, chunk.offset);
        let (chunk_mac, body) = tokio::task::spawn_blocking(move || {
            let chunk_mac = MacAccumulator::new(aes_key, nonce).chunk_mac(&plain);
            ctr_apply(&aes_key, &nonce, offset, &mut plain);
            (chunk_mac, plain)
        })
        .await
        .map_err(|e| UploadError::Io(e.to_string()))?;

        let token = tokio::select! {
            sent = send_with_retries(&shared, &chunk, body) => sent?,
            () = shared.cancel.cancelled() => return Ok(()),
        };
        shared.progress.update(|state| {
            state.done.insert(chunk.offset, chunk_mac);
            if token.is_some() {
                state.completion_token = token;
            }
        });
        shared
            .progress
            .done
            .fetch_add(chunk.size, Ordering::Relaxed);
    }
}

/// Sends one chunk; returns the completion token when the server sent one.
async fn send_with_retries<T: UploadTransport>(
    shared: &Shared<T>,
    chunk: &Chunk,
    body: Vec<u8>,
) -> Result<Option<String>, UploadError> {
    if let Some(limiter) = &shared.limiter {
        limiter.acquire(body.len() as u64).await;
    }
    let url = format!("{}/{}", shared.url, chunk.offset);
    let mut attempt = 0;
    loop {
        let (reason, status) = match shared.transport.post(&url, body.clone()).await {
            Ok((200, reply)) => {
                let text = String::from_utf8_lossy(&reply).trim().to_owned();
                match text.parse::<i64>() {
                    // Temporary storage congestion: retry like a network error.
                    Ok(code) if ErrorCode::from_code(code).is_transient() => (
                        format!("storage busy ({})", ErrorCode::from_code(code)),
                        Some(200),
                    ),
                    Ok(code) if code < 0 => {
                        return Err(UploadError::Rejected(ErrorCode::from_code(code)));
                    }
                    _ if text.is_empty() => return Ok(None),
                    _ => return Ok(Some(text)),
                }
            }
            Ok((status, _)) => (format!("HTTP {status}"), Some(status)),
            Err(e) => (format!("network error: {e}"), None),
        };
        if attempt >= shared.retry.max_retries {
            return Err(UploadError::ChunkFailed {
                offset: chunk.offset,
                reason,
                status,
            });
        }
        tokio::time::sleep(shared.retry.delay(attempt)).await;
        attempt += 1;
    }
}

/// Registers a node with the `p` command; returns its handle.
#[allow(clippy::too_many_arguments)]
async fn put_node<A: ApiTransport>(
    api: &MegaApi<A>,
    session: &Session,
    parent: &str,
    handle: &str,
    node_type: u8,
    name: &str,
    node_key: &[u8],
    attribute_key: &AesKey,
) -> Result<String, UploadError> {
    let attributes = encrypt_attributes(&Attributes::with_name(name), attribute_key)
        .map_err(|e| UploadError::Malformed(e.to_string()))?;
    let wrapped = ecb_encrypt(&session.master_key, node_key)
        .map_err(|e| UploadError::Malformed(e.to_string()))?;
    let reply = api
        .call(json!({
            "a": "p",
            "t": parent,
            "n": [{
                "h": handle,
                "t": node_type,
                "a": b64url_encode(&attributes),
                "k": b64url_encode(&wrapped),
            }],
        }))
        .await?;
    reply["f"][0]["h"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| UploadError::Malformed(format!("no node handle in {reply}")))
}

/// Creates a folder named `name` inside `parent`; returns its handle.
pub async fn create_folder<A: ApiTransport>(
    api: &MegaApi<A>,
    session: &Session,
    parent: &str,
    name: &str,
) -> Result<String, UploadError> {
    let folder_key: AesKey = rand::random();
    put_node(
        api,
        session,
        parent,
        "xxxxxxxx",
        1,
        name,
        &folder_key,
        &folder_key,
    )
    .await
}

/// Creates a public link for an uploaded file.
pub async fn export_link<A: ApiTransport>(
    api: &MegaApi<A>,
    handle: &str,
    key: &FileKey,
) -> Result<MegaLink, UploadError> {
    let reply = api.call(json!({"a": "l", "n": handle})).await?;
    let public = reply
        .as_str()
        .ok_or_else(|| UploadError::Malformed(format!("no public handle in {reply}")))?;
    Ok(MegaLink::File {
        handle: public.to_owned(),
        key: key.clone(),
    })
}

/// The handle of the account's root ("Cloud Drive") folder.
pub async fn root_handle<A: ApiTransport>(api: &MegaApi<A>) -> Result<String, UploadError> {
    let reply = api.call(json!({"a": "f", "c": 1})).await?;
    reply["f"]
        .as_array()
        .and_then(|nodes| nodes.iter().find(|n| n["t"].as_u64() == Some(2)))
        .and_then(|n| n["h"].as_str())
        .map(str::to_owned)
        .ok_or_else(|| UploadError::Malformed("no root folder in the node list".into()))
}
