//! The real [`TransferRunner`]: drives the download and upload engines.
//!
//! Payloads:
//! - download: `{"link", "name", "size", "destination"}` where `link` is a
//!   file or folder-node link (it carries the key);
//! - upload: `{"path", "parent", "checkpoint"?}`; the checkpoint is written
//!   back into the stored entry while uploading so a later run resumes.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use super::{AbortOnDrop, JobContext, JobOutcome, TransferRunner};
use crate::api::{ApiError, ApiTransport, ErrorCode, MegaApi};
use crate::download::{ApiUrlSource, DownloadError, DownloadTransport, Downloader, Progress};
use crate::link::{MegaLink, parse_link};
use crate::public::{PublicError, RemoteFile};
use crate::session::Session;
use crate::store::{QueueKind, Store};
use crate::upload::{UploadCheckpoint, UploadError, UploadProgress, UploadTransport, Uploader};

/// Delay before retrying an ordinary transient failure.
const RETRY_SOON: Duration = Duration::from_secs(3);
/// Delay before retrying after a quota or rate limit.
const RETRY_LATER: Duration = Duration::from_secs(60);
/// How often live progress is mirrored and upload checkpoints saved.
const TICK: Duration = Duration::from_millis(250);

/// Runs queue entries against MEGA.
pub struct MegaRunner<A, D, U> {
    api: Arc<MegaApi<A>>,
    session: Option<Session>,
    store: Arc<Store>,
    downloader: Downloader<D>,
    uploader: Uploader<U>,
    export_links: bool,
}

impl<A, D, U> MegaRunner<A, D, U>
where
    A: ApiTransport + 'static,
    D: DownloadTransport,
    U: UploadTransport,
{
    /// `session` is needed for uploads; `export_links` creates and prints a
    /// public link after every upload (`upload_public_links`). An upload
    /// entry with `"public_link": true` gets one either way.
    pub fn new(
        api: Arc<MegaApi<A>>,
        session: Option<Session>,
        store: Arc<Store>,
        downloader: Downloader<D>,
        uploader: Uploader<U>,
        export_links: bool,
    ) -> Self {
        Self {
            api,
            session,
            store,
            downloader,
            uploader,
            export_links,
        }
    }

    async fn download(&self, payload: Value, ctx: JobContext) -> JobOutcome {
        let file = match download_job(&payload) {
            Ok(file) => file,
            Err(error) => return permanent(error),
        };
        let destination = PathBuf::from(payload["destination"].as_str().unwrap_or_default());
        let progress = Arc::new(Progress::default());
        let ticker = {
            let (progress, mirror) = (progress.clone(), ctx.progress.clone());
            AbortOnDrop(tokio::spawn(async move {
                loop {
                    mirror.set(progress.done(), progress.total());
                    tokio::time::sleep(TICK).await;
                }
            }))
        };
        let urls = Arc::new(ApiUrlSource::new(self.api.clone(), file.link.clone()));
        let result = self
            .downloader
            .run(
                &file,
                &destination,
                urls,
                progress.clone(),
                ctx.cancel.clone(),
            )
            .await;
        stop(ticker).await;
        ctx.progress.set(progress.done(), progress.total());
        match result {
            Ok(path) => JobOutcome::Done {
                summary: format!("downloaded {}", path.display()),
            },
            Err(DownloadError::Cancelled) => JobOutcome::Cancelled,
            Err(e) => JobOutcome::Failed {
                retry_after: download_retry(&e),
                error: e.to_string(),
            },
        }
    }

    async fn upload(&self, payload: Value, ctx: JobContext) -> JobOutcome {
        let Some(session) = &self.session else {
            return permanent("uploads need an account: log in first".into());
        };
        let (Some(path), Some(parent)) = (payload["path"].as_str(), payload["parent"].as_str())
        else {
            return permanent("invalid upload entry: `path` and `parent` are required".into());
        };
        let export_link = self.export_links || payload["public_link"].as_bool() == Some(true);
        let progress = Arc::new(match UploadCheckpoint::from_json(&payload["checkpoint"]) {
            Some(checkpoint) => UploadProgress::resuming(checkpoint),
            None => UploadProgress::default(),
        });
        let ticker = {
            let (progress, mirror) = (progress.clone(), ctx.progress.clone());
            let (store, id) = (self.store.clone(), ctx.id);
            AbortOnDrop(tokio::spawn(async move {
                let mut saved = None;
                loop {
                    mirror.set(progress.done(), progress.total());
                    let checkpoint = progress.checkpoint();
                    if checkpoint != saved {
                        save_checkpoint(&store, id, checkpoint.as_ref());
                        saved = checkpoint;
                    }
                    tokio::time::sleep(TICK).await;
                }
            }))
        };
        let result = self
            .uploader
            .run(
                &self.api,
                session,
                std::path::Path::new(path),
                parent,
                progress.clone(),
                ctx.cancel.clone(),
            )
            .await;
        // Wait for the ticker to stop so it cannot overwrite the final save.
        stop(ticker).await;
        ctx.progress.set(progress.done(), progress.total());

        match result {
            Ok(uploaded) => {
                let mut summary = format!("uploaded {} ({})", uploaded.name, uploaded.handle);
                if export_link {
                    match crate::upload::export_link(&self.api, &uploaded.handle, &uploaded.key)
                        .await
                    {
                        Ok(link) => summary.push_str(&format!(" {}", link.to_url())),
                        Err(e) => summary.push_str(&format!(" (no public link: {e})")),
                    }
                }
                JobOutcome::Done { summary }
            }
            Err(e) => {
                // Keep the checkpoint for a resume, except when the upload
                // can only succeed by starting over.
                let checkpoint = match &e {
                    // These can only succeed by starting over with a new URL.
                    UploadError::NoCompletionToken => None,
                    UploadError::ChunkFailed {
                        status: Some(403 | 404 | 410),
                        ..
                    } => None,
                    _ => progress.checkpoint(),
                };
                save_checkpoint(&self.store, ctx.id, checkpoint.as_ref());
                match e {
                    UploadError::Cancelled => JobOutcome::Cancelled,
                    e => JobOutcome::Failed {
                        retry_after: upload_retry(&e),
                        error: e.to_string(),
                    },
                }
            }
        }
    }
}

impl<A, D, U> TransferRunner for MegaRunner<A, D, U>
where
    A: ApiTransport + 'static,
    D: DownloadTransport,
    U: UploadTransport,
{
    async fn run(&self, kind: QueueKind, payload: Value, ctx: JobContext) -> JobOutcome {
        match kind {
            QueueKind::Download => self.download(payload, ctx).await,
            QueueKind::Upload => self.upload(payload, ctx).await,
        }
    }
}

async fn stop<T>(task: AbortOnDrop<T>) {
    task.0.abort();
    let mut task = task;
    let _ = (&mut task.0).await;
}

fn permanent(error: String) -> JobOutcome {
    JobOutcome::Failed {
        error,
        retry_after: None,
    }
}

/// The remote file described by a download payload.
fn download_job(payload: &Value) -> Result<RemoteFile, String> {
    let link = payload["link"]
        .as_str()
        .and_then(|l| parse_link(l).ok())
        .ok_or_else(|| "invalid download entry: missing or malformed `link`".to_owned())?;
    let key = match &link {
        MegaLink::File { key, .. } | MegaLink::FolderNode { key, .. } => key.clone(),
        _ => return Err("download entries must point at a single file".into()),
    };
    if payload["destination"].as_str().is_none_or(str::is_empty) {
        return Err("invalid download entry: `destination` is required".into());
    }
    Ok(RemoteFile {
        name: payload["name"].as_str().unwrap_or_default().to_owned(),
        size: payload["size"].as_u64().unwrap_or(0),
        key,
        link,
    })
}

/// Writes (or clears) the checkpoint in the stored entry, keeping its other
/// fields (the stored payload is the source of truth).
fn save_checkpoint(store: &Store, id: i64, checkpoint: Option<&UploadCheckpoint>) {
    // Field-level updates: a concurrent pause or other change is kept. A
    // failed save only costs re-sending chunks on resume.
    let _ = match checkpoint {
        Some(checkpoint) => store.set_entry_field(id, "checkpoint", &checkpoint.to_json()),
        None => store.remove_entry_field(id, "checkpoint"),
    };
}

fn api_retry(error: &ApiError) -> Option<Duration> {
    match error {
        ApiError::Mega(ErrorCode::OverQuota | ErrorCode::RateLimit) => Some(RETRY_LATER),
        ApiError::Mega(code) if code.is_transient() => Some(RETRY_SOON),
        ApiError::Mega(
            ErrorCode::TempUnavailable | ErrorCode::TooManyConnections | ErrorCode::TooMany,
        ) => Some(RETRY_SOON),
        ApiError::Mega(_) | ApiError::Hashcash(_) => None,
        ApiError::Http(_) | ApiError::Transport(_) | ApiError::InvalidResponse(_) => {
            Some(RETRY_SOON)
        }
    }
}

fn download_retry(error: &DownloadError) -> Option<Duration> {
    match error {
        DownloadError::ChunkFailed {
            status: Some(509), ..
        } => Some(RETRY_LATER),
        DownloadError::ChunkFailed { .. } | DownloadError::Corrupted => Some(RETRY_SOON),
        DownloadError::Url(PublicError::Api(e)) => api_retry(e),
        DownloadError::Url(_)
        | DownloadError::DestinationExists(_)
        | DownloadError::Io(_)
        | DownloadError::Cancelled => None,
    }
}

fn upload_retry(error: &UploadError) -> Option<Duration> {
    match error {
        UploadError::Rejected(ErrorCode::OverQuota | ErrorCode::RateLimit) => Some(RETRY_LATER),
        UploadError::Api(e) => api_retry(e),
        UploadError::ChunkFailed {
            status: Some(509), ..
        } => Some(RETRY_LATER),
        UploadError::ChunkFailed { .. } | UploadError::NoCompletionToken => Some(RETRY_SOON),
        UploadError::Rejected(_)
        | UploadError::NotAFile(_)
        | UploadError::Malformed(_)
        | UploadError::Cancelled
        | UploadError::Io(_) => None,
    }
}
