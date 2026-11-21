//! The transfer queue: runs persisted downloads and uploads in order.
//!
//! Entries live in the store (`transfers` table) as JSON payloads. The
//! scheduler starts them FIFO within per-kind concurrency limits
//! (default 4 + 4), never runs two downloads to the same destination at once,
//! retries transient failures after a delay (3 s, 60 s on quota) and
//! keeps cancelled entries queued so a later run resumes them.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::store::{QueueKind, Store, StoreError};

mod runner;

pub use runner::MegaRunner;

/// Payload `state` of an entry the scheduler must not start.
const PAUSED: &str = "paused";
const FAILED: &str = "failed";

/// Concurrency and retry limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueLimits {
    pub max_downloads: usize,
    pub max_uploads: usize,
    /// Automatic retries of a transient failure before giving up.
    pub max_auto_retries: u32,
}

impl Default for QueueLimits {
    fn default() -> Self {
        Self {
            max_downloads: 4,
            max_uploads: 4,
            max_auto_retries: 3,
        }
    }
}

/// How one run of a job ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobOutcome {
    Done {
        summary: String,
    },
    /// `retry_after` is `Some` for transient failures worth retrying.
    Failed {
        error: String,
        retry_after: Option<Duration>,
    },
    Cancelled,
}

/// Byte counters a runner updates while a job runs.
#[derive(Debug, Default)]
pub struct JobProgress {
    done: AtomicU64,
    total: AtomicU64,
}

impl JobProgress {
    pub fn set(&self, done: u64, total: u64) {
        self.done.store(done, Ordering::Relaxed);
        self.total.store(total, Ordering::Relaxed);
    }

    pub fn done(&self) -> u64 {
        self.done.load(Ordering::Relaxed)
    }

    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }
}

/// What a runner gets for one job.
#[derive(Debug, Clone)]
pub struct JobContext {
    pub id: i64,
    pub cancel: CancellationToken,
    pub progress: Arc<JobProgress>,
}

/// Port: executes one queue entry (the real one drives the engines).
pub trait TransferRunner: Send + Sync + 'static {
    fn run(
        &self,
        kind: QueueKind,
        payload: Value,
        ctx: JobContext,
    ) -> impl Future<Output = JobOutcome> + Send;
}

/// Notifications for a user interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueEvent {
    Started {
        id: i64,
        kind: QueueKind,
    },
    Finished {
        id: i64,
        summary: String,
    },
    Retrying {
        id: i64,
        error: String,
        after: Duration,
    },
    Failed {
        id: i64,
        error: String,
    },
    Cancelled {
        id: i64,
    },
}

/// Totals of one scheduler run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Report {
    pub completed: usize,
    pub failed: usize,
    pub cancelled: usize,
}

/// Runs the queue with a [`TransferRunner`].
pub struct Scheduler<R> {
    store: Arc<Store>,
    runner: Arc<R>,
    limits: QueueLimits,
    kinds: Vec<QueueKind>,
    progress: std::sync::Mutex<HashMap<i64, Arc<JobProgress>>>,
}

struct Running {
    kind: QueueKind,
    destination: Option<String>,
}

impl<R: TransferRunner> Scheduler<R> {
    pub fn new(store: Arc<Store>, runner: Arc<R>, limits: QueueLimits) -> Self {
        Self {
            store,
            runner,
            limits,
            kinds: vec![QueueKind::Download, QueueKind::Upload],
            progress: std::sync::Mutex::default(),
        }
    }

    /// Runs only entries of these kinds (others stay queued untouched).
    pub fn only(mut self, kinds: &[QueueKind]) -> Self {
        self.kinds = kinds.to_vec();
        self
    }

    /// `(id, done, total)` of every running job.
    pub fn progress(&self) -> Vec<(i64, u64, u64)> {
        let mut all: Vec<_> = self
            .progress
            .lock()
            .expect("lock")
            .iter()
            .map(|(id, p)| (*id, p.done(), p.total()))
            .collect();
        all.sort_unstable();
        all
    }

    /// Runs queued entries until none is left to start, or until `cancel`.
    pub async fn run(
        &self,
        cancel: CancellationToken,
        events: Option<UnboundedSender<QueueEvent>>,
    ) -> Result<Report, StoreError> {
        let emit = |event: QueueEvent| {
            if let Some(tx) = &events {
                let _ = tx.send(event);
            }
        };
        let mut report = Report::default();
        let mut tasks: JoinSet<(i64, JobOutcome)> = JoinSet::new();
        let mut running: HashMap<i64, Running> = HashMap::new();
        let mut attempts: HashMap<i64, u32> = HashMap::new();
        let mut waiting: HashMap<i64, Instant> = HashMap::new();

        loop {
            if !cancel.is_cancelled() {
                for kind in self.kinds.clone() {
                    self.start_ready(kind, &cancel, &mut tasks, &mut running, &mut waiting, &emit)?;
                }
            }
            // Forget retries of entries that were removed, paused or failed
            // meanwhile; they would otherwise keep the loop alive forever.
            self.prune_waiting(&mut waiting)?;
            if tasks.is_empty() && (waiting.is_empty() || cancel.is_cancelled()) {
                break;
            }
            // Only future deadlines can wake the loop: an entry that is due but
            // blocked (limit or busy destination) starts when a running job
            // ends, which `join_next` reports. A past deadline would spin.
            let now = Instant::now();
            let next_retry = waiting.values().filter(|at| **at > now).min().copied();
            tokio::select! {
                Some(joined) = tasks.join_next() => {
                    let (id, outcome) = joined.expect("job tasks catch their own panics");
                    running.remove(&id);
                    self.progress.lock().expect("lock").remove(&id);
                    match outcome {
                        JobOutcome::Done { summary } => {
                            // Someone may have removed the entry meanwhile.
                            match self.store.remove_entry(id) {
                                Ok(()) | Err(StoreError::NotFound) => {}
                                Err(e) => return Err(e),
                            }
                            report.completed += 1;
                            emit(QueueEvent::Finished { id, summary });
                        }
                        JobOutcome::Cancelled => {
                            report.cancelled += 1;
                            emit(QueueEvent::Cancelled { id });
                        }
                        JobOutcome::Failed { error, retry_after } => {
                            let tries = attempts.entry(id).or_insert(0);
                            match retry_after {
                                // Stopped by the user while failing: keep it
                                // queued rather than marking it failed.
                                Some(_) if cancel.is_cancelled() => {
                                    report.cancelled += 1;
                                    emit(QueueEvent::Cancelled { id });
                                }
                                Some(after)
                                    if *tries < self.limits.max_auto_retries
                                        && !cancel.is_cancelled() =>
                                {
                                    *tries += 1;
                                    waiting.insert(id, Instant::now() + after);
                                    emit(QueueEvent::Retrying { id, error, after });
                                }
                                _ => {
                                    self.mark(id, FAILED, Some(&error))?;
                                    report.failed += 1;
                                    emit(QueueEvent::Failed { id, error });
                                }
                            }
                        }
                    }
                }
                () = sleep_until(next_retry), if next_retry.is_some() => {}
                () = cancel.cancelled(), if !cancel.is_cancelled() => {}
            }
        }
        Ok(report)
    }

    fn prune_waiting(&self, waiting: &mut HashMap<i64, Instant>) -> Result<(), StoreError> {
        let mut gone = Vec::new();
        for id in waiting.keys() {
            let runnable = self
                .store
                .entry(*id)?
                .is_some_and(|e| !matches!(e.payload["state"].as_str(), Some(PAUSED | FAILED)));
            if !runnable {
                gone.push(*id);
            }
        }
        for id in gone {
            waiting.remove(&id);
        }
        Ok(())
    }

    fn start_ready(
        &self,
        kind: QueueKind,
        cancel: &CancellationToken,
        tasks: &mut JoinSet<(i64, JobOutcome)>,
        running: &mut HashMap<i64, Running>,
        waiting: &mut HashMap<i64, Instant>,
        emit: &impl Fn(QueueEvent),
    ) -> Result<(), StoreError> {
        let limit = match kind {
            QueueKind::Download => self.limits.max_downloads,
            QueueKind::Upload => self.limits.max_uploads,
        }
        .max(1);
        let now = Instant::now();
        let busy: HashSet<String> = running
            .values()
            .filter_map(|r| r.destination.clone())
            .collect();
        let mut busy = busy;

        for entry in self.store.entries(kind)? {
            if running.values().filter(|r| r.kind == kind).count() >= limit {
                break;
            }
            let state = entry.payload["state"].as_str();
            if running.contains_key(&entry.id)
                || matches!(state, Some(PAUSED | FAILED))
                || waiting.get(&entry.id).is_some_and(|at| *at > now)
            {
                continue;
            }
            let destination = (kind == QueueKind::Download)
                .then(|| entry.payload["destination"].as_str().map(str::to_owned))
                .flatten();
            if destination.as_ref().is_some_and(|d| busy.contains(d)) {
                continue;
            }
            if let Some(d) = &destination {
                busy.insert(d.clone());
            }
            waiting.remove(&entry.id);

            let progress = Arc::new(JobProgress::default());
            self.progress
                .lock()
                .expect("lock")
                .insert(entry.id, progress.clone());
            let ctx = JobContext {
                id: entry.id,
                cancel: cancel.child_token(),
                progress,
            };
            let runner = self.runner.clone();
            let id = entry.id;
            tasks.spawn(async move {
                // The inner task isolates a panicking runner so the entry is
                // reported as failed instead of being lost; the guard aborts
                // it when the scheduler (and so this task) is dropped.
                let mut job = AbortOnDrop(tokio::spawn(async move {
                    runner.run(kind, entry.payload, ctx).await
                }));
                let outcome = (&mut job.0).await.unwrap_or_else(|e| JobOutcome::Failed {
                    error: format!("internal error: {e}"),
                    retry_after: None,
                });
                (id, outcome)
            });
            running.insert(id, Running { kind, destination });
            emit(QueueEvent::Started { id, kind });
        }
        Ok(())
    }

    /// Sets `state` (and `error`) on the stored payload, keeping the rest.
    fn mark(&self, id: i64, state: &str, error: Option<&str>) -> Result<(), StoreError> {
        let result = self
            .store
            .set_entry_field(id, "state", &json!(state))
            .and_then(|()| match error {
                Some(error) => self.store.set_entry_field(id, "error", &json!(error)),
                None => Ok(()),
            });
        match result {
            // Removed meanwhile: nothing left to mark.
            Ok(()) | Err(StoreError::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// Aborts a spawned task when dropped.
pub(crate) struct AbortOnDrop<T>(pub(crate) tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn sleep_until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// Clears `paused`/`failed` from an entry so the next run starts it.
pub fn requeue(store: &Store, id: i64) -> Result<(), StoreError> {
    store.remove_entry_field(id, "state")?;
    store.remove_entry_field(id, "error")
}

/// Requeues every failed entry of both queues.
pub fn requeue_failed(store: &Store) -> Result<usize, StoreError> {
    let mut count = 0;
    for kind in [QueueKind::Download, QueueKind::Upload] {
        for entry in store.entries(kind)? {
            if entry.payload["state"].as_str() == Some(FAILED) {
                requeue(store, entry.id)?;
                count += 1;
            }
        }
    }
    Ok(count)
}

/// Marks an entry paused so the scheduler skips it.
pub fn pause(store: &Store, id: i64) -> Result<(), StoreError> {
    store.set_entry_field(id, "state", &json!(PAUSED))
}
