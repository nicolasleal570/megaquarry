use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use megaquarry_core::queue::{
    JobContext, JobOutcome, QueueEvent, QueueLimits, Scheduler, TransferRunner,
};
use megaquarry_core::store::{QueueKind, Store};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

/// Scripted runner: each job (by `name`) returns its outcomes in order and
/// takes `ms` milliseconds; tracks peak concurrency per kind.
#[derive(Default)]
struct FakeRunner {
    script: Mutex<HashMap<String, Vec<JobOutcome>>>,
    started: Mutex<Vec<String>>,
    running: [AtomicUsize; 2],
    peak: [AtomicUsize; 2],
}

impl FakeRunner {
    fn with(script: &[(&str, Vec<JobOutcome>)]) -> Arc<Self> {
        Arc::new(Self {
            script: Mutex::new(
                script
                    .iter()
                    .map(|(n, o)| (n.to_string(), o.clone()))
                    .collect(),
            ),
            ..Self::default()
        })
    }

    fn started(&self) -> Vec<String> {
        self.started.lock().unwrap().clone()
    }
}

fn slot(kind: QueueKind) -> usize {
    match kind {
        QueueKind::Download => 0,
        QueueKind::Upload => 1,
    }
}

impl TransferRunner for FakeRunner {
    async fn run(&self, kind: QueueKind, payload: Value, ctx: JobContext) -> JobOutcome {
        let name = payload["name"].as_str().unwrap().to_owned();
        self.started.lock().unwrap().push(name.clone());
        assert_ne!(name, "boom", "runner bug");
        let s = slot(kind);
        let now = self.running[s].fetch_add(1, Ordering::SeqCst) + 1;
        self.peak[s].fetch_max(now, Ordering::SeqCst);
        let ms = payload["ms"].as_u64().unwrap_or(10);
        let outcome = tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(ms)) => {
                let mut script = self.script.lock().unwrap();
                match script.get_mut(&name) {
                    Some(list) if !list.is_empty() => list.remove(0),
                    _ => JobOutcome::Done { summary: format!("{name} ok") },
                }
            }
            () = ctx.cancel.cancelled() => JobOutcome::Cancelled,
        };
        self.running[s].fetch_sub(1, Ordering::SeqCst);
        outcome
    }
}

fn job(name: &str, ms: u64) -> Value {
    json!({"name": name, "ms": ms, "destination": format!("/out/{name}")})
}

fn limits(downloads: usize, uploads: usize) -> QueueLimits {
    QueueLimits {
        max_downloads: downloads,
        max_uploads: uploads,
        max_auto_retries: 2,
    }
}

#[tokio::test(start_paused = true)]
async fn runs_jobs_in_order_within_the_concurrency_limits() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    for i in 0..5 {
        store
            .enqueue(QueueKind::Download, &job(&format!("d{i}"), 100))
            .unwrap();
    }
    for i in 0..3 {
        store
            .enqueue(QueueKind::Upload, &job(&format!("u{i}"), 100))
            .unwrap();
    }
    let runner = FakeRunner::with(&[]);
    let report = Scheduler::new(store.clone(), runner.clone(), limits(2, 1))
        .run(CancellationToken::new(), None)
        .await
        .unwrap();

    assert_eq!(report.completed, 8);
    assert_eq!(runner.peak[0].load(Ordering::SeqCst), 2);
    assert_eq!(runner.peak[1].load(Ordering::SeqCst), 1);
    let downloads: Vec<String> = runner
        .started()
        .into_iter()
        .filter(|n| n.starts_with('d'))
        .collect();
    assert_eq!(downloads, ["d0", "d1", "d2", "d3", "d4"]);
    assert!(store.entries(QueueKind::Download).unwrap().is_empty());
    assert!(store.entries(QueueKind::Upload).unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn retries_transient_failures_and_keeps_permanent_ones() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    store
        .enqueue(QueueKind::Download, &job("flaky", 10))
        .unwrap();
    store
        .enqueue(QueueKind::Download, &job("broken", 10))
        .unwrap();
    store
        .enqueue(QueueKind::Download, &job("hopeless", 10))
        .unwrap();
    let transient = || JobOutcome::Failed {
        error: "HTTP 500".into(),
        retry_after: Some(Duration::from_secs(3)),
    };
    let runner = FakeRunner::with(&[
        ("flaky", vec![transient(), transient()]),
        (
            "broken",
            vec![JobOutcome::Failed {
                error: "file not found".into(),
                retry_after: None,
            }],
        ),
        ("hopeless", vec![transient(), transient(), transient()]),
    ]);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let started = tokio::time::Instant::now();
    let report = Scheduler::new(store.clone(), runner.clone(), limits(4, 1))
        .run(CancellationToken::new(), Some(tx))
        .await
        .unwrap();

    assert_eq!((report.completed, report.failed), (1, 2));
    // Two 3 s waits before the flaky job's third attempt succeeds.
    assert!(started.elapsed() >= Duration::from_secs(6));
    let left = store.entries(QueueKind::Download).unwrap();
    assert_eq!(left.len(), 2);
    assert_eq!(left[0].payload["name"], json!("broken"));
    assert_eq!(left[0].payload["state"], json!("failed"));
    assert_eq!(left[0].payload["error"], json!("file not found"));
    assert_eq!(left[1].payload["state"], json!("failed"));

    let mut retrying = 0;
    while let Ok(event) = rx.try_recv() {
        if matches!(event, QueueEvent::Retrying { .. }) {
            retrying += 1;
        }
    }
    assert_eq!(retrying, 4, "flaky twice, hopeless twice");
}

#[tokio::test(start_paused = true)]
async fn skips_paused_and_failed_entries_until_requeued() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    let paused = store
        .enqueue(
            QueueKind::Download,
            &json!({"name": "p", "state": "paused"}),
        )
        .unwrap();
    store
        .enqueue(
            QueueKind::Download,
            &json!({"name": "f", "state": "failed", "error": "x"}),
        )
        .unwrap();
    let runner = FakeRunner::with(&[]);
    let scheduler = Scheduler::new(store.clone(), runner.clone(), limits(2, 1));
    let report = scheduler.run(CancellationToken::new(), None).await.unwrap();
    assert_eq!(report.completed, 0);
    assert!(runner.started().is_empty());

    megaquarry_core::queue::requeue(&store, paused).unwrap();
    megaquarry_core::queue::requeue_failed(&store).unwrap();
    let report = scheduler.run(CancellationToken::new(), None).await.unwrap();
    assert_eq!(report.completed, 2);
    assert!(store.entries(QueueKind::Download).unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn cancellation_stops_running_jobs_and_keeps_them_queued() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    for i in 0..3 {
        store
            .enqueue(QueueKind::Download, &job(&format!("d{i}"), 10_000))
            .unwrap();
    }
    let runner = FakeRunner::with(&[]);
    let cancel = CancellationToken::new();
    {
        let cancel = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            cancel.cancel();
        });
    }
    let report = Scheduler::new(store.clone(), runner.clone(), limits(2, 1))
        .run(cancel, None)
        .await
        .unwrap();
    assert_eq!(report.cancelled, 2);
    assert_eq!(runner.started().len(), 2, "the third never started");
    let left = store.entries(QueueKind::Download).unwrap();
    assert_eq!(left.len(), 3);
    assert!(left.iter().all(|e| e.payload.get("state").is_none()));
}

#[tokio::test(start_paused = true)]
async fn never_runs_two_downloads_to_the_same_destination_at_once() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    let same = json!({"name": "a", "ms": 100, "destination": "/out/same"});
    let also = json!({"name": "b", "ms": 100, "destination": "/out/same"});
    store.enqueue(QueueKind::Download, &same).unwrap();
    store.enqueue(QueueKind::Download, &also).unwrap();
    store.enqueue(QueueKind::Download, &job("c", 100)).unwrap();
    let runner = FakeRunner::with(&[]);
    let report = Scheduler::new(store.clone(), runner.clone(), limits(3, 1))
        .run(CancellationToken::new(), None)
        .await
        .unwrap();
    assert_eq!(report.completed, 3);
    // `a` and `c` overlap, `b` waits for `a`.
    assert_eq!(runner.peak[0].load(Ordering::SeqCst), 2);
    assert_eq!(runner.started(), ["a", "c", "b"]);
}

#[tokio::test(start_paused = true)]
async fn reports_progress_events() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    let id = store.enqueue(QueueKind::Upload, &job("u", 10)).unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    Scheduler::new(store, FakeRunner::with(&[]), limits(1, 1))
        .run(CancellationToken::new(), Some(tx))
        .await
        .unwrap();
    let events: Vec<QueueEvent> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    assert!(matches!(events[0], QueueEvent::Started { id: i, kind: QueueKind::Upload } if i == id));
    assert!(
        matches!(&events[1], QueueEvent::Finished { id: i, summary } if *i == id && summary == "u ok")
    );
}

#[tokio::test(start_paused = true)]
async fn a_panicking_runner_marks_the_entry_failed() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    store
        .enqueue(QueueKind::Download, &job("boom", 10))
        .unwrap();
    store
        .enqueue(QueueKind::Download, &job("fine", 10))
        .unwrap();
    let report = Scheduler::new(store.clone(), FakeRunner::with(&[]), limits(2, 1))
        .run(CancellationToken::new(), None)
        .await
        .unwrap();
    assert_eq!((report.completed, report.failed), (1, 1));
    let left = store.entries(QueueKind::Download).unwrap();
    assert_eq!(left[0].payload["state"], json!("failed"));
    assert!(
        left[0].payload["error"]
            .as_str()
            .unwrap()
            .starts_with("internal error")
    );
}
