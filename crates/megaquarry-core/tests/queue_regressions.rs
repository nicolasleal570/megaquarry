//! Regression probes from the independent verification of the scheduler.
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use megaquarry_core::queue::{
    self, JobContext, JobOutcome, QueueLimits, Scheduler, TransferRunner,
};
use megaquarry_core::store::{QueueKind, Store};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

#[derive(Default)]
struct R {
    store: Mutex<Option<Arc<Store>>>,
    script: Mutex<HashMap<String, Vec<JobOutcome>>>,
    started: Mutex<Vec<String>>,
    finished_after_drop: AtomicBool,
}

impl R {
    fn new(store: &Arc<Store>, script: &[(&str, Vec<JobOutcome>)]) -> Arc<Self> {
        Arc::new(Self {
            store: Mutex::new(Some(store.clone())),
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

impl TransferRunner for R {
    async fn run(&self, _kind: QueueKind, payload: Value, ctx: JobContext) -> JobOutcome {
        let name = payload["name"].as_str().unwrap().to_owned();
        self.started.lock().unwrap().push(name.clone());
        if payload["write"].as_bool() == Some(true) {
            let store = self.store.lock().unwrap().clone().unwrap();
            let mut p = store.entry(ctx.id).unwrap().unwrap().payload;
            p["checkpoint"] = json!({"saved": "by runner"});
            store.update_entry(ctx.id, &p).unwrap();
        }
        let ms = payload["ms"].as_u64().unwrap_or(10);
        let ignore_cancel = payload["ignore_cancel"].as_bool() == Some(true);
        let sleep = tokio::time::sleep(Duration::from_millis(ms));
        let outcome = if ignore_cancel {
            sleep.await;
            None
        } else {
            tokio::select! {
                () = sleep => None,
                () = ctx.cancel.cancelled() => Some(JobOutcome::Cancelled),
            }
        };
        if name == "leak" {
            self.finished_after_drop.store(true, Ordering::SeqCst);
        }
        outcome.unwrap_or_else(|| {
            let mut s = self.script.lock().unwrap();
            match s.get_mut(&name) {
                Some(l) if !l.is_empty() => l.remove(0),
                _ => JobOutcome::Done {
                    summary: "ok".into(),
                },
            }
        })
    }
}

fn job(name: &str, ms: u64, dest: &str) -> Value {
    json!({"name": name, "ms": ms, "destination": dest})
}

fn lim(d: usize, retries: u32) -> QueueLimits {
    QueueLimits {
        max_downloads: d,
        max_uploads: 1,
        max_auto_retries: retries,
    }
}

fn transient(ms: u64) -> JobOutcome {
    JobOutcome::Failed {
        error: "flaky".into(),
        retry_after: Some(Duration::from_millis(ms)),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn q1_entry_removed_by_someone_else_while_running() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    let a = store
        .enqueue(QueueKind::Download, &job("a", 100, "/a"))
        .unwrap();
    store
        .enqueue(QueueKind::Download, &job("b", 400, "/b"))
        .unwrap();
    let runner = R::new(&store, &[]);
    {
        let s = store.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            s.remove_entry(a).unwrap();
        });
    }
    let r = Scheduler::new(store.clone(), runner.clone(), lim(4, 2))
        .run(CancellationToken::new(), None)
        .await;
    assert!(r.is_ok(), "scheduler aborted: {r:?}");
    assert_eq!(r.unwrap().completed, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn q2_entry_removed_while_waiting_for_retry() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    let a = store
        .enqueue(QueueKind::Download, &job("a", 10, "/a"))
        .unwrap();
    let runner = R::new(&store, &[("a", vec![transient(300)])]);
    {
        let s = store.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            s.remove_entry(a).unwrap();
        });
    }
    let r = tokio::time::timeout(
        Duration::from_secs(3),
        Scheduler::new(store.clone(), runner.clone(), lim(4, 2))
            .run(CancellationToken::new(), None),
    )
    .await;
    assert!(
        r.is_ok(),
        "scheduler never returned after the waiting entry was removed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn q3_entry_paused_while_waiting_for_retry() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    let a = store
        .enqueue(QueueKind::Download, &job("a", 10, "/a"))
        .unwrap();
    let runner = R::new(&store, &[("a", vec![transient(300)])]);
    {
        let s = store.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            queue::pause(&s, a).unwrap();
        });
    }
    let r = tokio::time::timeout(
        Duration::from_secs(3),
        Scheduler::new(store.clone(), runner.clone(), lim(4, 2))
            .run(CancellationToken::new(), None),
    )
    .await;
    assert!(
        r.is_ok(),
        "scheduler never returned after the waiting entry was paused"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn q5_permanent_failure_keeps_runner_fields() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    let mut p = job("a", 10, "/a");
    p["write"] = json!(true);
    let a = store.enqueue(QueueKind::Upload, &p).unwrap();
    let runner = R::new(
        &store,
        &[(
            "a",
            vec![
                transient(5),
                JobOutcome::Failed {
                    error: "bad".into(),
                    retry_after: None,
                },
            ],
        )],
    );
    let r = Scheduler::new(store.clone(), runner.clone(), lim(4, 2))
        .run(CancellationToken::new(), None)
        .await
        .unwrap();
    assert_eq!(r.failed, 1);
    let e = store.entry(a).unwrap().unwrap().payload;
    assert_eq!(e["state"], json!("failed"));
    assert_eq!(e["error"], json!("bad"));
    assert_eq!(e["checkpoint"], json!({"saved": "by runner"}));
    assert_eq!(runner.started(), ["a", "a"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn q6_cancel_while_retry_pending_restarts_nothing() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    let a = store
        .enqueue(QueueKind::Download, &job("a", 10, "/a"))
        .unwrap();
    let b = store
        .enqueue(QueueKind::Download, &job("b", 5000, "/b"))
        .unwrap();
    let runner = R::new(&store, &[("a", vec![transient(200)])]);
    let cancel = CancellationToken::new();
    {
        let c = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(80)).await;
            c.cancel();
        });
    }
    let r = tokio::time::timeout(
        Duration::from_secs(3),
        Scheduler::new(store.clone(), runner.clone(), lim(4, 2)).run(cancel, None),
    )
    .await
    .unwrap()
    .unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(runner.started(), ["a", "b"]);
    assert_eq!(r.cancelled, 1);
    for id in [a, b] {
        assert!(
            store
                .entry(id)
                .unwrap()
                .unwrap()
                .payload
                .get("state")
                .is_none()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn q7_no_starvation_behind_paused_failed_or_busy_destination() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    let p = store
        .enqueue(QueueKind::Download, &job("paused", 10, "/p"))
        .unwrap();
    queue::pause(&store, p).unwrap();
    let mut f = job("failed", 10, "/f");
    f["state"] = json!("failed");
    store.enqueue(QueueKind::Download, &f).unwrap();
    store
        .enqueue(QueueKind::Download, &job("x1", 300, "/x"))
        .unwrap();
    store
        .enqueue(QueueKind::Download, &job("x2", 10, "/x"))
        .unwrap();
    store
        .enqueue(QueueKind::Download, &job("y", 10, "/y"))
        .unwrap();
    let runner = R::new(&store, &[]);
    let r = Scheduler::new(store.clone(), runner.clone(), lim(2, 2))
        .run(CancellationToken::new(), None)
        .await
        .unwrap();
    let started = runner.started();
    let position = |n: &str| started.iter().position(|s| s == n).unwrap();
    assert!(position("x2") > position("x1"), "{started:?}");
    assert!(!started.iter().any(|s| s == "paused" || s == "failed"));
    assert_eq!(r.completed, 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn q8_dropping_the_scheduler_leaves_no_job_running() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    let mut l = job("leak", 300, "/l");
    l["ignore_cancel"] = json!(false);
    store.enqueue(QueueKind::Download, &l).unwrap();
    let runner = R::new(&store, &[]);
    let sched = Scheduler::new(store.clone(), runner.clone(), lim(4, 2));
    let _ = tokio::time::timeout(
        Duration::from_millis(50),
        sched.run(CancellationToken::new(), None),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !runner.finished_after_drop.load(Ordering::SeqCst),
        "job kept running after the scheduler was dropped"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn q9_a_transient_failure_racing_a_cancel_stays_queued() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    let mut p = job("a", 150, "/a");
    p["ignore_cancel"] = json!(true);
    let a = store.enqueue(QueueKind::Download, &p).unwrap();
    let runner = R::new(&store, &[("a", vec![transient(5)])]);
    let cancel = CancellationToken::new();
    {
        let c = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            c.cancel();
        });
    }
    Scheduler::new(store.clone(), runner.clone(), lim(4, 2))
        .run(cancel, None)
        .await
        .unwrap();
    let e = store.entry(a).unwrap().unwrap().payload;
    assert!(e.get("state").is_none(), "{e}");
}

/// A due retry blocked by the concurrency limit must not spin. Under a
/// paused clock a spinning loop keeps the runtime busy, so time never
/// advances and the run never finishes; a watchdog thread detects that.
#[test]
fn q4_a_due_retry_blocked_by_the_limit_does_not_spin() {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap();
        let report = runtime.block_on(async {
            let store = Arc::new(Store::open_in_memory().unwrap());
            store
                .enqueue(QueueKind::Download, &job("a", 10, "/a"))
                .unwrap();
            store
                .enqueue(QueueKind::Download, &job("b", 1500, "/b"))
                .unwrap();
            let runner = R::new(&store, &[("a", vec![transient(20)])]);
            Scheduler::new(store, runner, lim(1, 2))
                .run(CancellationToken::new(), None)
                .await
                .unwrap()
        });
        let _ = tx.send(report.completed);
    });
    let completed = rx
        .recv_timeout(Duration::from_secs(20))
        .expect("the scheduler spun instead of waiting");
    assert_eq!(completed, 2);
}
