//! Exit IP rotation: cooldowns, reconnects, attempts and deduplication.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use megaquarry_core::egress::{
    ControlError, QuotaRotation, RotateError, RotationEvent, RotationOptions, Rotator, VpnControl,
    VpnStatus,
};
use megaquarry_core::store::Store;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

/// A scripted gluetun: each reconnect takes the next entry of `next`;
/// `None` means that tunnel never comes up.
struct FakeControl {
    state: Mutex<State>,
}

struct State {
    running: bool,
    ip: Option<String>,
    next: VecDeque<Option<String>>,
    /// Status polls that still report an empty IP after a start (gluetun
    /// says `running` before the tunnel is up).
    empty_polls: u32,
    empty_polls_after_start: u32,
    calls: Vec<&'static str>,
    fail: bool,
    /// Public IP requests received.
    ip_reads: u32,
}

impl FakeControl {
    fn new(ip: Option<&str>, next: &[Option<&str>]) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                running: ip.is_some(),
                ip: ip.map(str::to_owned),
                next: next.iter().map(|ip| ip.map(str::to_owned)).collect(),
                empty_polls: 0,
                empty_polls_after_start: 0,
                calls: Vec::new(),
                fail: false,
                ip_reads: 0,
            }),
        })
    }

    fn calls(&self) -> Vec<&'static str> {
        self.state.lock().unwrap().calls.clone()
    }
}

impl VpnControl for FakeControl {
    async fn status(&self) -> Result<VpnStatus, ControlError> {
        let s = self.state.lock().unwrap();
        if s.fail {
            return Err(ControlError("connection refused".into()));
        }
        Ok(if s.running {
            VpnStatus::Running
        } else {
            VpnStatus::Stopped
        })
    }

    async fn set_running(&self, running: bool) -> Result<(), ControlError> {
        let mut s = self.state.lock().unwrap();
        if s.fail {
            return Err(ControlError("connection refused".into()));
        }
        s.calls.push(if running { "run" } else { "stop" });
        s.running = running;
        if running {
            s.ip = s.next.pop_front().flatten();
            s.empty_polls = s.empty_polls_after_start;
        } else {
            s.ip = None;
        }
        Ok(())
    }

    async fn public_ip(&self) -> Result<Option<String>, ControlError> {
        let mut s = self.state.lock().unwrap();
        s.ip_reads += 1;
        if s.fail {
            return Err(ControlError("connection refused".into()));
        }
        if s.empty_polls > 0 {
            s.empty_polls -= 1;
            return Ok(None);
        }
        Ok(if s.running { s.ip.clone() } else { None })
    }
}

fn options() -> RotationOptions {
    RotationOptions {
        fallback_cooldown: Duration::from_secs(3600),
        max_attempts: 5,
        reconnect_timeout: Duration::from_secs(90),
        poll_interval: Duration::from_secs(1),
        retry_wait: Duration::from_secs(60),
    }
}

fn rotator(
    control: &Arc<FakeControl>,
    store: &Arc<Store>,
) -> (
    Arc<Rotator<Arc<FakeControl>>>,
    UnboundedReceiver<RotationEvent>,
) {
    let (tx, rx) = unbounded_channel();
    let rotator = Rotator::new(control.clone(), store.clone(), options()).with_events(tx);
    (Arc::new(rotator), rx)
}

fn store() -> Arc<Store> {
    Arc::new(Store::open_in_memory().unwrap())
}

fn events(rx: &mut UnboundedReceiver<RotationEvent>) -> Vec<RotationEvent> {
    let mut all = Vec::new();
    while let Ok(event) = rx.try_recv() {
        all.push(event);
    }
    all
}

/// Seconds from now until `until` (negative when past).
fn secs_left(until: SystemTime) -> i64 {
    match until.duration_since(SystemTime::now()) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

#[tokio::test(start_paused = true)]
async fn rotation_cools_the_current_ip_for_megas_wait_and_reconnects() {
    let control = FakeControl::new(Some("1.1.1.1"), &[Some("2.2.2.2")]);
    let store = store();
    let (rotator, mut rx) = rotator(&control, &store);

    rotator
        .rotate(0, Some(Duration::from_secs(120)))
        .await
        .unwrap();

    assert_eq!(control.calls(), ["stop", "run"]);
    assert_eq!(rotator.generation(), 1);
    let until = store
        .ip_cooling_until("1.1.1.1", SystemTime::now())
        .unwrap()
        .unwrap();
    assert!((100..=121).contains(&secs_left(until)), "{until:?}");
    assert_eq!(
        store
            .ip_cooling_until("2.2.2.2", SystemTime::now())
            .unwrap(),
        None
    );
    assert_eq!(
        events(&mut rx),
        [
            RotationEvent::QuotaHit {
                ip: Some("1.1.1.1".into()),
                cooldown: Duration::from_secs(120),
            },
            RotationEvent::Rotated {
                ip: "2.2.2.2".into(),
                cooling: 1,
            },
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn without_megas_wait_the_fallback_cooldown_applies() {
    let control = FakeControl::new(Some("1.1.1.1"), &[Some("2.2.2.2")]);
    let store = store();
    let (rotator, _rx) = rotator(&control, &store);

    rotator.rotate(0, None).await.unwrap();

    let until = store
        .ip_cooling_until("1.1.1.1", SystemTime::now())
        .unwrap()
        .unwrap();
    assert!((3500..=3601).contains(&secs_left(until)), "{until:?}");
}

#[tokio::test(start_paused = true)]
async fn cooling_ips_are_skipped_with_another_reconnect() {
    let control = FakeControl::new(Some("1.1.1.1"), &[Some("3.3.3.3"), Some("4.4.4.4")]);
    let store = store();
    let hour = SystemTime::now() + Duration::from_secs(3600);
    store.cool_down_ip("3.3.3.3", hour).unwrap();
    let (rotator, mut rx) = rotator(&control, &store);

    rotator.rotate(0, None).await.unwrap();

    assert_eq!(control.calls(), ["stop", "run", "stop", "run"]);
    let events = events(&mut rx);
    assert!(events.contains(&RotationEvent::SkippedCooling {
        ip: "3.3.3.3".into()
    }));
    assert_eq!(
        events.last(),
        Some(&RotationEvent::Rotated {
            ip: "4.4.4.4".into(),
            cooling: 2,
        })
    );
}

#[tokio::test(start_paused = true)]
async fn gives_up_after_the_attempt_limit_when_every_ip_is_cooling() {
    let next: Vec<Option<&str>> = vec![Some("9.9.9.9"); 10];
    let control = FakeControl::new(Some("1.1.1.1"), &next);
    let store = store();
    store
        .cool_down_ip("9.9.9.9", SystemTime::now() + Duration::from_secs(60))
        .unwrap();
    let (rotator, mut rx) = rotator(&control, &store);

    let result = rotator.rotate(0, None).await;

    assert_eq!(result, Err(RotateError::Exhausted));
    assert_eq!(control.calls().len(), 10, "5 reconnects of stop + run");
    assert_eq!(rotator.generation(), 1, "the tunnel did change");
    assert_eq!(
        events(&mut rx).last(),
        Some(&RotationEvent::Exhausted { cooling: 2 })
    );
}

#[tokio::test(start_paused = true)]
async fn waits_for_a_non_empty_ip_after_gluetun_reports_running() {
    let control = FakeControl::new(Some("1.1.1.1"), &[Some("2.2.2.2")]);
    control.state.lock().unwrap().empty_polls_after_start = 3;
    let store = store();
    let (rotator, mut rx) = rotator(&control, &store);

    rotator.rotate(0, None).await.unwrap();

    assert_eq!(
        events(&mut rx).last(),
        Some(&RotationEvent::Rotated {
            ip: "2.2.2.2".into(),
            cooling: 1,
        })
    );
}

#[tokio::test(start_paused = true)]
async fn a_tunnel_that_never_comes_up_counts_as_one_attempt() {
    let control = FakeControl::new(Some("1.1.1.1"), &[None, Some("2.2.2.2")]);
    let store = store();
    let (rotator, mut rx) = rotator(&control, &store);
    let started = tokio::time::Instant::now();

    rotator.rotate(0, None).await.unwrap();

    assert!(started.elapsed() >= Duration::from_secs(90));
    assert_eq!(control.calls(), ["stop", "run", "stop", "run"]);
    assert_eq!(
        events(&mut rx).last(),
        Some(&RotationEvent::Rotated {
            ip: "2.2.2.2".into(),
            cooling: 1,
        })
    );
}

#[tokio::test(start_paused = true)]
async fn only_timeouts_end_as_unavailable() {
    let control = FakeControl::new(Some("1.1.1.1"), &[None; 5]);
    let store = store();
    let (rotator, _rx) = rotator(&control, &store);

    let result = rotator.rotate(0, None).await;

    assert!(
        matches!(result, Err(RotateError::Unavailable(_))),
        "{result:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn concurrent_quota_hits_share_one_rotation() {
    let control = FakeControl::new(Some("1.1.1.1"), &[Some("2.2.2.2"), Some("3.3.3.3")]);
    let store = store();
    let (rotator, _rx) = rotator(&control, &store);

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let rotator = rotator.clone();
        tasks.push(tokio::spawn(async move { rotator.rotate(0, None).await }));
    }
    for task in tasks {
        task.await.unwrap().unwrap();
    }

    assert_eq!(control.calls(), ["stop", "run"]);
    assert_eq!(rotator.generation(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_request_that_saw_an_older_generation_does_not_rotate_again() {
    let control = FakeControl::new(Some("1.1.1.1"), &[Some("2.2.2.2"), Some("3.3.3.3")]);
    let store = store();
    let (rotator, _rx) = rotator(&control, &store);
    rotator.rotate(0, None).await.unwrap();

    rotator.rotate(0, None).await.unwrap();

    assert_eq!(control.calls(), ["stop", "run"]);
    assert_eq!(
        store
            .ip_cooling_until("2.2.2.2", SystemTime::now())
            .unwrap(),
        None
    );
}

#[tokio::test(start_paused = true)]
async fn an_unreachable_control_is_unavailable_and_changes_nothing() {
    let control = FakeControl::new(Some("1.1.1.1"), &[Some("2.2.2.2")]);
    control.state.lock().unwrap().fail = true;
    let store = store();
    let (rotator, mut rx) = rotator(&control, &store);

    let result = rotator.rotate(0, None).await;

    assert!(
        matches!(result, Err(RotateError::Unavailable(_))),
        "{result:?}"
    );
    assert_eq!(rotator.generation(), 0);
    assert!(matches!(
        events(&mut rx).last(),
        Some(RotationEvent::Unavailable { .. })
    ));
}

#[tokio::test(start_paused = true)]
async fn wait_ready_returns_once_a_rotation_ends() {
    let control = FakeControl::new(Some("1.1.1.1"), &[Some("2.2.2.2")]);
    control.state.lock().unwrap().empty_polls_after_start = 5;
    let store = store();
    let (rotator, _rx) = rotator(&control, &store);
    let rotating = {
        let rotator = rotator.clone();
        tokio::spawn(async move { rotator.rotate(0, None).await })
    };
    tokio::task::yield_now().await;

    rotator.wait_ready().await;

    assert_eq!(rotator.generation(), 1);
    rotating.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn prepare_keeps_a_fresh_ip_without_reconnecting() {
    let control = FakeControl::new(Some("1.1.1.1"), &[]);
    let store = store();
    let (rotator, _rx) = rotator(&control, &store);

    assert_eq!(rotator.prepare().await.unwrap(), "1.1.1.1");
    assert!(control.calls().is_empty());
    assert_eq!(rotator.generation(), 0);
}

#[tokio::test(start_paused = true)]
async fn prepare_rotates_away_from_a_cooling_ip() {
    let control = FakeControl::new(Some("1.1.1.1"), &[Some("2.2.2.2")]);
    let store = store();
    store
        .cool_down_ip("1.1.1.1", SystemTime::now() + Duration::from_secs(600))
        .unwrap();
    let (rotator, _rx) = rotator(&control, &store);

    assert_eq!(rotator.prepare().await.unwrap(), "2.2.2.2");
    assert_eq!(control.calls(), ["stop", "run"]);
}

#[tokio::test(start_paused = true)]
async fn prepare_fails_when_the_tunnel_is_not_up_in_time() {
    let control = FakeControl::new(None, &[]);
    let store = store();
    let (rotator, _rx) = rotator(&control, &store);

    let result = rotator.prepare().await;

    assert!(
        matches!(result, Err(RotateError::Unavailable(_))),
        "{result:?}"
    );
    // A stopped VPN is started once, then waited for.
    assert_eq!(control.calls(), ["run"]);
}

#[test]
fn cooldowns_persist_keep_the_later_end_and_expire() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    let now = SystemTime::now();
    {
        let store = Store::open(&path).unwrap();
        store
            .cool_down_ip("1.1.1.1", now + Duration::from_secs(600))
            .unwrap();
        // A shorter wait never shortens an existing cooldown.
        store
            .cool_down_ip("1.1.1.1", now + Duration::from_secs(60))
            .unwrap();
        store
            .cool_down_ip("2.2.2.2", now - Duration::from_secs(1))
            .unwrap();
    }
    let store = Store::open(&path).unwrap();
    let until = store.ip_cooling_until("1.1.1.1", now).unwrap().unwrap();
    assert!((590..=601).contains(&secs_left(until)));
    assert_eq!(store.ip_cooling_until("2.2.2.2", now).unwrap(), None);
    assert_eq!(store.cooling_ips(now).unwrap(), 1);
    assert_eq!(store.prune_cooldowns(now).unwrap(), 1);
    assert_eq!(store.cooling_ips(now).unwrap(), 1);
    drop(store);
    // The table is added without a schema bump, so older builds still open it.
    let conn = rusqlite::Connection::open(&path).unwrap();
    let version: i64 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(version, 1);
}

// Regression test from the independent verification (B2).

/// gluetun-like: a stop applies at once on the server, but its reply comes
/// only after OpenVPN exits; a client that goes away does not undo it. Each
/// start gets a new exit IP.
struct SlowStop {
    running: Mutex<bool>,
    starts: Mutex<u32>,
}

impl VpnControl for SlowStop {
    async fn status(&self) -> Result<VpnStatus, ControlError> {
        Ok(if *self.running.lock().unwrap() {
            VpnStatus::Running
        } else {
            VpnStatus::Stopped
        })
    }

    async fn set_running(&self, running: bool) -> Result<(), ControlError> {
        *self.running.lock().unwrap() = running;
        if running {
            *self.starts.lock().unwrap() += 1;
        } else {
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        Ok(())
    }

    async fn public_ip(&self) -> Result<Option<String>, ControlError> {
        let starts = *self.starts.lock().unwrap();
        Ok(self
            .running
            .lock()
            .unwrap()
            .then(|| format!("1.1.1.{}", starts + 1)))
    }
}

#[tokio::test(start_paused = true)]
async fn a_rotation_cancelled_between_stop_and_start_does_not_block_the_next_start() {
    let control = Arc::new(SlowStop {
        running: Mutex::new(true),
        starts: Mutex::new(0),
    });
    let store = store();
    let rotator = Rotator::new(control.clone(), store.clone(), options());
    // Ctrl-C one second into the rotation.
    let _ = tokio::time::timeout(Duration::from_secs(1), rotator.rotate(0, None)).await;
    assert!(
        !*control.running.lock().unwrap(),
        "gluetun was left stopped"
    );

    let next = Rotator::new(control.clone(), store, options());
    assert_eq!(next.prepare().await.unwrap(), "1.1.1.2");
}

#[tokio::test(start_paused = true)]
async fn the_tunnel_check_needs_a_running_vpn_with_an_ip() {
    let control = FakeControl::new(Some("1.1.1.1"), &[]);
    let store = store();
    let (rotator, _rx) = rotator(&control, &store);
    assert!(rotator.tunnel_up().await);

    control.state.lock().unwrap().running = false;
    assert!(!rotator.tunnel_up().await);

    control.state.lock().unwrap().fail = true;
    assert!(!rotator.tunnel_up().await);
}

#[tokio::test(start_paused = true)]
async fn callers_covered_by_a_failed_rotation_get_its_failure() {
    let next: Vec<Option<&str>> = vec![Some("9.9.9.9"); 10];
    let control = FakeControl::new(Some("1.1.1.1"), &next);
    let store = store();
    store
        .cool_down_ip("9.9.9.9", SystemTime::now() + Duration::from_secs(600))
        .unwrap();
    let (rotator, _rx) = rotator(&control, &store);

    let mut tasks = Vec::new();
    for _ in 0..4 {
        let rotator = rotator.clone();
        tasks.push(tokio::spawn(async move { rotator.rotate(0, None).await }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap(), Err(RotateError::Exhausted));
    }
    assert_eq!(control.calls().len(), 10, "one rotation of 5 reconnects");
}

#[tokio::test(start_paused = true)]
async fn no_new_rotation_starts_within_a_minute_of_a_failure() {
    let next: Vec<Option<&str>> = vec![Some("9.9.9.9"); 5];
    let control = FakeControl::new(Some("1.1.1.1"), &[&next[..], &[Some("2.2.2.2")]].concat());
    let store = store();
    store
        .cool_down_ip("9.9.9.9", SystemTime::now() + Duration::from_secs(3600))
        .unwrap();
    let (rotator, _rx) = rotator(&control, &store);
    assert_eq!(rotator.rotate(0, None).await, Err(RotateError::Exhausted));
    let generation = rotator.generation();

    // A request that saw the new generation hits the quota again at once.
    assert_eq!(
        rotator.rotate(generation, None).await,
        Err(RotateError::Exhausted)
    );
    assert_eq!(
        control.calls().len(),
        10,
        "no reconnect in the quiet minute"
    );
    assert_eq!(rotator.generation(), generation);

    tokio::time::advance(Duration::from_secs(61)).await;
    rotator.rotate(generation, None).await.unwrap();
    assert_eq!(control.calls().len(), 12);
}

// Regressions from the native review.

#[tokio::test(start_paused = true)]
async fn an_absurd_wait_from_mega_is_capped_instead_of_crashing() {
    let control = FakeControl::new(Some("1.1.1.1"), &[Some("2.2.2.2")]);
    let store = store();
    let (rotator, mut rx) = rotator(&control, &store);

    rotator
        .rotate(0, Some(Duration::from_secs(u64::MAX)))
        .await
        .unwrap();

    let until = store
        .ip_cooling_until("1.1.1.1", SystemTime::now())
        .unwrap()
        .unwrap();
    assert!(secs_left(until) <= 24 * 3600, "{until:?}");
    assert!(matches!(
        events(&mut rx).first(),
        Some(RotationEvent::QuotaHit { cooldown, .. }) if *cooldown == Duration::from_secs(24 * 3600)
    ));
}

#[tokio::test(start_paused = true)]
async fn an_unreachable_control_is_not_asked_again_within_a_minute() {
    let control = FakeControl::new(Some("1.1.1.1"), &[Some("2.2.2.2")]);
    control.state.lock().unwrap().fail = true;
    let store = store();
    let (rotator, _rx) = rotator(&control, &store);

    for _ in 0..4 {
        assert!(matches!(
            rotator.rotate(0, None).await,
            Err(RotateError::Unavailable(_))
        ));
    }
    assert_eq!(control.state.lock().unwrap().ip_reads, 1);

    tokio::time::advance(Duration::from_secs(61)).await;
    let _ = rotator.rotate(0, None).await;
    assert_eq!(control.state.lock().unwrap().ip_reads, 2);
}
