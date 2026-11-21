//! Exit IP rotation when MEGA reports the transfer quota as exhausted.
//!
//! MEGA limits how much one IP may download. When a download hits the limit
//! (HTTP 509), the [`Rotator`] marks the current exit IP as cooling down for
//! as long as MEGA asked (`X-MEGA-Time-Left`), asks the VPN to reconnect
//! through [`VpnControl`] and waits for a new exit IP that is not cooling.
//! Concurrent quota hits share one rotation: callers pass the generation they
//! saw before their request, and a rotation that already happened since then
//! is not repeated. Cooldowns live in the store so they survive restarts.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use tokio::sync::mpsc::UnboundedSender;

use crate::store::Store;

/// State of the VPN tunnel as the control server reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpnStatus {
    Running,
    Stopped,
    /// gluetun refuses requests while crashed and restarts by itself.
    Crashed,
    Other(String),
}

/// The VPN control server could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ControlError(pub String);

/// Port: controls the VPN that carries this process's traffic.
pub trait VpnControl: Send + Sync + 'static {
    fn status(&self) -> impl Future<Output = Result<VpnStatus, ControlError>> + Send;

    /// Stops (`false`) or starts (`true`) the tunnel.
    fn set_running(&self, running: bool) -> impl Future<Output = Result<(), ControlError>> + Send;

    /// The current exit IP; `None` while the tunnel is down or the IP is not
    /// known yet.
    fn public_ip(&self) -> impl Future<Output = Result<Option<String>, ControlError>> + Send;
}

impl<C: VpnControl> VpnControl for Arc<C> {
    fn status(&self) -> impl Future<Output = Result<VpnStatus, ControlError>> + Send {
        (**self).status()
    }

    fn set_running(&self, running: bool) -> impl Future<Output = Result<(), ControlError>> + Send {
        (**self).set_running(running)
    }

    fn public_ip(&self) -> impl Future<Output = Result<Option<String>, ControlError>> + Send {
        (**self).public_ip()
    }
}

/// Longest cooldown accepted from MEGA's wait (its quota window is 6 h); a
/// larger or malformed value is capped rather than trusted.
pub const MAX_COOLDOWN: Duration = Duration::from_secs(24 * 3600);

/// Rotation tuning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationOptions {
    /// Cooldown when MEGA does not say how long to wait (the MEGA SDK uses 1 h).
    pub fallback_cooldown: Duration,
    /// Reconnects per rotation before giving up.
    pub max_attempts: u32,
    /// How long one reconnect may take to bring the tunnel back.
    pub reconnect_timeout: Duration,
    /// Delay between status checks while waiting for the tunnel.
    pub poll_interval: Duration,
    /// After a failed rotation, no new one starts for this long: requests in
    /// that window get the same failure and wait.
    pub retry_wait: Duration,
}

impl Default for RotationOptions {
    fn default() -> Self {
        Self {
            fallback_cooldown: Duration::from_secs(3600),
            max_attempts: 5,
            reconnect_timeout: Duration::from_secs(90),
            poll_interval: Duration::from_secs(1),
            retry_wait: Duration::from_secs(60),
        }
    }
}

/// Why a rotation did not produce a usable exit IP.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RotateError {
    #[error("every exit IP tried is cooling down")]
    Exhausted,
    #[error("the VPN control is unavailable: {0}")]
    Unavailable(String),
}

/// Notifications for a user interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationEvent {
    /// The quota was hit on `ip` (when known), which now cools down.
    QuotaHit {
        ip: Option<String>,
        cooldown: Duration,
    },
    /// A reconnect gave an IP that is still cooling down.
    SkippedCooling { ip: String },
    /// Traffic now leaves through `ip`; `cooling` IPs are cooling down.
    Rotated { ip: String, cooling: usize },
    /// Every attempt gave a cooling IP.
    Exhausted { cooling: usize },
    /// The VPN control failed; downloads wait and retry.
    Unavailable { error: String },
}

/// Boxed future, so [`QuotaRotation`] can be used as a trait object.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What the download engine needs from a rotator.
pub trait QuotaRotation: Send + Sync {
    /// Increments after every rotation that changed the tunnel.
    fn generation(&self) -> u64;

    /// Rotates away from the current exit IP, unless a rotation already
    /// happened since the caller saw generation `seen`; such a caller gets
    /// the result of the latest rotation. `time_left` is MEGA's wait for the
    /// current IP.
    fn rotate(
        &self,
        seen: u64,
        time_left: Option<Duration>,
    ) -> BoxFuture<'_, Result<(), RotateError>>;

    /// Resolves when no rotation is in progress.
    fn wait_ready(&self) -> BoxFuture<'_, ()>;

    /// Whether the tunnel is up now (running, with a known exit IP). Network
    /// errors while it is down are the VPN's, not the download's.
    fn tunnel_up(&self) -> BoxFuture<'_, bool>;
}

/// Rotates the exit IP through a [`VpnControl`].
pub struct Rotator<C> {
    control: C,
    store: Arc<Store>,
    options: RotationOptions,
    generation: AtomicU64,
    /// Held for the whole rotation: one at a time, and `wait_ready` queues on it.
    busy: tokio::sync::Mutex<()>,
    /// How the latest rotation ended, shared with the callers it covered,
    /// and when it failed.
    last_failure: std::sync::Mutex<Option<(RotateError, tokio::time::Instant)>>,
    events: Option<UnboundedSender<RotationEvent>>,
}

/// How one reconnect ended.
enum Attempt {
    Fresh(String),
    Cooling,
    TimedOut(String),
}

impl<C: VpnControl> Rotator<C> {
    pub fn new(control: C, store: Arc<Store>, options: RotationOptions) -> Self {
        Self {
            control,
            store,
            options,
            generation: AtomicU64::new(0),
            busy: tokio::sync::Mutex::new(()),
            last_failure: std::sync::Mutex::new(None),
            events: None,
        }
    }

    pub fn with_events(mut self, events: UnboundedSender<RotationEvent>) -> Self {
        self.events = Some(events);
        self
    }

    pub fn options(&self) -> &RotationOptions {
        &self.options
    }

    fn emit(&self, event: RotationEvent) {
        if let Some(tx) = &self.events {
            let _ = tx.send(event);
        }
    }

    fn unavailable(&self, error: String) -> RotateError {
        self.emit(RotationEvent::Unavailable {
            error: error.clone(),
        });
        RotateError::Unavailable(error)
    }

    fn store_error(&self, error: crate::store::StoreError) -> RotateError {
        self.unavailable(format!("cannot read or save cooldowns: {error}"))
    }

    /// Waits for the tunnel at startup and moves away from a cooling IP.
    /// Returns the exit IP downloads will use.
    pub async fn prepare(&self) -> Result<String, RotateError> {
        let _busy = self.busy.lock().await;
        let now = SystemTime::now();
        self.store
            .prune_cooldowns(now)
            .map_err(|e| self.store_error(e))?;
        // A rotation interrupted between stop and start (Ctrl-C) leaves the
        // VPN stopped: start it again.
        if let Ok(VpnStatus::Stopped) = self.control.status().await {
            self.control
                .set_running(true)
                .await
                .map_err(|e| self.unavailable(format!("cannot start the VPN: {}", e.0)))?;
        }
        let ip = match self.wait_tunnel().await {
            Ok(ip) => ip,
            Err(error) => return Err(self.unavailable(error)),
        };
        if self
            .store
            .ip_cooling_until(&ip, now)
            .map_err(|e| self.store_error(e))?
            .is_none()
        {
            return Ok(ip);
        }
        self.emit(RotationEvent::SkippedCooling { ip });
        let result = self.reconnect_until_fresh().await;
        self.finish(&result);
        result
    }

    /// See [`QuotaRotation::rotate`].
    pub async fn rotate(&self, seen: u64, time_left: Option<Duration>) -> Result<(), RotateError> {
        let _busy = self.busy.lock().await;
        if self.generation.load(Ordering::SeqCst) != seen {
            // Covered by a rotation that already ran: share how it ended, so
            // every caller waits after a failure, not only the one that ran it.
            return match self.last_failure.lock().expect("lock").clone() {
                Some((error, _)) => Err(error),
                None => Ok(()),
            };
        }
        // Shortly after a failure, do not reconnect again: every caller waits.
        if let Some((error, at)) = self.last_failure.lock().expect("lock").clone() {
            if at.elapsed() < self.options.retry_wait {
                return Err(error);
            }
        }
        // Read the IP now: gluetun may have reconnected by itself since the
        // last rotation.
        let ip = match self.control.public_ip().await {
            Ok(ip) => ip,
            Err(e) => return Err(self.failed_early(self.unavailable(e.0))),
        };
        let cooldown = time_left
            .unwrap_or(self.options.fallback_cooldown)
            .min(MAX_COOLDOWN);
        if let Some(ip) = &ip {
            if let Err(e) = self.store.cool_down_ip(ip, SystemTime::now() + cooldown) {
                return Err(self.failed_early(self.store_error(e)));
            }
        }
        self.emit(RotationEvent::QuotaHit { ip, cooldown });
        let result = self.reconnect_until_fresh().await;
        self.finish(&result);
        result.map(|_| ())
    }

    /// Records how a rotation ended and starts a new generation: even a failed
    /// rotation may have replaced the tunnel, so callers must drop their
    /// connections and URLs either way.
    fn finish(&self, result: &Result<String, RotateError>) {
        *self.last_failure.lock().expect("lock") = result
            .as_ref()
            .err()
            .map(|e| (e.clone(), tokio::time::Instant::now()));
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    /// Records a failure that happened before the tunnel was touched: the
    /// quiet period applies, but the generation stays (connections are fine).
    fn failed_early(&self, error: RotateError) -> RotateError {
        *self.last_failure.lock().expect("lock") =
            Some((error.clone(), tokio::time::Instant::now()));
        error
    }

    /// See [`QuotaRotation::tunnel_up`].
    pub async fn tunnel_up(&self) -> bool {
        matches!(self.control.status().await, Ok(VpnStatus::Running))
            && matches!(self.control.public_ip().await, Ok(Some(ip)) if !ip.is_empty())
    }

    /// Reconnects until the exit IP is not cooling, within the attempt limit.
    async fn reconnect_until_fresh(&self) -> Result<String, RotateError> {
        let mut last = Attempt::Cooling;
        for _ in 0..self.options.max_attempts.max(1) {
            last = match self.reconnect().await {
                Ok(attempt) => attempt,
                Err(e) => {
                    return Err(self.unavailable(format!("VPN control request failed: {}", e.0)));
                }
            };
            match &last {
                Attempt::Fresh(ip) => {
                    let cooling = self
                        .store
                        .cooling_ips(SystemTime::now())
                        .map_err(|e| self.store_error(e))?;
                    self.emit(RotationEvent::Rotated {
                        ip: ip.clone(),
                        cooling,
                    });
                    return Ok(ip.clone());
                }
                Attempt::Cooling | Attempt::TimedOut(_) => {}
            }
        }
        match last {
            Attempt::TimedOut(error) => Err(self.unavailable(error)),
            _ => {
                let cooling = self
                    .store
                    .cooling_ips(SystemTime::now())
                    .map_err(|e| self.store_error(e))?;
                self.emit(RotationEvent::Exhausted { cooling });
                Err(RotateError::Exhausted)
            }
        }
    }

    /// One stop + start, then the new IP.
    async fn reconnect(&self) -> Result<Attempt, ControlError> {
        self.control.set_running(false).await?;
        self.control.set_running(true).await?;
        let ip = match self.wait_tunnel().await {
            Ok(ip) => ip,
            Err(error) => return Ok(Attempt::TimedOut(error)),
        };
        let cooling = self
            .store
            .ip_cooling_until(&ip, SystemTime::now())
            .map_err(|e| ControlError(format!("cannot read cooldowns: {e}")))?;
        if cooling.is_some() {
            self.emit(RotationEvent::SkippedCooling { ip });
            Ok(Attempt::Cooling)
        } else {
            Ok(Attempt::Fresh(ip))
        }
    }

    /// Polls until the tunnel runs with a known exit IP. gluetun reports
    /// `running` once OpenVPN starts, before the tunnel is up, and clears the
    /// IP while down, so both are required.
    async fn wait_tunnel(&self) -> Result<String, String> {
        let mut last_error = None;
        let poll = async {
            loop {
                match self.control.status().await {
                    Ok(VpnStatus::Running) => match self.control.public_ip().await {
                        Ok(Some(ip)) if !ip.is_empty() => return ip,
                        Ok(_) => {}
                        Err(e) => last_error = Some(e.0),
                    },
                    Ok(_) => {}
                    Err(e) => last_error = Some(e.0),
                }
                tokio::time::sleep(self.options.poll_interval).await;
            }
        };
        match tokio::time::timeout(self.options.reconnect_timeout, poll).await {
            Ok(ip) => Ok(ip),
            Err(_) => {
                let timeout = self.options.reconnect_timeout.as_secs();
                Err(match last_error {
                    Some(e) => format!("the VPN tunnel was not up within {timeout} s ({e})"),
                    None => format!("the VPN tunnel was not up within {timeout} s"),
                })
            }
        }
    }
}

impl<C: VpnControl> QuotaRotation for Rotator<C> {
    fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    fn rotate(
        &self,
        seen: u64,
        time_left: Option<Duration>,
    ) -> BoxFuture<'_, Result<(), RotateError>> {
        Box::pin(Rotator::rotate(self, seen, time_left))
    }

    fn wait_ready(&self) -> BoxFuture<'_, ()> {
        Box::pin(async {
            drop(self.busy.lock().await);
        })
    }

    fn tunnel_up(&self) -> BoxFuture<'_, bool> {
        Box::pin(Rotator::tunnel_up(self))
    }
}
