//! MEGA API client: request envelope, sequence ids, error mapping and retries.

mod error;
pub mod hashcash;
mod transport;

use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use serde_json::Value;

pub use error::{ApiError, ErrorCode};
pub use transport::{ApiTransport, HttpRequest, HttpResponse, TransportError};

/// Default MEGA API endpoint.
pub const DEFAULT_API_URL: &str = "https://g.api.mega.co.nz";
/// MEGAcmd's application key; without one MEGA throttles with HTTP 402.
pub const DEFAULT_APP_KEY: &str = "BdARkQSQ";
/// Default bound on the total time one request may spend retrying.
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(600);
/// Hashcash challenges answered per request before giving up.
const MAX_HASHCASH_ROUNDS: u32 = 5;

/// Retry schedule for transient failures: `min(base * 2^n, cap)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub base: Duration,
    pub cap: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 30,
            base: Duration::from_secs(1),
            cap: Duration::from_secs(8),
        }
    }
}

impl RetryPolicy {
    /// Delay before retry number `attempt` (0-based).
    pub fn delay(&self, attempt: u32) -> Duration {
        self.base
            .checked_mul(1 << attempt.min(16))
            .map_or(self.cap, |d| d.min(self.cap))
    }
}

/// API client settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiConfig {
    pub api_url: String,
    pub app_key: String,
    pub retry: RetryPolicy,
    /// Upper bound on the time spent retrying one request (`None`: no bound).
    /// Retries stop when the next backoff would end past the deadline.
    pub deadline: Option<Duration>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            api_url: DEFAULT_API_URL.into(),
            app_key: DEFAULT_APP_KEY.into(),
            retry: RetryPolicy::default(),
            deadline: Some(DEFAULT_DEADLINE),
        }
    }
}

/// Outcome of a single HTTP exchange.
enum Attempt {
    Done(Value),
    Retry(ApiError),
    Hashcash(String),
}

/// The MEGA API client, generic over its HTTP transport.
pub struct MegaApi<T> {
    transport: T,
    config: ApiConfig,
    sequence: AtomicU32,
    session_id: Mutex<Option<String>>,
}

impl<T: ApiTransport> MegaApi<T> {
    pub fn new(transport: T, config: ApiConfig) -> Self {
        Self {
            transport,
            config,
            sequence: AtomicU32::new(rand::random()),
            session_id: Mutex::new(None),
        }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn session_id(&self) -> Option<String> {
        self.session_id.lock().expect("lock").clone()
    }

    /// Sets (or clears) the session id sent as `sid`.
    pub fn set_session_id(&self, sid: Option<String>) {
        *self.session_id.lock().expect("lock") = sid;
    }

    /// Sends one command and returns its reply.
    pub async fn call(&self, command: Value) -> Result<Value, ApiError> {
        self.call_with_query(command, &[]).await
    }

    /// Sends one command with extra query parameters (e.g. `n` for folder links).
    pub async fn call_with_query(
        &self,
        command: Value,
        query: &[(&str, &str)],
    ) -> Result<Value, ApiError> {
        self.call_inner(command, query, true).await
    }

    /// Like [`MegaApi::call_with_query`] but never sends the session id
    /// (public folder listings are anonymous).
    pub async fn call_anonymous(
        &self,
        command: Value,
        query: &[(&str, &str)],
    ) -> Result<Value, ApiError> {
        self.call_inner(command, query, false).await
    }

    async fn call_inner(
        &self,
        command: Value,
        query: &[(&str, &str)],
        with_session: bool,
    ) -> Result<Value, ApiError> {
        let mut replies = self
            .send(vec![command], &self.url(query, with_session))
            .await?;
        let reply = replies
            .drain(..)
            .next()
            .ok_or_else(|| ApiError::InvalidResponse("empty reply array".into()))?;
        match reply.as_i64() {
            Some(code) if code < 0 => Err(ApiError::Mega(ErrorCode::from_code(code))),
            _ => Ok(reply),
        }
    }

    /// Sends a batch of commands; returns one reply per command.
    pub async fn request(
        &self,
        commands: Vec<Value>,
        query: &[(&str, &str)],
    ) -> Result<Vec<Value>, ApiError> {
        self.send(commands, &self.url(query, true)).await
    }

    async fn send(&self, commands: Vec<Value>, url: &str) -> Result<Vec<Value>, ApiError> {
        let body = serde_json::to_vec(&commands).expect("JSON values always serialize");
        let mut hashcash: Option<String> = None;
        let mut hashcash_rounds = 0;
        let mut attempt = 0;
        let started = tokio::time::Instant::now();

        loop {
            let mut headers = vec![(
                "Content-Type".to_owned(),
                "text/plain;charset=UTF-8".to_owned(),
            )];
            if let Some(answer) = &hashcash {
                headers.push(("X-Hashcash".to_owned(), answer.clone()));
            }
            let request = HttpRequest {
                url: url.to_owned(),
                headers,
                body: body.clone(),
            };

            // The deadline bounds the attempt in flight too, not only the
            // backoff between attempts (a server may trickle bytes forever).
            let exchange = self.exchange(request);
            let outcome = match self.config.deadline {
                Some(limit) => {
                    let remaining = limit.saturating_sub(started.elapsed());
                    tokio::time::timeout(remaining, exchange)
                        .await
                        .map_err(|_| {
                            ApiError::Transport(format!("no reply within {}s", limit.as_secs()))
                        })??
                }
                None => exchange.await?,
            };
            let failure = match outcome {
                Attempt::Done(Value::Array(replies)) => return Ok(replies),
                Attempt::Done(other) => {
                    return Err(ApiError::InvalidResponse(format!(
                        "expected an array, got {other}"
                    )));
                }
                Attempt::Hashcash(challenge) => {
                    hashcash_rounds += 1;
                    if hashcash_rounds > MAX_HASHCASH_ROUNDS {
                        return Err(ApiError::Hashcash("too many challenges".into()));
                    }
                    let solved = tokio::task::spawn_blocking(move || hashcash::solve(&challenge))
                        .await
                        .map_err(|e| ApiError::Hashcash(e.to_string()))?
                        .map_err(ApiError::Hashcash)?;
                    hashcash = Some(solved);
                    continue;
                }
                Attempt::Retry(failure) => failure,
            };

            let delay = self.config.retry.delay(attempt);
            let past_deadline = self
                .config
                .deadline
                .is_some_and(|limit| started.elapsed() + delay > limit);
            if attempt >= self.config.retry.max_retries || past_deadline {
                return Err(failure);
            }
            tokio::time::sleep(delay).await;
            attempt += 1;
        }
    }

    async fn exchange(&self, request: HttpRequest) -> Result<Attempt, ApiError> {
        let response = match self.transport.post(request).await {
            Ok(response) => response,
            Err(e) => return Ok(Attempt::Retry(ApiError::Transport(e.0))),
        };
        match response.status {
            200 => {}
            402 => {
                return Ok(match response.header("X-Hashcash") {
                    Some(challenge) => Attempt::Hashcash(challenge.to_owned()),
                    None => Attempt::Retry(ApiError::Http(402)),
                });
            }
            500 | 503 => return Ok(Attempt::Retry(ApiError::Http(response.status))),
            other => return Err(ApiError::Http(other)),
        }

        let text = String::from_utf8_lossy(&response.body);
        let text = text.trim();
        if text.is_empty() {
            return Ok(Attempt::Retry(ApiError::InvalidResponse(
                "empty body".into(),
            )));
        }
        let value: Value = serde_json::from_str(text)
            .map_err(|e| ApiError::InvalidResponse(format!("{e}: {text:.200}")))?;

        let whole_body_error = match &value {
            Value::Number(n) => n.as_i64(),
            Value::Array(items) if items.len() == 1 => items[0].as_i64(),
            _ => None,
        }
        .filter(|code| *code < 0)
        .map(ErrorCode::from_code);

        match whole_body_error {
            Some(code) if code.is_transient() => Ok(Attempt::Retry(ApiError::Mega(code))),
            Some(code) if matches!(value, Value::Number(_)) => Err(ApiError::Mega(code)),
            _ => Ok(Attempt::Done(value)),
        }
    }

    fn url(&self, query: &[(&str, &str)], with_session: bool) -> String {
        let id = self.sequence.fetch_add(1, Ordering::Relaxed);
        let mut url = format!("{}/cs?id={id}", self.config.api_url);
        if let Some(sid) = self.session_id().filter(|_| with_session) {
            url.push_str(&format!("&sid={sid}"));
        }
        url.push_str(&format!("&ak={}", self.config.app_key));
        for (key, value) in query {
            url.push_str(&format!("&{key}={}", percent_encode(value)));
        }
        url
    }
}

/// Percent-encodes everything except RFC 3986 unreserved characters.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}
