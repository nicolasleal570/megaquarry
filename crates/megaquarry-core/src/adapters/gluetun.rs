//! [`VpnControl`] over gluetun's HTTP control server (pinned to v3.41.3).
//!
//! Routes: `GET /v1/vpn/status`, `PUT /v1/vpn/status` and
//! `GET /v1/publicip/ip`. The API key goes only in the `X-API-Key` header,
//! never in the URL, and never appears in errors or `Debug` output.

use std::time::Duration;

use serde_json::{Value, json};

use crate::egress::{ControlError, VpnControl, VpnStatus};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// gluetun answers a stop only after OpenVPN exited, so allow a slow reply.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const API_KEY_HEADER: &str = "X-API-Key";

pub struct GluetunControl {
    client: reqwest::Client,
    base: String,
    api_key: String,
}

impl std::fmt::Debug for GluetunControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GluetunControl")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl GluetunControl {
    /// `base` is the control server URL, e.g. `http://127.0.0.1:8000`.
    pub fn new(base: &str, api_key: String) -> Result<Self, ControlError> {
        let base = base.trim().trim_end_matches('/').to_owned();
        if !(base.starts_with("http://") || base.starts_with("https://")) {
            return Err(ControlError(format!(
                "the VPN control URL must start with http:// or https:// (got `{base}`)"
            )));
        }
        let client = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            // Each request is a fresh connection to the local server: nothing
            // to gain from pooling across tunnel restarts.
            .pool_max_idle_per_host(0)
            .build()
            .map_err(|e| ControlError(e.without_url().to_string()))?;
        Ok(Self {
            client,
            base,
            api_key,
        })
    }

    /// True when the control server refuses a request without the key.
    /// gluetun v3.41.3 leaves its routes open when its auth file is missing
    /// or defines no roles; callers refuse to run against such a server.
    pub async fn requires_auth(&self) -> Result<bool, ControlError> {
        let response = self
            .client
            .get(self.url("/v1/vpn/status"))
            .send()
            .await
            .map_err(|e| self.unreachable(e))?;
        match response.status().as_u16() {
            401 => Ok(true),
            200..=299 => Ok(false),
            other => Err(ControlError(format!(
                "unexpected answer from the VPN control at {} (HTTP {other})",
                self.base
            ))),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    fn unreachable(&self, error: reqwest::Error) -> ControlError {
        ControlError(format!(
            "cannot reach the VPN control at {}: {}",
            self.base,
            error.without_url()
        ))
    }

    async fn send(&self, request: reqwest::RequestBuilder) -> Result<Value, ControlError> {
        let response = request
            .header(API_KEY_HEADER, &self.api_key)
            .send()
            .await
            .map_err(|e| self.unreachable(e))?;
        match response.status().as_u16() {
            200..=299 => {}
            401 => {
                return Err(ControlError(
                    "the VPN control refused the API key (HTTP 401)".into(),
                ));
            }
            other => {
                return Err(ControlError(format!(
                    "the VPN control answered HTTP {other}"
                )));
            }
        }
        let body = response.bytes().await.map_err(|e| {
            ControlError(format!("unreadable VPN control reply: {}", e.without_url()))
        })?;
        serde_json::from_slice(&body)
            .map_err(|e| ControlError(format!("unreadable VPN control reply: {e}")))
    }
}

impl VpnControl for GluetunControl {
    async fn status(&self) -> Result<VpnStatus, ControlError> {
        let reply = self
            .send(self.client.get(self.url("/v1/vpn/status")))
            .await?;
        Ok(match reply["status"].as_str() {
            Some("running") => VpnStatus::Running,
            Some("stopped") => VpnStatus::Stopped,
            Some("crashed") => VpnStatus::Crashed,
            other => VpnStatus::Other(other.unwrap_or_default().to_owned()),
        })
    }

    async fn set_running(&self, running: bool) -> Result<(), ControlError> {
        let status = if running { "running" } else { "stopped" };
        // The reply's `outcome` (e.g. "already running") needs no handling:
        // callers poll the status afterwards.
        self.send(
            self.client
                .put(self.url("/v1/vpn/status"))
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(json!({ "status": status }).to_string()),
        )
        .await?;
        Ok(())
    }

    async fn public_ip(&self) -> Result<Option<String>, ControlError> {
        let reply = self
            .send(self.client.get(self.url("/v1/publicip/ip")))
            .await?;
        Ok(reply["public_ip"]
            .as_str()
            .map(str::trim)
            .filter(|ip| !ip.is_empty())
            .map(str::to_owned))
    }
}
