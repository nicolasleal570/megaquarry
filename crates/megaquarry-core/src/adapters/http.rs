//! HTTP adapter built on `reqwest` with rustls.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::api::{ApiTransport, HttpRequest, HttpResponse, TransportError};
use crate::download::{ChunkBody, DownloadTransport};
use crate::upload::UploadTransport;

/// Browser-like user agent.
pub const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Idle timeout between reads: a stalled connection fails, while a large but
/// steadily streaming reply (e.g. a big folder listing) is not cut off.
/// The overall bound per request comes from `ApiConfig::deadline`.
const READ_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// A client that can be rebuilt, dropping its pooled connections (they may
/// belong to a VPN tunnel that was replaced). Clones share it.
#[derive(Debug, Clone)]
struct ResettableClient {
    build: fn() -> reqwest::Result<reqwest::Client>,
    current: Arc<RwLock<reqwest::Client>>,
}

impl ResettableClient {
    fn new(build: fn() -> reqwest::Result<reqwest::Client>) -> Result<Self, TransportError> {
        Ok(Self {
            build,
            current: Arc::new(RwLock::new(build().map_err(transport_error)?)),
        })
    }

    fn get(&self) -> reqwest::Client {
        self.current.read().expect("client lock poisoned").clone()
    }

    /// Requests in flight keep the old client until they finish.
    fn reset(&self) {
        // The builder succeeded once with the same settings; should it fail
        // now, the old client stays in use.
        if let Ok(client) = (self.build)() {
            *self.current.write().expect("client lock poisoned") = client;
        }
    }
}

/// `reqwest`-backed transport for the MEGA API.
#[derive(Debug, Clone)]
pub struct ReqwestTransport {
    client: ResettableClient,
}

impl ReqwestTransport {
    pub fn new() -> Result<Self, TransportError> {
        Ok(Self {
            client: ResettableClient::new(|| {
                reqwest::Client::builder()
                    .user_agent(USER_AGENT)
                    .connect_timeout(CONNECT_TIMEOUT)
                    .read_timeout(READ_IDLE_TIMEOUT)
                    .gzip(true)
                    .build()
            })?,
        })
    }
}

impl ApiTransport for ReqwestTransport {
    fn reset_connections(&self) {
        self.client.reset();
    }

    async fn post(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let mut builder = self.client.get().post(&request.url).body(request.body);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        let response = builder.send().await.map_err(transport_error)?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect();
        let body = response.bytes().await.map_err(transport_error)?.to_vec();
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

/// Timeouts for chunk transfers.
const CHUNK_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
const CHUNK_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// `reqwest`-backed transport for chunk downloads from storage servers.
#[derive(Debug, Clone)]
pub struct ReqwestDownloadTransport {
    client: ResettableClient,
}

impl ReqwestDownloadTransport {
    pub fn new() -> Result<Self, TransportError> {
        Ok(Self {
            client: ResettableClient::new(|| {
                reqwest::Client::builder()
                    .user_agent(USER_AGENT)
                    .connect_timeout(CHUNK_CONNECT_TIMEOUT)
                    .read_timeout(CHUNK_READ_TIMEOUT)
                    .build()
            })?,
        })
    }
}

/// Body stream of a chunk response.
pub struct ReqwestBody(reqwest::Response);

impl ChunkBody for ReqwestBody {
    async fn next_piece(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        self.0
            .chunk()
            .await
            .map(|piece| piece.map(|b| b.to_vec()))
            .map_err(transport_error)
    }

    fn header(&self, name: &str) -> Option<String> {
        self.0
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    }
}

impl DownloadTransport for ReqwestDownloadTransport {
    type Body = ReqwestBody;

    async fn get(&self, url: &str) -> Result<(u16, ReqwestBody), TransportError> {
        let response = self
            .client
            .get()
            .get(url)
            .send()
            .await
            .map_err(transport_error)?;
        Ok((response.status().as_u16(), ReqwestBody(response)))
    }

    fn reset_connections(&self) {
        self.client.reset();
    }
}

/// Converts a reqwest error without its URL: request URLs carry the session
/// id (`sid=`), which must never end up in messages or logs.
fn transport_error(error: reqwest::Error) -> TransportError {
    TransportError(error.without_url().to_string())
}

/// `reqwest`-backed transport for chunk uploads to storage servers.
#[derive(Debug, Clone)]
pub struct ReqwestUploadTransport {
    client: reqwest::Client,
}

impl ReqwestUploadTransport {
    pub fn new() -> Result<Self, TransportError> {
        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .connect_timeout(CHUNK_CONNECT_TIMEOUT)
            .read_timeout(CHUNK_READ_TIMEOUT)
            .build()
            .map_err(transport_error)?;
        Ok(Self { client })
    }
}

impl UploadTransport for ReqwestUploadTransport {
    async fn post(&self, url: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>), TransportError> {
        let response = self
            .client
            .post(url)
            .body(body)
            .send()
            .await
            .map_err(transport_error)?;
        let status = response.status().as_u16();
        let body = response.bytes().await.map_err(transport_error)?.to_vec();
        Ok((status, body))
    }
}
