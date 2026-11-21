//! Shared test doubles.
#![allow(dead_code)]

pub mod gluetun;

use std::collections::VecDeque;
use std::sync::Mutex;

use megaquarry_core::api::{
    ApiConfig, ApiTransport, HttpRequest, HttpResponse, MegaApi, RetryPolicy, TransportError,
};

/// A scripted transport that records requests and replays canned responses.
#[derive(Default)]
pub struct FakeTransport {
    responses: Mutex<VecDeque<Result<HttpResponse, TransportError>>>,
    requests: Mutex<Vec<HttpRequest>>,
}

impl FakeTransport {
    pub fn with(responses: Vec<Result<HttpResponse, TransportError>>) -> Self {
        Self {
            responses: Mutex::new(responses.into()),
            requests: Mutex::default(),
        }
    }

    pub fn requests(&self) -> Vec<HttpRequest> {
        self.requests.lock().unwrap().clone()
    }

    /// Request bodies parsed as JSON.
    pub fn bodies(&self) -> Vec<serde_json::Value> {
        self.requests()
            .iter()
            .map(|r| serde_json::from_slice(&r.body).unwrap())
            .collect()
    }
}

impl ApiTransport for FakeTransport {
    async fn post(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        self.requests.lock().unwrap().push(request);
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected extra request")
    }
}

pub fn ok(body: &str) -> Result<HttpResponse, TransportError> {
    status(200, body)
}

pub fn status(code: u16, body: &str) -> Result<HttpResponse, TransportError> {
    Ok(HttpResponse {
        status: code,
        headers: vec![],
        body: body.as_bytes().to_vec(),
    })
}

/// An API client over `transport` with a short retry budget.
pub fn api(transport: FakeTransport) -> MegaApi<FakeTransport> {
    MegaApi::new(
        transport,
        ApiConfig {
            retry: RetryPolicy {
                max_retries: 3,
                ..RetryPolicy::default()
            },
            ..ApiConfig::default()
        },
    )
}
