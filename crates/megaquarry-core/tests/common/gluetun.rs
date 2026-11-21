//! A local fake of gluetun's control server (v3.41.3 behavior): `{"status"}`
//! and `{"outcome"}` bodies, an empty `public_ip` while stopped, `already
//! running` as a no-op, and 401 without the right `X-API-Key`.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

pub struct FakeGluetun {
    pub base: String,
    pub state: Mutex<GluetunState>,
    /// Called each time the tunnel starts with a new exit IP.
    pub on_start: Mutex<Option<Box<dyn Fn() + Send>>>,
}

pub struct GluetunState {
    pub key: String,
    /// No auth at all (gluetun v3.41.3 without a `config.toml`).
    pub open: bool,
    pub status: String,
    pub ip: String,
    /// Exit IPs handed out by the next starts.
    pub next_ips: VecDeque<String>,
    /// `(method, path with query, sent the right key)` of every request.
    pub requests: Vec<(String, String, bool)>,
}

impl FakeGluetun {
    pub fn start(key: &str, ip: &str, next_ips: &[&str]) -> Arc<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let fake = Arc::new(Self {
            base: format!("http://{}", listener.local_addr().unwrap()),
            state: Mutex::new(GluetunState {
                key: key.to_owned(),
                open: false,
                status: "running".into(),
                ip: ip.to_owned(),
                next_ips: next_ips.iter().map(|s| (*s).to_owned()).collect(),
                requests: Vec::new(),
            }),
            on_start: Mutex::new(None),
        });
        let server = fake.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let server = server.clone();
                std::thread::spawn(move || server.handle(stream));
            }
        });
        fake
    }

    pub fn requests(&self) -> Vec<(String, String, bool)> {
        self.state.lock().unwrap().requests.clone()
    }

    fn handle(&self, mut stream: TcpStream) {
        let Some((head, body)) = read_request(&mut stream) else {
            return;
        };
        let mut lines = head.lines();
        let mut first = lines.next().unwrap_or_default().split_whitespace();
        let method = first.next().unwrap_or_default().to_owned();
        let target = first.next().unwrap_or_default().to_owned();
        let sent_key = lines
            .filter_map(|l| l.split_once(':'))
            .find(|(name, _)| name.trim().eq_ignore_ascii_case("x-api-key"))
            .map(|(_, value)| value.trim().to_owned());

        let mut state = self.state.lock().unwrap();
        let authorized = sent_key.as_deref() == Some(state.key.as_str());
        state
            .requests
            .push((method.clone(), target.clone(), authorized));
        let (code, reply) = if !(authorized || state.open) {
            (401, "Unauthorized\n".to_owned())
        } else {
            match (method.as_str(), target.as_str()) {
                ("GET", "/v1/vpn/status") => {
                    (200, format!("{{\"status\":\"{}\"}}\n", state.status))
                }
                ("GET", "/v1/publicip/ip") => {
                    (200, format!("{{\"public_ip\":\"{}\"}}\n", state.ip))
                }
                ("PUT", "/v1/vpn/status") => {
                    let wanted: serde_json::Value =
                        serde_json::from_slice(&body).unwrap_or_default();
                    let outcome = match (wanted["status"].as_str(), state.status.as_str()) {
                        (Some("stopped"), "running") => {
                            state.status = "stopped".into();
                            state.ip.clear();
                            "stopped"
                        }
                        (Some("running"), "stopped") => {
                            state.status = "running".into();
                            state.ip = state.next_ips.pop_front().unwrap_or_default();
                            if let Some(hook) = self.on_start.lock().unwrap().as_ref() {
                                hook();
                            }
                            "running"
                        }
                        (Some("running"), _) => "already running",
                        (Some("stopped"), _) => "already stopped",
                        _ => return respond(&mut stream, 400, "invalid status\n"),
                    };
                    (200, format!("{{\"outcome\":\"{outcome}\"}}\n"))
                }
                _ => (404, "Not found\n".to_owned()),
            }
        };
        drop(state);
        respond(&mut stream, code, &reply);
    }
}

fn read_request(stream: &mut TcpStream) -> Option<(String, Vec<u8>)> {
    let mut data = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            return None;
        }
        data.extend_from_slice(&buf[..n]);
        let text = String::from_utf8_lossy(&data).into_owned();
        if let Some(end) = text.find("\r\n\r\n") {
            let length: usize = text[..end]
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse().unwrap())
                })
                .unwrap_or(0);
            if data.len() >= end + 4 + length {
                return Some((
                    text[..end].to_owned(),
                    data[end + 4..end + 4 + length].to_vec(),
                ));
            }
        }
    }
}

fn respond(stream: &mut TcpStream, code: u16, body: &str) {
    let _ = write!(
        stream,
        "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}
