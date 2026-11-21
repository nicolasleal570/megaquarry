use megaquarry_core::adapters::http::{
    ReqwestDownloadTransport, ReqwestTransport, ReqwestUploadTransport,
};
use megaquarry_core::api::{ApiTransport, HttpRequest};
use megaquarry_core::download::{ChunkBody, DownloadTransport};
use megaquarry_core::upload::UploadTransport;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Serves one canned HTTP response and returns the raw request it received.
async fn serve_once(response: &'static str) -> (String, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = socket.read(&mut buf).await.unwrap();
            received.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&received);
            if let Some(end) = text.find("\r\n\r\n") {
                let length: usize = text
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .map(|v| v.trim().parse().unwrap())
                    })
                    .unwrap_or(0);
                if received.len() >= end + 4 + length {
                    break;
                }
            }
        }
        socket.write_all(response.as_bytes()).await.unwrap();
        String::from_utf8_lossy(&received).into_owned()
    });
    (format!("http://{addr}"), handle)
}

#[tokio::test]
async fn posts_body_and_headers_and_returns_the_reply() {
    let (base, server) = serve_once(
        "HTTP/1.1 402 Payment Required\r\nX-Hashcash: 1:2:3:abc\r\nContent-Length: 3\r\nConnection: close\r\n\r\n[1]",
    )
    .await;
    let transport = ReqwestTransport::new().unwrap();
    let response = transport
        .post(HttpRequest {
            url: format!("{base}/cs?id=1"),
            headers: vec![("Content-Type".into(), "text/plain;charset=UTF-8".into())],
            body: b"[{\"a\":\"x\"}]".to_vec(),
        })
        .await
        .unwrap();

    assert_eq!(response.status, 402);
    assert_eq!(response.header("x-hashcash"), Some("1:2:3:abc"));
    assert_eq!(response.body, b"[1]");

    let request = server.await.unwrap();
    assert!(request.starts_with("POST /cs?id=1 HTTP/1.1"), "{request}");
    assert!(
        request
            .to_ascii_lowercase()
            .contains("content-type: text/plain;charset=utf-8")
    );
    assert!(request.contains("Firefox/61.0"));
    assert!(request.ends_with("[{\"a\":\"x\"}]"));
}

#[tokio::test]
async fn reports_connection_failures_as_transport_errors() {
    let transport = ReqwestTransport::new().unwrap();
    let result = transport
        .post(HttpRequest {
            url: "http://127.0.0.1:1/cs".into(),
            headers: vec![],
            body: vec![],
        })
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn streams_chunk_bodies() {
    let (base, server) =
        serve_once("HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello world")
            .await;
    let transport = ReqwestDownloadTransport::new().unwrap();
    let (status, mut body) = transport.get(&format!("{base}/dl/0-10")).await.unwrap();
    assert_eq!(status, 200);
    let mut data = Vec::new();
    while let Some(piece) = body.next_piece().await.unwrap() {
        data.extend(piece);
    }
    assert_eq!(data, b"hello world");
    assert!(server.await.unwrap().starts_with("GET /dl/0-10 HTTP/1.1"));
}

#[tokio::test]
async fn posts_upload_chunks() {
    let (base, server) =
        serve_once("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nTOKEN").await;
    let transport = ReqwestUploadTransport::new().unwrap();
    let (status, body) = transport
        .post(&format!("{base}/ul/131072"), b"cipher".to_vec())
        .await
        .unwrap();
    assert_eq!((status, body.as_slice()), (200, b"TOKEN".as_slice()));
    let request = server.await.unwrap();
    assert!(request.starts_with("POST /ul/131072 HTTP/1.1"), "{request}");
    assert!(request.ends_with("cipher"));
}
