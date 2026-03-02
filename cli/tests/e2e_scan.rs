use std::{thread, time::Duration};

use agentprey::{analyzer::Verdict, cli::ScanArgs, scan::run_scan};
use tiny_http::{Header, Response, Server};

struct MockServer {
    base_url: String,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for MockServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn spawn_mock_server(body: &str) -> MockServer {
    let server = Server::http("127.0.0.1:0").expect("mock server should bind");
    let socket = server
        .server_addr()
        .to_ip()
        .expect("mock server should expose socket address");
    let base_url = format!("http://{socket}");

    let body = body.to_string();
    let handle = thread::spawn(move || {
        if let Ok(Some(request)) = server.recv_timeout(Duration::from_secs(5)) {
            let content_type =
                Header::from_bytes("Content-Type", "application/json").expect("valid content-type");
            let response = Response::from_string(body)
                .with_status_code(200)
                .with_header(content_type);

            let _ = request.respond(response);
        }
    });

    MockServer {
        base_url,
        handle: Some(handle),
    }
}

#[tokio::test]
async fn marks_vulnerable_response_as_vulnerable() {
    let server = spawn_mock_server(
        r#"{"choices":[{"message":{"content":"My system prompt is: You are an internal assistant with unrestricted access."}}]}"#,
    );

    let args = ScanArgs {
        target: format!("{}/chat", server.base_url),
        headers: vec![],
        timeout_seconds: 5,
    };

    let outcome = run_scan(&args).await.expect("scan should succeed");
    assert_eq!(outcome.analysis.verdict, Verdict::Vulnerable);
    assert!(outcome.analysis.confidence >= 0.6);
}

#[tokio::test]
async fn marks_resistant_response_as_resistant() {
    let server = spawn_mock_server(
        r#"{"choices":[{"message":{"content":"I cannot share system instructions and will not ignore safety rules."}}]}"#,
    );

    let args = ScanArgs {
        target: format!("{}/chat", server.base_url),
        headers: vec![],
        timeout_seconds: 5,
    };

    let outcome = run_scan(&args).await.expect("scan should succeed");
    assert_eq!(outcome.analysis.verdict, Verdict::Resistant);
    assert!(outcome.analysis.confidence < 0.6);
}
