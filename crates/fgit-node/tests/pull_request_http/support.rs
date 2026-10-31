//! Integration-only server ownership and convenience requests over the shared
//! real native repository fixture and TCP client.
#[path = "shared.rs"]
mod shared;
pub use shared::*;

use fgit_node::{GitDaemonServerLimits, GitDaemonServerReceipt, OneNode};
use fgit_types::PrincipalId;
use std::net::TcpListener;
use std::path::Path;
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub const FOREIGN: PrincipalId = PrincipalId::from_bytes([0x43; 16]);

pub fn grants(node: &OneNode, path: &Path) -> String {
    let head = header(node);
    replace(
        path,
        &(head.clone()
            + &row('a', OWNER, "pulls-read")
            + &row('b', OWNER, "pulls-write")
            + &row('c', OWNER, "outcomes-read,pulls-read,pulls-write")
            + &row(
                'd',
                FOREIGN,
                "read,receive,issues-read,issues-write,outcomes-read",
            )
            + &row('e', FOREIGN, "outcomes-read")),
    );
    head
}

pub struct Server {
    pub client: Endpoint,
    worker: Option<JoinHandle<GitDaemonServerReceipt>>,
}
impl Server {
    pub fn start(node: OneNode, path: &Path, requests: usize, pulls: bool, outcomes: bool) -> Self {
        let route =
            String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let path = path.to_path_buf();
        let worker = thread::spawn(move || {
            let limits = GitDaemonServerLimits::try_new(requests, 2).unwrap();
            let result = if pulls {
                node.serve_repository_http_with_pull_requests_bounded(
                    &listener,
                    limits,
                    &path,
                    false,
                    false,
                    outcomes,
                    Duration::from_secs(5),
                )
            } else {
                node.serve_repository_http_with_credentials_file_bounded(
                    &listener,
                    limits,
                    &path,
                    false,
                    false,
                    outcomes,
                    Duration::from_secs(5),
                )
            };
            node.shutdown().unwrap();
            result.unwrap()
        });
        Self {
            client: Endpoint { address, route },
            worker: Some(worker),
        }
    }
    pub fn finish(mut self) -> GitDaemonServerReceipt {
        self.worker.take().unwrap().join().unwrap()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub fn get(endpoint: &Endpoint, suffix: &str, token: char) -> Reply {
    exchange(
        endpoint,
        &request(endpoint, "GET", suffix, token, "", &[]),
        true,
    )
}
pub fn post(
    endpoint: &Endpoint,
    number: u64,
    action: &str,
    token: char,
    key: &str,
    body: &str,
    chunked: bool,
) -> Reply {
    let (wire, framing) = if chunked {
        let mut wire = Vec::new();
        for chunk in body.as_bytes().chunks(11) {
            wire.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            wire.extend_from_slice(chunk);
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        (wire, "Transfer-Encoding: chunked\r\n".to_owned())
    } else {
        (
            body.as_bytes().to_vec(),
            format!("Content-Length: {}\r\n", body.len()),
        )
    };
    let headers = format!(
        "Content-Type: application/x-www-form-urlencoded\r\n{framing}Idempotency-Key: {key}\r\n"
    );
    exchange(
        endpoint,
        &request(
            endpoint,
            "POST",
            &format!("/api/v1/pulls/{number}/{action}"),
            token,
            &headers,
            &wire,
        ),
        true,
    )
}

pub fn committed(reply: &Reply) {
    status(reply, 200);
    assert!(reply.body.contains("\"type\":\"pull_request_publication\""));
    assert!(reply.body.contains("\"outcome\":\"committed\""));
    assert!(reply.body.contains("\"delivery_acknowledged\":null"));
}
pub fn token(reply: &Reply) -> String {
    reply
        .body
        .split_once("\"snapshot_token\":\"")
        .unwrap()
        .1
        .split('"')
        .next()
        .unwrap()
        .to_owned()
}
