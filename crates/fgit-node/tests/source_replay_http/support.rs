//! Real imported replay histories and the existing TCP client. The production
//! source gateway performs all preparation, inspection and durable admission.
#[path = "../candidate_preparation_http/support.rs"]
mod common;
pub use common::{
    BinaryReply, Endpoint, OWNER, Scratch, binary_exchange, encode, generation, header,
    non_clean_fixture, numeric, reopen, replace, request, row,
};

use fgit_crypto::sha256_digest;
use fgit_node::{GitDaemonServerLimits, GitDaemonServerReceipt, OneNode};
use fgit_types::{GitOid, RefName};
use std::net::TcpListener;
use std::path::Path;
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub struct SourceServer {
    pub client: Endpoint,
    worker: Option<JoinHandle<GitDaemonServerReceipt>>,
}
impl SourceServer {
    pub fn start(node: OneNode, credentials: &Path, count: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = Endpoint {
            address: listener.local_addr().unwrap(),
            route: String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec())
                .unwrap(),
        };
        let credentials = credentials.to_path_buf();
        let worker = thread::spawn(move || {
            let result = node.serve_repository_http_with_source_bounded(
                &listener,
                GitDaemonServerLimits::try_new(count, 2).unwrap(),
                &credentials,
                true,
                false,
                true,
                false,
                Duration::from_secs(5),
            );
            node.shutdown().unwrap();
            result.unwrap()
        });
        Self {
            client,
            worker: Some(worker),
        }
    }
    pub fn finish(mut self) -> GitDaemonServerReceipt {
        self.worker.take().unwrap().join().unwrap()
    }
}
impl Drop for SourceServer {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
pub fn configure(node: &OneNode, path: &Path) -> String {
    let value = header(node);
    replace(
        path,
        &(value.clone()
            + &row('a', OWNER, "read,outcomes-read")
            + &row('b', OWNER, "receive,outcomes-read")),
    );
    value
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn form(
    target: &RefName,
    source: &RefName,
    target_tip: GitOid,
    source_tip: GitOid,
    commit: GitOid,
) -> String {
    format!(
        "profile=path-v1&object_format={}&target_ref_hex={}&source_ref_hex={}&expected_target={target_tip}&expected_source={source_tip}&commit={commit}&author=Fixture+%3Cfixture%40example.invalid%3E&timestamp=7&message=Remote+replay%0A",
        target_tip.algorithm().as_str(),
        hex(target.as_bytes()),
        hex(source.as_bytes())
    )
}
pub fn post_form(
    endpoint: &Endpoint,
    action: &str,
    token: char,
    form: &str,
    chunked: bool,
) -> BinaryReply {
    let (body, framing) = if chunked {
        let mut bytes = Vec::new();
        for chunk in form.as_bytes().chunks(13) {
            bytes.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            bytes.extend_from_slice(chunk);
            bytes.extend_from_slice(b"\r\n");
        }
        bytes.extend_from_slice(b"0\r\n\r\n");
        (bytes, "Transfer-Encoding: chunked\r\n".into())
    } else {
        (
            form.as_bytes().to_vec(),
            format!("Content-Length: {}\r\n", form.len()),
        )
    };
    binary_exchange(
        endpoint,
        &request(
            endpoint,
            "POST",
            &format!("/api/v1/source/{action}"),
            token,
            &format!("Content-Type: application/x-www-form-urlencoded\r\n{framing}"),
            &body,
        ),
        true,
    )
}
pub fn multipart(
    endpoint: &Endpoint,
    action: &str,
    token: char,
    form: &str,
    bundle: &[u8],
    key: Option<&str>,
) -> BinaryReply {
    let boundary = "source-replay-fixture";
    assert!(
        !bundle
            .windows(boundary.len())
            .any(|part| part == boundary.as_bytes())
    );
    let mut body = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"command\"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n{form}\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"bundle\"; filename=\"candidate.bundle\"\r\nContent-Type: application/x-git-bundle\r\n\r\n").into_bytes();
    body.extend_from_slice(bundle);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let key = key.map_or_else(String::new, |key| format!("Idempotency-Key: {key}\r\n"));
    binary_exchange(
        endpoint,
        &request(
            endpoint,
            "POST",
            &format!("/api/v1/source/{action}"),
            token,
            &format!(
                "Content-Type: multipart/form-data; boundary={boundary}\r\nContent-Length: {}\r\n{key}",
                body.len()
            ),
            &body,
        ),
        true,
    )
}
pub fn status(reply: &BinaryReply, expected: u16) {
    assert_eq!(
        reply.status,
        expected,
        "{}\n{}",
        reply.head,
        String::from_utf8_lossy(&reply.body)
    );
}
pub fn json(reply: &BinaryReply) -> &str {
    std::str::from_utf8(&reply.body).unwrap()
}
pub fn field<'a>(text: &'a str, key: &str) -> &'a str {
    text.split_once(&format!("\"{key}\":\""))
        .unwrap()
        .1
        .split('"')
        .next()
        .unwrap()
}
pub fn extract_candidate(reply: &BinaryReply) -> (String, Vec<u8>) {
    status(reply, 200);
    let media = reply
        .head
        .lines()
        .find_map(|line| line.strip_prefix("Content-Type: "))
        .unwrap()
        .trim();
    let boundary = media.strip_prefix("multipart/mixed; boundary=").unwrap();
    assert!(boundary.len() <= 70);
    let body = reply
        .body
        .strip_prefix(format!("--{boundary}\r\n").as_bytes())
        .unwrap();
    let header_end = body
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .unwrap()
        + 4;
    let body = &body[header_end..];
    let delimiter = format!("\r\n--{boundary}\r\n");
    let end = body
        .windows(delimiter.len())
        .position(|part| part == delimiter.as_bytes())
        .unwrap();
    let metadata = String::from_utf8(body[..end].to_vec()).unwrap();
    let body = &body[end + delimiter.len()..];
    let header_end = body
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .unwrap()
        + 4;
    let bundle = body[header_end..]
        .strip_suffix(format!("\r\n--{boundary}--\r\n").as_bytes())
        .unwrap()
        .to_vec();
    assert_eq!(numeric(&metadata, "bytes"), bundle.len() as u64);
    assert_eq!(field(&metadata, "sha256"), hex(&sha256_digest(&bundle)));
    for flag in [
        "\"read_only\":true",
        "\"objects_staged\":false",
        "\"transaction_created\":false",
        "\"published\":false",
        "\"publication_authorized\":false",
    ] {
        assert!(metadata.contains(flag));
    }
    (metadata, bundle)
}
