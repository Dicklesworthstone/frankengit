//! Test-only clients over the real node listener, reusing imported source
//! fixtures. No substitute patch engine, candidate store or publication path.
#[path = "../source_http/support.rs"]
mod base;
pub use base::{Scratch, Endpoint, Reply, OWNER, FOREIGN, TEXT, BINARY, BINARY_PATH,
    LINK, fixture, reopen, generation, hex, row, replace, credentials, request,
    exchange, post, common, status, text, number};

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::Path;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use fgit_crypto::sha256_digest;
use fgit_node::{GitDaemonServerLimits, GitDaemonServerReceipt, OneNode};
use fgit_types::{GitHashAlgorithm, GitOid};

pub struct Server { pub client: Endpoint, worker: Option<JoinHandle<GitDaemonServerReceipt>> }
impl Server {
    pub fn start(node: OneNode, path: &Path, count: usize, source: bool, receive: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = Endpoint { address: listener.local_addr().unwrap(),
            route: String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec()).unwrap() };
        let path = path.to_path_buf();
        let worker = thread::spawn(move || {
            let limits = GitDaemonServerLimits::try_new(count, 2).unwrap();
            let result = if source {
                node.serve_repository_http_with_source_bounded(&listener, limits, &path,
                    receive, false, true, false, Duration::from_secs(5))
            } else {
                node.serve_repository_http_with_credentials_file_bounded(&listener, limits, &path,
                    receive, false, true, Duration::from_secs(5))
            };
            node.shutdown().unwrap();
            result.unwrap()
        });
        Self { client, worker: Some(worker) }
    }
    pub fn finish(mut self) -> GitDaemonServerReceipt { self.worker.take().unwrap().join().unwrap() }
}
impl Drop for Server {
    fn drop(&mut self) { if let Some(worker) = self.worker.take() { let _ = worker.join(); } }
}
pub fn configure(node: &OneNode, path: &Path) -> String {
    let header = credentials(node, path);
    replace(path, &(header.clone() + &row('a', OWNER, "read") + &row('b', OWNER, "receive")
        + &row('c', OWNER, "outcomes-read") + &row('d', FOREIGN, "outcomes-read")));
    header
}

#[derive(Debug, Eq, PartialEq)]
pub struct BinaryReply { pub status: u16, pub head: String, pub body: Vec<u8> }
pub fn connect(client: &Endpoint) -> TcpStream {
    let socket = TcpStream::connect(client.address).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    socket.set_write_timeout(Some(Duration::from_secs(60))).unwrap();
    socket
}
pub fn binary_exchange(client: &Endpoint, bytes: &[u8]) -> BinaryReply {
    let mut socket = connect(client);
    socket.write_all(bytes).unwrap(); socket.shutdown(Shutdown::Write).unwrap();
    let mut bytes = Vec::new(); (&mut socket).take(9 * 1024 * 1024).read_to_end(&mut bytes).unwrap();
    let split = bytes.windows(4).position(|x| x == b"\r\n\r\n").unwrap() + 4;
    let head = String::from_utf8(bytes[..split].to_vec()).unwrap();
    let length: usize = head.lines().find_map(|line| line.strip_prefix("Content-Length: ")).unwrap().trim().parse().unwrap();
    assert_eq!(bytes.len() - split, length, "no truncated or appended response");
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    BinaryReply { status, head, body: bytes[split..].to_vec() }
}
fn part(name: &str, media: &str, bytes: &[u8]) -> Vec<u8> {
    let mut out = format!("--source-edit\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"ignored\"\r\nContent-Type: {media}\r\n\r\n").into_bytes();
    out.extend_from_slice(bytes); out.extend_from_slice(b"\r\n"); out
}
pub fn change_bytes(client: &Endpoint, action: &str, token: char, key: Option<&str>,
    form: &str, payload: &[u8], chunked: bool,
) -> Vec<u8> {
    let command = part("command", "application/x-www-form-urlencoded", form.as_bytes());
    let data = if action == "prepare" { part("patch", "text/x-diff", payload) }
        else { part("bundle", "application/x-git-bundle", payload) };
    let mut body = if chunked { [data, command].concat() } else { [command, data].concat() };
    body.extend_from_slice(b"--source-edit--\r\n");
    let (wire, framing) = if chunked {
        let mut wire = Vec::new();
        for chunk in body.chunks(37) {
            wire.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            wire.extend_from_slice(chunk); wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n"); (wire, "Transfer-Encoding: chunked\r\n".into())
    } else { (body.clone(), format!("Content-Length: {}\r\n", body.len())) };
    let key = key.map_or_else(String::new, |key| format!("Idempotency-Key: {key}\r\n"));
    request(client, &format!("/api/v1/source/{action}"), token,
        &format!("Content-Type: multipart/form-data; boundary=source-edit\r\n{framing}{key}"), &wire)
}
pub fn metadata(base: GitOid, message: &str) -> String {
    format!("{}&expected_commit={base}&author=Editor+%3Ce%40example.invalid%3E&committer=Editor+%3Ce%40example.invalid%3E&timestamp=1&message={message}%0A",
        common(base.algorithm()))
}
pub fn candidate_form(base: GitOid, candidate: GitOid) -> String {
    format!("{}&expected_commit={base}&candidate_commit={candidate}", common(base.algorithm()))
}
pub fn prepare(client: &Endpoint, base: GitOid, patch: &[u8], message: &str, chunked: bool) -> BinaryReply {
    binary_exchange(client, &change_bytes(client, "prepare", 'a', None, &metadata(base, message), patch, chunked))
}
#[derive(Clone)]
pub struct Artifact { pub commit: GitOid, pub bundle: Vec<u8>, pub metadata: String }
pub fn extract(reply: &BinaryReply, format: GitHashAlgorithm) -> Artifact {
    assert_eq!(reply.status, 200, "{}", String::from_utf8_lossy(&reply.body));
    let content_type = reply.head.lines().find_map(|line| line.strip_prefix("Content-Type: ")).unwrap();
    let boundary = content_type.strip_prefix("multipart/mixed; boundary=").unwrap().trim();
    assert!(boundary.len() <= 70);
    let bytes = reply.body.strip_prefix(format!("--{boundary}\r\n").as_bytes()).unwrap();
    let split = bytes.windows(4).position(|x| x == b"\r\n\r\n").unwrap() + 4;
    let bytes = &bytes[split..];
    let delimiter = format!("\r\n--{boundary}\r\n");
    let end = bytes.windows(delimiter.len()).position(|x| x == delimiter.as_bytes()).unwrap();
    let metadata = String::from_utf8(bytes[..end].to_vec()).unwrap();
    let bytes = &bytes[end + delimiter.len()..];
    let split = bytes.windows(4).position(|x| x == b"\r\n\r\n").unwrap() + 4;
    let bundle = bytes[split..].strip_suffix(format!("\r\n--{boundary}--\r\n").as_bytes()).unwrap().to_vec();
    assert_eq!(text(&metadata, "sha256"), hex(&sha256_digest(&bundle)));
    assert_eq!(number(&metadata, "bytes"), bundle.len() as u64);
    assert!(metadata.contains("\"objects_staged\":false"));
    assert!(metadata.contains("\"publication_authorized\":false"));
    let commit = GitOid::from_hex(format, text(&metadata, "candidate_commit")).unwrap();
    Artifact { commit, bundle, metadata }
}
pub fn inspect(client: &Endpoint, base: GitOid, artifact: &Artifact) -> Reply {
    exchange(client, &change_bytes(client, "inspect", 'a', None,
        &candidate_form(base, artifact.commit), &artifact.bundle, true), true)
}
pub fn apply(client: &Endpoint, base: GitOid, artifact: &Artifact, key: &str, chunked: bool) -> Reply {
    exchange(client, &change_bytes(client, "apply", 'b', Some(key),
        &candidate_form(base, artifact.commit), &artifact.bundle, chunked), true)
}
pub fn recover(client: &Endpoint, token: char, key: &str) -> Reply {
    exchange(client, &request(client, "/api/v1/outcomes", token,
        &format!("Content-Length: 0\r\nIdempotency-Key: {key}\r\n"), &[]), true)
}
pub fn blob(client: &Endpoint, format: GitHashAlgorithm, path: &[u8]) -> Reply {
    post(client, "blob", 'a', &(common(format) + "&path_hex=" + &hex(path)), false)
}
pub fn committed(reply: &Reply) { status(reply, 200); assert!(reply.body.contains("\"outcome\":\"committed\"")); }
pub fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}
pub fn patch() -> Vec<u8> {
    concat!("diff --git a/alpha.txt b/alpha.txt\n--- a/alpha.txt\n+++ b/alpha.txt\n@@ -1,2 +1,2 @@\n",
        "-Needle needle\r\n+Edited needle\r\n ababa\n",
        "diff --git a/empty b/empty\ndeleted file mode 100644\n",
        "diff --git a/new.txt b/new.txt\nnew file mode 100644\n--- /dev/null\n+++ b/new.txt\n@@ -0,0 +1 @@\n+no final newline\n\\ No newline at end of file\n",
        "diff --git a/run b/run\nold mode 100755\nnew mode 100644\n").as_bytes().to_vec()
}
