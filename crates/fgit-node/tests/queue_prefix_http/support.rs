//! Real server/client helpers around the canonical prefix fixture.
use super::{http, native};
use fgit_crypto::sha256_digest;
use fgit_node::QueuePrefixEntry;
use fgit_schema::json::{self, Value};
use fgit_types::GitHashAlgorithm;
use std::path::PathBuf;

pub(super) const ROUTE: &str = "/api/v1/queues/1/prepare-prefix";

pub(super) struct Fixture {
    pub native: native::Fixture,
    pub entries: Vec<QueuePrefixEntry>,
    credentials: PathBuf,
}
impl Fixture {
    pub fn new(format: GitHashAlgorithm, conflict: bool, queues: bool) -> Self {
        let (mut native, mut entries) = native::fixture(format, conflict);
        for entry in &mut entries {
            entry.metadata = native::metadata(0);
        }
        if queues {
            native.config = native.config.clone().with_http_queue_management();
        }
        native.reopen();
        let credentials = native.root.join("prefix-http-credentials");
        let mut contents = format!(
            "frankengit-http-credentials-v2 {} {} {}\n",
            native::TENANT,
            native::REPOSITORY,
            native.node().repository_incarnation_id(),
        );
        for (token, scopes, refs) in [
            ('a', "read,pulls-read,queues-read", "none"),
            ('b', "read,pulls-read", "none"),
            ('c', "read,queues-read", "none"),
            ('d', "pulls-read,queues-read", "none"),
            ('e', "reviews-write", "none"),
            ('f', "queues-read,queues-write,queues-land", "all"),
        ] {
            contents.push_str(&format!(
                "{} {refs}\n",
                http::row(token, http::FOREIGN, scopes).trim_end()
            ));
        }
        http::replace(&credentials, &contents);
        Self {
            native,
            entries,
            credentials,
        }
    }

    pub fn start(&mut self, requests: usize, pulls: bool) -> http::Server {
        http::Server::start(
            self.native.node.take().unwrap(),
            &self.credentials,
            requests,
            pulls,
            false,
        )
    }

    pub fn form(&self, entries: &[QueuePrefixEntry], version: u64, profile: &str) -> String {
        let first = &entries[0];
        let mut body = format!(
            concat!(
                "expected_incarnation={}&object_format={}&expected_version={}&expected_policy_epoch={}",
                "&target_ref_hex={}&expected_target_tip={}&author={}&committer={}&timestamp={}",
                "&message_hex={}&entry_count={}&profile={}"
            ),
            self.native.node().repository_incarnation_id(),
            first.subject.source_tip.algorithm().as_str(),
            version,
            first.subject.policy_epoch.get(),
            hex(first.subject.target_ref.as_bytes()),
            first.subject.target_tip,
            http::encode(first.metadata.author.as_bytes()),
            http::encode(first.metadata.committer.as_bytes()),
            first.metadata.timestamp,
            hex(&first.metadata.message),
            entries.len(),
            profile,
        );
        for (index, entry) in entries.iter().enumerate() {
            assert_eq!(entry.metadata, first.metadata);
            body.push_str(&format!(
                "&pull_request_{index}={}&expected_pull_request_version_{index}={}&source_ref_hex_{index}={}&expected_source_tip_{index}={}",
                entry.subject.pull_request.get(),
                entry.subject.pull_request_version.get(),
                hex(entry.subject.source_ref.as_bytes()),
                entry.subject.source_tip,
            ));
        }
        body
    }
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
pub(super) fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.object().unwrap().get(key).unwrap()
}
pub(super) fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    field(value, key).text().unwrap()
}
pub(super) fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    let Value::Array(values) = field(value, key) else {
        panic!("expected array {key}")
    };
    values
}
pub(super) fn replace_field(body: &str, name: &str, value: &str) -> String {
    let prefix = format!("{name}=");
    let mut found = false;
    let changed = body
        .split('&')
        .map(|part| {
            if part.starts_with(&prefix) {
                assert!(!found);
                found = true;
                format!("{name}={value}")
            } else {
                part.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("&");
    assert!(found, "missing fixture field {name}");
    changed
}

pub(super) fn send(client: &http::Endpoint, body: &str, chunked: bool) -> http::BinaryReply {
    let (wire, framing) = if chunked {
        let mut wire = Vec::new();
        for chunk in body.as_bytes().chunks(127) {
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
    http::binary_exchange(
        client,
        &http::request(
            client,
            "POST",
            ROUTE,
            'a',
            &format!("Content-Type: application/x-www-form-urlencoded\r\n{framing}"),
            &wire,
        ),
        true,
    )
}

pub(super) fn withheld(
    client: &http::Endpoint,
    token: char,
    extra: &str,
    length: usize,
) -> http::BinaryReply {
    http::binary_exchange(
        client,
        &http::request(
            client,
            "POST",
            ROUTE,
            token,
            &format!(
                "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {length}\r\nExpect: 100-continue\r\n{extra}"
            ),
            &[],
        ),
        false,
    )
}

pub(super) fn extract(reply: &http::BinaryReply) -> (Value, Vec<u8>) {
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    let boundary = reply
        .head
        .lines()
        .find_map(|line| line.strip_prefix("Content-Type: multipart/mixed; boundary="))
        .unwrap()
        .trim();
    assert!(boundary.len() <= 70);
    let body = reply
        .body
        .strip_prefix(format!("--{boundary}\r\n").as_bytes())
        .unwrap();
    let header_end = body
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap();
    let headers = std::str::from_utf8(&body[..header_end]).unwrap();
    assert!(headers.contains("application/json") && headers.contains("name=\"metadata\""));
    let body = &body[header_end + 4..];
    let delimiter = format!("\r\n--{boundary}\r\n");
    let end = body
        .windows(delimiter.len())
        .position(|bytes| bytes == delimiter.as_bytes())
        .unwrap();
    let metadata = json::parse(&body[..end]).unwrap();
    let body = &body[end + delimiter.len()..];
    let header_end = body
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap();
    let headers = std::str::from_utf8(&body[..header_end]).unwrap();
    assert!(headers.contains("application/x-git-bundle"));
    assert!(headers.contains("filename=\"candidate.bundle\""));
    let bundle = body[header_end + 4..]
        .strip_suffix(format!("\r\n--{boundary}--\r\n").as_bytes())
        .unwrap()
        .to_vec();
    let receipt = field(&metadata, "bundle");
    assert_eq!(
        field(receipt, "bytes").unsigned().unwrap(),
        bundle.len() as u64
    );
    assert_eq!(text(receipt, "sha256"), hex(&sha256_digest(&bundle)));
    read_only(&metadata);
    assert_eq!(text(&metadata, "state"), "clean");
    assert_eq!(field(&metadata, "stop"), &Value::Null);
    let id = text(&metadata, "preparation_id");
    assert_eq!(id.len(), 64);
    assert!(
        id.bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    (metadata, bundle)
}

pub(super) fn read_only(value: &Value) {
    assert_eq!(text(value, "type"), "queue_prefix_preparation");
    for name in [
        "objects_staged",
        "transaction_created",
        "merge_authorized",
        "publication_supported",
    ] {
        assert_eq!(field(value, name), &Value::Bool(false), "{name}");
    }
    assert_eq!(field(value, "read_only"), &Value::Bool(true));
    assert!(!value.object().unwrap().contains_key("landing"));
}

pub(super) fn large_message() -> Vec<u8> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut state = 0x2b98_06fe_537a_c421_u64;
    (0..48 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            alphabet[(state % alphabet.len() as u64) as usize]
        })
        .collect()
}
