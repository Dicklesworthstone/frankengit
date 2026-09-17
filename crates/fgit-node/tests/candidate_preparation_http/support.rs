//! Test-only TCP client and native Git fixtures. No alternate serving engine.
#[path = "../review_merge_http/support.rs"]
mod common;
pub use common::*;

use std::fs;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::path::Path;
use fgit_crypto::{GitObjectKind, git_object_id, sha256_digest};
use fgit_forge::event::pull_request::PullRequestData;
use fgit_forge::event::review::CandidateBinding;
use fgit_node::OneNode;
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, PolicyEpoch, RefName};

#[derive(Debug, Eq, PartialEq)]
pub struct BinaryReply {
    pub status: u16,
    pub head: String,
    pub body: Vec<u8>,
}
pub fn binary_exchange(endpoint: &Endpoint, bytes: &[u8], half_close: bool) -> BinaryReply {
    let mut socket = connection(endpoint);
    socket.write_all(bytes).unwrap();
    if half_close { socket.shutdown(Shutdown::Write).unwrap(); }
    let mut response = Vec::new();
    (&mut socket).take(4 * 1024 * 1024 + 1).read_to_end(&mut response).unwrap();
    assert!(response.len() <= 4 * 1024 * 1024, "fixture response exceeded its envelope");
    let split = response.windows(4).position(|bytes| bytes == b"\r\n\r\n").unwrap() + 4;
    let head = String::from_utf8(response[..split].to_vec()).unwrap();
    let length: usize = head.lines().find_map(|line| line.strip_prefix("Content-Length: ")).unwrap().trim().parse().unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    let body = response[split..].to_vec();
    assert_eq!(body.len(), length, "no truncation or appended second response");
    BinaryReply { status, head, body }
}
pub fn preparation_form(data: &PullRequestData, epoch: PolicyEpoch) -> String {
    format!(concat!("object_format={}&pull_request_version=1&policy_epoch={}&source_ref={}&target_ref={}",
        "&source_tip={}&target_tip={}&author=Fixture+%3Cfixture%40example.invalid%3E",
        "&committer=Fixture+%3Cfixture%40example.invalid%3E&timestamp=1&message=Remote+candidate%0A"),
        data.source_tip.algorithm().as_str(), epoch.get(), data.source_ref, data.target_ref,
        data.source_tip, data.target_tip)
}
pub fn prepare_bytes(endpoint: &Endpoint, number: u64, token: char, body: &str, chunked: bool) -> Vec<u8> {
    let (wire, framing) = if chunked {
        let mut wire = Vec::new();
        for bytes in body.as_bytes().chunks(13) {
            wire.extend_from_slice(format!("{:x}\r\n", bytes.len()).as_bytes());
            wire.extend_from_slice(bytes); wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        (wire, "Transfer-Encoding: chunked\r\n".to_owned())
    } else { (body.as_bytes().to_vec(), format!("Content-Length: {}\r\n", body.len())) };
    request(endpoint, "POST", &format!("/api/v1/pulls/{number}/prepare"), token,
        &format!("Content-Type: application/x-www-form-urlencoded\r\n{framing}"), &wire)
}
pub fn prepare(endpoint: &Endpoint, number: u64, token: char, body: &str, chunked: bool) -> BinaryReply {
    binary_exchange(endpoint, &prepare_bytes(endpoint, number, token, body, chunked), true)
}
// These readers inspect only fixed fixture scalar/hex fields, not arbitrary JSON.
// Production response JSON and the external-client example use proper decoders.
pub fn numeric(text: &str, key: &str) -> u64 {
    let prefix = format!("\"{key}\":");
    text.split_once(&prefix).unwrap().1.split(|c: char| !c.is_ascii_digit()).next().unwrap().parse().unwrap()
}
fn text<'a>(value: &'a str, key: &str) -> &'a str {
    value.split_once(&format!("\"{key}\":\"")).unwrap().1.split('"').next().unwrap()
}
pub fn extract(reply: &BinaryReply, data: PullRequestData) -> (Candidate, String) {
    assert_eq!(reply.status, 200, "{}", String::from_utf8_lossy(&reply.body));
    let content_type = reply.head.lines().find_map(|line| line.strip_prefix("Content-Type: ")).unwrap();
    let boundary = content_type.strip_prefix("multipart/mixed; boundary=").unwrap().trim();
    assert!(boundary.len() <= 70);
    let body = reply.body.strip_prefix(format!("--{boundary}\r\n").as_bytes()).unwrap();
    let header_end = body.windows(4).position(|bytes| bytes == b"\r\n\r\n").unwrap();
    let metadata_headers = std::str::from_utf8(&body[..header_end]).unwrap();
    assert!(metadata_headers.contains("application/json"));
    assert!(metadata_headers.contains("name=\"metadata\""));
    let body = &body[header_end + 4..];
    let delimiter = format!("\r\n--{boundary}\r\n");
    let metadata_end = body.windows(delimiter.len()).position(|bytes| bytes == delimiter.as_bytes()).unwrap();
    let metadata = String::from_utf8(body[..metadata_end].to_vec()).unwrap();
    let body = &body[metadata_end + delimiter.len()..];
    let header_end = body.windows(4).position(|bytes| bytes == b"\r\n\r\n").unwrap();
    let bundle_headers = std::str::from_utf8(&body[..header_end]).unwrap();
    assert!(bundle_headers.contains("application/x-git-bundle"));
    let bundle = body[header_end + 4..].strip_suffix(format!("\r\n--{boundary}--\r\n").as_bytes()).unwrap().to_vec();
    assert_eq!(numeric(&metadata, "bytes"), bundle.len() as u64);
    let checksum: String = sha256_digest(&bundle).iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(text(&metadata, "sha256"), checksum);
    assert!(metadata.contains("\"read_only\":true"));
    assert!(metadata.contains("\"objects_staged\":false"));
    assert!(metadata.contains("\"transaction_created\":false"));
    assert!(metadata.contains("\"merge_authorized\":false"));
    assert_eq!(text(&metadata, "source_tip"), data.source_tip.to_string());
    assert_eq!(text(&metadata, "target_tip"), data.target_tip.to_string());
    let format = data.source_tip.algorithm();
    let binding = CandidateBinding { merge_base: GitOid::from_hex(format, text(&metadata, "merge_base")).unwrap(),
        commit: GitOid::from_hex(format, text(&metadata, "commit")).unwrap() };
    let epoch = PolicyEpoch::try_new(numeric(&metadata, "policy_epoch")).unwrap();
    assert!(bundle.starts_with(match format { GitHashAlgorithm::Sha1 => b"# v2 git bundle\n".as_slice(),
        GitHashAlgorithm::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".as_slice() }));
    (Candidate { data, binding, epoch, bundle }, metadata)
}

fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, name: &str, body: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, body);
    let raw = [format!("{name} {}\0", body.len()).as_bytes(), body].concat();
    let length = u16::try_from(raw.len()).unwrap();
    let mut encoded = vec![0x78, 0x01, 0x01];
    encoded.extend(length.to_le_bytes()); encoded.extend((!length).to_le_bytes()); encoded.extend(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), value| {
        let next = (a + u32::from(*value)) % 65_521; (next, (b + next) % 65_521)
    });
    encoded.extend(((b << 16) | a).to_be_bytes());
    let hex = id.to_string(); let directory = root.join("objects").join(&hex[..2]);
    fs::create_dir_all(&directory).unwrap(); fs::write(directory.join(&hex[2..]), encoded).unwrap(); id
}
pub fn non_clean_fixture(root: &Scratch, format: GitHashAlgorithm, conflict: bool) -> (OneNode, PullRequestData) {
    let (mut node, _) = OneNode::init(root.config(format)).unwrap();
    let selected = node.runtime().block_on(node.authenticate_authority_head()).unwrap();
    node.bring_into_service(selected.receipt().generation()).unwrap();
    let source = root.0.join("source-conflict"); fs::create_dir_all(source.join("refs/heads")).unwrap();
    fs::write(source.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    fs::write(source.join("config"), match format {
        GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
        GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
    }).unwrap();
    let tree = |content: &[u8]| {
        let blob = loose(&source, format, GitObjectKind::Blob, "blob", content);
        loose(&source, format, GitObjectKind::Tree, "tree", &[b"100644 file\xff.txt\0".as_slice(), blob.as_bytes()].concat())
    };
    let commit = |tree: GitOid, parent: Option<GitOid>, message: &str| {
        let mut body = format!("tree {tree}\n");
        if let Some(parent) = parent { body.push_str(&format!("parent {parent}\n")); }
        body.push_str("author Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\n");
        body.push_str(message); body.push('\n');
        loose(&source, format, GitObjectKind::Commit, "commit", body.as_bytes())
    };
    let base = commit(tree(b"base\n"), None, "base");
    let ours = commit(tree(b"left\n"), Some(base), "ours");
    let theirs = if conflict { commit(tree(b"right\n"), Some(base), "theirs") } else { base };
    fs::write(source.join("refs/heads/main"), format!("{ours}\n")).unwrap();
    fs::write(source.join("refs/heads/topic"), format!("{theirs}\n")).unwrap();
    let imported = node.runtime().block_on(node.import_loose_git_directory_durable_in(
        &node.request_context(), &source, OWNER, b"non-clean-fixture")).unwrap();
    assert!(imported.commands.iter().all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. })));
    (node, PullRequestData { source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
        target_ref: RefName::try_new(b"refs/heads/main").unwrap(), source_tip: theirs, target_tip: ours,
        title: "Non-clean candidate".into(), body: String::new() })
}

#[test]
fn candidate_forms_preserve_reference_bytes() {
    let root = Scratch::new();
    let (node, mut candidate) = prepared(&root, GitHashAlgorithm::Sha1);
    node.shutdown().unwrap();
    for (raw, encoded) in [
        (b"refs/heads/a+b&c%d".as_slice(), "refs%2Fheads%2Fa%2Bb%26c%25d"),
        (b"refs/heads/nonutf8\xff".as_slice(), "refs%2Fheads%2Fnonutf8%FF"),
    ] {
        candidate.data.source_ref = RefName::try_new(raw).unwrap();
        candidate.data.target_ref = RefName::try_new(raw).unwrap();
        for body in [common(&candidate), preparation_form(&candidate.data, candidate.epoch)] {
            for field in ["source_ref", "target_ref"] {
                let prefix = format!("{field}=");
                let values: Vec<_> = body.split('&').filter_map(|part| part.strip_prefix(&prefix)).collect();
                assert_eq!(values, [encoded], "{body}");
            }
        }
    }
}
