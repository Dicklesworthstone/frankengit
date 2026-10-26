#![forbid(unsafe_code)]
//! Smart HTTP answers a push refused before admission the way git-http-backend
//! answers a fatal error: a 200 receive-pack body holding one ERR packet with
//! the typed cause, which a stock client prints as "fatal: remote error: ...".
//! A 4xx/5xx body is discarded by the client, so the cause used to be lost
//! (frankengit-yrff). The command-count bound has its own report and test
//! (smart_http_non_atomic, command_limit).

use std::io::Cursor;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_admission::{AdmissionLimits, AdmissionResult};
use fgit_authority::{IdempotencyKey, MAX_PUSH_OPTION_BYTES};
use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest, sha256_digest};
use fgit_node::{LoopbackReceiveSession, NodeConfig, NodeSmartHttpRefusal, OneNode};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, PrincipalId, RefName, RepositoryId, TenantId,
};
use fgit_wire::smart_http::{HttpLimits, parse_head};
use fgit_wire::{Packet, WireLimits, encode_packets};
use std::collections::BTreeMap;

static NEXT: AtomicU64 = AtomicU64::new(1);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "fg-http-typed-refusal-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn start(scratch: &Scratch, format: GitHashAlgorithm) -> OneNode {
    let config = NodeConfig::new(
        scratch.0.clone(),
        TenantId::from_bytes([0xf1; 16]),
        RepositoryId::from_bytes([0xf2; 16]),
    )
    .with_object_format(format);
    let mut node = OneNode::init(config).unwrap().0;
    let generation = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap()
        .receipt()
        .generation();
    node.bring_into_service(generation).unwrap();
    node
}
fn refs(node: &OneNode) -> BTreeMap<RefName, GitOid> {
    node.runtime()
        .block_on(node.materialize_admission())
        .unwrap()
        .snapshot()
        .refs
        .clone()
}
fn blob_pack(format: GitHashAlgorithm) -> (GitOid, GitOid, Vec<u8>) {
    let oid = git_object_id(format, GitObjectKind::Blob, b"x");
    let zero = GitOid::from_hex(format, &"0".repeat(format.digest_len() * 2)).unwrap();
    let mut bytes = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
    bytes.extend_from_slice(&[
        0x31, 0x78, 0x01, 0x01, 1, 0, 0xfe, 0xff, b'x', 0, 121, 0, 121,
    ]);
    let checksum = match format {
        GitHashAlgorithm::Sha1 => sha1_digest(&bytes).to_vec(),
        GitHashAlgorithm::Sha256 => sha256_digest(&bytes).to_vec(),
    };
    bytes.extend_from_slice(&checksum);
    (oid, zero, bytes)
}
/// A receive-pack request body: `names` created at `oid`, then the options
/// section when `options` is `Some`, then the pack.
fn body(
    format: GitHashAlgorithm,
    zero: GitOid,
    oid: GitOid,
    names: &[String],
    options: Option<&[Vec<u8>]>,
    pack: &[u8],
) -> Vec<u8> {
    let mut packets = Vec::new();
    for (index, name) in names.iter().enumerate() {
        let mut line = format!("{zero} {oid} {name}");
        if index == 0 {
            let options = if options.is_some() {
                " push-options"
            } else {
                ""
            };
            line = format!(
                "{line}\0report-status delete-refs object-format={}{options}",
                format.as_str()
            );
        }
        packets.push(Packet::Data(line.into_bytes()));
    }
    packets.push(Packet::Flush);
    if let Some(options) = options {
        packets.extend(options.iter().cloned().map(Packet::Data));
        packets.push(Packet::Flush);
    }
    let mut bytes = encode_packets(&packets, &WireLimits::default()).unwrap();
    bytes.extend_from_slice(pack);
    bytes
}
fn push(
    node: &OneNode,
    key: &[u8],
    body: &[u8],
) -> (Result<AdmissionResult, NodeSmartHttpRefusal>, Vec<u8>) {
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let head = format!(
        "POST {route}/git-receive-pack HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-git-receive-pack-request\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let request = parse_head(head.as_bytes(), HttpLimits::default())
        .unwrap()
        .unwrap();
    let session = LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0xf3; 16]),
        IdempotencyKey::new(key.to_vec()).unwrap(),
    );
    let mut response = Vec::new();
    let outcome = node.smart_http_receive_stream_in(
        &request,
        &session,
        &mut Cursor::new(body),
        HttpLimits::default(),
        AdmissionLimits::default(),
        &mut || true,
        &mut response,
    );
    (outcome, response)
}
/// The response is a 200 whose whole body is exactly one ERR packet naming
/// `cause`.
fn assert_typed_refusal(response: &[u8], cause: &str) {
    let text = String::from_utf8_lossy(response);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .expect("a complete HTTP response");
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    let message = format!("ERR {cause}; no ref decision was attempted\n");
    let expected = encode_packets(
        &[Packet::Data(message.into_bytes())],
        &WireLimits::default(),
    )
    .unwrap();
    assert_eq!(body.as_bytes(), expected.as_slice(), "{text}");
}

#[test]
fn a_push_option_past_the_sealable_bound_gets_a_typed_200_refusal() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = start(&scratch, format);
        let (oid, zero, pack) = blob_pack(format);
        let names = vec!["refs/tags/option".to_owned()];

        let long = vec![vec![b'o'; MAX_PUSH_OPTION_BYTES + 1]];
        let (result, response) = push(
            &node,
            b"long",
            &body(format, zero, oid, &names, Some(&long), &pack),
        );
        assert!(result.is_err());
        assert_typed_refusal(
            &response,
            "a push option is empty, longer than this server accepts, or contains NUL, CR or LF",
        );
        assert!(refs(&node).is_empty());

        let bound = vec![vec![b'o'; MAX_PUSH_OPTION_BYTES]];
        let (result, _) = push(
            &node,
            b"bound",
            &body(format, zero, oid, &names, Some(&bound), &pack),
        );
        assert!(matches!(
            result.unwrap().commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        node.shutdown().unwrap();
    }
}
