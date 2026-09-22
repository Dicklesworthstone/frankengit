#![forbid(unsafe_code)]
//! Production quarantine and durable authority, without a subprocess Git server.

use std::collections::BTreeMap;
use std::io::{self, Cursor, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_admission::{AdmissionLimits, AdmissionResult};
use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest, sha256_digest};
use fgit_node::{LoopbackReceiveSession, NodeConfig, NodeSmartHttpRefusal, OneNode};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RefName, RefusalCode,
    RepositoryId, TenantId,
};
use fgit_wire::smart_http::{HttpLimits, parse_head};
use fgit_wire::{Packet, PktLineDecoder, WireLimits, encode_packets};

static NEXT: AtomicU64 = AtomicU64::new(1);
const BLOB: &[u8] = b"continuation\n";

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "fg-http-non-atomic-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        )))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn config(root: &Scratch, format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(
        root.0.clone(),
        TenantId::from_bytes([0xd1; 16]),
        RepositoryId::from_bytes([0xd2; 16]),
    )
    .with_object_format(format)
}
fn start(config: NodeConfig, reopen: bool) -> OneNode {
    let mut node = if reopen {
        OneNode::open_existing(config).unwrap()
    } else {
        OneNode::init(config).unwrap().0
    };
    let generation = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap()
        .receipt()
        .generation();
    node.bring_into_service(generation).unwrap();
    node
}
fn state(node: &OneNode) -> (HeadGeneration, BTreeMap<RefName, GitOid>) {
    let state = node
        .runtime()
        .block_on(node.materialize_admission())
        .unwrap();
    (state.basis().generation(), state.snapshot().refs.clone())
}
fn blob_pack(format: GitHashAlgorithm) -> (GitOid, GitOid, Vec<u8>) {
    assert!(BLOB.len() < 16);
    let oid = git_object_id(format, GitObjectKind::Blob, BLOB);
    let zero = GitOid::from_hex(format, &"0".repeat(oid.as_bytes().len() * 2)).unwrap();
    let mut pack = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
    pack.push(0x30 | BLOB.len() as u8);
    let length = u16::try_from(BLOB.len()).unwrap();
    pack.extend_from_slice(&[0x78, 0x01, 0x01]);
    pack.extend_from_slice(&length.to_le_bytes());
    pack.extend_from_slice(&(!length).to_le_bytes());
    pack.extend_from_slice(BLOB);
    let (a, b) = BLOB.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521;
        (a, (b + a) % 65_521)
    });
    pack.extend_from_slice(&((b << 16) | a).to_be_bytes());
    let trailer = match format {
        GitHashAlgorithm::Sha1 => sha1_digest(&pack).to_vec(),
        GitHashAlgorithm::Sha256 => sha256_digest(&pack).to_vec(),
    };
    pack.extend_from_slice(&trailer);
    (oid, zero, pack)
}
fn perform(
    node: &OneNode,
    key: &[u8],
    commands: &[(GitOid, GitOid, &str)],
    pack: &[u8],
    atomic: bool,
    streaming: bool,
    writer: &mut impl Write,
) -> Result<AdmissionResult, NodeSmartHttpRefusal> {
    let mut packets = Vec::new();
    for (index, (old, new, name)) in commands.iter().enumerate() {
        let mut command = format!("{old} {new} {name}");
        if index == 0 {
            command.push_str(&format!(
                "\0report-status delete-refs object-format={}{}",
                new.algorithm().as_str(),
                if atomic { " atomic" } else { "" }
            ));
        }
        packets.push(Packet::Data(command.into_bytes()));
    }
    packets.push(Packet::Flush);
    let mut body = encode_packets(&packets, &WireLimits::default()).unwrap();
    body.extend_from_slice(pack);
    let framing = if streaming {
        let mut wire = Vec::new();
        for chunk in body.chunks(5) {
            wire.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            wire.extend_from_slice(chunk);
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        body = wire;
        "Transfer-Encoding: chunked\r\n".to_owned()
    } else {
        format!("Content-Length: {}\r\n", body.len())
    };
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let head = format!(
        "POST {route}/git-receive-pack HTTP/1.1\r\nHost: loopback\r\nContent-Type: application/x-git-receive-pack-request\r\n{framing}\r\n"
    );
    let request = parse_head(head.as_bytes(), HttpLimits::default())
        .unwrap()
        .unwrap();
    let session = LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0xd3; 16]),
        IdempotencyKey::new(key.to_vec()).unwrap(),
    );
    if streaming {
        node.smart_http_receive_stream_in(
            &request,
            &session,
            &mut Cursor::new(body),
            HttpLimits::default(),
            AdmissionLimits::default(),
            &mut || true,
            writer,
        )
    } else {
        node.smart_http_receive_rpc_in(
            &request,
            &session,
            &body,
            HttpLimits::default(),
            AdmissionLimits::default(),
            &mut || true,
            writer,
        )
    }
}
fn committed(result: &AdmissionResult, index: usize) {
    assert!(
        matches!(
            result.commands[index].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ),
        "{:?}",
        result.commands[index]
    );
}
fn stale(result: &AdmissionResult, index: usize) {
    assert!(
        matches!(
            result.commands[index].terminal.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::ExpectedOldRefMismatch,
                ..
            }
        ),
        "an expected-old failure must not poison later commands as a stale validation basis: {:?}",
        result.commands[index]
    );
}
fn reports(response: &[u8]) -> Vec<Vec<u8>> {
    let offset = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    let mut decoder = PktLineDecoder::new(WireLimits::default()).unwrap();
    let packets = decoder.push(&response[offset..]).unwrap();
    decoder.finish().unwrap();
    packets
        .into_iter()
        .filter_map(|packet| match packet {
            Packet::Data(line) => Some(line),
            _ => None,
        })
        .collect()
}

#[test]
fn refused_first_ref_allows_later_creates_and_deletes_with_reopenable_retries() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for streaming in [false, true] {
            let scratch = Scratch::new();
            let configuration = config(&scratch, format);
            let node = start(configuration.clone(), false);
            let (oid, zero, pack) = blob_pack(format);
            let commands = [
                (oid, oid, "refs/tags/stale"),
                (zero, oid, "refs/tags/good"),
                (zero, oid, "refs/tags/also-good"),
            ];
            let before = state(&node).0;
            let mut output = Vec::new();
            let first = perform(
                &node,
                b"mixed-create",
                &commands,
                &pack,
                false,
                streaming,
                &mut output,
            )
            .unwrap();
            assert!(!first.session.atomic);
            assert_eq!(first.session.tx_ids.len(), 3);
            assert_ne!(first.session.tx_ids[0], first.session.tx_ids[1]);
            stale(&first, 0);
            committed(&first, 1);
            committed(&first, 2);
            assert_eq!(state(&node).0.get(), before.get() + 3);
            assert_eq!(state(&node).1.len(), 2);
            assert_eq!(
                reports(&output),
                vec![
                    b"unpack ok\n".to_vec(),
                    b"ng refs/tags/stale stale info\n".to_vec(),
                    b"ok refs/tags/good\n".to_vec(),
                    b"ok refs/tags/also-good\n".to_vec()
                ]
            );
            let published = state(&node);
            node.shutdown().unwrap();
            let node = start(configuration, true);
            let retry = perform(
                &node,
                b"mixed-create",
                &commands,
                &pack,
                false,
                streaming,
                &mut Vec::new(),
            )
            .unwrap();
            assert_eq!(retry, first);
            assert_eq!(state(&node), published);
            let deletes = [
                (oid, zero, "refs/tags/stale"),
                (oid, zero, "refs/tags/good"),
                (oid, zero, "refs/tags/also-good"),
            ];
            let removed = perform(
                &node,
                b"mixed-delete",
                &deletes,
                &[],
                false,
                streaming,
                &mut Vec::new(),
            )
            .unwrap();
            stale(&removed, 0);
            committed(&removed, 1);
            committed(&removed, 2);
            assert!(state(&node).1.is_empty());
            let deleted = state(&node);
            assert_eq!(
                perform(
                    &node,
                    b"mixed-delete",
                    &deletes,
                    &[],
                    false,
                    streaming,
                    &mut Vec::new()
                )
                .unwrap(),
                removed
            );
            assert_eq!(state(&node), deleted);
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn a_middle_refusal_does_not_discard_success_before_or_after_it() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = start(config(&scratch, format), false);
        let (oid, zero, pack) = blob_pack(format);
        let commands = [
            (zero, oid, "refs/tags/first"),
            (oid, oid, "refs/tags/stale"),
            (zero, oid, "refs/tags/last"),
        ];
        let result = perform(
            &node,
            b"middle-refusal",
            &commands,
            &pack,
            false,
            true,
            &mut Vec::new(),
        )
        .unwrap();
        committed(&result, 0);
        stale(&result, 1);
        committed(&result, 2);
        let refs = state(&node).1;
        assert_eq!(refs.len(), 2);
        assert_eq!(
            refs.get(&RefName::try_new(b"refs/tags/first").unwrap()),
            Some(&oid)
        );
        assert_eq!(
            refs.get(&RefName::try_new(b"refs/tags/last").unwrap()),
            Some(&oid)
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn consecutive_refusals_keep_their_real_reason_instead_of_authority_receipt_stale() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = start(config(&scratch, format), false);
        let (oid, _, pack) = blob_pack(format);
        let commands = [
            (oid, oid, "refs/tags/one"),
            (oid, oid, "refs/tags/two"),
            (oid, oid, "refs/tags/three"),
        ];
        let before = state(&node).0;
        let result = perform(
            &node,
            b"three-refusals",
            &commands,
            &pack,
            false,
            false,
            &mut Vec::new(),
        )
        .unwrap();
        for index in 0..3 {
            stale(&result, index);
        }
        assert_eq!(state(&node).0.get(), before.get() + 3);
        assert!(state(&node).1.is_empty());
        node.shutdown().unwrap();
    }
}

#[test]
fn atomic_twin_still_refuses_every_ref_under_one_transaction() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = start(config(&scratch, format), false);
        let (oid, zero, pack) = blob_pack(format);
        let commands = [(oid, oid, "refs/tags/stale"), (zero, oid, "refs/tags/good")];
        let before = state(&node).0;
        let result = perform(
            &node,
            b"atomic-twin",
            &commands,
            &pack,
            true,
            true,
            &mut Vec::new(),
        )
        .unwrap();
        assert!(result.session.atomic);
        assert_eq!(result.session.tx_ids.len(), 1);
        stale(&result, 0);
        stale(&result, 1);
        assert_eq!(result.commands[0], result.commands[1]);
        assert_eq!(state(&node).0.get(), before.get() + 1);
        assert!(state(&node).1.is_empty());
        node.shutdown().unwrap();
    }
}

#[test]
fn a_lost_mixed_report_retains_all_outcomes_and_retry_does_not_publish_again() {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = start(config(&scratch, format), false);
        let (oid, zero, pack) = blob_pack(format);
        let commands = [(oid, oid, "refs/tags/stale"), (zero, oid, "refs/tags/good")];
        let error = perform(
            &node,
            b"lost-mixed-report",
            &commands,
            &pack,
            false,
            true,
            &mut Broken,
        )
        .unwrap_err();
        let NodeSmartHttpRefusal::ReceiveResponse { outcome, .. } = error else {
            panic!("canonical outcomes must survive failed delivery")
        };
        stale(&outcome, 0);
        committed(&outcome, 1);
        let published = state(&node);
        let recovered = perform(
            &node,
            b"lost-mixed-report",
            &commands,
            &pack,
            false,
            false,
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(recovered, *outcome);
        assert_eq!(state(&node), published);
        node.shutdown().unwrap();
    }
}

#[test]
fn the_complete_command_limit_is_checked_before_any_command_is_admitted() {
    let scratch = Scratch::new();
    let node = start(config(&scratch, GitHashAlgorithm::Sha1), false);
    let (oid, zero, pack) = blob_pack(GitHashAlgorithm::Sha1);
    let names: Vec<_> = (0..65).map(|n| format!("refs/tags/ref-{n:02}")).collect();
    let commands: Vec<_> = names
        .iter()
        .map(|name| (zero, oid, name.as_str()))
        .collect();
    let before = state(&node);
    let error = perform(
        &node,
        b"too-many-refs",
        &commands,
        &pack,
        false,
        true,
        &mut Vec::new(),
    )
    .unwrap_err();
    let NodeSmartHttpRefusal::ReceiveInterrupted(error) = error else {
        panic!("session planning preserves its typed failure")
    };
    assert!(error.session().is_none());
    assert!(error.completed_commands().is_empty());
    assert!(matches!(
        error.admission_error(),
        fgit_admission::AdmissionError::CommandLimitExceeded { limit: 64 }
    ));
    assert_eq!(state(&node), before);
    node.shutdown().unwrap();
}
