#![forbid(unsafe_code)]
//! Actual native quarantine and embedded authority through two authenticated
//! adapters. Tests the new raw session API / HTTP RPC parity, not the legacy
//! TCP daemon's key derivation or stock-Git network interoperability.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use fgit_admission::{AdmissionError, AdmissionLimits, AdmissionResult};
use fgit_admission::policy_bridge::receive_session::recovery::SessionRecovery;
use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest, sha256_digest};
use fgit_git_object::ParseLimits;
use fgit_node::{LoopbackReceiveSession, NodeConfig, NodeSmartHttpRefusal, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, PrincipalId, RefName,
    RefusalCode, RepositoryId, TenantId};
use fgit_wire::{Capabilities, Packet, WireLimits, encode_packets};
use fgit_wire::receive::{ReceiveContext, ReceiveLimits, SignedPushProfile};
use fgit_wire::smart_http::{HttpLimits, parse_head};

static NEXT: AtomicU64 = AtomicU64::new(0);
const PRINCIPAL: PrincipalId = PrincipalId::from_bytes([0xe3; 16]);
const BLOB: &[u8] = b"continuation\n";
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("fg-receive-parity-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))))
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(self.0.clone(), TenantId::from_bytes([0xe1; 16]),
            RepositoryId::from_bytes([0xe2; 16])).with_object_format(format)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}
fn start(config: NodeConfig, reopen: bool) -> OneNode {
    let mut node = if reopen { OneNode::open_existing(config).unwrap() }
        else { OneNode::init(config).unwrap().0 };
    let generation = node.runtime().block_on(node.authenticate_authority_head()).unwrap()
        .receipt().generation();
    node.bring_into_service(generation).unwrap();
    node
}
fn state(node: &OneNode) -> (u64, BTreeMap<RefName, GitOid>) {
    let selected = node.runtime().block_on(node.materialize_admission()).unwrap();
    (selected.basis().generation().get(), selected.snapshot().refs.clone())
}
fn session(key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(PRINCIPAL, IdempotencyKey::new(key.to_vec()).unwrap())
}
fn pack(format: GitHashAlgorithm) -> (GitOid, GitOid, Vec<u8>) {
    assert!(BLOB.len() < 16);
    let oid = git_object_id(format, GitObjectKind::Blob, BLOB);
    let zero = GitOid::from_hex(format, &"0".repeat(format.digest_len() * 2)).unwrap();
    let mut bytes = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
    bytes.push(0x30 | u8::try_from(BLOB.len()).unwrap());
    let length = u16::try_from(BLOB.len()).unwrap();
    bytes.extend_from_slice(&[0x78, 0x01, 0x01]);
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(&(!length).to_le_bytes());
    bytes.extend_from_slice(BLOB);
    let (a, b) = BLOB.iter().fold((1_u32, 0_u32), |(a, b), value| {
        let a = (a + u32::from(*value)) % 65_521; (a, (b + a) % 65_521)
    });
    bytes.extend_from_slice(&((b << 16) | a).to_be_bytes());
    let trailer = match format {
        GitHashAlgorithm::Sha1 => sha1_digest(&bytes).to_vec(),
        GitHashAlgorithm::Sha256 => sha256_digest(&bytes).to_vec(),
    };
    bytes.extend_from_slice(&trailer);
    (oid, zero, bytes)
}
fn body(format: GitHashAlgorithm, commands: &[(GitOid, GitOid, &str)],
    pack: &[u8], atomic: bool) -> Vec<u8> {
    let mut packets = Vec::new();
    for (index, (old, new, name)) in commands.iter().enumerate() {
        let mut row = format!("{old} {new} {name}");
        if index == 0 {
            row.push_str(&format!("\0report-status delete-refs object-format={}{}",
                format.as_str(), if atomic { " atomic" } else { "" }));
        }
        packets.push(Packet::Data(row.into_bytes()));
    }
    packets.push(Packet::Flush);
    let mut bytes = encode_packets(&packets, &WireLimits::default()).unwrap();
    bytes.extend_from_slice(pack); bytes
}
fn wire_context(format: GitHashAlgorithm) -> ReceiveContext {
    let limits = ReceiveLimits::default();
    let caps = format!("report-status atomic delete-refs object-format={}", format.as_str());
    let capabilities = Capabilities::parse_v1(caps.as_bytes(), &limits.wire).unwrap();
    ReceiveContext::new(format, capabilities, limits, SignedPushProfile::Refuse).unwrap()
}
fn raw(node: &OneNode, format: GitHashAlgorithm, key: &[u8], bytes: &[u8])
    -> Result<AdmissionResult, NodeSmartHttpRefusal> {
    let request = node.request_context();
    let selected = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
    node.runtime().block_on(node.receive_pack_session_durable_in(
        &request, &session(key), &selected, wire_context(format), bytes,
        ParseLimits { tree_reference_bytes: format.digest_len(), ..ParseLimits::default() },
        AdmissionLimits::default(), &mut || true,
    ))
}
fn http(node: &OneNode, key: &[u8], bytes: &[u8], chunked: bool) -> AdmissionResult {
    let (input, framing) = if chunked {
        let mut wire = Vec::new();
        for chunk in bytes.chunks(7) {
            wire.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            wire.extend_from_slice(chunk); wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        (wire, "Transfer-Encoding: chunked\r\n".to_owned())
    } else { (bytes.to_vec(), format!("Content-Length: {}\r\n", bytes.len())) };
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let head = format!("POST {route}/git-receive-pack HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-git-receive-pack-request\r\n{framing}\r\n");
    let request = parse_head(head.as_bytes(), HttpLimits::default()).unwrap().unwrap();
    node.smart_http_receive_stream_in(&request, &session(key), &mut Cursor::new(input),
        HttpLimits::default(), AdmissionLimits::default(), &mut || true, &mut Vec::new()).unwrap()
}
fn mixed(result: &AdmissionResult) {
    assert!(!result.session.atomic); assert_eq!(result.commands.len(), 3);
    assert!(matches!(result.commands[0].terminal.outcome, DecisionOutcome::Refused {
        code: RefusalCode::ExpectedOldRefMismatch, .. }));
    for index in [1, 2] {
        assert!(matches!(result.commands[index].terminal.outcome, DecisionOutcome::Committed { .. }), "{result:?}");
    }
}
fn recover(node: &OneNode, key: &[u8], expected: &AdmissionResult, names: &[&str]) {
    let request = node.request_context();
    let recovered = node.runtime().block_on(node.recover_receive_session_in(&request, &session(key))).unwrap();
    let SessionRecovery::Recovered(recovered) = recovered else { panic!("raw admission must record its whole session") };
    assert!(recovered.all_terminal()); assert_eq!(recovered.commands().len(), names.len());
    for (index, command) in recovered.commands().iter().enumerate() {
        assert_eq!(command.index(), index);
        assert_eq!(command.reference().as_bytes(), names[index].as_bytes());
        assert_eq!(command.recovery().terminal(), Some(expected.commands[index].terminal));
    }
}

#[test]
fn raw_mixed_create_delete_sessions_retry_over_http_and_recover_after_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let node = start(config.clone(), false);
        let (oid, zero, pack) = pack(format);
        let names = ["refs/tags/stale", "refs/tags/z", "refs/tags/a"];
        let commands = [(oid, oid, names[0]), (zero, oid, names[1]), (zero, oid, names[2])];
        let bytes = body(format, &commands, &pack, false);
        let before = state(&node).0;
        let first = raw(&node, format, b"cross-create", &bytes).unwrap();
        mixed(&first); assert_eq!(state(&node).0, before + 3);
        assert_eq!(state(&node).1.len(), 2);
        let published = state(&node);
        assert_eq!(http(&node, b"cross-create", &bytes, true), first);
        recover(&node, b"cross-create", &first, &names);
        assert_eq!(state(&node), published);
        node.shutdown().unwrap();
        let node = start(config, true);
        recover(&node, b"cross-create", &first, &names);
        assert_eq!(raw(&node, format, b"cross-create", &bytes).unwrap(), first);
        assert_eq!(state(&node), published);
        let deletes = [(oid, zero, names[0]), (oid, zero, names[1]), (oid, zero, names[2])];
        let bytes = body(format, &deletes, &[], false);
        let removed = raw(&node, format, b"cross-delete", &bytes).unwrap();
        mixed(&removed); assert!(state(&node).1.is_empty());
        let deleted = state(&node);
        assert_eq!(http(&node, b"cross-delete", &bytes, false), removed);
        recover(&node, b"cross-delete", &removed, &names);
        assert_eq!(state(&node), deleted); node.shutdown().unwrap();
    }
}

#[test]
fn http_session_bindings_cannot_be_extended_shortened_or_reordered_through_raw_admission() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let node = start(root.config(format), false);
        let (oid, zero, pack) = pack(format);
        let a = (zero, oid, "refs/tags/a"); let b = (zero, oid, "refs/tags/b");
        let original = body(format, &[a, b], &pack, false);
        let first = http(&node, b"closed-session", &original, false);
        assert!(first.commands.iter().all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. })));
        let before = state(&node);
        for changed in [vec![a], vec![a, b, (zero, oid, "refs/tags/c")], vec![b, a]] {
            let error = raw(&node, format, b"closed-session", &body(format, &changed, &pack, false)).unwrap_err();
            assert!(matches!(error, NodeSmartHttpRefusal::ReceiveInterrupted(ref error)
                if matches!(error.admission_error(), AdmissionError::Seal(_))), "{error:?}");
            assert_eq!(state(&node), before);
        }
        assert_eq!(raw(&node, format, b"closed-session", &original).unwrap(), first);
        recover(&node, b"closed-session", &first, &[a.2, b.2]);
        assert_eq!(state(&node), before); node.shutdown().unwrap();
    }
}

#[test]
fn atomic_raw_twin_keeps_one_decision_and_the_original_transaction_recovery_path() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let node = start(root.config(format), false);
        let (oid, zero, pack) = pack(format);
        let bytes = body(format, &[(oid, oid, "refs/tags/stale"),
            (zero, oid, "refs/tags/good")], &pack, true);
        let before = state(&node).0;
        let result = raw(&node, format, b"atomic-twin", &bytes).unwrap();
        assert!(result.session.atomic); assert_eq!(result.session.tx_ids.len(), 1);
        assert_eq!(result.commands[0], result.commands[1]);
        assert!(matches!(result.commands[0].terminal.outcome, DecisionOutcome::Refused {
            code: RefusalCode::ExpectedOldRefMismatch, .. }));
        assert_eq!(state(&node).0, before + 1); assert!(state(&node).1.is_empty());
        assert_eq!(http(&node, b"atomic-twin", &bytes, true), result);
        let request = node.request_context();
        let recovered = node.runtime().block_on(node.recover_transaction_in(&request, &session(b"atomic-twin"))).unwrap();
        assert_eq!(recovered.terminal(), Some(result.commands[0].terminal));
        assert_eq!(state(&node).0, before + 1); node.shutdown().unwrap();
    }
}

#[test]
fn corrupt_truncated_and_over_limit_native_input_create_no_session_binding() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let node = start(root.config(format), false);
        let (oid, zero, pack) = pack(format);
        let good = body(format, &[(zero, oid, "refs/tags/a")], &pack, false);
        let mut corrupt = good.clone(); *corrupt.last_mut().unwrap() ^= 1;
        let mut trailing = good.clone(); trailing.extend_from_slice(b"extra");
        let before = state(&node);
        for input in [&corrupt[..], &good[..good.len() - 1], &trailing[..]] {
            assert!(raw(&node, format, b"invalid-input", input).is_err());
            assert_eq!(state(&node), before);
            assert!(node.read_git_object(oid).is_err());
            assert!(matches!(node.runtime().block_on(node.recover_receive_session_in(
                &node.request_context(), &session(b"invalid-input"))).unwrap(), SessionRecovery::NotObserved));
        }
        let request = node.request_context();
        let selected = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        let two = body(format, &[(zero, oid, "refs/tags/a"), (zero, oid, "refs/tags/b")], &pack, false);
        let error = node.runtime().block_on(node.receive_pack_session_durable_in(
            &request, &session(b"command-limit"), &selected, wire_context(format), &two,
            ParseLimits { tree_reference_bytes: format.digest_len(), ..ParseLimits::default() },
            AdmissionLimits { max_commands: 1, ..AdmissionLimits::default() }, &mut || true,
        )).unwrap_err();
        assert!(matches!(error, NodeSmartHttpRefusal::ReceiveInterrupted(error)
            if error.session().is_none() && error.completed_commands().is_empty()
                && matches!(error.admission_error(), AdmissionError::CommandLimitExceeded { limit: 1 })));
        // Quarantine may have staged objects before the admission command bound;
        // that is not publication and must not produce a session descriptor.
        assert_eq!(state(&node), before);
        assert!(matches!(node.runtime().block_on(node.recover_receive_session_in(
            &node.request_context(), &session(b"command-limit"))).unwrap(), SessionRecovery::NotObserved));
        node.shutdown().unwrap();
    }
}

#[test]
fn authentication_cell_state_format_and_cancellation_guard_native_retention() {
    use fgit_node::NodeReceiveTransportRefusal;
    use fgit_wire::receive::ReceiveError;
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (mut node, _) = OneNode::init(root.config(format)).unwrap();
        let request = node.request_context();
        let selected = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        let call = |session: &LoopbackReceiveSession| node.runtime().block_on(node.receive_pack_session_durable_in(
            &request, session, &selected, wire_context(format), b"not git", ParseLimits::default(),
            AdmissionLimits::default(), &mut || true,
        ));
        assert!(matches!(call(&LoopbackReceiveSession::Anonymous), Err(NodeSmartHttpRefusal::UnauthenticatedReceive)));
        assert!(matches!(call(&session(b"not-serving")), Err(NodeSmartHttpRefusal::ReceiveTransport(error))
            if matches!(*error, NodeReceiveTransportRefusal::CellState(_))));
        let generation = selected.basis().generation();
        drop(selected);
        node.bring_into_service(generation).unwrap();
        let (oid, zero, pack) = pack(format);
        let good = body(format, &[(zero, oid, "refs/tags/a")], &pack, false);
        let request = node.request_context();
        let selected = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        let other = match format { GitHashAlgorithm::Sha1 => GitHashAlgorithm::Sha256,
            GitHashAlgorithm::Sha256 => GitHashAlgorithm::Sha1 };
        assert!(matches!(node.runtime().block_on(node.receive_pack_session_durable_in(
            &request, &session(b"wrong-format"), &selected, wire_context(other), &good,
            ParseLimits::default(), AdmissionLimits::default(), &mut || true,
        )), Err(NodeSmartHttpRefusal::Receive(error))
            if matches!(*error, ReceiveError::AuthoritativeRefusal(RefusalCode::HashAlgorithmDomainMismatch))));
        let before = state(&node);
        let mut checkpoints = 0;
        assert!(node.runtime().block_on(node.receive_pack_session_durable_in(
            &request, &session(b"cancelled"), &selected, wire_context(format), &good,
            ParseLimits::default(), AdmissionLimits::default(), &mut || { checkpoints += 1; false },
        )).is_err());
        assert_eq!(checkpoints, 1);
        assert_eq!(state(&node), before);
        assert!(node.read_git_object(oid).is_err());
        assert!(matches!(node.runtime().block_on(node.recover_receive_session_in(
            &node.request_context(), &session(b"cancelled"))).unwrap(), SessionRecovery::NotObserved));
        node.shutdown().unwrap();
    }
}
