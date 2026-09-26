#![forbid(unsafe_code)]
//! Real raw TCP framing, native quarantine and embedded authority. These tests
//! exercise the guarded receiver, not a hand-built outcome or transport model.

use fgit_admission::policy_bridge::receive_session::recovery::SessionRecovery;
use fgit_admission::{AdmissionLimits, AdmissionResult};
use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest, sha256_digest};
use fgit_node::{
    GitDaemonServerLimits, GitDaemonSessionTimeout, LoopbackReceiveSession, NodeConfig,
    NodeSmartHttpRefusal, OneNode,
};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, PrincipalId, RefName, RefusalCode, RepositoryId,
    TenantId,
};
use fgit_wire::smart_http::{HttpLimits, parse_head};
use fgit_wire::{Packet, WireLimits, encode_packets};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const PRINCIPAL: PrincipalId = PrincipalId::from_bytes([0xb3; 16]);
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-guarded-daemon-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn config(&self, format: GitHashAlgorithm, receive: bool) -> NodeConfig {
        let config = NodeConfig::new(
            self.0.join("node"),
            TenantId::from_bytes([0xb1; 16]),
            RepositoryId::from_bytes([0xb2; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(2)
        .with_git_daemon_session_timeout(
            GitDaemonSessionTimeout::try_new(Duration::from_secs(30)).unwrap(),
        );
        if receive {
            config.with_git_daemon_receive_principal(PRINCIPAL)
        } else {
            config
        }
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn start(config: NodeConfig, reopen: bool) -> OneNode {
    let mut node = if reopen {
        OneNode::open_existing(config).unwrap()
    } else {
        OneNode::init(config).unwrap().0
    };
    let selected = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap();
    node.bring_into_service(selected.receipt().generation())
        .unwrap();
    node
}
fn state(node: &OneNode) -> (u64, BTreeMap<RefName, GitOid>) {
    let selected = node
        .runtime()
        .block_on(node.materialize_admission())
        .unwrap();
    (
        selected.basis().generation().get(),
        selected.snapshot().refs.clone(),
    )
}
fn pack(format: GitHashAlgorithm) -> (GitOid, GitOid, Vec<u8>) {
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
fn prefix(format: GitHashAlgorithm, commands: &[(GitOid, GitOid, &str)], atomic: bool) -> Vec<u8> {
    let mut packets = Vec::new();
    for (index, (old, new, name)) in commands.iter().enumerate() {
        let mut line = format!("{old} {new} {name}");
        if index == 0 {
            line.push_str(&format!(
                "\0report-status delete-refs object-format={}{}",
                format.as_str(),
                if atomic { " atomic" } else { "" }
            ));
        }
        packets.push(Packet::Data(line.into_bytes()));
    }
    packets.push(Packet::Flush);
    encode_packets(&packets, &WireLimits::default()).unwrap()
}
fn session(route: &str, prefix: &[u8]) -> LoopbackReceiveSession {
    let mut bytes = b"frankengit.git-daemon.receive-idempotency/v1\0".to_vec();
    bytes.extend_from_slice(route.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(prefix);
    LoopbackReceiveSession::authenticated(
        PRINCIPAL,
        IdempotencyKey::new(sha256_digest(&bytes).to_vec()).unwrap(),
    )
}
fn route(node: &OneNode) -> String {
    std::str::from_utf8(node.git_daemon_repository_path().as_bytes())
        .unwrap()
        .to_owned()
}
fn connect(address: SocketAddr, route: &str) -> TcpStream {
    let mut socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    let greeting = encode_packets(
        &[Packet::Data(
            format!("git-receive-pack {route}\0host=localhost\0").into_bytes(),
        )],
        &WireLimits::default(),
    )
    .unwrap();
    // Splitting the greeting also exercises bounded non-consuming dispatch.
    for part in greeting.chunks(3) {
        socket.write_all(part).unwrap();
    }
    socket
}
fn records(socket: &mut TcpStream) -> Vec<Vec<u8>> {
    let mut rows = Vec::new();
    loop {
        let mut header = [0; 4];
        socket.read_exact(&mut header).unwrap();
        let length = usize::from_str_radix(std::str::from_utf8(&header).unwrap(), 16).unwrap();
        if length == 0 {
            return rows;
        }
        assert!((4..=65_520).contains(&length));
        let mut row = vec![0; length - 4];
        socket.read_exact(&mut row).unwrap();
        let fatal = row.starts_with(b"ERR ");
        rows.push(row);
        if fatal {
            return rows;
        }
        assert!(rows.len() <= 100, "bounded fixture response");
    }
}
fn launch(
    node: OneNode,
) -> (
    SocketAddr,
    String,
    JoinHandle<(
        OneNode,
        Result<Option<AdmissionResult>, NodeSmartHttpRefusal>,
    )>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let path = route(&node);
    let worker = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let result = node.serve_guarded_git_daemon_stream(stream);
        (node, result)
    });
    (address, path, worker)
}
fn push(
    node: OneNode,
    prefix: &[u8],
    pack: &[u8],
    truncated: bool,
) -> (
    OneNode,
    Result<Option<AdmissionResult>, NodeSmartHttpRefusal>,
    Vec<Vec<u8>>,
) {
    let (address, route, worker) = launch(node);
    let mut socket = connect(address, &route);
    let advertised = records(&mut socket);
    assert!(!advertised.is_empty() && !advertised[0].starts_with(b"ERR "));
    socket.write_all(prefix).unwrap();
    for chunk in pack.chunks(7) {
        socket.write_all(chunk).unwrap();
    }
    if truncated {
        socket.shutdown(Shutdown::Write).unwrap();
    }
    // A complete push must finish at its native frame boundary WITHOUT EOF.
    let response = records(&mut socket);
    let _ = socket.shutdown(Shutdown::Write);
    let (node, result) = worker.join().unwrap();
    (node, result, response)
}
fn mixed(result: &AdmissionResult) {
    assert_eq!(result.commands.len(), 3);
    assert!(matches!(
        result.commands[0].terminal.outcome,
        DecisionOutcome::Refused {
            code: RefusalCode::ExpectedOldRefMismatch,
            ..
        }
    ));
    assert!(
        result.commands[1..]
            .iter()
            .all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
}
fn recovered(node: &OneNode, route: &str, prefix: &[u8], expected: &AdmissionResult) {
    let before = state(node);
    let observed = node
        .runtime()
        .block_on(node.recover_receive_session_in(&node.request_context(), &session(route, prefix)))
        .unwrap();
    let SessionRecovery::Recovered(known) = observed else {
        panic!("guarded daemon must persist a descriptor")
    };
    assert!(known.all_terminal());
    assert_eq!(known.commands().len(), expected.commands.len());
    for (index, (row, result)) in known.commands().iter().zip(&expected.commands).enumerate() {
        assert_eq!(row.index(), index);
        assert_eq!(row.recovery().terminal(), Some(result.terminal));
    }
    assert_eq!(state(node), before);
}

#[test]
fn real_tcp_mixed_pushes_continue_after_refusal_and_recover_across_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format, true);
        let node = start(config.clone(), false);
        let path = route(&node);
        let before = state(&node).0;
        let (oid, zero, pack) = pack(format);
        let commands = prefix(
            format,
            &[
                (oid, oid, "refs/tags/stale"),
                (zero, oid, "refs/tags/z"),
                (zero, oid, "refs/tags/a"),
            ],
            false,
        );
        let (node, result, rows) = push(node, &commands, &pack, false);
        let first = result.unwrap().unwrap();
        mixed(&first);
        assert_eq!(
            rows,
            [
                b"unpack ok\n".to_vec(),
                b"ng refs/tags/stale stale info\n".to_vec(),
                b"ok refs/tags/z\n".to_vec(),
                b"ok refs/tags/a\n".to_vec()
            ]
        );
        assert_eq!(state(&node).0, before + 3);
        recovered(&node, &path, &commands, &first);
        let published = state(&node);
        node.shutdown().unwrap();
        let node = start(config, true);
        recovered(&node, &path, &commands, &first);
        let (node, result, retry_rows) = push(node, &commands, &pack, false);
        assert_eq!(result.unwrap().unwrap(), first);
        assert_eq!(retry_rows, rows);
        assert_eq!(state(&node), published);
        let deletes = prefix(
            format,
            &[
                (oid, zero, "refs/tags/stale"),
                (oid, zero, "refs/tags/z"),
                (oid, zero, "refs/tags/a"),
            ],
            false,
        );
        let (node, result, _) = push(node, &deletes, &[], false);
        let removed = result.unwrap().unwrap();
        mixed(&removed);
        assert!(state(&node).1.is_empty());
        recovered(&node, &path, &deletes, &removed);
        node.shutdown().unwrap();
    }
}

#[test]
fn validation_uses_post_ingress_authority_not_the_earlier_advertisement() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format, true);
        let node = start(config.clone(), false);
        let before = state(&node).0;
        let (oid, zero, pack) = pack(format);
        let (address, path, worker) = launch(node);
        let mut socket = connect(address, &path);
        let advertised = records(&mut socket);
        assert!(!advertised[0].starts_with(b"ERR "));
        // Another real writer publishes after advertisement but BEFORE this
        // request's bytes arrive. Its mutation is not part of our continuation.
        let other = start(config, true);
        let command = prefix(format, &[(zero, oid, "refs/tags/other")], true);
        let body = [command, pack.clone()].concat();
        let headers = format!(
            "POST {path}/git-receive-pack HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-git-receive-pack-request\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let head = parse_head(headers.as_bytes(), HttpLimits::default())
            .unwrap()
            .unwrap();
        let unrelated = LoopbackReceiveSession::authenticated(
            PRINCIPAL,
            IdempotencyKey::new(b"unrelated-http".to_vec()).unwrap(),
        );
        let result = other
            .smart_http_receive_rpc_in(
                &head,
                &unrelated,
                &body,
                HttpLimits::default(),
                AdmissionLimits::default(),
                &mut || true,
                &mut Vec::new(),
            )
            .unwrap();
        assert!(matches!(
            result.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        other.shutdown().unwrap();
        let commands = prefix(format, &[(zero, oid, "refs/tags/after")], false);
        socket.write_all(&commands).unwrap();
        socket.write_all(&pack).unwrap();
        let rows = records(&mut socket);
        socket.shutdown(Shutdown::Write).unwrap();
        assert_eq!(
            rows,
            [b"unpack ok\n".to_vec(), b"ok refs/tags/after\n".to_vec()]
        );
        let (node, result) = worker.join().unwrap();
        assert!(matches!(
            result.unwrap().unwrap().commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert_eq!(state(&node).0, before + 2);
        assert_eq!(state(&node).1.len(), 2);
        node.shutdown().unwrap();
    }
}

#[test]
fn atomic_failure_is_one_real_decision_and_invalid_pack_input_publishes_nothing() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let node = start(root.config(format, true), false);
        let (oid, zero, pack) = pack(format);
        let before = state(&node).0;
        let commands = prefix(
            format,
            &[
                (oid, oid, "refs/tags/stale"),
                (zero, oid, "refs/tags/valid"),
            ],
            true,
        );
        let (mut node, result, _) = push(node, &commands, &pack, false);
        let atomic = result.unwrap().unwrap();
        assert!(atomic.session.atomic);
        assert_eq!(atomic.commands[0], atomic.commands[1]);
        assert!(matches!(
            atomic.commands[0].terminal.outcome,
            DecisionOutcome::Refused { .. }
        ));
        assert_eq!(state(&node).0, before + 1);
        assert!(state(&node).1.is_empty());
        let commands = prefix(format, &[(zero, oid, "refs/tags/bad")], false);
        let before = state(&node);
        let path = route(&node);
        let mut corrupt = pack.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        for bytes in [corrupt, pack[..pack.len() - 1].to_vec()] {
            let (returned, result, rows) = push(node, &commands, &bytes, true);
            node = returned;
            assert!(result.is_err());
            assert_eq!(state(&node), before);
            assert_eq!(rows.len(), 1);
            assert!(rows[0].starts_with(b"ERR "));
            assert!(!rows[0].windows(3).any(|x| x == b"ng "));
            assert!(matches!(
                node.runtime()
                    .block_on(node.recover_receive_session_in(
                        &node.request_context(),
                        &session(&path, &commands)
                    ))
                    .unwrap(),
                SessionRecovery::NotObserved
            ));
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn bounded_supervisor_settles_duplicate_clients_without_duplicate_publication() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format, true);
        let node = start(config.clone(), false);
        let path = route(&node);
        let before = state(&node).0;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let result = node.serve_guarded_git_daemon_bounded(
                &listener,
                GitDaemonServerLimits::try_new(2, 2).unwrap(),
            );
            node.shutdown().unwrap();
            result.unwrap()
        });
        let (oid, zero, pack) = pack(format);
        let commands = prefix(format, &[(zero, oid, "refs/tags/duplicate")], false);
        let mut clients = Vec::new();
        for _ in 0..2 {
            let path = path.clone();
            let commands = commands.clone();
            let pack = pack.clone();
            clients.push(thread::spawn(move || {
                let mut socket = connect(address, &path);
                records(&mut socket);
                socket.write_all(&commands).unwrap();
                socket.write_all(&pack).unwrap();
                let rows = records(&mut socket);
                socket.shutdown(Shutdown::Write).unwrap();
                rows
            }));
        }
        let first = clients.remove(0).join().unwrap();
        let second = clients.remove(0).join().unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first,
            [
                b"unpack ok\n".to_vec(),
                b"ok refs/tags/duplicate\n".to_vec()
            ]
        );
        let receipt = server.join().unwrap();
        assert_eq!(receipt.accepted_sessions(), 2);
        assert_eq!(receipt.completed_sessions(), 2);
        assert_eq!(receipt.refused_sessions(), 0);
        let node = start(config, true);
        assert_eq!(state(&node).0, before + 1);
        assert_eq!(state(&node).1.len(), 1);
        node.shutdown().unwrap();
    }
}

#[test]
fn receive_disabled_refuses_before_advertisement_and_client_lost_receipt_is_recoverable() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format, false);
        let node = start(config, false);
        let before = state(&node);
        let (address, path, worker) = launch(node);
        let mut socket = connect(address, &path);
        let rows = records(&mut socket);
        socket.shutdown(Shutdown::Write).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].starts_with(b"ERR "));
        let (node, result) = worker.join().unwrap();
        assert!(matches!(
            result,
            Err(NodeSmartHttpRefusal::UnauthenticatedReceive)
        ));
        assert_eq!(state(&node), before);
        node.shutdown().unwrap();
        let config = root.config(format, true);
        let node = start(config.clone(), true);
        let (oid, zero, pack) = pack(format);
        let commands = prefix(format, &[(zero, oid, "refs/tags/lost")], false);
        let (address, path, worker) = launch(node);
        let mut socket = connect(address, &path);
        records(&mut socket);
        socket.write_all(&commands).unwrap();
        socket.write_all(&pack).unwrap();
        socket.shutdown(Shutdown::Write).unwrap();
        // Client deliberately never reads/stores its final report. This is a
        // lost client receipt, not an injected pre-CAS process crash.
        let (node, result) = worker.join().unwrap();
        drop(socket);
        let outcome = result.unwrap().unwrap();
        node.shutdown().unwrap();
        let node = start(config, true);
        recovered(&node, &path, &commands, &outcome);
        assert_eq!(state(&node).0, before.0 + 1);
        node.shutdown().unwrap();
    }
}

#[test]
fn a_stalled_upload_holds_no_writer_admission_while_another_push_commits() {
    // One writer admission per serving process (x2mv.4.27) covers only the
    // validation and publication after ingress. Client A stops halfway
    // through its pack; client B's complete push must still be decided
    // promptly, and A is then admitted normally once its upload completes.
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format, true);
        let node = start(config.clone(), false);
        let path = route(&node);
        let before = state(&node).0;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let result = node.serve_guarded_git_daemon_bounded(
                &listener,
                GitDaemonServerLimits::try_new(2, 2).unwrap(),
            );
            node.shutdown().unwrap();
            result.unwrap()
        });
        let (oid, zero, pack) = pack(format);
        let (half, rest) = pack.split_at(pack.len() / 2);

        let mut stalled = connect(address, &path);
        assert!(!records(&mut stalled)[0].starts_with(b"ERR "));
        stalled
            .write_all(&prefix(format, &[(zero, oid, "refs/tags/stalled")], false))
            .unwrap();
        stalled.write_all(half).unwrap();

        let started = std::time::Instant::now();
        let mut prompt = connect(address, &path);
        assert!(!records(&mut prompt)[0].starts_with(b"ERR "));
        prompt
            .write_all(&prefix(format, &[(zero, oid, "refs/tags/prompt")], false))
            .unwrap();
        prompt.write_all(&pack).unwrap();
        assert_eq!(
            records(&mut prompt),
            [b"unpack ok\n".to_vec(), b"ok refs/tags/prompt\n".to_vec()]
        );
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "a stalled upload delayed an unrelated push by {:?}",
            started.elapsed()
        );
        prompt.shutdown(Shutdown::Write).unwrap();

        // Twin: the stalled client finishes its upload and is admitted too.
        stalled.write_all(rest).unwrap();
        assert_eq!(
            records(&mut stalled),
            [b"unpack ok\n".to_vec(), b"ok refs/tags/stalled\n".to_vec()]
        );
        stalled.shutdown(Shutdown::Write).unwrap();

        let receipt = server.join().unwrap();
        assert_eq!(receipt.completed_sessions(), 2);
        assert_eq!(receipt.refused_sessions(), 0);
        let node = start(config, true);
        let (generation, refs) = state(&node);
        assert_eq!(generation, before + 2);
        assert_eq!(refs.len(), 2);
        node.shutdown().unwrap();
    }
}
