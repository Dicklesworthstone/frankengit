//! Native SSH receive with real persisted authority, quarantine and recovery.
//! Encrypted command-grant propagation is covered in fgit-ssh's session suite.

use super::*;
use crate::{LoopbackReceiveSession, NodeConfig, NodeSmartHttpRefusal};
use fgit_admission::policy_bridge::receive_session::recovery::SessionRecovery;
use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest, sha256_digest};
use fgit_types::ref_write_scope::RefWriteScope;
use fgit_types::{DecisionOutcome, GitHashAlgorithm, RefName, TenantId};
use fgit_wire::{Packet, encode_packets};
use std::io::Cursor;

const PRINCIPAL: PrincipalId = PrincipalId::from_bytes([0xb3; 16]);
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "fg-ssh-ref-scope-{}-{}",
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

#[derive(Default)]
struct Reply(Vec<u8>);
impl Write for Reply {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl ReceiveResponseWriter for Reply {
    fn restart_deadline(&mut self, _: GitDaemonSessionDeadline) {}
}

fn grant(scope: &str) -> SshCommandGrant {
    SshCommandGrant::new(PRINCIPAL, RefWriteScope::parse(scope).unwrap())
}
fn deadline() -> GitDaemonSessionDeadline {
    GitDaemonSessionDeadline::new(
        crate::GitDaemonSessionTimeout::try_new(Duration::from_secs(60)).unwrap(),
        GitDaemonSessionWorkScaling::FLAT,
    )
}
fn generation(node: &OneNode) -> u64 {
    node.runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap()
        .receipt()
        .generation()
        .get()
}
fn prefix(format: GitHashAlgorithm) -> Vec<u8> {
    let zero = "0".repeat(format.digest_len() * 2);
    let oid = git_object_id(format, GitObjectKind::Blob, b"x");
    let mut first = format!("{zero} {oid} ").into_bytes();
    first.extend_from_slice(b"refs/tags/agent/topic-\xff");
    first
        .extend_from_slice(format!("\0report-status object-format={}", format.as_str()).as_bytes());
    encode_packets(
        &[
            Packet::Data(first),
            Packet::Data(format!("{zero} {oid} refs/tags/release").into_bytes()),
            Packet::Flush,
        ],
        &WireLimits::default(),
    )
    .unwrap()
}
fn pack(format: GitHashAlgorithm) -> Vec<u8> {
    let mut bytes = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
    bytes.extend_from_slice(&[
        0x31, 0x78, 0x01, 0x01, 1, 0, 0xfe, 0xff, b'x', 0, 121, 0, 121,
    ]);
    let checksum = match format {
        GitHashAlgorithm::Sha1 => sha1_digest(&bytes).to_vec(),
        GitHashAlgorithm::Sha256 => sha256_digest(&bytes).to_vec(),
    };
    bytes.extend_from_slice(&checksum);
    bytes
}
fn identity(node: &OneNode, prefix: &[u8]) -> LoopbackReceiveSession {
    let bytes = [
        b"frankengit.git-daemon.receive-idempotency/v1\0".as_slice(),
        node.git_daemon_repository_path().as_bytes(),
        &[0],
        prefix,
    ]
    .concat();
    LoopbackReceiveSession::authenticated(
        PRINCIPAL,
        IdempotencyKey::new(sha256_digest(&bytes).to_vec()).unwrap(),
    )
}
fn serve(
    node: &OneNode,
    input: &mut Cursor<Vec<u8>>,
    output: &mut Reply,
    grant: Option<SshCommandGrant>,
) -> Result<Option<fgit_admission::AdmissionResult>, NodeSmartHttpRefusal> {
    node.serve_ssh_receive_pack(
        input,
        output,
        grant,
        b"",
        &crate::WriterGate::new(1),
        &PushQuota::default(),
        &deadline(),
    )
}

#[test]
fn ssh_ref_scope_preflight_prevents_a_non_atomic_prefix_and_preserves_durable_recovery() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let config = NodeConfig::new(
            scratch.0.clone(),
            TenantId::from_bytes([0xb1; 16]),
            RepositoryId::from_bytes([0xb2; 16]),
        )
        .with_worker_threads(1)
        .with_object_format(format)
        .with_git_daemon_receive_principal(PRINCIPAL);
        let (mut node, _) = OneNode::init(config.clone()).unwrap();
        let selected = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        node.bring_into_service(selected.receipt().generation())
            .unwrap();
        let before = generation(&node);
        let prefix = prefix(format);
        let session = identity(&node, &prefix);
        let body = [prefix.clone(), pack(format)].concat();
        let mut input = Cursor::new(body.clone());
        let mut output = Reply::default();
        let result = serve(
            &node,
            &mut input,
            &mut output,
            Some(grant("prefix:726566732f746167732f6167656e742f")),
        );
        assert!(matches!(
            result,
            Err(NodeSmartHttpRefusal::RefWriteScopeDenied)
        ));
        assert_eq!(
            input.position(),
            prefix.len() as u64,
            "denied sibling refuses before consuming PACK bytes"
        );
        assert_eq!(generation(&node), before);
        assert!(
            node.runtime()
                .block_on(node.materialize_admission())
                .unwrap()
                .snapshot()
                .refs
                .is_empty()
        );
        assert_eq!(
            node.runtime()
                .block_on(node.recover_receive_session_in(&node.request_context(), &session))
                .unwrap(),
            SessionRecovery::NotObserved
        );
        assert!(
            output
                .0
                .windows(b"credential does not permit".len())
                .any(|window| window == b"credential does not permit")
        );

        let allowed = serve(
            &node,
            &mut Cursor::new(body.clone()),
            &mut Reply::default(),
            Some(grant("prefix:726566732f746167732f")),
        )
        .unwrap()
        .unwrap();
        assert_eq!(allowed.commands.len(), 2);
        for command in &allowed.commands {
            assert!(matches!(
                command.terminal.outcome,
                DecisionOutcome::Committed { .. }
            ));
        }
        let after = generation(&node);
        assert!(after > before);
        let selected = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert!(
            selected
                .snapshot()
                .refs
                .contains_key(&RefName::try_new(b"refs/tags/agent/topic-\xff").unwrap())
        );
        assert!(
            selected
                .snapshot()
                .refs
                .contains_key(&RefName::try_new(b"refs/tags/release").unwrap())
        );
        drop(selected);
        node.shutdown().unwrap();

        let mut node = OneNode::open_existing(config).unwrap();
        let selected = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        node.bring_into_service(selected.receipt().generation())
            .unwrap();
        let mut input = Cursor::new(body);
        assert!(matches!(
            serve(
                &node,
                &mut input,
                &mut Reply::default(),
                Some(grant("none"))
            ),
            Err(NodeSmartHttpRefusal::RefWriteScopeDenied)
        ));
        assert_eq!(input.position(), prefix.len() as u64);
        assert_eq!(generation(&node), after);
        let SessionRecovery::Recovered(recovered) = node
            .runtime()
            .block_on(node.recover_receive_session_in(&node.request_context(), &session))
            .unwrap()
        else {
            panic!("original session remains recoverable");
        };
        assert!(recovered.all_terminal());
        for (command, original) in recovered.commands().iter().zip(&allowed.commands) {
            assert_eq!(command.recovery().terminal(), Some(original.terminal));
        }
        // The raw-daemon operator principal must never fill in a missing SSH grant.
        let mut input = Cursor::new(prefix);
        assert!(matches!(
            serve(&node, &mut input, &mut Reply::default(), None),
            Err(NodeSmartHttpRefusal::UnauthenticatedReceive)
        ));
        assert_eq!(input.position(), 0);
        assert_eq!(generation(&node), after);
        node.shutdown().unwrap();
    }
}
