use super::*;
use crate::NodeConfig;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_types::{DecisionOutcome, HeadGeneration, RepositoryId, TenantId};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-import-profile-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn object(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, body);
    let text = id.to_string();
    let path = root.join("objects").join(&text[..2]).join(&text[2..]);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut raw = format!("{} {}\0", kind.label(), body.len()).into_bytes();
    raw.extend(body);
    let n = u16::try_from(raw.len()).unwrap();
    let mut bytes = vec![0x78, 0x01, 0x01];
    bytes.extend(n.to_le_bytes());
    bytes.extend((!n).to_le_bytes());
    bytes.extend(&raw);
    let (mut a, mut b) = (1_u32, 0_u32);
    for byte in raw {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    bytes.extend(((b << 16) | a).to_be_bytes());
    fs::write(path, bytes).unwrap();
    id
}
fn fixture(scratch: &Scratch, format: GitHashAlgorithm) -> (OneNode, PathBuf, u64) {
    let source = scratch.0.join("source");
    fs::create_dir(&source).unwrap();
    let blob_body = b"native profile contents";
    let blob = object(&source, format, GitObjectKind::Blob, blob_body);
    let tree_body = [b"100644 file\0".as_slice(), blob.as_bytes()].concat();
    let tree = object(&source, format, GitObjectKind::Tree, &tree_body);
    let commit_body = format!(
        "tree {tree}\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\nprofile\n"
    );
    let commit = object(
        &source,
        format,
        GitObjectKind::Commit,
        commit_body.as_bytes(),
    );
    fs::create_dir_all(source.join("refs/heads")).unwrap();
    fs::write(source.join("refs/heads/main"), format!("{commit}\n")).unwrap();
    fs::write(source.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    let config = NodeConfig::new(
        scratch.0.join("node"),
        TenantId::from_bytes([0xa1; 16]),
        RepositoryId::from_bytes([0xa2; 16]),
    )
    .with_worker_threads(2)
    .with_object_format(format);
    let (mut node, _) = OneNode::init(config).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    (
        node,
        source,
        (blob_body.len() + tree_body.len() + commit_body.len()) as u64,
    )
}
#[test]
fn explicit_byte_refusal_has_a_matching_permitted_twin_and_unchanged_retry_identity() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, source, bytes) = fixture(&scratch, format);
        let before = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        let request = node
            .import_request_context_with_byte_limit(None, bytes - 1)
            .unwrap();
        let refused =
            node.runtime()
                .block_on(node.import_loose_git_directory_with_byte_limit_durable_in(
                    &request,
                    &source,
                    PrincipalId::from_bytes([3; 16]),
                    b"profile-key",
                    bytes - 1,
                ));
        assert!(
            matches!(refused, Err(NodeSourceImportRefusal::Staging(error)) if matches!(*error, LooseGitImportRefusal::TotalObjectBytesExceeded { limit, observed } if limit == bytes - 1 && observed == bytes))
        );
        let after = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        assert_eq!(before.receipt().generation(), after.receipt().generation());
        assert!(!fs::read_dir(node.storage_root()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".fg-import-quarantine-")
        }));
        let request = node
            .import_request_context_with_byte_limit(None, bytes)
            .unwrap();
        let accepted = node
            .runtime()
            .block_on(node.import_loose_git_directory_with_byte_limit_durable_in(
                &request,
                &source,
                PrincipalId::from_bytes([3; 16]),
                b"profile-key",
                bytes,
            ))
            .unwrap();
        assert!(
            accepted.commands.iter().all(|command| matches!(
                command.terminal.outcome,
                DecisionOutcome::Committed { .. }
            ))
        );
        let request = node.import_request_context(None);
        let retried = node
            .runtime()
            .block_on(node.import_loose_git_directory_durable_in(
                &request,
                &source,
                PrincipalId::from_bytes([3; 16]),
                b"profile-key",
            ))
            .unwrap();
        assert_eq!(accepted.session.tx_ids, retried.session.tx_ids);
        assert_eq!(accepted.commands[0].terminal, retried.commands[0].terminal);
        node.shutdown().unwrap();
    }
}
#[test]
fn explicit_profiles_reject_zero_and_overflow_before_source_access() {
    let scratch = Scratch::new();
    let (node, _, _) = fixture(&scratch, GitHashAlgorithm::Sha1);
    for limit in [0, graph::MAX_EXPLICIT_OBJECT_BYTES + 1, u64::MAX] {
        assert!(
            node.import_request_context_with_byte_limit(None, limit)
                .is_err()
        );
        let request = node.request_context();
        assert!(matches!(
            node.runtime()
                .block_on(node.import_loose_git_directory_with_byte_limit_durable_in(
                    &request,
                    &scratch.0.join("absent-source"),
                    PrincipalId::from_bytes([3; 16]),
                    b"invalid-profile",
                    limit
                )),
            Err(NodeSourceImportRefusal::Staging(_))
        ));
    }
    for limit in [
        1,
        graph::MAX_REACHABLE_OBJECT_BYTES,
        graph::MAX_EXPLICIT_OBJECT_BYTES,
    ] {
        let request = node
            .import_request_context_with_byte_limit(None, limit)
            .unwrap();
        let budget = request.authority().attached_native_cx().unwrap().budget();
        assert!(budget.deadline.is_some());
        assert!(budget.poll_quota < u32::MAX);
        assert!(budget.cost_quota.is_some());
    }
    node.shutdown().unwrap();
}
#[test]
fn inherited_cancellation_and_explicit_timeout_are_not_replenished() {
    let scratch = Scratch::new();
    let (node, source, bytes) = fixture(&scratch, GitHashAlgorithm::Sha256);
    let request = node
        .import_request_context_with_byte_limit(None, bytes)
        .unwrap();
    request.cancel();
    assert!(
        matches!(node.runtime().block_on(node.import_loose_git_directory_with_byte_limit_durable_in(&request, &source, PrincipalId::from_bytes([3; 16]), b"cancelled-profile", bytes)), Err(NodeSourceImportRefusal::Staging(error)) if matches!(*error, LooseGitImportRefusal::Interrupted { .. }))
    );
    let timeout = crate::GitDaemonSessionTimeout::try_new(Duration::from_nanos(1)).unwrap();
    let request = node
        .import_request_context_with_byte_limit(Some(timeout), graph::MAX_EXPLICIT_OBJECT_BYTES)
        .unwrap();
    std::thread::sleep(Duration::from_millis(1));
    assert!(
        matches!(node.runtime().block_on(node.import_loose_git_directory_with_byte_limit_durable_in(&request, &source, PrincipalId::from_bytes([3; 16]), b"expired-profile", graph::MAX_EXPLICIT_OBJECT_BYTES)), Err(NodeSourceImportRefusal::Staging(error)) if matches!(*error, LooseGitImportRefusal::Interrupted { code: RefusalCode::ResourceBudgetExceeded, exhaustion: Some(fgit_runtime::Exhaustion::Deadline) }))
    );
    node.shutdown().unwrap();
}
