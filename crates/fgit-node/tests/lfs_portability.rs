#![forbid(unsafe_code)]
#![cfg(unix)]
//! Real native source, immutable LFS custody, and the public host command.
//! No external Git, mutable source checkout, or forged inventory is involved.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand};
use fgit_crypto::GitObjectKind;
use fgit_forge::preparation::MergeMetadata;
use fgit_node::source_retrieval::{backup, lfs_transfer};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_object_fabric::artifact::storage::lfs::{LfsObject, LfsOid, LfsStore, MAX_OBJECT_BYTES};
use fgit_object_fabric::artifact::storage::{ArtifactOperation, ArtifactPut};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RefName, RepositoryId,
    RepositoryIncarnationId, TenantId,
};

const TENANT: TenantId = TenantId::from_bytes([0x71; 16]);
const REPOSITORY: RepositoryId = RepositoryId::from_bytes([0x72; 16]);
const OWNER: PrincipalId = PrincipalId::from_bytes([0x73; 16]);
static NEXT: AtomicU64 = AtomicU64::new(1);

#[path = "lfs_portability/streaming.rs"]
mod streaming;
#[path = "lfs_portability/verification.rs"]
mod verification;

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let base = fs::canonicalize(std::env::temp_dir()).unwrap_or_else(|_| std::env::temp_dir());
        let path = base.join(format!(
            "fg-lfs-portability-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn private(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        path
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn object(bytes: &[u8]) -> LfsObject {
    LfsObject {
        oid: LfsOid::of_payload(bytes),
        size: bytes.len() as u64,
    }
}
fn checksum(bytes: &[u8]) -> String {
    fgit_crypto::sha256_digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn text(path: &Path) -> String {
    path.to_str().unwrap().to_owned()
}
fn config(path: &Path, format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(path.to_path_buf(), TENANT, REPOSITORY)
        .with_object_format(format)
        .with_worker_threads(2)
}
fn operation() -> ArtifactOperation<'static> {
    ArtifactOperation::new(MAX_OBJECT_BYTES, Duration::from_secs(30), &|| true).unwrap()
}
fn source(node: &OneNode, name: &[u8], files: &[(&str, String)]) -> GitOid {
    let mut patch = String::new();
    for (path, body) in files {
        patch.push_str(&format!(
            "diff --git a/{path} b/{path}\nnew file mode 100644\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1,{} @@\n",
            body.lines().count()
        ));
        for line in body.lines() {
            patch.push('+');
            patch.push_str(line);
            patch.push('\n');
        }
    }
    let reference = RefName::try_new(name).unwrap();
    let metadata = MergeMetadata {
        author: "LFS Fixture <lfs@example.invalid>".into(),
        committer: "LFS Fixture <lfs@example.invalid>".into(),
        timestamp: 17,
        message: b"native LFS portability source\n".to_vec(),
    };
    let request = node.command_request_context(None);
    let (_, plan, bundle) = node
        .runtime()
        .block_on(node.prepare_trusted_initial_patch_in(
            &request,
            &reference,
            patch.as_bytes(),
            &metadata,
            Default::default(),
            None,
        ))
        .unwrap();
    let session =
        LoopbackReceiveSession::authenticated(OWNER, IdempotencyKey::new(name.to_vec()).unwrap());
    let admitted = node
        .runtime()
        .block_on(node.apply_initial_patch_bundle_durable_in(
            &request,
            &session,
            &reference,
            plan.commit,
            bundle.bytes(),
            Default::default(),
        ))
        .unwrap();
    assert!(
        admitted
            .commands
            .iter()
            .all(|row| matches!(row.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    plan.commit
}
fn init(path: &Path, format: GitHashAlgorithm, files: &[(&str, String)]) -> OneNode {
    let (mut node, _) = OneNode::init(config(path, format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    source(&node, b"refs/heads/main", files);
    node
}
fn custody(path: &Path, incarnation: RepositoryIncarnationId) -> LfsStore {
    LfsStore::open(path, TENANT, REPOSITORY, incarnation).unwrap()
}
fn put(store: &LfsStore, bytes: &[u8]) {
    assert_eq!(
        store
            .put(object(bytes), &mut &*bytes, &operation())
            .unwrap(),
        ArtifactPut::Created
    );
}
fn args(action: &str, root: &Path, format: GitHashAlgorithm) -> Vec<String> {
    vec![
        action.into(),
        text(root),
        TENANT.to_string(),
        REPOSITORY.to_string(),
        "--trusted-local".into(),
        "--object-format".into(),
        format.as_str().into(),
    ]
}
fn transfer_args(
    action: &str,
    root: &Path,
    custody: &Path,
    archive: &Path,
    format: GitHashAlgorithm,
) -> Vec<String> {
    let mut out = args(action, root, format);
    out.splice(2..2, [text(custody), text(archive)]);
    out
}
fn verify_args(root: &Path, custody: &Path, format: GitHashAlgorithm) -> Vec<String> {
    let mut out = args("verify", root, format);
    out.insert(2, text(custody));
    out
}
fn invoke(args: &[String]) -> Result<String, String> {
    let mut output = Vec::new();
    match lfs_transfer::run_with_timeout(args, &mut output, Some(Duration::from_secs(30))) {
        Ok(()) => Ok(String::from_utf8(output).unwrap()),
        Err(error) => {
            assert!(output.is_empty(), "failed commands must not emit success");
            Err(lfs_transfer::error_json(&error))
        }
    }
}
// These public fields contain fixed lowercase hex, not escaped free text.
fn field(receipt: &str, name: &str) -> String {
    receipt
        .split_once(&format!("\"{name}\":\""))
        .unwrap_or_else(|| panic!("missing {name}: {receipt}"))
        .1
        .split_once('"')
        .unwrap()
        .0
        .to_owned()
}
fn import_args(
    root: &Path,
    custody: &Path,
    archive: &Path,
    format: GitHashAlgorithm,
    pin: &str,
    digest: &str,
) -> Vec<String> {
    let mut out = transfer_args("import", root, custody, archive, format);
    out.extend([
        "--expected-incarnation".into(),
        field(pin, "incarnation_id"),
        "--expected-head-sha256".into(),
        field(pin, "head_sha256"),
        "--expected-sha256".into(),
        digest.into(),
    ]);
    out
}
fn private_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn refused_without_put(result: Result<String, String>) -> String {
    let error = result.unwrap_err();
    assert!(error.contains("\"complete\":false"), "{error}");
    assert!(error.contains("\"put_attempts\":0"), "{error}");
    assert!(
        error.contains("\"retained_custody_may_exist\":false"),
        "{error}"
    );
    error
}

#[test]
fn exact_native_inventory_transfers_across_incarnations_and_keeps_history_without_orphans() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let root = scratch.0.join("source");
        let source_custody = scratch.private("source-lfs");
        let archives = scratch.private("archives");
        let current = b"binary current payload\0\xff\n";
        let historical = b"payload from a deleted branch\0";
        let orphan = b"physical orphan must stay out";
        let node = init(
            &root,
            format,
            &[
                ("current.bin", object(current).pointer()),
                ("duplicate.bin", object(current).pointer()),
                ("README", "ordinary source\n".into()),
            ],
        );
        let old = source(
            &node,
            b"refs/heads/old",
            &[("old.bin", object(historical).pointer())],
        );
        let request = node.command_request_context(None);
        let deleted = node
            .runtime()
            .block_on(node.admit_branch_updates_durable_in(
                &request,
                &LoopbackReceiveSession::authenticated(
                    OWNER,
                    IdempotencyKey::new(b"delete-old".to_vec()).unwrap(),
                ),
                &[RefCommand {
                    name: RefName::try_new(b"refs/heads/old").unwrap(),
                    expected_old: ExpectedOld::Exactly(old),
                    proposed_new: ProposedNew::Delete,
                    force: false,
                }],
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            deleted.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        node.put_git_object(GitObjectKind::Blob, object(orphan).pointer().into_bytes())
            .unwrap();
        let source_incarnation = node.repository_incarnation_id();
        let source_store = custody(&source_custody, source_incarnation);
        for payload in [current.as_slice(), historical.as_slice(), orphan.as_slice()] {
            put(&source_store, payload);
        }
        node.shutdown().unwrap();

        let inventory = invoke(&args("inventory", &root, format)).unwrap();
        assert!(inventory.contains("\"objects\":2"), "{inventory}");
        assert!(inventory.contains(&object(current).oid.to_string()));
        assert!(inventory.contains(&object(historical).oid.to_string()));
        assert!(!inventory.contains(&object(orphan).oid.to_string()));
        let verified = invoke(&verify_args(&root, &source_custody, format)).unwrap();
        assert!(verified.contains("\"type\":\"lfs_verify\""), "{verified}");
        assert!(verified.contains("\"custody_verified\":true"), "{verified}");
        assert!(verified.contains("\"objects\":2"), "{verified}");
        assert!(verified.contains("\"physical_orphans_included\":false"));
        assert_eq!(
            field(&verified, "head_sha256"),
            field(&inventory, "head_sha256")
        );
        let archive = archives.join("payloads.fglfs");
        let exported = invoke(&transfer_args(
            "export",
            &root,
            &source_custody,
            &archive,
            format,
        ))
        .unwrap();
        let digest = checksum(&fs::read(&archive).unwrap());
        assert_eq!(field(&exported, "sha256"), digest);
        let second = archives.join("payloads-again.fglfs");
        invoke(&transfer_args(
            "export",
            &root,
            &source_custody,
            &second,
            format,
        ))
        .unwrap();
        assert_eq!(fs::read(&archive).unwrap(), fs::read(&second).unwrap());

        let target = scratch.0.join("target");
        let target_custody = scratch.private("target-lfs");
        let target_format = match format {
            GitHashAlgorithm::Sha1 => GitHashAlgorithm::Sha256,
            GitHashAlgorithm::Sha256 => GitHashAlgorithm::Sha1,
        };
        let target_node = init(
            &target,
            target_format,
            &[("current.bin", object(current).pointer())],
        );
        let target_incarnation = target_node.repository_incarnation_id();
        assert_ne!(source_incarnation, target_incarnation);
        target_node.shutdown().unwrap();
        let pins = invoke(&args("inventory", &target, target_format)).unwrap();
        let command = import_args(
            &target,
            &target_custody,
            &archive,
            target_format,
            &pins,
            &digest,
        );
        let imported = invoke(&command).unwrap();
        assert!(imported.contains("\"objects_created\":1"), "{imported}");
        assert!(
            imported.contains("\"unreferenced_objects_skipped\":1"),
            "{imported}"
        );
        let store = custody(&target_custody, target_incarnation);
        assert_eq!(store.read(object(current), &operation()).unwrap(), current);
        assert!(!store.contains(object(historical), &operation()).unwrap());
        assert!(!store.contains(object(orphan), &operation()).unwrap());
        let retried = invoke(&command).unwrap();
        assert!(retried.contains("\"objects_created\":0"), "{retried}");
        assert!(
            retried.contains("\"objects_already_present\":1"),
            "{retried}"
        );
        assert_eq!(
            invoke(&args("inventory", &target, target_format)).unwrap(),
            pins
        );
        let verified = invoke(&verify_args(&target, &target_custody, target_format)).unwrap();
        assert!(verified.contains("\"objects\":1"), "{verified}");
        assert!(verified.contains("\"custody_verified\":true"), "{verified}");
    }
}

#[test]
fn checksum_payload_destination_and_coverage_refusals_precede_every_immutable_put() {
    let scratch = Scratch::new();
    let format = GitHashAlgorithm::Sha256;
    let root = scratch.0.join("source");
    let source_custody = scratch.private("source-lfs");
    let archives = scratch.private("archives");
    let bytes = b"whole payload checked before target writes";
    let other = b"a later damaged record must prevent all earlier custody";
    let files = [
        ("asset.bin", object(bytes).pointer()),
        ("other.bin", object(other).pointer()),
    ];
    let node = init(&root, format, &files);
    let store = custody(&source_custody, node.repository_incarnation_id());
    put(&store, bytes);
    put(&store, other);
    node.shutdown().unwrap();
    let archive = archives.join("valid.fglfs");
    let exported = invoke(&transfer_args(
        "export",
        &root,
        &source_custody,
        &archive,
        format,
    ))
    .unwrap();
    let digest = field(&exported, "sha256");
    let target = scratch.0.join("target");
    let target_custody = scratch.private("target-lfs");
    let node = init(&target, format, &files);
    let target_incarnation = node.repository_incarnation_id();
    node.shutdown().unwrap();
    let pins = invoke(&args("inventory", &target, format)).unwrap();
    let valid = import_args(&target, &target_custody, &archive, format, &pins, &digest);
    let mut wrong_checksum = valid.clone();
    *wrong_checksum.last_mut().unwrap() = "00".repeat(32);
    assert!(refused_without_put(invoke(&wrong_checksum)).contains("DigestMismatch"));
    for flag in ["--expected-incarnation", "--expected-head-sha256"] {
        let mut wrong = valid.clone();
        let index = wrong.iter().position(|s| s == flag).unwrap() + 1;
        wrong[index] = "ee".repeat(if flag.ends_with("incarnation") {
            16
        } else {
            32
        });
        refused_without_put(invoke(&wrong));
    }
    let mut damaged = fs::read(&archive).unwrap();
    *damaged.last_mut().unwrap() ^= 1;
    let damaged_path = archives.join("damaged.fglfs");
    private_file(&damaged_path, &damaged);
    let damaged_command = import_args(
        &target,
        &target_custody,
        &damaged_path,
        format,
        &pins,
        &checksum(&damaged),
    );
    assert!(refused_without_put(invoke(&damaged_command)).contains("PayloadMismatch"));
    let mut limited = valid.clone();
    limited.extend(["--max-payload-bytes".into(), "1".into()]);
    refused_without_put(invoke(&limited));
    assert!(
        !custody(&target_custody, target_incarnation)
            .contains(object(bytes), &operation())
            .unwrap()
    );
    assert!(
        !custody(&target_custody, target_incarnation)
            .contains(object(other), &operation())
            .unwrap()
    );
    assert_eq!(invoke(&args("inventory", &target, format)).unwrap(), pins);

    // One available record must not be copied before a later missing target
    // pointer has been discovered. Coverage is a whole-inventory precondition.
    let uncovered = scratch.0.join("uncovered");
    let uncovered_custody = scratch.private("uncovered-lfs");
    let absent = b"not in the exported archive";
    let node = init(
        &uncovered,
        format,
        &[
            ("asset.bin", object(bytes).pointer()),
            ("absent.bin", object(absent).pointer()),
        ],
    );
    let incarnation = node.repository_incarnation_id();
    node.shutdown().unwrap();
    let pins = invoke(&args("inventory", &uncovered, format)).unwrap();
    let command = import_args(
        &uncovered,
        &uncovered_custody,
        &archive,
        format,
        &pins,
        &digest,
    );
    assert!(refused_without_put(invoke(&command)).contains("does not cover every target"));
    let store = custody(&uncovered_custody, incarnation);
    assert!(!store.contains(object(bytes), &operation()).unwrap());
    assert!(!store.contains(object(absent), &operation()).unwrap());
    assert_eq!(
        invoke(&args("inventory", &uncovered, format)).unwrap(),
        pins
    );
}

#[test]
fn missing_source_custody_never_publishes_an_archive_and_identical_retry_recovers() {
    let scratch = Scratch::new();
    let format = GitHashAlgorithm::Sha1;
    let root = scratch.0.join("source");
    let lfs = scratch.private("lfs");
    let archives = scratch.private("archives");
    let bytes = b"upload arrives after the first export attempt";
    let node = init(&root, format, &[("asset.bin", object(bytes).pointer())]);
    let incarnation = node.repository_incarnation_id();
    node.shutdown().unwrap();
    let before = invoke(&args("inventory", &root, format)).unwrap();
    let archive = archives.join("payloads.fglfs");
    let command = transfer_args("export", &root, &lfs, &archive, format);
    let error = refused_without_put(invoke(&command));
    assert!(
        error.contains("source custody missing or invalid"),
        "{error}"
    );
    assert!(!archive.exists());
    assert_eq!(fs::read_dir(&archives).unwrap().count(), 0);
    put(&custody(&lfs, incarnation), bytes);
    let exported = invoke(&command).unwrap();
    assert_eq!(
        field(&exported, "sha256"),
        checksum(&fs::read(&archive).unwrap())
    );
    refused_without_put(invoke(&command));
    assert_eq!(invoke(&args("inventory", &root, format)).unwrap(), before);
}

#[test]
fn native_source_backup_and_lfs_companion_restore_a_cold_repository() {
    let scratch = Scratch::new();
    let format = GitHashAlgorithm::Sha256;
    let root = scratch.0.join("source");
    let lfs = scratch.private("source-lfs");
    let archives = scratch.private("archives");
    let bytes = b"LFS byte custody survives source recovery\0\xff";
    let node = init(&root, format, &[("asset.bin", object(bytes).pointer())]);
    let incarnation = node.repository_incarnation_id();
    put(&custody(&lfs, incarnation), bytes);
    node.shutdown().unwrap();
    let archive = archives.join("lfs.fglfs");
    let exported = invoke(&transfer_args("export", &root, &lfs, &archive, format)).unwrap();
    let source_archive = archives.join("source.fgsrc");
    let mut output = Vec::new();
    backup::run(
        &[
            "export".into(),
            text(&root),
            text(&source_archive),
            TENANT.to_string(),
            REPOSITORY.to_string(),
            "--trusted-local".into(),
            "--object-format".into(),
            format.as_str().into(),
        ],
        &mut output,
    )
    .unwrap();
    let target = scratch.0.join("restored");
    output.clear();
    backup::run(
        &[
            "restore".into(),
            text(&source_archive),
            text(&target),
            "--trusted-local".into(),
            "--expected-sha256".into(),
            checksum(&fs::read(&source_archive).unwrap()),
            "--destination-instance".into(),
            "71".into(),
        ],
        &mut output,
    )
    .unwrap();
    let restored_lfs = scratch.private("restored-lfs");
    let pins = invoke(&args("inventory", &target, format)).unwrap();
    assert_eq!(field(&pins, "incarnation_id"), incarnation.to_string());
    let imported = invoke(&import_args(
        &target,
        &restored_lfs,
        &archive,
        format,
        &pins,
        &field(&exported, "sha256"),
    ))
    .unwrap();
    assert!(imported.contains("\"objects_created\":1"), "{imported}");
    let mut node = OneNode::open_existing(config(&target, format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    assert_eq!(
        custody(&restored_lfs, node.repository_incarnation_id())
            .read(object(bytes), &operation())
            .unwrap(),
        bytes
    );
    node.shutdown().unwrap();
    assert_eq!(invoke(&args("inventory", &target, format)).unwrap(), pins);
}
