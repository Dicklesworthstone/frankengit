#![forbid(unsafe_code)]
//! Real source recovery through the command and node, with no external Git.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand};
use fgit_crypto::{DigestHasher, GitObjectKind, Sha256Hasher, git_object_id};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RefName, RepositoryId,
    TenantId,
};

const TENANT: &str = "11111111111111111111111111111111";
const REPOSITORY: &str = "22222222222222222222222222222222";
static NEXT: AtomicU64 = AtomicU64::new(1);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-repository-recovery-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}
fn config(root: &Path, format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(
        root.to_path_buf(),
        TenantId::from_hex(TENANT).unwrap(),
        RepositoryId::from_hex(REPOSITORY).unwrap(),
    )
    .with_object_format(format)
}
fn command(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fg-repository-backup"))
        .args(args)
        .output()
        .unwrap()
}
fn success(output: Output) -> String {
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn refusal(output: Output) -> String {
    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    let text = String::from_utf8(output.stderr).unwrap();
    assert!(text.contains("\"complete\":false"));
    text
}
fn checksum(bytes: &[u8]) -> String {
    let mut hash = Sha256Hasher::new();
    hash.update(bytes);
    hash.finish()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
const fn principal() -> PrincipalId {
    PrincipalId::from_bytes([3; 16])
}
fn branch(node: &OneNode, key: &[u8], name: &[u8], old: ExpectedOld, new: ProposedNew) {
    let session = LoopbackReceiveSession::authenticated(
        principal(),
        IdempotencyKey::new(key.to_vec()).unwrap(),
    );
    let command = RefCommand {
        name: RefName::try_new(name).unwrap(),
        expected_old: old,
        proposed_new: new,
        force: false,
    };
    let request = node.request_context();
    let admission = node
        .runtime()
        .block_on(node.admit_branch_updates_durable_in(
            &request,
            &session,
            &[command],
            Default::default(),
        ))
        .unwrap();
    assert_eq!(admission.commands.len(), 1);
    assert!(matches!(
        admission.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
}
fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let oid = git_object_id(format, kind, body);
    let text = oid.to_string();
    let path = root.join("objects").join(&text[..2]).join(&text[2..]);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut framed = format!("{} {}\0", kind.label(), body.len()).into_bytes();
    framed.extend_from_slice(body);
    let count = u16::try_from(framed.len()).unwrap();
    let mut zlib = vec![0x78, 0x01, 0x01];
    zlib.extend_from_slice(&count.to_le_bytes());
    zlib.extend_from_slice(&(!count).to_le_bytes());
    zlib.extend_from_slice(&framed);
    let (mut a, mut b) = (1_u32, 0_u32);
    for byte in framed {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    zlib.extend_from_slice(&((b << 16) | a).to_be_bytes());
    fs::write(path, zlib).unwrap();
    oid
}
fn history(root: &Path, format: GitHashAlgorithm, payload: &[u8]) -> (GitOid, GitOid) {
    let blob = loose(root, format, GitObjectKind::Blob, payload);
    let mut tree = b"100644 README\0".to_vec();
    tree.extend_from_slice(blob.as_bytes());
    let tree = loose(root, format, GitObjectKind::Tree, &tree);
    let commit = format!(
        "tree {tree}\nauthor Recovery <r@example.invalid> 1 +0000\ncommitter Recovery <r@example.invalid> 1 +0000\n\nsource recovery\n"
    );
    (
        loose(root, format, GitObjectKind::Commit, commit.as_bytes()),
        blob,
    )
}
fn fixture(
    scratch: &Scratch,
    format: GitHashAlgorithm,
) -> (PathBuf, PathBuf, GitOid, GitOid, GitOid) {
    let source = scratch.0.join("source.git");
    let root = scratch.0.join("node");
    let (main, _) = history(&source, format, b"current content\n");
    let (old, old_blob) = history(
        &source,
        format,
        b"historical deleted-branch content\0\xff\n",
    );
    fs::create_dir_all(source.join("refs/heads")).unwrap();
    fs::write(source.join("refs/heads/main"), format!("{main}\n")).unwrap();
    fs::write(source.join("refs/heads/obsolete"), format!("{old}\n")).unwrap();
    fs::write(source.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    let git_config = match format {
        GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
        GitHashAlgorithm::Sha256 => {
            "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n"
        }
    };
    fs::write(source.join("config"), git_config).unwrap();
    let (mut node, _) = OneNode::init(config(&root, format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let request = node.request_context();
    let imported = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &request,
            &source,
            principal(),
            b"recovery-import",
        ))
        .unwrap();
    assert_eq!(imported.commands.len(), 2);
    assert!(
        imported
            .commands
            .iter()
            .all(|row| matches!(row.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    branch(
        &node,
        b"remove-old",
        b"refs/heads/obsolete",
        ExpectedOld::Exactly(old),
        ProposedNew::Delete,
    );
    let orphan = node
        .put_git_object(
            GitObjectKind::Blob,
            b"physical orphan, not canonical".to_vec(),
        )
        .unwrap()
        .identity();
    node.shutdown().unwrap();
    (root, source, main, old_blob, orphan)
}
fn export(root: &Path, backup: &Path, format: GitHashAlgorithm) -> String {
    success(command(&[
        "export",
        text(root),
        text(backup),
        TENANT,
        REPOSITORY,
        "--trusted-local",
        "--object-format",
        format.as_str(),
    ]))
}
fn restore(backup: &Path, output: &Path, expected: &str) -> Output {
    command(&[
        "restore",
        text(backup),
        text(output),
        "--trusted-local",
        "--expected-sha256",
        expected,
        "--destination-instance",
        "991",
    ])
}
#[test]
fn backup_alone_restores_both_domains_historical_objects_and_future_publication() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (root, source, main, old_blob, orphan) = fixture(&scratch, format);
        let backup = scratch.0.join("source.fg");
        let exported = export(&root, &backup, format);
        assert!(exported.contains("\"objects\":6,"), "{exported}");
        let original = fs::read(&backup).unwrap();
        let digest = checksum(&original);
        assert!(exported.contains(&digest));
        refusal(command(&[
            "export",
            text(&root),
            text(&backup),
            TENANT,
            REPOSITORY,
            "--trusted-local",
            "--object-format",
            format.as_str(),
        ]));
        assert_eq!(
            fs::read(&backup).unwrap(),
            original,
            "export never replaces an existing backup"
        );
        // Delete ONLY the two isolated fixture directories: the restore has no source.
        fs::remove_dir_all(&root).unwrap();
        fs::remove_dir_all(&source).unwrap();
        let target = scratch.0.join("restored");
        let restored = success(restore(&backup, &target, &digest));
        assert!(restored.contains("\"objects\":6,"));
        assert!(restored.contains("\"reopened_and_verified\":true"));
        assert!(!target.join(".restore-quarantine").exists());
        let mut node = OneNode::open_existing(config(&target, format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let request = node.request_context();
        let selected = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        assert_eq!(selected.snapshot().refs.len(), 1);
        assert_eq!(
            selected.snapshot().refs[&RefName::try_new(b"refs/heads/main").unwrap()],
            main
        );
        assert_eq!(selected.selected_closure().closure().objects().len(), 6);
        assert_eq!(
            node.read_git_object(old_blob).unwrap().payload(),
            b"historical deleted-branch content\0\xff\n"
        );
        assert!(
            node.read_git_object(orphan).is_err(),
            "physical residue is not a recovery root"
        );
        branch(
            &node,
            b"after-restore",
            b"refs/heads/recovered",
            ExpectedOld::Absent,
            ProposedNew::Update(main),
        );
        node.shutdown().unwrap();
        refusal(restore(&backup, &target, &digest));
        let mut reopened = OneNode::open_existing(config(&target, format)).unwrap();
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        let request = reopened.request_context();
        let selected = reopened
            .runtime()
            .block_on(reopened.materialize_admission_in(&request))
            .unwrap();
        assert_eq!(
            selected.snapshot().refs.len(),
            2,
            "refused restore did not rewind new history"
        );
        reopened.shutdown().unwrap();
    }
}
#[test]
fn checksum_valid_but_incomplete_inventory_cannot_publish_a_destination_head() {
    let scratch = Scratch::new();
    let format = GitHashAlgorithm::Sha1;
    let (root, _, _, _, _) = fixture(&scratch, format);
    let backup = scratch.0.join("complete.fg");
    export(&root, &backup, format);
    let bytes = fs::read(&backup).unwrap();
    let authority_length =
        usize::try_from(u64::from_be_bytes(bytes[57..65].try_into().unwrap())).unwrap();
    let count_at = 65 + authority_length;
    let count = u64::from_be_bytes(bytes[count_at..count_at + 8].try_into().unwrap());
    assert_eq!(count, 6);
    let mut cursor = count_at + 8;
    for _ in 0..count - 1 {
        let length = usize::try_from(u64::from_be_bytes(
            bytes[cursor + 21..cursor + 29].try_into().unwrap(),
        ))
        .unwrap();
        cursor += 20 + 1 + 8 + 32 + length;
    }
    let mut incomplete = bytes[..cursor].to_vec();
    incomplete[count_at..count_at + 8].copy_from_slice(&(count - 1).to_be_bytes());
    let corrupt = scratch.0.join("incomplete.fg");
    fs::write(&corrupt, &incomplete).unwrap();
    let target = scratch.0.join("refused");
    let error = refusal(restore(&corrupt, &target, &checksum(&incomplete)));
    assert!(error.contains("inventory does not equal"), "{error}");
    assert!(!target.join("authority.fsqlite").exists());
    assert!(
        target.join(".restore-quarantine").exists(),
        "retain rejected metadata for investigation"
    );
    let wrong_pin_target = scratch.0.join("wrong-pin");
    refusal(restore(&backup, &wrong_pin_target, &"00".repeat(32)));
    assert!(
        !wrong_pin_target.exists(),
        "wrong trust pin must precede destination creation"
    );
}
