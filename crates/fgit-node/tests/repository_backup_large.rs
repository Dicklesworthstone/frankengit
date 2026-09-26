#![forbid(unsafe_code)]
//! A real 72 MiB source-recovery round trip, larger than the former whole-file
//! ceiling. The fixture writer uses stored DEFLATE blocks, not external Git.
use fgit_crypto::{DigestHasher, GitObjectKind, Sha256Hasher, git_object_id};
use fgit_node::{NodeConfig, OneNode};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RefName, RepositoryId,
    TenantId,
};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const TENANT: &str = "11111111111111111111111111111111";
const REPOSITORY: &str = "22222222222222222222222222222222";
const FORMAT: GitHashAlgorithm = GitHashAlgorithm::Sha256;
const PAYLOAD_BYTES: usize = 24 * 1024 * 1024;
static NEXT: AtomicU64 = AtomicU64::new(1);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-large-backup-{}-{}",
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
fn config(path: &Path) -> NodeConfig {
    NodeConfig::new(
        path.to_path_buf(),
        TenantId::from_hex(TENANT).unwrap(),
        RepositoryId::from_hex(REPOSITORY).unwrap(),
    )
    .with_object_format(FORMAT)
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
fn refused(output: Output) -> String {
    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    String::from_utf8(output.stderr).unwrap()
}
fn loose(root: &Path, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let oid = git_object_id(FORMAT, kind, body);
    let oid_text = oid.to_string();
    let path = root
        .join("objects")
        .join(&oid_text[..2])
        .join(&oid_text[2..]);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut file = File::create(path).unwrap();
    file.write_all(&[0x78, 0x01]).unwrap();
    let header = format!("{} {}\0", kind.label(), body.len()).into_bytes();
    let mut remaining = header.len() + body.len();
    let mut input = header.as_slice().chain(body);
    let mut block = vec![0; u16::MAX as usize];
    let (mut a, mut b) = (1_u32, 0_u32);
    while remaining > 0 {
        let count = remaining.min(block.len());
        input.read_exact(&mut block[..count]).unwrap();
        let size = u16::try_from(count).unwrap();
        file.write_all(&[u8::from(remaining == count)]).unwrap();
        file.write_all(&size.to_le_bytes()).unwrap();
        file.write_all(&(!size).to_le_bytes()).unwrap();
        file.write_all(&block[..count]).unwrap();
        for &byte in &block[..count] {
            a = (a + u32::from(byte)) % 65521;
            b = (b + a) % 65521;
        }
        remaining -= count;
    }
    file.write_all(&((b << 16) | a).to_be_bytes()).unwrap();
    oid
}
fn checksum(path: &Path) -> String {
    let mut file = File::open(path).unwrap();
    let mut block = vec![0; 64 * 1024];
    let mut hash = Sha256Hasher::new();
    loop {
        let size = file.read(&mut block).unwrap();
        if size == 0 {
            break;
        }
        hash.update(&block[..size]);
    }
    hash.finish()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
#[test]
fn larger_than_64_mib_backup_restores_from_disk_and_respects_smaller_explicit_budgets() {
    let scratch = Scratch::new();
    let root = scratch.0.join("node");
    let source = scratch.0.join("source.git");
    let mut blobs = Vec::new();
    let mut tree = Vec::new();
    for ordinal in 0_u8..3 {
        let body = vec![b'a' + ordinal; PAYLOAD_BYTES];
        let oid = loose(&source, GitObjectKind::Blob, &body);
        tree.extend_from_slice(format!("100644 data{ordinal}\0").as_bytes());
        tree.extend_from_slice(oid.as_bytes());
        blobs.push((oid, b'a' + ordinal));
    }
    let tree = loose(&source, GitObjectKind::Tree, &tree);
    let body = format!(
        "tree {tree}\nauthor Large <large@example.invalid> 1 +0000\ncommitter Large <large@example.invalid> 1 +0000\n\nlarge recovery fixture\n"
    );
    let commit = loose(&source, GitObjectKind::Commit, body.as_bytes());
    fs::create_dir_all(source.join("refs/heads")).unwrap();
    fs::write(source.join("refs/heads/main"), format!("{commit}\n")).unwrap();
    fs::write(source.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(
        source.join("config"),
        b"[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
    )
    .unwrap();
    let (mut node, _) = OneNode::init(config(&root)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    // The >64 MiB fixture imports under the node's reserved import budget
    // (x2mv.4.28), not a fixture-specific override.
    let request = node.import_request_context(None);
    let admission = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &request,
            &source,
            PrincipalId::from_bytes([3; 16]),
            b"large-backup-fixture",
        ))
        .unwrap();
    assert_eq!(admission.commands.len(), 1);
    assert!(matches!(
        admission.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    node.shutdown().unwrap();

    let too_small = scratch.0.join("small-budget.fg");
    let error = refused(command(&[
        "export",
        text(&root),
        text(&too_small),
        TENANT,
        REPOSITORY,
        "--trusted-local",
        "--object-format",
        "sha256",
        "--max-archive-bytes",
        "67108864",
        "--timeout-secs",
        "1800",
    ]));
    assert!(error.contains("archive-byte limit"), "{error}");
    assert!(!too_small.exists());
    let backup = scratch.0.join("large.fg");
    let receipt = success(command(&[
        "export",
        text(&root),
        text(&backup),
        TENANT,
        REPOSITORY,
        "--trusted-local",
        "--object-format",
        "sha256",
        "--timeout-secs",
        "1800",
    ]));
    assert!(fs::metadata(&backup).unwrap().len() > 64 * 1024 * 1024);
    let pin = checksum(&backup);
    assert!(receipt.contains(&pin));
    let refused_root = scratch.0.join("refused");
    let error = refused(command(&[
        "restore",
        text(&backup),
        text(&refused_root),
        "--trusted-local",
        "--expected-sha256",
        &pin,
        "--destination-instance",
        "991",
        "--max-archive-bytes",
        "67108864",
    ]));
    assert!(error.contains("archive-byte limit"));
    assert!(!refused_root.exists());

    // The isolated source is gone: the archive is the ONLY recovery input.
    fs::remove_dir_all(&root).unwrap();
    fs::remove_dir_all(&source).unwrap();
    let target = scratch.0.join("restored");
    let receipt = success(command(&[
        "restore",
        text(&backup),
        text(&target),
        "--trusted-local",
        "--expected-sha256",
        &pin,
        "--destination-instance",
        "991",
        "--timeout-secs",
        "1800",
    ]));
    assert!(receipt.contains("\"streaming\":true"));
    assert!(receipt.contains("\"objects\":5,"));
    let mut reopened = OneNode::open_existing(config(&target)).unwrap();
    reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
    let request = reopened.request_context();
    let selected = reopened
        .runtime()
        .block_on(reopened.materialize_admission_in(&request))
        .unwrap();
    assert_eq!(
        selected.snapshot().refs[&RefName::try_new(b"refs/heads/main").unwrap()],
        commit
    );
    assert_eq!(selected.selected_closure().closure().objects().len(), 5);
    for (oid, byte) in blobs {
        let object = reopened.read_git_object(oid).unwrap();
        assert_eq!(object.payload().len(), PAYLOAD_BYTES);
        assert!(object.payload().iter().all(|b| *b == byte));
    }
    reopened.shutdown().unwrap();
}
