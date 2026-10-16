#![forbid(unsafe_code)]
//! Real 288 MiB native source import and cold reopen. No Git subprocess, mock
//! store, fixture-only import path, or large-fixture timeout override is used.
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_node::{NodeConfig, OneNode};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RefName, RepositoryId,
    TenantId,
};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

const FORMAT: GitHashAlgorithm = GitHashAlgorithm::Sha256;
const PAYLOAD_BYTES: usize = 24 * 1024 * 1024;
const BLOBS: u8 = 12;
static NEXT: AtomicU64 = AtomicU64::new(1);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-large-import-{}-{}",
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
fn config(root: &Path) -> NodeConfig {
    NodeConfig::new(
        root.to_path_buf(),
        TenantId::from_bytes([0xc1; 16]),
        RepositoryId::from_bytes([0xc2; 16]),
    )
    .with_object_format(FORMAT)
    .with_worker_threads(2)
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

#[test]
fn multi_hundred_mib_source_publishes_under_default_budget_and_survives_cold_reopen() {
    let scratch = Scratch::new();
    let root = scratch.0.join("node");
    let source = scratch.0.join("source.git");
    let mut blobs = Vec::new();
    let mut tree = Vec::new();
    for ordinal in 0..BLOBS {
        let body = vec![b'a' + ordinal; PAYLOAD_BYTES];
        let oid = loose(&source, GitObjectKind::Blob, &body);
        tree.extend_from_slice(format!("100644 data{ordinal:02}\0").as_bytes());
        tree.extend_from_slice(oid.as_bytes());
        blobs.push((oid, b'a' + ordinal));
    }
    let tree_id = loose(&source, GitObjectKind::Tree, &tree);
    let body = format!(
        "tree {tree_id}\nauthor Large <large@example.invalid> 1 +0000\ncommitter Large <large@example.invalid> 1 +0000\n\n288 MiB source import\n"
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
    let request = node.import_request_context(None);
    let started = Instant::now();
    let receipt = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &request,
            &source,
            PrincipalId::from_bytes([3; 16]),
            b"large-import-default-budget",
        ))
        .unwrap();
    assert_eq!(receipt.commands.len(), 1);
    assert!(matches!(
        receipt.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    eprintln!(
        "large-import.acceptance.publish: {} native blob bytes; {} ms; default bounded profile",
        usize::from(BLOBS) * PAYLOAD_BYTES,
        started.elapsed().as_millis()
    );
    node.shutdown().unwrap();
    fs::remove_dir_all(&source).unwrap();

    // Source removal and a new runtime exclude a warm source/cache as evidence.
    let mut reopened = OneNode::open_existing(config(&root)).unwrap();
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
    assert_eq!(
        selected.selected_closure().closure().objects().len(),
        usize::from(BLOBS) + 2
    );
    for (oid, byte) in blobs {
        let object = reopened.read_git_object(oid).unwrap();
        assert_eq!(object.payload().len(), PAYLOAD_BYTES);
        assert!(object.payload().iter().all(|b| *b == byte));
    }
    assert_eq!(reopened.read_git_object(tree_id).unwrap().payload(), tree);
    assert_eq!(
        reopened.read_git_object(commit).unwrap().payload(),
        body.as_bytes()
    );
    eprintln!(
        "large-import.acceptance.reopen: all 14 exact native objects verified after source removal"
    );
    reopened.shutdown().unwrap();
}
