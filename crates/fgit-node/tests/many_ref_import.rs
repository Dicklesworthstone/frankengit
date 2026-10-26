#![forbid(unsafe_code)]
//! Many refs retain one atomic native import and one recoverable decision.

use fgit_admission::{AdmissionResult, MAX_ADMISSION_COMMANDS};
use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_node::{
    LoopbackReceiveSession, LooseGitImportRefusal, MaterializedAdmission, NodeConfig,
    NodeSourceImportRefusal, OneNode,
};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RefName, RepositoryId,
    TenantId,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const PRINCIPAL: PrincipalId = PrincipalId::from_bytes([0x73; 16]);
const KEY: &[u8] = b"many-ref-native-import";
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-many-ref-import-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(
            self.0.join("node"),
            TenantId::from_bytes([0x71; 16]),
            RepositoryId::from_bytes([0x72; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(2)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let oid = git_object_id(format, kind, body);
    let raw = [
        format!("{} {}\0", kind.label(), body.len()).as_bytes(),
        body,
    ]
    .concat();
    let length = u16::try_from(raw.len()).unwrap();
    let mut encoded = vec![0x78, 0x01, 0x01];
    encoded.extend(length.to_le_bytes());
    encoded.extend((!length).to_le_bytes());
    encoded.extend(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let next = (a + u32::from(*byte)) % 65_521;
        (next, (b + next) % 65_521)
    });
    encoded.extend(((b << 16) | a).to_be_bytes());
    let hex = oid.to_string();
    let directory = root.join("objects").join(&hex[..2]);
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join(&hex[2..]), encoded).unwrap();
    oid
}

fn name(index: usize) -> RefName {
    if index == 0 {
        RefName::try_new(b"refs/heads/main").unwrap()
    } else if index % 2 == 0 {
        RefName::try_new(format!("refs/tags/import-{index:04}").as_bytes()).unwrap()
    } else {
        RefName::try_new(format!("refs/heads/import-{index:04}").as_bytes()).unwrap()
    }
}

fn source(root: &Path, format: GitHashAlgorithm, count: usize) -> (GitOid, GitOid, GitOid) {
    fs::create_dir_all(root).unwrap();
    fs::write(root.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(
        root.join("config"),
        match format {
            GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
            GitHashAlgorithm::Sha256 => {
                "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n"
            }
        },
    )
    .unwrap();
    let tree = loose(root, format, GitObjectKind::Tree, b"");
    let body = format!(
        "tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nmany-ref import\n"
    );
    let commit = loose(root, format, GitObjectKind::Commit, body.as_bytes());
    let tag = loose(
        root,
        format,
        GitObjectKind::Tag,
        format!(
            "object {commit}\ntype commit\ntag import-annotated\ntagger Fixture <fixture@example.invalid> 1 +0000\n\nmany-ref annotated tag\n"
        ).as_bytes(),
    );
    let packed_refs = (0..count)
        .map(|index| {
            let tip = if index == 2 { tag } else { commit };
            format!(
                "{tip} {}\n",
                std::str::from_utf8(name(index).as_bytes()).unwrap()
            )
        })
        .collect::<String>();
    fs::write(root.join("packed-refs"), packed_refs).unwrap();
    (commit, tree, tag)
}

fn import(node: &OneNode, source: &Path) -> Result<AdmissionResult, NodeSourceImportRefusal> {
    let request = node.import_request_context(None);
    node.runtime()
        .block_on(node.import_loose_git_directory_durable_in(&request, source, PRINCIPAL, KEY))
}

fn snapshot(node: &OneNode) -> MaterializedAdmission {
    node.runtime()
        .block_on(node.materialize_admission())
        .unwrap()
}

#[test]
fn a_thousand_refs_import_atomically_and_recover_after_cold_reopen_in_both_hash_domains() {
    const COUNT: usize = 1024;
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let source_path = scratch.0.join("source.git");
        let (commit, tree, tag) = source(&source_path, format, COUNT);
        let config = scratch.config(format);
        let (mut node, _) = OneNode::init(config.clone()).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let before = snapshot(&node);
        let result = import(&node, &source_path).unwrap();
        assert!(result.session.atomic);
        assert_eq!(result.session.tx_ids.len(), 1);
        assert_eq!(result.commands.len(), COUNT);
        assert!(matches!(
            result.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert!(
            result
                .commands
                .iter()
                .all(|command| command == &result.commands[0])
        );
        let after = snapshot(&node);
        assert_eq!(
            after.basis().generation().get(),
            before.basis().generation().get() + 1
        );
        assert_eq!(after.snapshot().refs.len(), COUNT);
        for index in 0..COUNT {
            let expected = if index == 2 { tag } else { commit };
            assert_eq!(after.snapshot().refs.get(&name(index)), Some(&expected));
        }
        assert_eq!(after.selected_closure().closure().objects().len(), 3);
        assert_eq!(import(&node, &source_path).unwrap(), result);
        assert_eq!(snapshot(&node).basis(), after.basis());
        node.shutdown().unwrap();
        fs::remove_dir_all(&source_path).unwrap();

        let node = OneNode::open_existing(config).unwrap();
        let reopened = snapshot(&node);
        assert_eq!(reopened.basis(), after.basis());
        assert_eq!(reopened.snapshot().refs, after.snapshot().refs);
        assert_eq!(node.read_git_object(tree).unwrap().payload(), b"");
        assert!(node.read_git_object(commit).is_ok());
        assert!(node.read_git_object(tag).is_ok());
        let session = LoopbackReceiveSession::authenticated(
            PRINCIPAL,
            IdempotencyKey::new(KEY.to_vec()).unwrap(),
        );
        let recovery = node
            .runtime()
            .block_on(node.recover_transaction_in(&node.request_context(), &session))
            .unwrap();
        assert_eq!(recovery.terminal(), Some(result.commands[0].terminal));
        assert_eq!(snapshot(&node).basis(), after.basis());
        node.shutdown().unwrap();
    }
}

#[test]
fn an_import_above_the_sealed_command_bound_reports_count_and_publishes_nothing() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let source_path = scratch.0.join("source.git");
        let (commit, _, _) = source(&source_path, format, MAX_ADMISSION_COMMANDS + 1);
        let (mut node, _) = OneNode::init(scratch.config(format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let before = snapshot(&node);
        let error = import(&node, &source_path).unwrap_err();
        let diagnostic = error.to_string();
        assert!(matches!(
            error,
            NodeSourceImportRefusal::Staging(error)
                if matches!(*error, LooseGitImportRefusal::RefLimitExceeded { observed, limit }
                    if observed == MAX_ADMISSION_COMMANDS + 1 && limit == MAX_ADMISSION_COMMANDS)
        ));
        assert!(diagnostic.contains(&(MAX_ADMISSION_COMMANDS + 1).to_string()));
        assert!(diagnostic.contains(&MAX_ADMISSION_COMMANDS.to_string()));
        assert!(diagnostic.contains("reduce the source ref set"));
        let after = snapshot(&node);
        assert_eq!(after.basis(), before.basis());
        assert!(after.snapshot().refs.is_empty());
        assert!(after.selected_closure().closure().objects().is_empty());
        assert!(
            node.read_git_object(commit).is_err(),
            "count refusal precedes object placement"
        );
        node.shutdown().unwrap();
    }
}
