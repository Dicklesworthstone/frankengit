#![forbid(unsafe_code)]
//! Real embedded authority, production quarantine, native objects and head CAS.
//! No in-memory authority replacement and no external Git engine are used.

use fgit_admission::AdmissionResult;
use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest, sha256_digest};
use fgit_node::{NodeConfig, NodeWorkspaceRefusal, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId,
    RefName, RepositoryId, TenantId};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(1);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("fgit-workspace-publish-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        if self.0.exists() { fs::remove_dir_all(&self.0).expect("owned test directory"); }
    }
}
fn reference() -> RefName { RefName::try_new(b"refs/heads/main").unwrap() }
fn principal() -> PrincipalId { PrincipalId::from_bytes([0x83; 16]) }
fn config(root: &Path, format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(root.join("node"), TenantId::from_bytes([0x81; 16]),
        RepositoryId::from_bytes([0x82; 16])).with_object_format(format)
}
fn zlib(body: &[u8]) -> Vec<u8> {
    let n = u16::try_from(body.len()).expect("small fixture");
    let mut bytes = vec![0x78, 0x01, 0x01];
    bytes.extend(n.to_le_bytes());
    bytes.extend((!n).to_le_bytes());
    bytes.extend(body);
    let (a, b) = body.iter().fold((1u32, 0u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521;
        (a, (b + a) % 65_521)
    });
    bytes.extend(((b << 16) | a).to_be_bytes());
    bytes
}
fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, body);
    let framed = [format!("{} {}\0", kind.label(), body.len()).as_bytes(), body].concat();
    let hex = id.to_string();
    let dir = root.join("objects").join(&hex[..2]);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(&hex[2..]), zlib(&framed)).unwrap();
    id
}
fn tree(changed: GitOid, untouched: GitOid) -> Vec<u8> {
    [b"100644 changed.txt\0".as_slice(), changed.as_bytes(),
        b"100644 untouched.txt\0", untouched.as_bytes()].concat()
}
fn commit(tree: GitOid, parents: &[GitOid], message: &str) -> Vec<u8> {
    let parents: String = parents.iter().map(|id| format!("parent {id}\n")).collect();
    format!("tree {tree}\n{parents}author Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\n{message}\n").into_bytes()
}
fn setup(root: &Path, format: GitHashAlgorithm) -> (OneNode, GitOid, GitOid) {
    let (mut node, _) = OneNode::init(config(root, format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let source = root.join("source");
    fs::create_dir_all(source.join("refs/heads")).unwrap();
    fs::write(source.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    let before = loose(&source, format, GitObjectKind::Blob, b"before\n");
    let untouched = loose(&source, format, GitObjectKind::Blob, b"preserve me\n");
    let root_tree = loose(&source, format, GitObjectKind::Tree, &tree(before, untouched));
    let base = loose(&source, format, GitObjectKind::Commit, &commit(root_tree, &[], "base"));
    fs::write(source.join("refs/heads/main"), format!("{base}\n")).unwrap();
    let request = node.request_context();
    let imported = node.runtime().block_on(node.import_loose_git_directory_durable_in(
        &request, &source, principal(), b"workspace-source",
    )).unwrap();
    assert!(matches!(imported.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
    (node, base, untouched)
}
fn pack(format: GitHashAlgorithm, objects: &[(GitObjectKind, Vec<u8>)]) -> Vec<u8> {
    let mut bytes = b"PACK\0\0\0\x02".to_vec();
    bytes.extend(u32::try_from(objects.len()).unwrap().to_be_bytes());
    for (kind, body) in objects {
        let mut size = body.len();
        let mut first = (kind.type_code() << 4) | u8::try_from(size & 15).unwrap();
        size >>= 4;
        if size != 0 { first |= 128; }
        bytes.push(first);
        while size != 0 {
            let mut next = u8::try_from(size & 127).unwrap();
            size >>= 7;
            if size != 0 { next |= 128; }
            bytes.push(next);
        }
        bytes.extend(zlib(body));
    }
    let checksum = match format {
        GitHashAlgorithm::Sha1 => sha1_digest(&bytes).to_vec(),
        GitHashAlgorithm::Sha256 => sha256_digest(&bytes).to_vec(),
    };
    bytes.extend(checksum);
    bytes
}
fn envelope(format: GitHashAlgorithm, base: GitOid, tip: GitOid, pack: &[u8]) -> Vec<u8> {
    [format!("# v3 git bundle\n@object-format={}\n-{base} source\n{tip} refs/heads/main\n\n",
        format.as_str()).as_bytes(), pack].concat()
}
fn candidate(format: GitHashAlgorithm, base: GitOid, untouched: GitOid,
    parents: &[GitOid], message: &str) -> (GitOid, GitOid, Vec<u8>) {
    let blob = format!("{message}\n").into_bytes();
    let blob_id = git_object_id(format, GitObjectKind::Blob, &blob);
    let tree = tree(blob_id, untouched);
    let tree_id = git_object_id(format, GitObjectKind::Tree, &tree);
    let commit = commit(tree_id, parents, message);
    let id = git_object_id(format, GitObjectKind::Commit, &commit);
    let pack = pack(format, &[(GitObjectKind::Blob, blob), (GitObjectKind::Tree, tree),
        (GitObjectKind::Commit, commit)]);
    (id, tree_id, envelope(format, base, id, &pack))
}
fn apply(node: &OneNode, key: &[u8], base: GitOid, tip: GitOid, bytes: &[u8])
    -> Result<AdmissionResult, NodeWorkspaceRefusal> {
    let request = node.request_context();
    node.runtime().block_on(node.apply_workspace_bundle_durable_in(
        &request, principal(), key, &reference(), base, tip, bytes,
    ))
}
fn observed(node: &OneNode) -> (GitOid, String) {
    let request = node.request_context();
    let state = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
    (state.snapshot().refs[&reference()], format!("{:?}", state.basis()))
}

#[test]
fn candidate_publishes_preserves_untouched_objects_and_replays_after_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, base, untouched) = setup(&scratch.0, format);
        let (tip, tree_id, bundle) = candidate(format, base, untouched, &[base], "accepted");
        let result = apply(&node, b"reviewed-change", base, tip, &bundle).unwrap();
        assert_eq!(result.commands.len(), 1);
        assert!(matches!(result.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        let after = observed(&node);
        assert_eq!(after.0, tip);
        assert_eq!(node.read_git_object(untouched).unwrap().payload(), b"preserve me\n");
        let emitted = node.read_git_object(tree_id).unwrap();
        assert!(emitted.payload().ends_with(untouched.as_bytes()));
        drop(emitted);
        node.shutdown().unwrap();

        let mut reopened = OneNode::open_existing(config(&scratch.0, format)).unwrap();
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(observed(&reopened), after);
        let retry = apply(&reopened, b"reviewed-change", base, tip, &bundle).unwrap();
        assert_eq!(retry.commands[0].terminal, result.commands[0].terminal);
        assert_eq!(observed(&reopened), after, "replay must not publish another head");
        reopened.shutdown().unwrap();
    }
}

#[test]
fn epoch_zero_candidate_refuses_before_publication_and_epoch_one_twin_commits() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, base, untouched) = setup(&scratch.0, format);
        let request = node.request_context();
        let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        let message = "reviewed timestamp";
        let (valid, tree_id, valid_bundle) = candidate(format, base, untouched, &[base], message);
        let permitted = String::from_utf8(commit(tree_id, &[base], message)).unwrap();
        assert_eq!(permitted.matches(" 1 +0000\n").count(), 2);
        let epoch_zero = permitted.replace(" 1 +0000\n", " 0 +0000\n");
        assert_eq!(epoch_zero.replace(" 0 +0000\n", " 1 +0000\n"), permitted);
        let refused_tip = git_object_id(format, GitObjectKind::Commit, epoch_zero.as_bytes());
        assert_ne!(refused_tip, valid);
        let blob = format!("{message}\n").into_bytes();
        let tree = tree(git_object_id(format, GitObjectKind::Blob, &blob), untouched);
        assert_eq!(git_object_id(format, GitObjectKind::Tree, &tree), tree_id);
        let packed = pack(format, &[
            (GitObjectKind::Blob, blob), (GitObjectKind::Tree, tree),
            (GitObjectKind::Commit, epoch_zero.as_bytes().to_vec()),
        ]);
        let refused_bundle = envelope(format, base, refused_tip, &packed);
        for _ in 0..2 {
            assert!(matches!(apply(&node, b"epoch-zero", base, refused_tip, &refused_bundle),
                Err(NodeWorkspaceRefusal::InvalidWorkspaceCandidate("candidate is not a bounded strict Git commit"))));
            let request = node.request_context();
            let after = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
            assert_eq!(after.basis().body(), before.basis().body(), "strict refusal cannot publish any root");
        }
        // Quarantine accepted and staged the import-compatible native object;
        // the workspace's additional strict creation profile refused it.
        assert_eq!(node.read_git_object(refused_tip).unwrap().payload(), epoch_zero.as_bytes());
        let accepted = apply(&node, b"epoch-one", base, valid, &valid_bundle).unwrap();
        assert!(matches!(accepted.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        let committed = observed(&node);
        assert_eq!(committed.0, valid);
        let retried = apply(&node, b"epoch-one", base, valid, &valid_bundle).unwrap();
        assert_eq!(retried.commands[0].terminal, accepted.commands[0].terminal);
        assert_eq!(observed(&node), committed);
        node.shutdown().unwrap();
    }
}

#[test]
fn competing_candidate_is_refused_and_key_reuse_cannot_alias_the_winner() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, base, untouched) = setup(&scratch.0, format);
        let (winner, _, first) = candidate(format, base, untouched, &[base], "winner");
        let (loser, _, second) = candidate(format, base, untouched, &[base], "loser");
        let accepted = apply(&node, b"first", base, winner, &first).unwrap();
        assert!(matches!(accepted.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        let after_winner = observed(&node);
        assert!(apply(&node, b"first", base, loser, &second).is_err());
        assert_eq!(observed(&node), after_winner, "different semantics must not reuse the seal");
        let refused = apply(&node, b"second", base, loser, &second).unwrap();
        assert!(matches!(refused.commands[0].terminal.outcome, DecisionOutcome::Refused { .. }));
        let after_refusal = observed(&node);
        assert_eq!(after_refusal.0, winner);
        let replay = apply(&node, b"second", base, loser, &second).unwrap();
        assert_eq!(replay.commands[0].terminal, refused.commands[0].terminal);
        assert_eq!(observed(&node), after_refusal);
        node.shutdown().unwrap();
    }
}

#[test]
fn corrupt_packs_wrong_reviewed_tips_and_non_fast_forward_shapes_never_publish() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, base, untouched) = setup(&scratch.0, format);
        let original = observed(&node);
        let (tip, _, valid) = candidate(format, base, untouched, &[base], "valid twin");
        let mut corrupt = valid.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(apply(&node, b"corrupt", base, tip, &corrupt).is_err());
        assert_eq!(observed(&node), original);
        assert!(apply(&node, b"wrong-review", base, untouched, &valid).is_err());
        assert_eq!(observed(&node), original);
        for (index, parents) in [vec![], vec![base, base]].iter().enumerate() {
            let (bad, _, bytes) = candidate(format, base, untouched, parents, "invalid shape");
            assert!(apply(&node, format!("shape-{index}").as_bytes(), base, bad, &bytes).is_err());
            assert_eq!(observed(&node), original);
        }
        let blob_pack = pack(format, &[(GitObjectKind::Blob, b"not a commit".to_vec())]);
        let blob = git_object_id(format, GitObjectKind::Blob, b"not a commit");
        assert!(apply(&node, b"blob", base, blob, &envelope(format, base, blob, &blob_pack)).is_err());
        assert_eq!(observed(&node), original);
        assert!(matches!(apply(&node, b"valid", base, tip, &valid).unwrap().commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }));
        node.shutdown().unwrap();
    }
}

#[test]
fn merely_staged_prerequisites_are_not_authority_and_unserving_nodes_do_not_publish() {
    let scratch = Scratch::new();
    let format = GitHashAlgorithm::Sha1;
    let (node, base, untouched) = setup(&scratch.0, format);
    let original = observed(&node);
    let fake_tree = git_object_id(format, GitObjectKind::Tree, b"");
    let staged = node.put_git_object(GitObjectKind::Commit, commit(fake_tree, &[], "not published")).unwrap().identity();
    let (tip, _, bytes) = candidate(format, staged, untouched, &[staged], "not authoritative");
    assert!(apply(&node, b"staged", staged, tip, &bytes).is_err());
    assert_eq!(observed(&node), original);
    let (valid_tip, _, valid) = candidate(format, base, untouched, &[base], "permitted twin");
    node.shutdown().unwrap();
    let reopened = OneNode::open_existing(config(&scratch.0, format)).unwrap();
    assert!(apply(&reopened, b"unserving", base, valid_tip, &valid).is_err());
    assert_eq!(observed(&reopened), original);
    reopened.shutdown().unwrap();
}
