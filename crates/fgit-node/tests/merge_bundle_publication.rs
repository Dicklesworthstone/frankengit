#![forbid(unsafe_code)]
//! Real artifact intake -> native merge -> coupled authority publication.
//! Fixture encoders produce transport bytes, not a replacement authority.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_admission::AdmissionLimits;
use fgit_admission::merge::native::{NativeMergeIntent, objects::MergeObjectLimits};
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest, sha256_digest};
use fgit_forge::aggregate::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_forge::event::NativeMerge;
use fgit_node::{LoopbackReceiveSession, MaterializedAdmission, NodeConfig, NodeWorkspaceRefusal, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId,
    RefName, RefusalCode, RepositoryId, TenantId, TxId};

static NEXT: AtomicU64 = AtomicU64::new(1);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("fgit-merge-bundle-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        if self.0.exists() { fs::remove_dir_all(&self.0).expect("owned scratch directory"); }
    }
}
fn principal() -> PrincipalId { PrincipalId::from_bytes([0x93; 16]) }
fn target() -> RefName { RefName::try_new(b"refs/heads/main").unwrap() }
fn source_ref() -> RefName { RefName::try_new(b"refs/heads/topic").unwrap() }
fn config(root: &Path, format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(root.join("node"), TenantId::from_bytes([0x91; 16]),
        RepositoryId::from_bytes([0x92; 16])).with_object_format(format)
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
    let parent = root.join("objects").join(&hex[..2]);
    fs::create_dir_all(&parent).unwrap();
    fs::write(parent.join(&hex[2..]), zlib(&framed)).unwrap();
    id
}
fn tree(entries: &[(&str, GitOid)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, id) in entries {
        body.extend(format!("100644 {name}\0").as_bytes());
        body.extend(id.as_bytes());
    }
    body
}
fn commit(tree: GitOid, parents: &[GitOid], label: &str) -> Vec<u8> {
    let parents: String = parents.iter().map(|id| format!("parent {id}\n")).collect();
    format!("tree {tree}\n{parents}author Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\n{label}\n").into_bytes()
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
fn envelope(format: GitHashAlgorithm, old: GitOid, tip: GitOid, name: &RefName, packed: &[u8]) -> Vec<u8> {
    [format!("# v3 git bundle\n@object-format={}\n-{old} target prerequisite\n{tip} {}\n\n",
        format.as_str(), String::from_utf8_lossy(name.as_bytes())).as_bytes(), packed].concat()
}
struct History {
    base: GitOid,
    target: GitOid,
    source: GitOid,
    common: GitOid,
    ours: GitOid,
    theirs: GitOid,
}
fn setup(root: &Path, format: GitHashAlgorithm) -> (OneNode, History) {
    let (mut node, _) = OneNode::init(config(root, format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let source = root.join("source");
    fs::create_dir_all(source.join("refs/heads")).unwrap();
    fs::write(source.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(source.join("config"), match format {
        GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
        GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
    }).unwrap();
    let common = loose(&source, format, GitObjectKind::Blob, b"common\n");
    let ours = loose(&source, format, GitObjectKind::Blob, b"ours\n");
    let theirs = loose(&source, format, GitObjectKind::Blob, b"theirs\n");
    let base_tree = loose(&source, format, GitObjectKind::Tree, &tree(&[("common.txt", common)]));
    let ours_tree = loose(&source, format, GitObjectKind::Tree,
        &tree(&[("common.txt", common), ("ours.txt", ours)]));
    let theirs_tree = loose(&source, format, GitObjectKind::Tree,
        &tree(&[("common.txt", common), ("theirs.txt", theirs)]));
    let base = loose(&source, format, GitObjectKind::Commit, &commit(base_tree, &[], "base"));
    let target = loose(&source, format, GitObjectKind::Commit, &commit(ours_tree, &[base], "ours"));
    let topic = loose(&source, format, GitObjectKind::Commit, &commit(theirs_tree, &[base], "theirs"));
    fs::write(source.join("refs/heads/main"), format!("{target}\n")).unwrap();
    fs::write(source.join("refs/heads/topic"), format!("{topic}\n")).unwrap();
    let request = node.request_context();
    let imported = node.runtime().block_on(node.import_loose_git_directory_durable_in(
        &request, &source, principal(), b"merge-artifact-source",
    )).unwrap();
    assert_eq!(imported.commands.len(), 2);
    assert!(imported.commands.iter().all(|command|
        matches!(command.terminal.outcome, DecisionOutcome::Committed { .. })));
    (node, History { base, target, source: topic, common, ours, theirs })
}
struct Candidate {
    merge: NativeMerge,
    bytes: Vec<u8>,
    tree: GitOid,
    tree_body: Vec<u8>,
}
fn candidate(format: GitHashAlgorithm, h: &History, old: GitOid, parents: &[GitOid], label: &str) -> Candidate {
    let blob = format!("reviewed {label}\n").into_bytes();
    let blob_id = git_object_id(format, GitObjectKind::Blob, &blob);
    let tree_body = tree(&[("common.txt", h.common), ("ours.txt", h.ours),
        ("reviewed.txt", blob_id), ("theirs.txt", h.theirs)]);
    let tree = git_object_id(format, GitObjectKind::Tree, &tree_body);
    let body = commit(tree, parents, label);
    let tip = git_object_id(format, GitObjectKind::Commit, &body);
    let packed = pack(format, &[(GitObjectKind::Blob, blob),
        (GitObjectKind::Tree, tree_body.clone()), (GitObjectKind::Commit, body)]);
    Candidate {
        merge: NativeMerge { source_ref: source_ref(), source_tip: h.source, base_tip: h.base,
            target_ref: target(), target_tip_before: old, merge_commit: tip },
        bytes: envelope(format, old, tip, &target(), &packed), tree, tree_body,
    }
}
fn snapshot(node: &OneNode) -> MaterializedAdmission {
    let request = node.request_context();
    node.runtime().block_on(node.materialize_admission_in(&request)).unwrap()
}
fn apply(node: &OneNode, candidate: &Candidate, number: u64, version: ExpectedVersion, key: &[u8])
    -> Result<(TxId, TerminalOutcome), NodeWorkspaceRefusal>
{
    let request = node.request_context();
    node.runtime().block_on(node.apply_merge_bundle_durable_in(
        &request, principal(), key, PullRequestNumber::try_new(number).unwrap(),
        version, &candidate.merge, &candidate.bytes,
    ))
}
fn unchanged_effects(before: &MaterializedAdmission, after: &MaterializedAdmission) {
    assert_eq!(before.snapshot().refs, after.snapshot().refs);
    assert_eq!(before.snapshot().head_target, after.snapshot().head_target);
    assert_eq!(before.basis().body().ref_root, after.basis().body().ref_root);
    assert_eq!(before.basis().body().forge_position_root, after.basis().body().forge_position_root);
    assert_eq!(before.basis().body().outbox_root, after.basis().body().outbox_root);
    assert_eq!(before.basis().body().retention_root, after.basis().body().retention_root);
}

#[test]
fn unstaged_bundle_publishes_one_complete_merge_and_shares_native_transaction_identity() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, h) = setup(&scratch.0, format);
        let proposed = candidate(format, &h, h.target, &[h.target, h.source], "reviewed");
        assert!(node.read_git_object(proposed.merge.merge_commit).is_err());
        assert!(node.read_git_object(proposed.tree).is_err());
        let before = snapshot(&node);
        let (tx_id, terminal) = apply(&node, &proposed, 1, ExpectedVersion::NewStream, b"artifact").unwrap();
        assert!(matches!(terminal.outcome, DecisionOutcome::Committed { .. }));
        let after = snapshot(&node);
        assert_eq!(after.basis().generation().get(), before.basis().generation().get() + 1,
            "there must be no intermediate ref-only publication");
        assert_eq!(after.snapshot().refs[&target()], proposed.merge.merge_commit);
        assert_eq!(after.snapshot().refs[&source_ref()], h.source);
        assert_eq!(after.snapshot().head_target, before.snapshot().head_target);
        assert_eq!(after.snapshot().forge_positions.len(), 1);
        assert_eq!(after.snapshot().outbox.len(), 1);
        assert_ne!(after.basis().body().ref_root, before.basis().body().ref_root);
        assert_ne!(after.basis().body().forge_position_root, before.basis().body().forge_position_root);
        assert_ne!(after.basis().body().outbox_root, before.basis().body().outbox_root);
        assert_eq!(node.read_git_object(proposed.tree).unwrap().payload(), proposed.tree_body);
        assert_eq!(node.read_git_object(h.common).unwrap().payload(), b"common\n");
        let request = node.request_context();
        let history = node.runtime().block_on(node.snapshot_history_in(&request)).unwrap();
        let last = history.last().unwrap();
        assert_eq!(last.batch.committed_rcrs.len(), 1);
        assert_eq!(last.batch.committed_rcrs[0].tx_id, tx_id);
        let intent = NativeMergeIntent::new(PullRequestNumber::try_new(1).unwrap(),
            ExpectedVersion::NewStream, proposed.merge.clone()).unwrap();
        assert_eq!(last.forge_events, vec![intent.event().clone()]);
        let session = LoopbackReceiveSession::authenticated(principal(), IdempotencyKey::new(b"artifact".to_vec()).unwrap());
        assert_eq!(node.runtime().block_on(node.admit_native_merge_durable_in(
            &request, &session, &intent, AdmissionLimits::default(), MergeObjectLimits::default(),
        )).unwrap(), terminal);
        assert_eq!(snapshot(&node).basis(), after.basis());
        node.shutdown().unwrap();
    }
}

#[test]
fn bundle_retry_after_reopen_and_later_merge_never_rolls_back_or_duplicates_delivery() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, h) = setup(&scratch.0, format);
        let first = candidate(format, &h, h.target, &[h.target, h.source], "first");
        let original = apply(&node, &first, 1, ExpectedVersion::NewStream, b"first").unwrap();
        assert!(matches!(original.1.outcome, DecisionOutcome::Committed { .. }));
        node.shutdown().unwrap();
        let mut node = OneNode::open_existing(config(&scratch.0, format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let next = candidate(format, &h, first.merge.merge_commit,
            &[first.merge.merge_commit, h.source], "next");
        let later = apply(&node, &next, 2, ExpectedVersion::NewStream, b"later").unwrap();
        assert!(matches!(later.1.outcome, DecisionOutcome::Committed { .. }));
        let after = snapshot(&node);
        assert_eq!(after.snapshot().outbox.len(), 2);
        assert_eq!(apply(&node, &first, 1, ExpectedVersion::NewStream, b"first").unwrap(), original);
        assert_eq!(snapshot(&node).basis(), after.basis());
        assert_eq!(snapshot(&node).snapshot().refs[&target()], next.merge.merge_commit);
        node.shutdown().unwrap();
    }
}

#[test]
fn competing_artifacts_and_changed_review_semantics_cannot_alias_a_winner() {
    let scratch = Scratch::new();
    let format = GitHashAlgorithm::Sha1;
    let (node, h) = setup(&scratch.0, format);
    let winner = candidate(format, &h, h.target, &[h.target, h.source], "winner");
    let loser = candidate(format, &h, h.target, &[h.target, h.source], "loser");
    let accepted = apply(&node, &winner, 1, ExpectedVersion::NewStream, b"winner").unwrap();
    assert!(matches!(accepted.1.outcome, DecisionOutcome::Committed { .. }));
    let before = snapshot(&node);
    assert!(apply(&node, &loser, 1, ExpectedVersion::NewStream, b"winner").is_err());
    assert!(apply(&node, &winner, 2, ExpectedVersion::NewStream, b"winner").is_err());
    assert_eq!(snapshot(&node).basis(), before.basis());
    let refusal = apply(&node, &loser, 2, ExpectedVersion::NewStream, b"loser").unwrap();
    assert!(matches!(refusal.1.outcome, DecisionOutcome::Refused { code: RefusalCode::TargetRefMoved, .. }));
    let after = snapshot(&node);
    unchanged_effects(&before, &after);
    assert_eq!(apply(&node, &loser, 2, ExpectedVersion::NewStream, b"loser").unwrap(), refusal);
    assert_eq!(snapshot(&node).basis(), after.basis());
    node.shutdown().unwrap();
}

#[test]
fn wrong_parent_shapes_and_wrong_aggregate_version_refuse_without_partial_merge() {
    for reversed in [false, true] {
        let scratch = Scratch::new();
        let format = GitHashAlgorithm::Sha256;
        let (node, h) = setup(&scratch.0, format);
        let parents = if reversed { vec![h.source, h.target] } else { vec![h.target] };
        let bad = candidate(format, &h, h.target, &parents, "invalid merge parents");
        let before = snapshot(&node);
        let rejected = apply(&node, &bad, 1, ExpectedVersion::NewStream, b"bad-parents").unwrap();
        assert!(matches!(rejected.1.outcome, DecisionOutcome::Refused { code: RefusalCode::EvidenceInvalid, .. }));
        unchanged_effects(&before, &snapshot(&node));
        let good = candidate(format, &h, h.target, &[h.target, h.source], "valid merge");
        let before = snapshot(&node);
        let version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
        let rejected = apply(&node, &good, 1, version, b"wrong-version").unwrap();
        assert!(matches!(rejected.1.outcome, DecisionOutcome::Refused { code: RefusalCode::EvidenceStale, .. }));
        unchanged_effects(&before, &snapshot(&node));
        assert!(matches!(apply(&node, &good, 1, ExpectedVersion::NewStream, b"valid").unwrap().1.outcome,
            DecisionOutcome::Committed { .. }));
        node.shutdown().unwrap();
    }
}

#[test]
fn corrupt_or_misbound_artifacts_do_not_publish_and_the_valid_twin_commits() {
    let scratch = Scratch::new();
    let format = GitHashAlgorithm::Sha1;
    let (node, h) = setup(&scratch.0, format);
    let mut good = candidate(format, &h, h.target, &[h.target, h.source], "reviewed");
    let valid = good.bytes.clone();
    let before = snapshot(&node);
    let boundary = valid.windows(4).position(|bytes| bytes == b"PACK").unwrap();
    let mut corrupt = valid.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    let alternatives = [
        corrupt,
        envelope(format, h.base, good.merge.merge_commit, &target(), &valid[boundary..]),
        envelope(format, h.target, good.merge.merge_commit, &source_ref(), &valid[boundary..]),
        envelope(format, h.target, h.source, &target(), &valid[boundary..]),
        envelope(format, h.target, good.merge.merge_commit, &target(), &pack(format, &[])),
    ];
    for bytes in alternatives {
        good.bytes = bytes;
        assert!(apply(&node, &good, 1, ExpectedVersion::NewStream, b"invalid-envelope").is_err());
        assert_eq!(snapshot(&node).basis(), before.basis());
    }
    good.bytes = valid;
    assert!(matches!(apply(&node, &good, 1, ExpectedVersion::NewStream, b"valid-envelope").unwrap().1.outcome,
        DecisionOutcome::Committed { .. }));
    node.shutdown().unwrap();
}

#[test]
fn workspace_apply_cannot_publish_the_merge_as_a_source_only_update() {
    let scratch = Scratch::new();
    let format = GitHashAlgorithm::Sha1;
    let (node, h) = setup(&scratch.0, format);
    let merge = candidate(format, &h, h.target, &[h.target, h.source], "reviewed");
    let before = snapshot(&node);
    let request = node.request_context();
    assert!(matches!(node.runtime().block_on(node.apply_workspace_bundle_durable_in(
        &request, principal(), b"workspace-refuses", &target(), h.target,
        merge.merge.merge_commit, &merge.bytes,
    )), Err(NodeWorkspaceRefusal::InvalidWorkspaceCandidate(_))));
    assert_eq!(snapshot(&node).basis(), before.basis());
    assert!(matches!(apply(&node, &merge, 1, ExpectedVersion::NewStream, b"merge-permits").unwrap().1.outcome,
        DecisionOutcome::Committed { .. }));
    assert_eq!(snapshot(&node).snapshot().outbox.len(), 1);
    node.shutdown().unwrap();
}

#[test]
fn an_unserving_node_refuses_before_staging_candidate_objects() {
    let scratch = Scratch::new();
    let format = GitHashAlgorithm::Sha256;
    let (node, h) = setup(&scratch.0, format);
    let merge = candidate(format, &h, h.target, &[h.target, h.source], "reviewed");
    let before = snapshot(&node);
    node.shutdown().unwrap();
    let mut node = OneNode::open_existing(config(&scratch.0, format)).unwrap();
    assert!(apply(&node, &merge, 1, ExpectedVersion::NewStream, b"service-gate").is_err());
    assert!(node.read_git_object(merge.merge.merge_commit).is_err());
    assert!(node.read_git_object(merge.tree).is_err());
    assert_eq!(snapshot(&node).basis(), before.basis());
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    assert!(matches!(apply(&node, &merge, 1, ExpectedVersion::NewStream, b"service-gate").unwrap().1.outcome,
        DecisionOutcome::Committed { .. }));
    node.shutdown().unwrap();
}
