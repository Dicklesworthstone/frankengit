//! Real file-backed node and imported native objects. No Git subprocess or
//! alternate authority implementation participates in these tests.
use super::*;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::preparation::replay::ReplayDirection;
use fgit_forge::review::{ComparisonMode, ReviewOptions};
use fgit_types::{DecisionOutcome, GitOid, HeadGeneration, PrincipalId, RepositoryId, TenantId};
use crate::NodeConfig;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("fg-replay-node-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&root).unwrap(); Self(root)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(self.0.join("node"), TenantId::from_bytes([0xc1;16]),
            RepositoryId::from_bytes([0xc2;16])).with_object_format(format).with_worker_threads(2)
    }
}
impl Drop for Scratch { fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); } }
fn main_ref() -> RefName { RefName::try_new(b"refs/heads/main").unwrap() }
fn topic_ref() -> RefName { RefName::try_new(b"refs/heads/topic").unwrap() }
fn principal() -> PrincipalId { PrincipalId::from_bytes([0xc3;16]) }
fn metadata() -> MergeMetadata {
    MergeMetadata { author: "Test <test@example.invalid>".into(), committer: "Test <test@example.invalid>".into(),
        timestamp: 2, message: b"exact replay\n".to_vec() }
}
fn loose(path: &Path, format: GitHashAlgorithm, kind: GitObjectKind, label: &str, body: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, body);
    let bytes = [format!("{label} {}\0", body.len()).as_bytes(), body].concat();
    let n = u16::try_from(bytes.len()).unwrap();
    let mut encoded = vec![0x78, 0x01, 0x01];
    encoded.extend(n.to_le_bytes()); encoded.extend((!n).to_le_bytes()); encoded.extend(&bytes);
    let (a,b) = bytes.iter().fold((1_u32, 0_u32), |(a,b), byte| {
        let a = (a + u32::from(*byte)) % 65521; (a, (b+a) % 65521)
    });
    encoded.extend(((b << 16) | a).to_be_bytes());
    let text = id.to_string(); let directory = path.join("objects").join(&text[..2]);
    fs::create_dir_all(&directory).unwrap(); fs::write(directory.join(&text[2..]), encoded).unwrap(); id
}
fn tree(entries: &[(&[u8], u32, GitOid)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, mode, id) in entries {
        body.extend(format!("{mode:o} ").as_bytes()); body.extend(*name); body.push(0); body.extend(id.as_bytes());
    }
    body
}
fn commit(tree: GitOid, parent: Option<GitOid>, label: &str) -> Vec<u8> {
    format!("tree {tree}\n{}author Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\n{label}\n",
        parent.map_or_else(String::new, |id| format!("parent {id}\n"))).into_bytes()
}
struct Fixture { target: GitOid, source: GitOid, picked: GitOid, base: GitOid, target_tree: GitOid, borrowed: GitOid }
fn fixture(scratch: &Scratch, format: GitHashAlgorithm, conflict: bool) -> (OneNode, Fixture) {
    let path = scratch.0.join("source"); fs::create_dir_all(path.join("refs/heads")).unwrap();
    fs::write(path.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(path.join("config"), match format {
        GitHashAlgorithm::Sha1 => "[core]\nbare=true\nrepositoryformatversion=0\n",
        GitHashAlgorithm::Sha256 => "[core]\nbare=true\nrepositoryformatversion=1\n[extensions]\nobjectformat=sha256\n",
    }).unwrap();
    let put = |kind, label, bytes: &[u8]| loose(&path, format, kind, label, bytes);
    let keep = put(GitObjectKind::Blob, "blob", b"keep\n");
    let target_only = put(GitObjectKind::Blob, "blob", b"target-only\n");
    let borrowed = put(GitObjectKind::Blob, "blob", b"selected source-only\n");
    let extra = put(GitObjectKind::Blob, "blob", b"later source must not appear\n");
    let base_tree = put(GitObjectKind::Tree, "tree", &tree(&[(b"keep",0o100644,keep)]));
    let base = put(GitObjectKind::Commit, "commit", &commit(base_tree, None, "base"));
    let target_name = if conflict { b"selected".as_slice() } else { b"target".as_slice() };
    let target_tree = put(GitObjectKind::Tree, "tree", &tree(&[(b"keep",0o100644,keep),(target_name,0o100755,target_only)]));
    let target = put(GitObjectKind::Commit, "commit", &commit(target_tree, Some(base), "target"));
    let picked_tree = put(GitObjectKind::Tree, "tree", &tree(&[(b"keep",0o100644,keep),(b"selected",0o100755,borrowed)]));
    let picked = put(GitObjectKind::Commit, "commit", &commit(picked_tree, Some(base), "selected"));
    let source_tree = put(GitObjectKind::Tree, "tree", &tree(&[(b"keep",0o100644,keep),(b"later",0o100644,extra),(b"selected",0o100755,borrowed)]));
    let source = put(GitObjectKind::Commit, "commit", &commit(source_tree, Some(picked), "later"));
    fs::write(path.join("refs/heads/main"), format!("{target}\n")).unwrap();
    fs::write(path.join("refs/heads/topic"), format!("{source}\n")).unwrap();
    let (mut node, _) = OneNode::init(scratch.config(format)).unwrap(); node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let request = node.request_context();
    let result = node.runtime().block_on(node.import_loose_git_directory_durable_in(&request, &path, principal(), b"replay-import")).unwrap();
    assert!(result.commands.iter().all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. })));
    (node, Fixture { target, source, picked, base, target_tree, borrowed })
}
fn inputs(f: &Fixture) -> ReplayRequest {
    ReplayRequest { target: f.target, source_tip: f.source, selected_commit: f.picked,
        direction: ReplayDirection::CherryPick, mainline: None }
}

#[test]
fn borrowed_source_objects_are_in_the_target_only_bundle_and_replay_round_trips() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let (node, f) = fixture(&scratch, format, false);
        let request = node.request_context();
        let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        let artifact = node.runtime().block_on(node.prepare_replay_bundle_in(&request, &main_ref(), &topic_ref(),
            inputs(&f), &Default::default(), Some(before.basis().id()), &metadata(), PreparationLimits::default())).unwrap();
        assert_eq!(artifact.source_head, before.basis().id());
        assert_eq!(artifact.borrowed_objects, 1);
        let ReplayPreparation::Clean(plan) = &artifact.outcome else { panic!("candidate required"); };
        assert!(!plan.objects.iter().any(|object| object.id == f.borrowed));
        assert_eq!(artifact.pack_objects, plan.objects.len() + 1);
        assert!(node.read_git_object(plan.commit).is_err());
        let bundle = artifact.bundle.as_ref().unwrap();
        let inspected = node.runtime().block_on(node.inspect_workspace_bundle_in(&request, &main_ref(),
            f.target, plan.commit, bundle, &Default::default(), Some(before.basis().id()), &ReviewOptions { mode: ComparisonMode::Direct, ..ReviewOptions::default() })).unwrap();
        assert_eq!(inspected.parents, vec![f.target]); assert_eq!(inspected.prerequisites, vec![f.target]);
        assert_eq!(inspected.pack_objects, artifact.pack_objects);
        assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis(), before.basis());
        let applied = node.runtime().block_on(node.apply_workspace_bundle_durable_in(&request, principal(), b"picked",
            &main_ref(), f.target, plan.commit, bundle)).unwrap();
        assert!(matches!(applied.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        let after = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        assert_eq!(after.snapshot().refs[&main_ref()], plan.commit);
        assert_eq!(after.snapshot().refs[&topic_ref()], f.source);
        assert_eq!(after.basis().body().forge_position_root, before.basis().body().forge_position_root);
        let reverse = ReplayRequest { direction: ReplayDirection::Revert, target: plan.commit,
            source_tip: plan.commit, selected_commit: plan.commit, mainline: None };
        let reverted = node.runtime().block_on(node.prepare_replay_bundle_in(&request, &main_ref(), &main_ref(),
            reverse, &Default::default(), Some(after.basis().id()), &metadata(), PreparationLimits::default())).unwrap();
        let ReplayPreparation::Clean(revert) = &reverted.outcome else { panic!("inverse candidate required"); };
        assert_eq!(revert.tree, f.target_tree);
        assert_eq!(reverted.borrowed_objects, 0);
        assert!(node.read_git_object(revert.commit).is_err());
        let result = node.runtime().block_on(node.apply_workspace_bundle_durable_in(&request, principal(), b"reverted",
            &main_ref(), plan.commit, revert.commit, reverted.bundle.as_ref().unwrap())).unwrap();
        assert!(matches!(result.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        // Replaying the original publication must not roll back its descendant.
        let retry = node.runtime().block_on(node.apply_workspace_bundle_durable_in(&request, principal(), b"picked",
            &main_ref(), f.target, plan.commit, bundle)).unwrap();
        assert_eq!(retry.commands[0].terminal, applied.commands[0].terminal);
        assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().snapshot().refs[&main_ref()], revert.commit);
        node.shutdown().unwrap();
    }
}

#[test]
fn conflict_staleness_visibility_history_and_byte_budgets_never_mutate_the_node() {
    let scratch = Scratch::new(); let (node, f) = fixture(&scratch, GitHashAlgorithm::Sha1, true);
    let request = node.request_context();
    let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
    let artifact = node.runtime().block_on(node.prepare_replay_bundle_in(&request, &main_ref(), &topic_ref(),
        inputs(&f), &Default::default(), None, &metadata(), PreparationLimits::default())).unwrap();
    assert!(matches!(artifact.outcome, ReplayPreparation::Conflicted { .. }));
    assert!(artifact.bundle.is_none()); assert_eq!(artifact.pack_objects, 0);
    let mut hidden = RefVisibility::new(); hidden.push_rule(b"refs/heads/topic", &fgit_wire::WireLimits::default()).unwrap();
    assert!(matches!(node.runtime().block_on(node.prepare_replay_bundle_in(&request, &main_ref(), &topic_ref(),
        inputs(&f), &hidden, None, &metadata(), PreparationLimits::default())), Err(ReplayPreparationRefusal::RefUnavailable)));
    let stale = ReplayRequest { target: f.base, ..inputs(&f) };
    assert!(matches!(node.runtime().block_on(node.prepare_replay_bundle_in(&request, &main_ref(), &topic_ref(),
        stale, &Default::default(), None, &metadata(), PreparationLimits::default())), Err(ReplayPreparationRefusal::TipMoved)));
    let unrelated = ReplayRequest { selected_commit: f.target, ..inputs(&f) };
    assert!(matches!(node.runtime().block_on(node.prepare_replay_bundle_in(&request, &main_ref(), &topic_ref(),
        unrelated, &Default::default(), None, &metadata(), PreparationLimits::default())),
        Err(ReplayPreparationRefusal::Preparation(error)) if matches!(*error, ReplayError::CommitOutsideSourceHistory)));
    let limits = PreparationLimits { max_commits: 1, ..PreparationLimits::default() };
    assert!(node.runtime().block_on(node.prepare_replay_bundle_in(&request, &main_ref(), &topic_ref(),
        inputs(&f), &Default::default(), None, &metadata(), limits)).is_err());
    assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis(), before.basis());
    node.shutdown().unwrap();
}

#[test]
fn snapshot_pin_rejects_later_authority_movement_even_when_selected_commit_remains_reachable() {
    let scratch = Scratch::new(); let (node, f) = fixture(&scratch, GitHashAlgorithm::Sha256, false);
    let request = node.request_context(); let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
    let artifact = node.runtime().block_on(node.prepare_replay_bundle_in(&request, &main_ref(), &topic_ref(),
        inputs(&f), &Default::default(), Some(before.basis().id()), &metadata(), PreparationLimits::default())).unwrap();
    let ReplayPreparation::Clean(plan) = artifact.outcome else { panic!("candidate"); };
    node.runtime().block_on(node.apply_workspace_bundle_durable_in(&request, principal(), b"pin-test",
        &main_ref(), f.target, plan.commit, &artifact.bundle.unwrap())).unwrap();
    let updated = ReplayRequest { target: plan.commit, ..inputs(&f) };
    assert!(matches!(node.runtime().block_on(node.prepare_replay_bundle_in(&request, &main_ref(), &topic_ref(),
        updated, &Default::default(), Some(before.basis().id()), &metadata(), PreparationLimits::default())),
        Err(ReplayPreparationRefusal::SnapshotMoved)));
    let no_change = node.runtime().block_on(node.prepare_replay_bundle_in(&request, &main_ref(), &topic_ref(),
        updated, &Default::default(), None, &metadata(), PreparationLimits::default())).unwrap();
    assert!(matches!(no_change.outcome, ReplayPreparation::NoChange { .. })); assert!(no_change.bundle.is_none());
    node.shutdown().unwrap();
}
