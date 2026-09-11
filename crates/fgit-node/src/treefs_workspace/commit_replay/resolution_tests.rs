//! End-to-end explicit replay resolution on the embedded authority. The fixtures
//! import actual native loose objects, never substitute an authority map.
use super::*;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::preparation::replay::ReplayDirection;
use fgit_forge::preparation::resolution::ResolutionChoice;
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
        let root = std::env::temp_dir().join(format!("fg-replay-resolution-{}-{}",
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
        timestamp: 2, message: b"resolved replay\n".to_vec() }
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
struct Fixture { input: ReplayRequest, borrowed: GitOid, source_tree: GitOid, keep_tree: GitOid }
fn fixture(scratch: &Scratch, format: GitHashAlgorithm) -> (OneNode, Fixture) {
    let path = scratch.0.join("source"); fs::create_dir_all(path.join("refs/heads")).unwrap();
    fs::write(path.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(path.join("config"), match format {
        GitHashAlgorithm::Sha1 => "[core]\nbare=true\nrepositoryformatversion=0\n",
        GitHashAlgorithm::Sha256 => "[core]\nbare=true\nrepositoryformatversion=1\n[extensions]\nobjectformat=sha256\n",
    }).unwrap();
    let put = |kind, label, bytes: &[u8]| loose(&path, format, kind, label, bytes);
    let keep = put(GitObjectKind::Blob, "blob", b"keep\n");
    let ours = put(GitObjectKind::Blob, "blob", b"target-only\n");
    let borrowed = put(GitObjectKind::Blob, "blob", b"selected source-only\n");
    let extra = put(GitObjectKind::Blob, "blob", b"later source must not appear\n");
    let base_tree = put(GitObjectKind::Tree, "tree", &tree(&[(b"keep",0o100644,keep)]));
    let base = put(GitObjectKind::Commit, "commit", &commit(base_tree, None, "base"));
    let target_tree = put(GitObjectKind::Tree, "tree", &tree(&[(b"keep",0o100644,keep),(b"selected",0o100755,ours)]));
    let target = put(GitObjectKind::Commit, "commit", &commit(target_tree, Some(base), "target"));
    let picked_tree = put(GitObjectKind::Tree, "tree", &tree(&[(b"keep",0o100644,keep),(b"selected",0o100755,borrowed)]));
    let picked = put(GitObjectKind::Commit, "commit", &commit(picked_tree, Some(base), "selected"));
    let source_tree = put(GitObjectKind::Tree, "tree", &tree(&[(b"keep",0o100644,keep),(b"later",0o100644,extra),(b"selected",0o100755,borrowed)]));
    let source = put(GitObjectKind::Commit, "commit", &commit(source_tree, Some(picked), "later"));
    fs::write(path.join("refs/heads/main"), format!("{target}\n")).unwrap();
    fs::write(path.join("refs/heads/topic"), format!("{source}\n")).unwrap();
    let (mut node, _) = OneNode::init(scratch.config(format)).unwrap(); node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let request = node.request_context();
    let result = node.runtime().block_on(node.import_loose_git_directory_durable_in(&request, &path, principal(), b"resolution-import")).unwrap();
    assert!(result.commands.iter().all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. })));
    (node, Fixture { input: ReplayRequest { direction: ReplayDirection::CherryPick, target, source_tip: source,
        selected_commit: picked, mainline: None }, borrowed, source_tree: picked_tree, keep_tree: base_tree })
}
fn choice(value: ResolutionChoice) -> ConflictResolution { ConflictResolution { path: b"selected".to_vec(), choice: value } }

#[test]
fn manual_pick_and_conflicted_revert_pass_inspection_publication_and_reopen_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let (node, f) = fixture(&scratch, format);
        let request = node.request_context();
        let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        let bytes = b"manual resolution\0\xff\r\nexact end";
        let choices = [choice(ResolutionChoice::File { mode: 0o100755, bytes: bytes.to_vec() })];
        let resolved = node.runtime().block_on(node.prepare_resolved_replay_bundle_in(&request,
            &main_ref(), &topic_ref(), f.input, &Default::default(), Some(before.basis().id()),
            &choices, &metadata(), PreparationLimits::default())).unwrap();
        let artifact = &resolved.artifact;
        let ReplayPreparation::Clean(plan) = &artifact.outcome else { panic!("resolved candidate"); };
        let blob = git_object_id(format, GitObjectKind::Blob, bytes);
        assert!(node.read_git_object(blob).is_err()); assert!(node.read_git_object(plan.commit).is_err());
        let bundle = artifact.bundle.as_ref().unwrap();
        let inspected = node.runtime().block_on(node.inspect_workspace_bundle_in(&request, &main_ref(), f.input.target,
            plan.commit, bundle, &Default::default(), Some(before.basis().id()),
            &ReviewOptions { mode: ComparisonMode::Direct, ..ReviewOptions::default() })).unwrap();
        assert_eq!(inspected.parents, vec![f.input.target]); assert_eq!(inspected.prerequisites, vec![f.input.target]);
        assert_eq!(resolved.resolutions[0].result.as_ref().unwrap().oid, blob);
        assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis(), before.basis());
        let applied = node.runtime().block_on(node.apply_workspace_bundle_durable_in(&request, principal(), b"resolved-pick",
            &main_ref(), f.input.target, plan.commit, bundle)).unwrap();
        assert!(matches!(applied.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        assert_eq!(node.read_git_object(blob).unwrap().payload(), bytes);
        let reverse = ReplayRequest { direction: ReplayDirection::Revert, target: plan.commit, ..f.input };
        let auto = node.runtime().block_on(node.prepare_replay_bundle_in(&request, &main_ref(), &topic_ref(), reverse,
            &Default::default(), None, &metadata(), PreparationLimits::default())).unwrap();
        assert!(matches!(auto.outcome, ReplayPreparation::Conflicted { .. }));
        let inverse = node.runtime().block_on(node.prepare_resolved_replay_bundle_in(&request, &main_ref(), &topic_ref(), reverse,
            &Default::default(), None, &[choice(ResolutionChoice::Delete)], &metadata(), PreparationLimits::default())).unwrap();
        let ReplayPreparation::Clean(revert) = &inverse.artifact.outcome else { panic!("inverse resolution"); };
        assert_eq!(revert.tree, f.keep_tree);
        let reverted = node.runtime().block_on(node.apply_workspace_bundle_durable_in(&request, principal(), b"resolved-revert",
            &main_ref(), plan.commit, revert.commit, inverse.artifact.bundle.as_ref().unwrap())).unwrap();
        assert!(matches!(reverted.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        let final_commit = revert.commit;
        assert_eq!(node.runtime().block_on(node.apply_workspace_bundle_durable_in(&request, principal(), b"resolved-pick",
            &main_ref(), f.input.target, plan.commit, bundle)).unwrap().commands[0].terminal, applied.commands[0].terminal);
        let after = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        assert_eq!(after.snapshot().refs[&main_ref()], final_commit);
        assert_eq!(after.snapshot().refs[&topic_ref()], f.input.source_tip);
        assert_eq!(after.basis().body().forge_position_root, before.basis().body().forge_position_root);
        assert_eq!(after.basis().body().outbox_root, before.basis().body().outbox_root);
        node.shutdown().unwrap();
        let reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        assert_eq!(reopened.read_git_object(blob).unwrap().payload(), bytes);
        let context = reopened.request_context();
        assert_eq!(reopened.runtime().block_on(reopened.materialize_admission_in(&context)).unwrap().snapshot().refs[&main_ref()], final_commit);
        reopened.shutdown().unwrap();
    }
}

#[test]
fn side_resolution_packs_source_only_dependencies_and_never_requires_later_source_history() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let (node, f) = fixture(&scratch, format);
        let request = node.request_context();
        let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        let resolved = node.runtime().block_on(node.prepare_resolved_replay_bundle_in(&request, &main_ref(), &topic_ref(),
            f.input, &Default::default(), None, &[choice(ResolutionChoice::Theirs)], &metadata(), PreparationLimits::default())).unwrap();
        let ReplayPreparation::Clean(plan) = &resolved.artifact.outcome else { panic!("side candidate"); };
        assert_eq!(plan.tree, f.source_tree);
        assert!(!plan.objects.iter().any(|object| object.id == f.borrowed));
        assert_eq!(resolved.artifact.borrowed_objects, 2, "source-only tree and blob must be packed");
        let inspected = node.runtime().block_on(node.inspect_workspace_bundle_in(&request, &main_ref(), f.input.target, plan.commit,
            resolved.artifact.bundle.as_ref().unwrap(), &Default::default(), None,
            &ReviewOptions { mode: ComparisonMode::Direct, ..ReviewOptions::default() })).unwrap();
        assert_eq!(inspected.prerequisites, vec![f.input.target]);
        assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis(), before.basis());
        node.shutdown().unwrap();
    }
}

#[test]
fn no_change_resolution_retains_receipts_but_never_builds_an_empty_commit() {
    let scratch = Scratch::new(); let (node, f) = fixture(&scratch, GitHashAlgorithm::Sha1);
    let request = node.request_context(); let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
    let resolved = node.runtime().block_on(node.prepare_resolved_replay_bundle_in(&request, &main_ref(), &topic_ref(),
        f.input, &Default::default(), None, &[choice(ResolutionChoice::Ours)], &metadata(), PreparationLimits::default())).unwrap();
    assert!(matches!(resolved.artifact.outcome, ReplayPreparation::NoChange { .. }));
    assert_eq!(resolved.resolutions.len(), 1); assert!(resolved.artifact.bundle.is_none());
    assert_eq!(resolved.artifact.pack_objects, 0); assert_eq!(resolved.artifact.borrowed_objects, 0);
    assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis(), before.basis());
    node.shutdown().unwrap();
}

#[test]
fn invalid_incomplete_hidden_stale_and_over_budget_resolution_cannot_mutate_state() {
    let scratch = Scratch::new(); let (node, f) = fixture(&scratch, GitHashAlgorithm::Sha256);
    let request = node.request_context(); let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
    for choices in [vec![], vec![choice(ResolutionChoice::Base)],
        vec![choice(ResolutionChoice::Ours), choice(ResolutionChoice::Theirs)],
        vec![ConflictResolution { path: b"keep".to_vec(), choice: ResolutionChoice::Delete }]] {
        assert!(node.runtime().block_on(node.prepare_resolved_replay_bundle_in(&request, &main_ref(), &topic_ref(), f.input,
            &Default::default(), None, &choices, &metadata(), PreparationLimits::default())).is_err());
    }
    let choices = [choice(ResolutionChoice::Theirs)];
    let mut hidden = RefVisibility::new(); hidden.push_rule(b"refs/heads/topic", &fgit_wire::WireLimits::default()).unwrap();
    assert!(matches!(node.runtime().block_on(node.prepare_resolved_replay_bundle_in(&request, &main_ref(), &topic_ref(), f.input,
        &hidden, None, &choices, &metadata(), PreparationLimits::default())), Err(ReplayPreparationRefusal::RefUnavailable)));
    let stale = ReplayRequest { target: f.input.selected_commit, ..f.input };
    assert!(matches!(node.runtime().block_on(node.prepare_resolved_replay_bundle_in(&request, &main_ref(), &topic_ref(), stale,
        &Default::default(), None, &choices, &metadata(), PreparationLimits::default())), Err(ReplayPreparationRefusal::TipMoved)));
    let limited = PreparationLimits { max_tree_entries: 5, ..PreparationLimits::default() };
    assert!(node.runtime().block_on(node.prepare_resolved_replay_bundle_in(&request, &main_ref(), &topic_ref(), f.input,
        &Default::default(), None, &choices, &metadata(), limited)).is_err());
    assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis(), before.basis());
    node.shutdown().unwrap();
}
