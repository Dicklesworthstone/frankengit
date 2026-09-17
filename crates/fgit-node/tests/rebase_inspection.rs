#![forbid(unsafe_code)]
//! Real imported nodes and real native packs; inspection never stages them.
#[path = "source_rebase_http/support.rs"]
mod support;
use support::{Scratch, fixture, generation, reopen};
use std::collections::BTreeMap;
use fgit_crypto::{GitObjectKind, git_object_id, sha256_digest};
use fgit_forge::preparation::rebase::{EmptyCommitPolicy, RebaseCommitter, RebasePreparation, RebaseRequest};
use fgit_forge::review::{ComparisonMode, ReviewOptions};
use fgit_node::OneNode;
use fgit_pack::{CanonicalObjectSource, CanonicalPackObject, PackLimits, PackPlanner, PackWriteError, PackWriteProfile, PackWriter};
use fgit_types::{GitHashAlgorithm, GitOid, RefName};

fn branch(name: &[u8]) -> RefName { RefName::try_new(name).unwrap() }
fn prepared(node: &OneNode, history: &support::History, empty: EmptyCommitPolicy) -> (GitOid, Vec<u8>) {
    let request = node.request_context();
    let result = node.runtime().block_on(node.prepare_rebase_bundle_in(&request,
        &branch(b"refs/heads/topic"), &branch(b"refs/heads/main"),
        RebaseRequest { source_tip: history.source, upstream: history.upstream, onto: history.onto, empty },
        &Default::default(), None, &RebaseCommitter { identity: "Reviewer <r@example.invalid>".into(), timestamp: 9 },
        Default::default())).unwrap();
    let RebasePreparation::Clean(plan) = result.outcome else { panic!("clean fixture"); };
    (plan.commit, result.bundle.unwrap())
}

#[test]
fn actual_commits_and_every_diff_survive_restart_without_staging() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let (node, history) = fixture(&root, format, 0);
        let before = generation(&node);
        let (candidate, bundle) = prepared(&node, &history, EmptyCommitPolicy::Stop);
        let request = node.request_context();
        let inspected = node.runtime().block_on(node.inspect_rebase_bundle_in(&request,
            &branch(b"refs/heads/topic"), &branch(b"refs/heads/main"), history.source, history.onto,
            candidate, &bundle, &Default::default(), None, &ReviewOptions::default())).unwrap();
        assert_eq!(inspected.commits.len(), 2);
        assert_eq!(inspected.comparisons.len(), 3);
        assert_eq!(inspected.commits[0].parent, history.onto);
        assert_eq!(inspected.commits[1].parent, inspected.commits[0].id);
        assert_eq!(inspected.commits[1].id, candidate);
        assert_eq!(inspected.comparisons[0].entries.iter().map(|e| e.path.as_slice()).collect::<Vec<_>>(), [b"onto".as_slice()]);
        assert_eq!(inspected.comparisons[1].entries[0].path, b"a\xff");
        assert_eq!(inspected.comparisons[2].entries[0].path, b"b");
        for commit in &inspected.commits {
            assert_eq!(git_object_id(format, GitObjectKind::Commit, &commit.body), commit.id);
            assert!(commit.body.windows(b"5 -0330".len()).any(|p| p == b"5 -0330"));
            assert!(node.read_git_object(commit.id).is_err());
        }
        assert_eq!(inspected.bundle.sha256, sha256_digest(&bundle));
        assert_eq!(generation(&node), before);
        let head = inspected.source_head;
        node.shutdown().unwrap();
        let node = reopen(&root.config(format));
        let again = node.runtime().block_on(node.inspect_rebase_bundle_in(&node.request_context(),
            &branch(b"refs/heads/topic"), &branch(b"refs/heads/main"), history.source, history.onto,
            candidate, &bundle, &Default::default(), Some(head), &ReviewOptions::default())).unwrap();
        assert_eq!(again.comparisons, inspected.comparisons);
        assert_eq!(again.bundle, inspected.bundle);
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}

#[test]
fn complete_scope_exact_tips_and_corrupt_packs_fail_without_an_inspection() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let (node, history) = fixture(&root, format, 0);
        let (candidate, bundle) = prepared(&node, &history, EmptyCommitPolicy::Stop);
        let before = generation(&node);
        for option in 0..3 {
            let mut options = ReviewOptions::default();
            match option { 0 => options.paths.push(b"onto".to_vec()), 1 => options.mode = ComparisonMode::MergeBase,
                _ => options.limits.max_changes = 1 }
            assert!(node.runtime().block_on(node.inspect_rebase_bundle_in(&node.request_context(),
                &branch(b"refs/heads/topic"), &branch(b"refs/heads/main"), history.source, history.onto,
                candidate, &bundle, &Default::default(), None, &options)).is_err());
        }
        let mut corrupted = bundle.clone(); *corrupted.last_mut().unwrap() ^= 1;
        for (source, onto, candidate, bytes) in [
            (history.first, history.onto, candidate, bundle.as_slice()),
            (history.source, history.upstream, candidate, bundle.as_slice()),
            (history.source, history.onto, history.first, bundle.as_slice()),
            (history.source, history.onto, candidate, corrupted.as_slice()),
        ] {
            assert!(node.runtime().block_on(node.inspect_rebase_bundle_in(&node.request_context(),
                &branch(b"refs/heads/topic"), &branch(b"refs/heads/main"), source, onto,
                candidate, bytes, &Default::default(), None, &ReviewOptions::default())).is_err());
        }
        assert_eq!(generation(&node), before);
        assert!(node.read_git_object(candidate).is_err());
        node.shutdown().unwrap();
    }
}

struct Objects(BTreeMap<GitOid, (GitObjectKind, Vec<u8>)>);
impl CanonicalObjectSource for Objects {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        let (kind, bytes) = self.0.get(id).ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        Ok(CanonicalPackObject::new(*id, *kind, bytes.clone(), Vec::new(), 0, 0))
    }
}
fn insert(objects: &mut Objects, format: GitHashAlgorithm, kind: GitObjectKind, body: Vec<u8>) -> GitOid {
    let id = git_object_id(format, kind, &body); objects.0.insert(id, (kind, body)); id
}
fn pack(objects: &Objects, format: GitHashAlgorithm, onto: GitOid, candidate: GitOid) -> Vec<u8> {
    let limits = PackLimits::default();
    let planned = PackPlanner::new(format, PackWriteProfile::COMPRESSED_NO_DELTA_V1, limits.clone())
        .plan_selected(objects, &objects.0.keys().copied().collect::<Vec<_>>(), &mut || true).unwrap();
    let (pack, _) = PackWriter::new(limits).write(&planned, &mut || true).unwrap();
    let mut body = match format { GitHashAlgorithm::Sha1 => b"# v2 git bundle\n".to_vec(),
        GitHashAlgorithm::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".to_vec() };
    body.extend_from_slice(format!("-{onto} onto\n{candidate} refs/heads/topic\n\n").as_bytes());
    body.extend_from_slice(&pack); body
}
fn commit(tree: GitOid, parent: GitOid, message: &str) -> Vec<u8> {
    format!("tree {tree}\nparent {parent}\nauthor Inspector <i@example.invalid> 1 +0000\ncommitter Inspector <i@example.invalid> 2 +0000\n\n{message}\n").into_bytes()
}
fn source_tree(node: &OneNode, source: GitOid) -> (GitOid, Vec<u8>) {
    let object = node.read_git_object(source).unwrap();
    let text = std::str::from_utf8(object.payload()).unwrap();
    let tree = GitOid::from_hex(source.algorithm(), text.lines().next().unwrap().strip_prefix("tree ").unwrap()).unwrap();
    (tree, node.read_git_object(tree).unwrap().payload().to_vec())
}

#[test]
fn transient_commit_changes_are_visible_even_when_final_source_tree_is_identical() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let (node, history) = fixture(&root, format, 2);
        let (tree, tree_body) = source_tree(&node, history.source);
        let mut objects = Objects(BTreeMap::new());
        insert(&mut objects, format, GitObjectKind::Tree, tree_body.clone());
        let blob = insert(&mut objects, format, GitObjectKind::Blob, b"transient content\n".to_vec());
        let mut transient = tree_body;
        transient.extend_from_slice(b"100644 zz-transient\0"); transient.extend_from_slice(blob.as_bytes());
        let changed = insert(&mut objects, format, GitObjectKind::Tree, transient);
        let first = insert(&mut objects, format, GitObjectKind::Commit, commit(changed, history.onto, "introduce"));
        let candidate = insert(&mut objects, format, GitObjectKind::Commit, commit(tree, first, "remove"));
        let bundle = pack(&objects, format, history.onto, candidate);
        let inspected = node.runtime().block_on(node.inspect_rebase_bundle_in(&node.request_context(),
            &branch(b"refs/heads/topic"), &branch(b"refs/heads/main"), history.source, history.onto,
            candidate, &bundle, &Default::default(), None, &ReviewOptions::default())).unwrap();
        assert!(inspected.comparisons[0].entries.is_empty(), "final source tree is exactly unchanged");
        for comparison in &inspected.comparisons[1..] {
            assert!(comparison.entries.iter().any(|entry| entry.path == b"zz-transient"));
        }
        insert(&mut objects, format, GitObjectKind::Blob, b"unrelated hidden transport payload".to_vec());
        assert!(node.runtime().block_on(node.inspect_rebase_bundle_in(&node.request_context(),
            &branch(b"refs/heads/topic"), &branch(b"refs/heads/main"), history.source, history.onto,
            candidate, &pack(&objects, format, history.onto, candidate), &Default::default(), None,
            &ReviewOptions::default())).is_err());
        assert!(node.read_git_object(candidate).is_err());
        node.shutdown().unwrap();
    }
}

#[test]
fn old_source_objects_are_not_implicit_pack_prerequisites_and_empty_series_are_real() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let (node, history) = fixture(&root, format, 0);
        let (tree, _) = source_tree(&node, history.source);
        let mut objects = Objects(BTreeMap::new());
        let candidate = insert(&mut objects, format, GitObjectKind::Commit, commit(tree, history.onto, "missing source objects"));
        assert!(node.runtime().block_on(node.inspect_rebase_bundle_in(&node.request_context(),
            &branch(b"refs/heads/topic"), &branch(b"refs/heads/main"), history.source, history.onto,
            candidate, &pack(&objects, format, history.onto, candidate), &Default::default(), None,
            &ReviewOptions::default())).is_err(), "the omitted tree is admitted but outside onto history");
        node.shutdown().unwrap();
        let root = Scratch::new(); let (node, history) = fixture(&root, format, 2);
        let (candidate, bundle) = prepared(&node, &history, EmptyCommitPolicy::Drop);
        assert_eq!(candidate, history.onto);
        let result = node.runtime().block_on(node.inspect_rebase_bundle_in(&node.request_context(),
            &branch(b"refs/heads/topic"), &branch(b"refs/heads/main"), history.source, history.onto,
            candidate, &bundle, &Default::default(), None, &ReviewOptions::default())).unwrap();
        assert!(result.commits.is_empty()); assert_eq!(result.bundle.pack_objects, 0);
        assert_eq!(result.comparisons.len(), 1); assert_eq!(result.comparisons[0].requested_before, history.source);
        node.shutdown().unwrap();
    }
}
