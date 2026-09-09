//! Pure native-object verification fixtures. The source is intentionally an
//! in-memory test corpus, not a durable authority or a publication substitute.
use std::collections::{BTreeMap, BTreeSet};
use fgit_admission::ProjectionFailure;
use fgit_admission::merge::native::objects::{MergeObjectLimits, validate_commit_closure, validate_merge_objects, validate_workspace_objects};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::event::NativeMerge;
use fgit_pack::{CanonicalObjectSource, CanonicalPackObject, PackWriteError};
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RefusalCode};

#[derive(Default)]
struct Source(BTreeMap<GitOid, (GitObjectKind, Vec<u8>)>);
impl CanonicalObjectSource for Source {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        let (kind, body) = self.0.get(id).ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        Ok(CanonicalPackObject::new(*id, *kind, body.clone(), Vec::new(), 0, 0))
    }
}
impl Source {
    fn put(&mut self, format: GitHashAlgorithm, kind: GitObjectKind, body: Vec<u8>) -> GitOid {
        let id = git_object_id(format, kind, &body); self.0.insert(id, (kind, body)); id
    }
    fn commit(&mut self, format: GitHashAlgorithm, tree: GitOid, parents: &[GitOid], label: &str) -> GitOid {
        let mut bytes = format!("tree {tree}\n");
        for parent in parents { bytes.push_str(&format!("parent {parent}\n")); }
        bytes.push_str(&format!("author Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\n{label}\n"));
        self.put(format, GitObjectKind::Commit, bytes.into_bytes())
    }
}
fn fixture(format: GitHashAlgorithm) -> (Source, GitOid, GitOid, GitOid, GitOid) {
    let mut source = Source::default();
    let blob = source.put(format, GitObjectKind::Blob, b"verified bytes\n".to_vec());
    let tree = source.put(format, GitObjectKind::Tree, [b"100644 file\0".as_slice(), blob.as_bytes()].concat());
    let parent = source.commit(format, tree, &[], "parent");
    let candidate = source.commit(format, tree, &[parent], "candidate");
    (source, parent, candidate, tree, blob)
}

#[test]
fn workspace_validation_hashes_complete_closure_in_both_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (source, parent, candidate, tree, blob) = fixture(format);
        let expected = BTreeSet::from([parent, candidate, tree, blob]);
        let verified = validate_workspace_objects(&source, candidate, parent, MergeObjectLimits::default(), &mut || true).unwrap();
        assert_eq!(verified.objects, expected);
        assert_eq!(verified.object_closure_root, fgit_admission::permitted_object_closure_root(
            &fgit_admission::PermittedObjectClosure::new(expected)).unwrap());
    }
}

#[test]
fn altered_bytes_kinds_and_parent_sets_do_not_become_workspace_candidates() {
    let format = GitHashAlgorithm::Sha1;
    let (mut source, parent, candidate, tree, blob) = fixture(format);
    let wrong = source.commit(format, tree, &[], "different parent");
    for offered in [parent, wrong, source.commit(format, tree, &[parent, wrong], "two parents")] {
        assert!(matches!(validate_workspace_objects(&source, offered, parent, MergeObjectLimits::default(), &mut || true),
            Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))));
    }
    let held = source.0.get(&blob).unwrap().clone();
    source.0.get_mut(&blob).unwrap().1.push(b'!');
    assert!(matches!(validate_workspace_objects(&source, candidate, parent, MergeObjectLimits::default(), &mut || true),
        Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))));
    source.0.insert(blob, held);
    let held = source.0.get(&tree).unwrap().clone();
    source.0.get_mut(&tree).unwrap().0 = GitObjectKind::Blob;
    assert!(matches!(validate_workspace_objects(&source, candidate, parent, MergeObjectLimits::default(), &mut || true),
        Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))));
    source.0.insert(tree, held);
    assert!(validate_workspace_objects(&source, candidate, parent, MergeObjectLimits::default(), &mut || true).is_ok());
}

#[test]
fn absent_dependencies_and_exhaustion_never_return_a_partial_closure() {
    let (mut source, parent, candidate, _, blob) = fixture(GitHashAlgorithm::Sha256);
    assert!(matches!(validate_workspace_objects(&source, candidate, parent, MergeObjectLimits::default(), &mut || false),
        Err(ProjectionFailure::Unavailable(RefusalCode::CancellationInProgress))));
    assert!(matches!(validate_workspace_objects(&source, candidate, parent,
        MergeObjectLimits { max_objects: 1, ..MergeObjectLimits::default() }, &mut || true),
        Err(ProjectionFailure::Unavailable(RefusalCode::ResourceBudgetExceeded))));
    source.0.remove(&blob);
    assert!(matches!(validate_workspace_objects(&source, candidate, parent, MergeObjectLimits::default(), &mut || true),
        Err(ProjectionFailure::Unavailable(RefusalCode::EvidenceMissing))));
}

#[test]
fn merge_adapter_keeps_ordered_parents_and_common_ancestor_checks() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut source, base, target, tree, _) = fixture(format);
        let incoming = source.commit(format, tree, &[base], "incoming");
        let commit = source.commit(format, tree, &[target, incoming], "merge");
        let mut merge = NativeMerge {
            source_ref: RefName::try_new(b"refs/heads/topic").unwrap(), source_tip: incoming,
            target_ref: RefName::try_new(b"refs/heads/main").unwrap(), target_tip_before: target,
            base_tip: base, merge_commit: commit,
        };
        assert!(validate_merge_objects(&source, &merge, MergeObjectLimits::default(), &mut || true).is_ok());
        assert!(validate_workspace_objects(&source, commit, target, MergeObjectLimits::default(), &mut || true).is_err());
        merge.base_tip = incoming;
        assert!(validate_merge_objects(&source, &merge, MergeObjectLimits::default(), &mut || true).is_err());
        merge.base_tip = base;
        merge.merge_commit = source.commit(format, tree, &[incoming, target], "reversed");
        assert!(validate_merge_objects(&source, &merge, MergeObjectLimits::default(), &mut || true).is_err());
    }
}

#[test]
fn source_closure_does_not_authorize_unreachable_repository_objects() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut source, parent, candidate, tree, blob) = fixture(format);
        let secret = source.put(format, GitObjectKind::Blob, b"not reachable".to_vec());
        let closure = validate_commit_closure(&source, parent, MergeObjectLimits::default(), &mut || true).unwrap();
        assert_eq!(closure.objects, BTreeSet::from([parent, tree, blob]));
        assert!(!closure.objects.contains(&candidate));
        assert!(!closure.objects.contains(&secret));
    }
}

#[test]
fn source_graph_rejects_ambiguous_commit_edges_without_reinterpreting_bytes() {
    let format = GitHashAlgorithm::Sha1;
    let (mut source, parent, _, tree, _) = fixture(format);
    let valid = source.commit(format, tree, &[parent], "unambiguous");
    assert!(validate_commit_closure(&source, valid, MergeObjectLimits::default(), &mut || true).is_ok());
    let bytes = source.0[&valid].1.clone();
    let original = String::from_utf8(bytes).unwrap();
    for altered in [original.replacen(&format!("tree {tree}\n"), &format!("tree {tree}\ntree {tree}\n"), 1),
        original.replacen(&format!("parent {parent}\n"), &format!("parent {parent}\n continuation\n"), 1)]
    {
        let ambiguous = source.put(format, GitObjectKind::Commit, altered.into_bytes());
        assert!(validate_commit_closure(&source, ambiguous, MergeObjectLimits::default(), &mut || true).is_err());
    }
}
