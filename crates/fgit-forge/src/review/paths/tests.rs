use super::*;
use crate::preparation::{CommitInput, MergeEntry, MergeSourceError};
use fgit_crypto::{GitObjectKind, git_object_id};
use std::{cell::Cell, collections::BTreeMap};
#[derive(Default)]
struct Source {
    commits: BTreeMap<GitOid, CommitInput>,
    trees: BTreeMap<GitOid, Vec<MergeEntry>>,
    cancel: Cell<bool>,
}
impl MergeObjectSource for Source {
    fn checkpoint(&self) -> Result<(), MergeSourceError> {
        if self.cancel.get() {
            Err(MergeSourceError::Cancelled)
        } else {
            Ok(())
        }
    }
    fn commit(&self, id: GitOid) -> Result<CommitInput, MergeSourceError> {
        self.commits
            .get(&id)
            .cloned()
            .ok_or(MergeSourceError::Unavailable(id))
    }
    fn tree(&self, id: GitOid) -> Result<Vec<MergeEntry>, MergeSourceError> {
        self.trees
            .get(&id)
            .cloned()
            .ok_or(MergeSourceError::Unavailable(id))
    }
    fn blob(&self, _: GitOid) -> Result<Vec<u8>, MergeSourceError> {
        panic!("path inventory must never read payloads")
    }
}
impl Source {
    fn tree_id(&mut self, f: GitHashAlgorithm, rows: &[(&[u8], u32, GitOid)]) -> GitOid {
        let mut entries: Vec<_> = rows
            .iter()
            .map(|(p, m, o)| MergeEntry {
                name: p.to_vec(),
                mode: *m,
                oid: *o,
            })
            .collect();
        entries.sort_by_key(|e| {
            let mut k = e.name.clone();
            k.push(if e.mode == 0o40000 { b'/' } else { 0 });
            k
        });
        let mut bytes = Vec::new();
        for e in &entries {
            bytes.extend(format!("{:o} ", e.mode).as_bytes());
            bytes.extend(&e.name);
            bytes.push(0);
            bytes.extend(e.oid.as_bytes());
        }
        let id = git_object_id(f, GitObjectKind::Tree, &bytes);
        self.trees.insert(id, entries);
        id
    }
    fn commit_id(
        &mut self,
        f: GitHashAlgorithm,
        tree: GitOid,
        parents: &[GitOid],
        label: &str,
    ) -> GitOid {
        let bytes = format!("{tree}{parents:?}{label}");
        let id = git_object_id(f, GitObjectKind::Commit, bytes.as_bytes());
        self.commits.insert(
            id,
            CommitInput {
                tree,
                parents: parents.to_vec(),
            },
        );
        id
    }
}
#[test]
fn changed_leaves_include_modes_deletions_raw_names_and_type_changes_without_payloads() {
    for f in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut s = Source::default();
        let blob = git_object_id(f, GitObjectKind::Blob, b"arbitrary unavailable payload");
        let child = s.tree_id(f, &[(b"new", 0o100644, blob)]);
        let a = s.tree_id(
            f,
            &[
                (b"mode", 0o100644, blob),
                (b"gone", 0o100644, blob),
                (b"switch", 0o100644, blob),
            ],
        );
        let b = s.tree_id(
            f,
            &[
                (b"mode", 0o100755, blob),
                (b"switch", 0o40000, child),
                (b"\xff", 0o120000, blob),
            ],
        );
        let a = s.commit_id(f, a, &[], "a");
        let b = s.commit_id(f, b, &[a], "b");
        let found = compare_source_paths(&s, f, Some(a), b, ComparisonMode::Direct).unwrap();
        assert_eq!(
            found.paths,
            vec![
                b"gone".to_vec(),
                b"mode".to_vec(),
                b"switch".to_vec(),
                b"switch/new".to_vec(),
                b"\xff".to_vec()
            ]
        );
        assert_eq!(
            found,
            compare_source_paths(&s, f, Some(a), b, ComparisonMode::Direct).unwrap()
        );
        assert!(
            compare_source_paths(&s, f, Some(b), b, ComparisonMode::Direct)
                .unwrap()
                .paths
                .is_empty()
        );
    }
}
#[test]
fn merge_base_excludes_target_only_changes_and_refuses_disconnected_history() {
    for f in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut s = Source::default();
        let blob = git_object_id(f, GitObjectKind::Blob, b"x");
        let empty = s.tree_id(f, &[]);
        let base = s.commit_id(f, empty, &[], "base");
        let t = s.tree_id(f, &[(b"target", 0o100644, blob)]);
        let target = s.commit_id(f, t, &[base], "target");
        let t = s.tree_id(f, &[(b"source", 0o100644, blob)]);
        let tip = s.commit_id(f, t, &[base], "source");
        let report =
            compare_source_paths(&s, f, Some(target), tip, ComparisonMode::MergeBase).unwrap();
        assert_eq!(report.compared_before, Some(base));
        assert_eq!(report.paths, vec![b"source".to_vec()]);
        assert_eq!(
            compare_source_paths(&s, f, Some(target), tip, ComparisonMode::Direct)
                .unwrap()
                .paths
                .len(),
            2
        );
        let other = s.commit_id(f, empty, &[], "other");
        assert!(matches!(
            compare_source_paths(&s, f, Some(other), tip, ComparisonMode::MergeBase),
            Err(ReviewError::NoCommonAncestor)
        ));
    }
}
#[test]
fn empty_base_is_explicit_and_unavailable_objects_or_cancellation_never_become_empty() {
    let f = GitHashAlgorithm::Sha256;
    let mut s = Source::default();
    let blob = git_object_id(f, GitObjectKind::Blob, b"x");
    let t = s.tree_id(f, &[(b"x", 0o100644, blob)]);
    let tip = s.commit_id(f, t, &[], "root");
    assert_eq!(
        compare_source_paths(&s, f, None, tip, ComparisonMode::Direct)
            .unwrap()
            .paths,
        vec![b"x".to_vec()]
    );
    assert!(matches!(
        compare_source_paths(&s, f, None, tip, ComparisonMode::MergeBase),
        Err(ReviewError::InvalidOptions)
    ));
    s.cancel.set(true);
    assert!(matches!(
        compare_source_paths(&s, f, None, tip, ComparisonMode::Direct),
        Err(ReviewError::Source(MergeSourceError::Cancelled))
    ));
    s.cancel.set(false);
    s.trees.clear();
    assert!(compare_source_paths(&s, f, None, tip, ComparisonMode::Direct).is_err());
}
#[test]
fn complete_inventory_limit_refuses_instead_of_returning_a_matching_prefix() {
    let f = GitHashAlgorithm::Sha1;
    let mut s = Source::default();
    let blob = git_object_id(f, GitObjectKind::Blob, b"x");
    let names: Vec<_> = (0..513).map(|i| format!("p{i:04}").into_bytes()).collect();
    let rows: Vec<_> = names
        .iter()
        .map(|p| (p.as_slice(), 0o100644, blob))
        .collect();
    let t = s.tree_id(f, &rows[..512]);
    let ok = s.commit_id(f, t, &[], "ok");
    assert_eq!(
        compare_source_paths(&s, f, None, ok, ComparisonMode::Direct)
            .unwrap()
            .paths
            .len(),
        512
    );
    let t = s.tree_id(f, &rows);
    let bad = s.commit_id(f, t, &[], "bad");
    assert!(matches!(
        compare_source_paths(&s, f, None, bad, ComparisonMode::Direct),
        Err(ReviewError::Budget(_))
    ));
}

#[test]
fn ambiguous_best_bases_are_not_replaced_by_an_arbitrary_parent() {
    let format = GitHashAlgorithm::Sha256;
    let mut source = Source::default();
    let tree = source.tree_id(format, &[]);
    let root = source.commit_id(format, tree, &[], "root");
    let first = source.commit_id(format, tree, &[root], "a");
    let second = source.commit_id(format, tree, &[root], "b");
    let left = source.commit_id(format, tree, &[first, second], "left");
    let right = source.commit_id(format, tree, &[second, first], "right");
    assert!(matches!(
        compare_source_paths(
            &source,
            format,
            Some(left),
            right,
            ComparisonMode::MergeBase
        ),
        Err(ReviewError::MultipleMergeBases(_))
    ));
    assert!(
        compare_source_paths(&source, format, Some(left), right, ComparisonMode::Direct)
            .unwrap()
            .paths
            .is_empty()
    );
}
