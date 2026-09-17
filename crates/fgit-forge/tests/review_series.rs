#![forbid(unsafe_code)]
//! Exact per-pair equivalence and whole-series accounting over native fixtures.
use std::cell::Cell;
use std::collections::BTreeMap;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::preparation::{CommitInput, MergeEntry, MergeObjectSource, MergeSourceError};
use fgit_forge::review::{ComparisonMode, MAX_SERIES_COMPARISONS, ReviewError, ReviewOptions,
    compare_source, compare_source_series};
use fgit_types::{GitHashAlgorithm, GitOid};

struct Source {
    commits: BTreeMap<GitOid, CommitInput>,
    trees: BTreeMap<GitOid, Vec<MergeEntry>>,
    blobs: BTreeMap<GitOid, Vec<u8>>,
    calls: Cell<usize>,
    stop_at: Cell<Option<usize>>,
    resource_stop: Cell<bool>,
}
impl Source {
    fn fixture(format: GitHashAlgorithm) -> (Self, [GitOid; 3]) {
        let mut source = Self { commits: BTreeMap::new(), trees: BTreeMap::new(), blobs: BTreeMap::new(),
            calls: Cell::new(0), stop_at: Cell::new(None), resource_stop: Cell::new(false) };
        let ids = [b"a\n".as_slice(), b"b\n", b"c\n"].map(|content| {
            let blob = git_object_id(format, GitObjectKind::Blob, content);
            let tree_body = [b"100644 f\0".as_slice(), blob.as_bytes()].concat();
            let tree = git_object_id(format, GitObjectKind::Tree, &tree_body);
            let body = format!("tree {tree}\nauthor A <a@example.invalid> 1 +0000\ncommitter A <a@example.invalid> 1 +0000\n\nfixture\n");
            let id = git_object_id(format, GitObjectKind::Commit, body.as_bytes());
            source.blobs.insert(blob, content.to_vec());
            source.trees.insert(tree, vec![MergeEntry { name: b"f".to_vec(), mode: 0o100644, oid: blob }]);
            source.commits.insert(id, CommitInput { tree, parents: Vec::new() });
            id
        });
        (source, ids)
    }
}
impl MergeObjectSource for Source {
    fn checkpoint(&self) -> Result<(), MergeSourceError> {
        let next = self.calls.get() + 1;
        self.calls.set(next);
        if self.stop_at.get() == Some(next) {
            return Err(if self.resource_stop.get() { MergeSourceError::BudgetExceeded } else { MergeSourceError::Cancelled });
        }
        Ok(())
    }
    fn commit(&self, id: GitOid) -> Result<CommitInput, MergeSourceError> {
        self.commits.get(&id).cloned().ok_or(MergeSourceError::Unavailable(id))
    }
    fn tree(&self, id: GitOid) -> Result<Vec<MergeEntry>, MergeSourceError> {
        self.trees.get(&id).cloned().ok_or(MergeSourceError::Unavailable(id))
    }
    fn blob(&self, id: GitOid) -> Result<Vec<u8>, MergeSourceError> {
        self.blobs.get(&id).cloned().ok_or(MergeSourceError::Unavailable(id))
    }
}

#[test]
fn every_pair_matches_single_review_including_transient_changes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (source, [a, b, c]) = Source::fixture(format);
        let options = ReviewOptions::default();
        let pairs = [(a, a), (a, b), (b, a), (a, c)];
        let actual = compare_source_series(&source, format, &pairs, &options).unwrap();
        let expected = pairs.iter().map(|&(old, new)| compare_source(&source, format, old, new, &options).unwrap()).collect::<Vec<_>>();
        assert_eq!(actual, expected);
        assert!(actual[0].entries.is_empty());
        assert_eq!(actual[1].entries.len(), 1);
        assert_eq!(actual[2].entries.len(), 1, "the transient change must not disappear with the final net diff");
    }
}

#[test]
fn every_cumulative_budget_is_shared_and_exact_boundaries_succeed() {
    let format = GitHashAlgorithm::Sha1;
    let (source, [a, b, c]) = Source::fixture(format);
    let pairs = [(a, b), (b, c)];
    let mut exact = ReviewOptions::default();
    exact.context_lines = 0;
    exact.limits.max_changes = 2;
    exact.limits.max_tree_entries = 4;
    exact.limits.max_text_files = 2;
    exact.limits.max_hunks = 2;
    exact.limits.max_output_bytes = 10; // two one-byte paths and four two-byte sides
    assert_eq!(compare_source_series(&source, format, &pairs, &exact).unwrap().len(), 2);
    for axis in 0..5 {
        let mut options = exact.clone();
        let (field, expected) = match axis {
            0 => (&mut options.limits.max_changes, "changed entries"),
            1 => (&mut options.limits.max_tree_entries, "tree entries"),
            2 => (&mut options.limits.max_text_files, "text files"),
            3 => (&mut options.limits.max_hunks, "hunks"),
            _ => (&mut options.limits.max_output_bytes, "output bytes"),
        };
        *field -= 1;
        // Each comparison fits on its own. Only accumulated use must refuse.
        for &(old, new) in &pairs { compare_source(&source, format, old, new, &options).unwrap(); }
        assert!(matches!(compare_source_series(&source, format, &pairs, &options), Err(ReviewError::Budget(reason)) if reason == expected));
    }
    let mut one = exact;
    one.limits.max_changes = 1;
    assert_eq!(compare_source_series(&source, format, &[(a, b), (b, b)], &one).unwrap().len(), 2);
}

#[test]
fn every_observed_stop_discards_the_prefix_and_preserves_one_shot_cause() {
    let format = GitHashAlgorithm::Sha256;
    let (source, [a, b, c]) = Source::fixture(format);
    let pairs = [(a, b), (b, c)];
    let options = ReviewOptions::default();
    let good = compare_source_series(&source, format, &pairs, &options).unwrap();
    let calls = source.calls.get();
    assert!(calls > 20);
    for resource in [false, true] {
        source.resource_stop.set(resource);
        for at in 1..=calls {
            source.calls.set(0);
            source.stop_at.set(Some(at));
            let result = compare_source_series(&source, format, &pairs, &options);
            assert!(matches!(result, Err(ReviewError::Source(ref error)) if *error ==
                if resource { MergeSourceError::BudgetExceeded } else { MergeSourceError::Cancelled }), "checkpoint {at}: {result:?}");
        }
    }
    source.stop_at.set(None);
    assert_eq!(compare_source_series(&source, format, &pairs, &options).unwrap(), good);
}

#[test]
fn shape_and_series_bounds_refuse_before_retrieval_and_late_source_failure_is_not_partial() {
    let format = GitHashAlgorithm::Sha1;
    let (mut source, [a, b, c]) = Source::fixture(format);
    let options = ReviewOptions::default();
    let pairs = vec![(a, b); MAX_SERIES_COMPARISONS + 1];
    assert!(matches!(compare_source_series(&source, format, &pairs, &options), Err(ReviewError::Budget("series comparisons"))));
    assert_eq!(source.calls.get(), 0);
    let mut invalid = options.clone(); invalid.mode = ComparisonMode::MergeBase;
    assert!(matches!(compare_source_series(&source, format, &[(a, b)], &invalid), Err(ReviewError::InvalidOptions)));
    assert_eq!(source.calls.get(), 0);
    source.commits.remove(&c);
    assert!(matches!(compare_source_series(&source, format, &[(a, b), (b, c)], &options), Err(ReviewError::Source(MergeSourceError::Unavailable(id))) if id == c));
    assert!(compare_source_series(&source, format, &[], &options).unwrap().is_empty());
    source.stop_at.set(Some(source.calls.get() + 1));
    assert!(matches!(compare_source_series(&source, format, &[], &options), Err(ReviewError::Source(MergeSourceError::Cancelled))));
}
