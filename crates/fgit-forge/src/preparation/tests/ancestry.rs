//! The actual forge graph adapter against the retained scalar ancestry oracle.
//! These are pure planner/source fixtures, not persisted-node evidence.

use super::*;
use crate::preparation::resolution::{
    ConflictResolution, ResolutionChoice, ResolutionError, ResolutionInputs, prepare_resolved_merge,
};
use crate::review::{ComparisonMode, ReviewError, ReviewOptions, compare_source};
use fgit_diff::merge_bases_all;
use std::cell::RefCell;

struct Observed<'a> {
    source: &'a Source,
    commits: RefCell<BTreeMap<GitOid, usize>>,
    other_reads: Cell<usize>,
    checkpoints: Cell<usize>,
    stop_at: Cell<Option<usize>>,
    budget_stop: Cell<bool>,
    outside_selection: Cell<Option<GitOid>>,
}

impl<'a> Observed<'a> {
    fn new(source: &'a Source) -> Self {
        Self {
            source,
            commits: RefCell::new(BTreeMap::new()),
            other_reads: Cell::new(0),
            checkpoints: Cell::new(0),
            stop_at: Cell::new(None),
            budget_stop: Cell::new(false),
            outside_selection: Cell::new(None),
        }
    }

    fn reset(&self) {
        self.commits.borrow_mut().clear();
        self.other_reads.set(0);
        self.checkpoints.set(0);
        self.stop_at.set(None);
    }
}

impl MergeObjectSource for Observed<'_> {
    fn checkpoint(&self) -> Result<(), MergeSourceError> {
        let count = self.checkpoints.get() + 1;
        self.checkpoints.set(count);
        if self.stop_at.get() == Some(count) {
            return Err(if self.budget_stop.get() {
                MergeSourceError::BudgetExceeded
            } else {
                MergeSourceError::Cancelled
            });
        }
        self.source.checkpoint()
    }

    fn commit(&self, id: GitOid) -> Result<CommitInput, MergeSourceError> {
        *self.commits.borrow_mut().entry(id).or_default() += 1;
        if self.outside_selection.get() == Some(id) {
            return Err(MergeSourceError::OutsideSelection);
        }
        self.source.commit(id)
    }

    fn tree(&self, id: GitOid) -> Result<Vec<MergeEntry>, MergeSourceError> {
        self.other_reads.set(self.other_reads.get() + 1);
        self.source.tree(id)
    }

    fn blob(&self, id: GitOid) -> Result<Vec<u8>, MergeSourceError> {
        self.other_reads.set(self.other_reads.get() + 1);
        self.source.blob(id)
    }
}

fn graph_fixture(format: GitHashAlgorithm) -> (Source, Vec<GitOid>) {
    let mut source = Source::new(format);
    let tree = source.store_tree(Vec::new());
    let root = source.store_commit(tree, &[], "root");
    let unrelated = source.store_commit(tree, &[], "unrelated");
    let a = source.store_commit(tree, &[root], "a");
    let b = source.store_commit(tree, &[root], "b");
    let c = source.store_commit(tree, &[root], "c");
    let left = source.store_commit(tree, &[a, b], "left");
    let right = source.store_commit(tree, &[b, a], "right");
    let octopus = source.store_commit(tree, &[left, right, c], "octopus");
    let mut ids = vec![root, unrelated, a, b, c, left, right, octopus];
    for step in 0..12 {
        let tip = source.store_commit(tree, &[*ids.last().unwrap()], &format!("linear {step}"));
        ids.push(tip);
    }
    (source, ids)
}

fn limits() -> MergeBaseLimits {
    MergeBaseLimits {
        max_commits: 4096,
        max_edges: 16_384,
    }
}

fn scalar(
    source: &Source,
    left: GitOid,
    right: GitOid,
    limits: MergeBaseLimits,
) -> MergeBaseQueryResult<GitOid, MergeSourceError> {
    merge_bases_all(
        &Graph {
            source,
            format: source.format,
        },
        left,
        right,
        limits,
    )
}

#[test]
fn selected_source_index_matches_scalar_and_reads_each_parent_object_once() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (source, ids) = graph_fixture(format);
        let observed = Observed::new(&source);
        for &left in &ids {
            for &right in &ids {
                observed.reset();
                let expected = scalar(&source, left, right, limits());
                let actual = source_merge_bases(&observed, format, left, right, limits());
                assert_eq!(actual, expected, "{format:?}: {left} / {right}");
                assert!(observed.commits.borrow().values().all(|&reads| reads == 1));
                assert_eq!(observed.other_reads.get(), 0);
            }
        }
        let mut expected = vec![ids[2], ids[3]];
        expected.sort_unstable();
        assert_eq!(
            source_merge_bases(&observed, format, ids[5], ids[6], limits()),
            Ok(MergeBaseResult::Bases(expected))
        );
    }
}

#[test]
fn graph_limits_keep_the_scalar_refusal_and_exact_success_boundaries() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (source, ids) = graph_fixture(format);
        let left = *ids.last().unwrap();
        let right = ids[6];
        let edges = source
            .commits
            .values()
            .map(|commit| commit.parents.len())
            .sum();
        for max_commits in 0..=source.commits.len() {
            let narrowed = MergeBaseLimits {
                max_commits,
                ..limits()
            };
            assert_eq!(
                source_merge_bases(&source, format, left, right, narrowed),
                scalar(&source, left, right, narrowed)
            );
        }
        for max_edges in 0..=edges {
            let narrowed = MergeBaseLimits {
                max_edges,
                ..limits()
            };
            assert_eq!(
                source_merge_bases(&source, format, left, right, narrowed),
                scalar(&source, left, right, narrowed)
            );
        }
    }
}

#[test]
fn malformed_parent_graphs_refuse_and_the_repaired_source_succeeds() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut source, ids) = graph_fixture(format);
        let root = ids[0];
        let left = ids[2];
        let right = ids[3];
        let original = source.commits[&root].clone();
        for corrupt in 0..4 {
            let mut changed = original.clone();
            match corrupt {
                0 => changed.parents = vec![left],
                1 => changed.parents = vec![ids[1], ids[1]],
                2 => {
                    changed.tree =
                        GitOid::from_hex(format, &"0".repeat(format.digest_len() * 2)).unwrap()
                }
                _ => {
                    let foreign = if format == GitHashAlgorithm::Sha1 {
                        GitHashAlgorithm::Sha256
                    } else {
                        GitHashAlgorithm::Sha1
                    };
                    changed.parents =
                        vec![git_object_id(foreign, GitObjectKind::Commit, b"foreign")];
                }
            }
            source.commits.insert(root, changed);
            let expected = scalar(&source, left, right, limits());
            assert!(expected.is_err());
            assert_eq!(
                source_merge_bases(&source, format, left, right, limits()),
                expected
            );
            source.commits.insert(root, original.clone());
            assert_eq!(
                source_merge_bases(&source, format, left, right, limits()),
                Ok(MergeBaseResult::Bases(vec![root]))
            );
        }
    }
}

#[test]
fn a_previous_index_cannot_expand_the_next_sources_selection() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (source, ids) = graph_fixture(format);
        let observed = Observed::new(&source);
        let left = ids[2];
        let right = ids[3];
        let good = source_merge_bases(&observed, format, left, right, limits()).unwrap();
        observed.outside_selection.set(Some(ids[0]));
        assert_eq!(
            source_merge_bases(&observed, format, left, right, limits()),
            Err(MergeBaseError::Source(MergeSourceError::OutsideSelection))
        );
        assert_eq!(observed.other_reads.get(), 0);
        observed.outside_selection.set(None);
        assert_eq!(
            source_merge_bases(&observed, format, left, right, limits()),
            Ok(good)
        );
    }
}

#[test]
fn every_build_or_query_checkpoint_propagates_its_original_stop_cause() {
    let (source, ids) = graph_fixture(GitHashAlgorithm::Sha256);
    let observed = Observed::new(&source);
    let left = *ids.last().unwrap();
    let right = ids[6];
    let good = source_merge_bases(&observed, source.format, left, right, limits()).unwrap();
    let checkpoints = observed.checkpoints.get();
    assert!(checkpoints > observed.commits.borrow().len() * 2);
    for budget in [false, true] {
        observed.budget_stop.set(budget);
        for stop_at in 1..=checkpoints {
            observed.reset();
            observed.stop_at.set(Some(stop_at));
            assert_eq!(
                source_merge_bases(&observed, source.format, left, right, limits()),
                Err(MergeBaseError::Source(if budget {
                    MergeSourceError::BudgetExceeded
                } else {
                    MergeSourceError::Cancelled
                })),
                "checkpoint {stop_at}, budget={budget}"
            );
        }
    }
    observed.reset();
    assert_eq!(
        source_merge_bases(&observed, source.format, left, right, limits()),
        Ok(good)
    );
}

#[test]
fn preparation_resolution_and_review_rebuild_from_the_current_owned_source() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let original = source.file(b"file", b"base\n", 0o100644);
        let ours = source.file(b"file", b"ours\n", 0o100644);
        let theirs = source.file(b"file", b"theirs\n", 0o100644);
        let (left, right) = branch_pair(&mut source, vec![original], vec![ours], vec![theirs]);
        let base = source.commits[&left].parents[0];
        let inputs = ResolutionInputs {
            base,
            target: left,
            source: right,
        };
        let choices = [ConflictResolution {
            path: b"file".to_vec(),
            choice: ResolutionChoice::Ours,
        }];
        let options = ReviewOptions {
            mode: ComparisonMode::MergeBase,
            ..ReviewOptions::default()
        };
        let prepare = |source: &Source| {
            prepare_merge(
                source,
                format,
                left,
                right,
                &metadata(),
                PreparationLimits::default(),
            )
        };
        let resolve = |source: &Source| {
            prepare_resolved_merge(
                source,
                format,
                inputs,
                &choices,
                &metadata(),
                PreparationLimits::default(),
            )
        };
        let review = |source: &Source| compare_source(source, format, left, right, &options);
        let prepared = prepare(&source).unwrap();
        assert!(
            matches!(prepared, MergePreparation::Conflicted { base: selected, .. } if selected == base)
        );
        let resolved = resolve(&source).unwrap();
        assert_eq!(resolved.plan.base, base);
        let reviewed = review(&source).unwrap();
        assert_eq!(reviewed.compared_before, base);

        let body = source.commits.remove(&base).unwrap();
        assert!(matches!(
            prepare(&source),
            Err(PreparationError::Graph(MergeBaseError::Source(MergeSourceError::Unavailable(id)))) if id == base
        ));
        assert!(matches!(
            resolve(&source),
            Err(ResolutionError::Preparation(PreparationError::Graph(MergeBaseError::Source(MergeSourceError::Unavailable(id))))) if id == base
        ));
        assert!(matches!(
            review(&source),
            Err(ReviewError::Graph(MergeBaseError::Source(MergeSourceError::Unavailable(id)))) if id == base
        ));
        source.commits.insert(base, body);
        assert_eq!(prepare(&source).unwrap(), prepared);
        assert_eq!(resolve(&source).unwrap(), resolved);
        assert_eq!(review(&source).unwrap(), reviewed);
    }
}
