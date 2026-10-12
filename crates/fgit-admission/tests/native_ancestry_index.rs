#![forbid(unsafe_code)]
//! Native byte fixtures for the request-owned merge/squash ancestry index and
//! the cold fast-forward scalar fallback. These exercise object admission,
//! not a durable authority or ref-publication substitute.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use fgit_admission::merge::native::objects::{
    MergeObjectLimits, validate_commit_closure, validate_fast_forward_objects,
    validate_merge_objects, validate_squash_objects, validate_workspace_objects,
};
use fgit_admission::{ProjectionFailure, ValidatedClosure};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::event::NativeMerge;
use fgit_pack::{CanonicalObjectSource, CanonicalPackObject, Deadline, PackWriteError};
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RefusalCode};

#[derive(Default)]
struct Objects {
    bodies: BTreeMap<GitOid, (GitObjectKind, Vec<u8>)>,
    // Fixture truth for a deliberately independent scalar traversal. The
    // production source supplies only native bytes, never these parent rows.
    parents: BTreeMap<GitOid, Vec<GitOid>>,
    reads: RefCell<BTreeMap<GitOid, usize>>,
    claimed: Vec<GitOid>,
}

impl Objects {
    fn put(&mut self, format: GitHashAlgorithm, kind: GitObjectKind, body: Vec<u8>) -> GitOid {
        let id = git_object_id(format, kind, &body);
        self.bodies.insert(id, (kind, body));
        id
    }

    fn commit(&mut self, tree: GitOid, parents: &[GitOid], message: &str) -> GitOid {
        let mut body = format!("tree {tree}\n");
        for parent in parents {
            writeln!(body, "parent {parent}").unwrap();
        }
        body.push_str("author Fixture <test@example.invalid> 1 +0000\ncommitter Fixture <test@example.invalid> 1 +0000\n\n");
        body.push_str(message);
        let id = self.put(tree.algorithm(), GitObjectKind::Commit, body.into_bytes());
        self.parents.insert(id, parents.to_vec());
        id
    }
}

impl CanonicalObjectSource for Objects {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        *self.reads.borrow_mut().entry(*id).or_default() += 1;
        let (kind, body) = self
            .bodies
            .get(id)
            .ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        Ok(CanonicalPackObject::new(
            *id,
            *kind,
            body.clone(),
            self.claimed.clone(),
            0,
            0,
        ))
    }
}

#[derive(Clone, Copy, Debug)]
enum Method {
    Merge,
    Squash,
    FastForward,
}

impl Method {
    fn validate(
        self,
        objects: &Objects,
        merge: &NativeMerge,
        limits: MergeObjectLimits,
        deadline: &mut impl Deadline,
    ) -> Result<ValidatedClosure, ProjectionFailure> {
        match self {
            Self::Merge => validate_merge_objects(objects, merge, limits, deadline),
            Self::Squash => validate_squash_objects(objects, merge, limits, deadline),
            Self::FastForward => validate_fast_forward_objects(objects, merge, limits, deadline),
        }
    }

    fn roots(self, merge: &NativeMerge) -> [GitOid; 2] {
        match self {
            Self::Squash => [merge.merge_commit, merge.source_tip],
            Self::Merge | Self::FastForward => [merge.merge_commit; 2],
        }
    }
}

fn coordinates(base: GitOid, target: GitOid, source: GitOid, candidate: GitOid) -> NativeMerge {
    NativeMerge {
        source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
        source_tip: source,
        base_tip: base,
        target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
        target_tip_before: target,
        merge_commit: candidate,
    }
}

fn scalar_reachable(parents: &BTreeMap<GitOid, Vec<GitOid>>, roots: &[GitOid]) -> BTreeSet<GitOid> {
    let mut pending = roots.to_vec();
    let mut visited = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if visited.insert(id) {
            pending.extend(parents.get(&id).unwrap());
        }
    }
    visited
}

fn assert_complete_once(
    objects: &Objects,
    tree: GitOid,
    method: Method,
    merge: &NativeMerge,
    actual: &ValidatedClosure,
) {
    let mut expected = scalar_reachable(&objects.parents, &method.roots(merge));
    expected.insert(tree);
    assert_eq!(actual.objects, expected, "{method:?} {merge:?}");
    let reads = objects.reads.borrow();
    assert_eq!(reads.keys().copied().collect::<BTreeSet<_>>(), expected);
    assert!(reads.values().all(|count| *count == 1), "{reads:?}");
}

fn duplicate_history_fixture(
    format: GitHashAlgorithm,
) -> (Objects, GitOid, GitOid, [(Method, NativeMerge); 3]) {
    let mut objects = Objects::default();
    let tree = objects.put(format, GitObjectKind::Tree, Vec::new());
    let base = objects.commit(tree, &[], "base\n");
    let repeated = objects.commit(tree, &[base, base], "imported repeated parent\n");
    let target = objects.commit(tree, &[repeated], "target\n");
    let source = objects.commit(tree, &[repeated], "source\n");
    let merged = objects.commit(tree, &[target, source], "merge\n");
    let squashed = objects.commit(tree, &[target], "squash\n");
    (
        objects,
        tree,
        repeated,
        [
            (Method::Merge, coordinates(base, target, source, merged)),
            (Method::Squash, coordinates(base, target, source, squashed)),
            (Method::FastForward, coordinates(base, base, source, source)),
        ],
    )
}

#[test]
fn native_methods_match_scalar_reachability_across_mixed_histories() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut objects = Objects::default();
        let tree = objects.put(format, GitObjectKind::Tree, Vec::new());
        let shapes: &[&[usize]] = &[
            &[],
            &[],
            &[0],
            &[0],
            &[2, 3],
            &[1, 3],
            &[4, 5],
            &[2, 2],
            &[6, 7],
            &[1],
        ];
        let mut commits = Vec::new();
        for (i, shape) in shapes.iter().enumerate() {
            let parents: Vec<_> = shape.iter().map(|&parent| commits[parent]).collect();
            commits.push(objects.commit(tree, &parents, &format!("commit {i}\n")));
        }
        let missing = GitOid::from_hex(format, &"9".repeat(format.digest_len() * 2)).unwrap();
        assert!(!objects.bodies.contains_key(&missing));
        // A stored tree and an unknown ID must not become commit ancestors.
        let mut bases = commits.clone();
        bases.extend([missing, tree]);
        for (target, source) in [(4, 5), (2, 3), (0, 8), (7, 6), (1, 9)] {
            let target = commits[target];
            let source = commits[source];
            let target_ancestors = scalar_reachable(&objects.parents, &[target]);
            let source_ancestors = scalar_reachable(&objects.parents, &[source]);
            let merged = objects.commit(tree, &[target, source], "matrix merge\n");
            let squashed = objects.commit(tree, &[target], "matrix squash\n");
            for base in &bases {
                let common = target_ancestors.contains(base) && source_ancestors.contains(base);
                objects.claimed = vec![*base];
                for (method, candidate) in [(Method::Merge, merged), (Method::Squash, squashed)] {
                    let merge = coordinates(*base, target, source, candidate);
                    objects.reads.borrow_mut().clear();
                    let actual = method.validate(
                        &objects,
                        &merge,
                        MergeObjectLimits::default(),
                        &mut || true,
                    );
                    if common {
                        assert_complete_once(&objects, tree, method, &merge, &actual.unwrap());
                    } else {
                        assert_eq!(
                            actual,
                            Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid)),
                            "{method:?} {merge:?}"
                        );
                    }
                }
            }
        }
        for source in &commits {
            let ancestors = scalar_reachable(&objects.parents, &[*source]);
            for target in bases.iter().filter(|target| *target != source) {
                let merge = coordinates(*target, *target, *source, *source);
                objects.claimed = vec![*target];
                objects.reads.borrow_mut().clear();
                let actual = Method::FastForward.validate(
                    &objects,
                    &merge,
                    MergeObjectLimits::default(),
                    &mut || true,
                );
                if ancestors.contains(target) {
                    assert_complete_once(
                        &objects,
                        tree,
                        Method::FastForward,
                        &merge,
                        &actual.unwrap(),
                    );
                } else {
                    assert_eq!(
                        actual,
                        Err(ProjectionFailure::Refuse(
                            RefusalCode::NonFastForwardRefused
                        )),
                        "{merge:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn historical_duplicate_headers_remain_native_bytes_and_consume_original_edge_budget() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (objects, tree, repeated, cases) = duplicate_history_fixture(format);
        let original = objects.bodies.clone();
        for ((method, merge), max_edges) in cases.iter().zip([11, 10, 6]) {
            let mut closure = scalar_reachable(&objects.parents, &method.roots(merge));
            closure.insert(tree);
            let limits = MergeObjectLimits {
                max_objects: closure.len(),
                max_edges,
                max_total_bytes: closure.iter().map(|id| objects.bodies[id].1.len()).sum(),
                ..MergeObjectLimits::default()
            };
            objects.reads.borrow_mut().clear();
            let actual = method
                .validate(&objects, merge, limits, &mut || true)
                .unwrap();
            assert_complete_once(&objects, tree, *method, merge, &actual);
            assert_eq!(
                method.validate(
                    &objects,
                    merge,
                    MergeObjectLimits {
                        max_edges: max_edges - 1,
                        ..limits
                    },
                    &mut || true,
                ),
                Err(ProjectionFailure::Unavailable(
                    RefusalCode::ResourceBudgetExceeded
                ))
            );
        }
        let base = cases[0].1.base_tip;
        // A fast-forward imports its source tip instead of enforcing a newly
        // constructed candidate shape; repeated source-tip parents stay valid.
        validate_fast_forward_objects(
            &objects,
            &coordinates(base, base, repeated, repeated),
            MergeObjectLimits::default(),
            &mut || true,
        )
        .unwrap();
        // The two non-ancestry entry points retain the same import semantics.
        validate_commit_closure(
            &objects,
            repeated,
            MergeObjectLimits::default(),
            &mut || true,
        )
        .unwrap();
        validate_workspace_objects(
            &objects,
            cases[0].1.target_tip_before,
            repeated,
            MergeObjectLimits::default(),
            &mut || true,
        )
        .unwrap();
        assert_eq!(objects.bodies, original);
    }
}

#[test]
fn derived_parent_deduplication_never_relaxes_candidate_parent_validation() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut objects, tree, _, cases) = duplicate_history_fixture(format);
        for (method, merge) in &cases[..2] {
            let mut parents = match method {
                Method::Merge => vec![merge.target_tip_before, merge.source_tip],
                Method::Squash => vec![merge.target_tip_before],
                Method::FastForward => unreachable!(),
            };
            parents.push(*parents.last().unwrap());
            let duplicate = objects.commit(tree, &parents, "bad duplicate candidate\n");
            let bad = NativeMerge {
                merge_commit: duplicate,
                ..merge.clone()
            };
            assert_eq!(
                method.validate(&objects, &bad, MergeObjectLimits::default(), &mut || true),
                Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))
            );
            method
                .validate(&objects, merge, MergeObjectLimits::default(), &mut || true)
                .unwrap();
        }
    }
}

#[test]
fn later_missing_or_corrupt_history_cannot_reuse_an_earlier_successful_ancestry_result() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut objects, _, repeated, cases) = duplicate_history_fixture(format);
        let successes: Vec<_> = cases
            .iter()
            .map(|(method, merge)| {
                method
                    .validate(&objects, merge, MergeObjectLimits::default(), &mut || true)
                    .unwrap()
            })
            .collect();
        let original = objects.bodies.remove(&repeated).unwrap();
        for (method, merge) in &cases {
            assert_eq!(
                method.validate(&objects, merge, MergeObjectLimits::default(), &mut || true),
                Err(ProjectionFailure::Unavailable(RefusalCode::EvidenceMissing))
            );
        }
        let mut corrupt = original.clone();
        corrupt.1.push(b'!');
        for replacement in [corrupt, (GitObjectKind::Blob, original.1.clone())] {
            objects.bodies.insert(repeated, replacement);
            for (method, merge) in &cases {
                assert_eq!(
                    method.validate(&objects, merge, MergeObjectLimits::default(), &mut || true),
                    Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))
                );
            }
        }
        objects.bodies.insert(repeated, original);
        for ((method, merge), expected) in cases.iter().zip(successes) {
            assert_eq!(
                method.validate(&objects, merge, MergeObjectLimits::default(), &mut || true),
                Ok(expected)
            );
        }
    }
}

#[test]
fn every_native_and_ancestry_checkpoint_preserves_cancellation_and_retry() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (objects, _, _, cases) = duplicate_history_fixture(format);
        for (method, merge) in cases {
            let mut checkpoints = 0;
            let expected = method
                .validate(&objects, &merge, MergeObjectLimits::default(), &mut || {
                    checkpoints += 1;
                    true
                })
                .unwrap();
            for stop in 1..=checkpoints {
                let mut seen = 0;
                assert_eq!(
                    method.validate(&objects, &merge, MergeObjectLimits::default(), &mut || {
                        seen += 1;
                        seen != stop
                    }),
                    Err(ProjectionFailure::Unavailable(
                        RefusalCode::CancellationInProgress
                    )),
                    "{format:?} {method:?} checkpoint {stop}/{checkpoints}"
                );
                assert_eq!(seen, stop);
            }
            assert_eq!(
                method.validate(&objects, &merge, MergeObjectLimits::default(), &mut || true),
                Ok(expected)
            );
        }
    }
}

#[test]
fn direct_parent_fast_forward_keeps_constant_ancestry_work_after_full_native_verification() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut counts = Vec::new();
        for depth in [0, 256] {
            let mut objects = Objects::default();
            let tree = objects.put(format, GitObjectKind::Tree, Vec::new());
            let mut target = objects.commit(tree, &[], "root\n");
            for i in 0..depth {
                target = objects.commit(tree, &[target], &format!("history {i}\n"));
            }
            let source = objects.commit(tree, &[target], "direct-parent source\n");
            // Both entry points perform the same complete native byte walk.
            // Subtract it to measure only the additional ancestry work, with
            // no dependency on the walk's absolute checkpoint count.
            let mut closure_checkpoints = 0;
            let expected = validate_commit_closure(
                &objects,
                source,
                MergeObjectLimits::default(),
                &mut || {
                    closure_checkpoints += 1;
                    true
                },
            )
            .unwrap();
            let merge = coordinates(target, target, source, source);
            objects.reads.borrow_mut().clear();
            let mut fast_forward_checkpoints = 0;
            let actual = validate_fast_forward_objects(
                &objects,
                &merge,
                MergeObjectLimits::default(),
                &mut || {
                    fast_forward_checkpoints += 1;
                    true
                },
            )
            .unwrap();
            assert_eq!(actual, expected);
            assert_complete_once(&objects, tree, Method::FastForward, &merge, &actual);
            assert!(fast_forward_checkpoints > closure_checkpoints);
            counts.push((
                closure_checkpoints,
                fast_forward_checkpoints - closure_checkpoints,
            ));
        }
        assert!(
            counts[1].0 > counts[0].0,
            "the deeper closure must be verified"
        );
        assert_eq!(
            counts[0].1, counts[1].1,
            "direct-parent ancestry work must not grow with older history"
        );
    }
}
