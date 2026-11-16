#![forbid(unsafe_code)]
//! Reviewed linear PR candidates use the same native object and authority
//! frontier contracts as merge and squash; fixture maps confer no authority.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use fgit_admission::merge::native::objects::{
    CanonicalObjectHeader, FrontierObjectHeaders, MAX_REBASE_MERGE_COMMITS, MergeObjectLimits,
    ObjectFrontier, validate_rebase_objects, validate_rebase_objects_above,
};
use fgit_admission::merge::native::protection::path_reviews::{
    verify_merge_paths, verify_rebase_paths,
};
use fgit_admission::merge::native::{NativeMergeIntent, NativeMergeMethod};
use fgit_admission::{
    AdmissionContext, PermittedObjectClosure, ProjectionFailure, permitted_object_closure_root,
};
use fgit_authority::{HeadKey, IdempotencyKey, ScopedEntry, SemanticRequest};
use fgit_crypto::git_object_id;
use fgit_forge::event::NativeMerge;
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_git_object::ObjectType;
use fgit_pack::{CanonicalObjectSource, CanonicalPackObject, PackWriteError};
use fgit_types::{
    AsciiSlug, GitHashAlgorithm, GitOid, PrincipalId, RefName, RefusalCode, RepositoryId, TenantId,
};

#[derive(Default)]
struct Objects {
    bodies: BTreeMap<GitOid, (ObjectType, Vec<u8>)>,
    reads: Cell<usize>,
}
impl Objects {
    fn add(&mut self, format: GitHashAlgorithm, kind: ObjectType, body: Vec<u8>) -> GitOid {
        let id = git_object_id(format, kind, &body);
        self.bodies.insert(id, (kind, body));
        id
    }
    fn tree(&mut self, format: GitHashAlgorithm, text: &[u8]) -> (GitOid, GitOid) {
        let blob = self.add(format, ObjectType::Blob, text.to_vec());
        let mut body = b"100644 file\0".to_vec();
        body.extend_from_slice(blob.as_bytes());
        (self.add(format, ObjectType::Tree, body), blob)
    }
    fn commit(&mut self, tree: GitOid, parents: &[GitOid], message: &str) -> GitOid {
        let mut body = format!("tree {tree}\n");
        for parent in parents {
            writeln!(body, "parent {parent}").unwrap();
        }
        body.push_str("author Fixture <fixture@example.invalid> 1 +0000\n");
        body.push_str("committer Fixture <fixture@example.invalid> 2 +0000\n\n");
        body.push_str(message);
        self.add(tree.algorithm(), ObjectType::Commit, body.into_bytes())
    }
}
impl CanonicalObjectSource for Objects {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        self.reads.set(self.reads.get() + 1);
        let (kind, body) = self
            .bodies
            .get(id)
            .ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        Ok(CanonicalPackObject::new(
            *id,
            *kind,
            body.clone(),
            Vec::new(),
            0,
            0,
        ))
    }
}
impl FrontierObjectHeaders for Objects {
    fn load_header(&self, id: &GitOid) -> Result<Option<CanonicalObjectHeader>, PackWriteError> {
        Ok(self
            .bodies
            .get(id)
            .map(|(kind, body)| CanonicalObjectHeader {
                id: *id,
                object_type: *kind,
                body_bytes: body.len(),
            }))
    }
}

struct Fixture {
    objects: Objects,
    selected: BTreeSet<GitOid>,
    merge: NativeMerge,
    intermediate: GitOid,
    transient_tree: GitOid,
    transient_blob: GitOid,
    original: GitOid,
    source_tree: GitOid,
    target_tree: GitOid,
}
fn fixture(format: GitHashAlgorithm) -> Fixture {
    let mut objects = Objects::default();
    let (base_tree, _) = objects.tree(format, b"base\n");
    let base = objects.commit(base_tree, &[], "base");
    let target = objects.commit(base_tree, &[base], "target");
    let (first_tree, _) = objects.tree(format, b"original first\n");
    let original = objects.commit(first_tree, &[base], "first");
    let (source_tree, _) = objects.tree(format, b"original second\n");
    let source = objects.commit(source_tree, &[original], "second");
    let selected = objects.bodies.keys().copied().collect();
    let (transient_tree, transient_blob) = objects.tree(format, b"transient candidate content\n");
    let intermediate = objects.commit(transient_tree, &[target], "reviewed first");
    let candidate = objects.commit(source_tree, &[intermediate], "reviewed second");
    Fixture {
        objects,
        selected,
        merge: NativeMerge {
            source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
            source_tip: source,
            base_tip: base,
            target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
            target_tip_before: target,
            merge_commit: candidate,
        },
        intermediate,
        transient_tree,
        transient_blob,
        original,
        source_tree,
        target_tree: base_tree,
    }
}
fn validate(
    f: &Fixture,
    limits: MergeObjectLimits,
) -> Result<fgit_admission::ValidatedClosure, ProjectionFailure> {
    validate_rebase_objects_above(
        &f.objects,
        &f.merge,
        ObjectFrontier::with_headers(&f.selected, &f.objects),
        limits,
        &mut || true,
    )
}
fn invalid(result: Result<fgit_admission::ValidatedClosure, ProjectionFailure>) {
    assert!(matches!(
        result,
        Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))
    ));
}
fn budget(result: Result<fgit_admission::ValidatedClosure, ProjectionFailure>) {
    assert!(matches!(
        result,
        Err(ProjectionFailure::Unavailable(
            RefusalCode::ResourceBudgetExceeded
        ))
    ));
}

#[test]
fn complete_reviewed_series_validates_all_intermediate_content_in_both_hash_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = fixture(format);
        let above = validate(&f, MergeObjectLimits::default()).unwrap();
        let expected: BTreeSet<_> = [
            f.merge.merge_commit,
            f.intermediate,
            f.transient_tree,
            f.transient_blob,
            f.merge.source_tip,
            f.merge.target_tip_before,
            f.merge.base_tip,
        ]
        .into();
        assert_eq!(above.objects, expected);
        assert_eq!(
            above.object_closure_root,
            permitted_object_closure_root(&PermittedObjectClosure::new(expected)).unwrap()
        );
        let full = validate_rebase_objects(
            &f.objects,
            &f.merge,
            MergeObjectLimits::default(),
            &mut || true,
        )
        .unwrap();
        assert!(full.objects.is_superset(&above.objects));
        let union: BTreeSet<_> = f.selected.union(&above.objects).copied().collect();
        assert!(union.is_superset(&full.objects));
    }
}

#[test]
fn a_selected_intermediate_cannot_hide_a_merge_or_wrong_stopping_boundary() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for parents in [0, 2] {
            let mut f = fixture(format);
            let bad_parents = if parents == 0 {
                vec![]
            } else {
                vec![f.merge.target_tip_before, f.merge.source_tip]
            };
            let intermediate = f
                .objects
                .commit(f.source_tree, &bad_parents, "bad intermediate");
            f.selected.insert(intermediate);
            f.merge.merge_commit = f
                .objects
                .commit(f.source_tree, &[intermediate], "candidate");
            invalid(validate(&f, MergeObjectLimits::default()));
            assert!(
                verify_rebase_paths(
                    &f.objects,
                    &f.merge,
                    MergeObjectLimits::default(),
                    &mut || true,
                )
                .is_err()
            );
            f.merge.merge_commit = f.objects.commit(
                f.source_tree,
                &[f.merge.target_tip_before],
                "permitted one commit",
            );
            validate(&f, MergeObjectLimits::default()).unwrap();
        }
        let mut f = fixture(format);
        f.merge.merge_commit = f
            .objects
            .commit(f.source_tree, &[f.merge.base_tip], "wrong onto");
        invalid(validate(&f, MergeObjectLimits::default()));
    }
}

#[test]
fn original_suffix_and_common_base_are_independently_checked() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = fixture(format);
        let source = f.objects.commit(
            f.source_tree,
            &[f.original, f.merge.target_tip_before],
            "source merge",
        );
        f.selected.insert(source);
        f.merge.source_tip = source;
        invalid(validate(&f, MergeObjectLimits::default()));
        f.merge.source_tip = f.original;
        validate(&f, MergeObjectLimits::default()).unwrap();
        // A selected but unrelated base cannot be used to relabel the source.
        let unrelated = f.objects.commit(f.source_tree, &[], "unrelated");
        f.selected.insert(unrelated);
        f.merge.base_tip = unrelated;
        invalid(validate(&f, MergeObjectLimits::default()));
    }
}

#[test]
fn no_op_and_unselected_coordinates_refuse_beside_a_nonempty_permitted_series() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = fixture(format);
        let candidate = f.merge.merge_commit;
        f.merge.merge_commit = f.merge.target_tip_before;
        invalid(validate(&f, MergeObjectLimits::default()));
        f.merge.merge_commit = candidate;
        validate(&f, MergeObjectLimits::default()).unwrap();
        for missing in [
            f.merge.source_tip,
            f.merge.target_tip_before,
            f.merge.base_tip,
            f.original,
        ] {
            f.selected.remove(&missing);
            assert!(matches!(
                validate(&f, MergeObjectLimits::default()),
                Err(ProjectionFailure::Refuse(
                    RefusalCode::ObjectClosureIncomplete
                ))
            ));
            f.selected.insert(missing);
        }
        f.merge.base_tip = f.merge.source_tip;
        invalid(validate(&f, MergeObjectLimits::default()));
    }
}

#[test]
fn chain_limits_are_inclusive_for_candidates_and_originals() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = fixture(format);
        let mut candidate = f.merge.target_tip_before;
        for index in 0..MAX_REBASE_MERGE_COMMITS {
            candidate =
                f.objects
                    .commit(f.source_tree, &[candidate], &format!("candidate {index}"));
        }
        f.merge.merge_commit = candidate;
        validate(&f, MergeObjectLimits::default()).unwrap();
        verify_rebase_paths(
            &f.objects,
            &f.merge,
            MergeObjectLimits::default(),
            &mut || true,
        )
        .unwrap();
        f.merge.merge_commit = f
            .objects
            .commit(f.source_tree, &[candidate], "one too many");
        budget(validate(&f, MergeObjectLimits::default()));
        assert!(matches!(
            verify_rebase_paths(
                &f.objects,
                &f.merge,
                MergeObjectLimits::default(),
                &mut || true
            ),
            Err(ProjectionFailure::Unavailable(
                RefusalCode::ResourceBudgetExceeded
            ))
        ));
        f.merge.merge_commit = candidate;
        let mut source = f.merge.base_tip;
        for index in 0..MAX_REBASE_MERGE_COMMITS {
            source = f
                .objects
                .commit(f.source_tree, &[source], &format!("original {index}"));
            f.selected.insert(source);
        }
        f.merge.source_tip = source;
        validate(&f, MergeObjectLimits::default()).unwrap();
        f.merge.source_tip = f
            .objects
            .commit(f.source_tree, &[source], "original too many");
        f.selected.insert(f.merge.source_tip);
        budget(validate(&f, MergeObjectLimits::default()));
    }
}

#[test]
fn same_original_and_candidate_commit_reuses_verified_work_without_skipping_topology() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = fixture(format);
        // An already linear source may already have the reviewed native bytes.
        f.merge.source_tip = f.merge.merge_commit;
        f.selected.extend([
            f.merge.merge_commit,
            f.intermediate,
            f.transient_tree,
            f.transient_blob,
        ]);
        validate(&f, MergeObjectLimits::default()).unwrap();
    }
}

#[test]
fn intermediate_missing_corrupt_or_wrong_kind_objects_never_disappear_in_final_tree() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = fixture(format);
        let original = f.objects.bodies[&f.transient_blob].clone();
        f.objects.bodies.remove(&f.transient_blob);
        assert!(validate(&f, MergeObjectLimits::default()).is_err());
        f.objects
            .bodies
            .insert(f.transient_blob, (ObjectType::Blob, b"corrupt".to_vec()));
        assert!(validate(&f, MergeObjectLimits::default()).is_err());
        f.objects
            .bodies
            .insert(f.transient_blob, (ObjectType::Tree, original.1.clone()));
        assert!(validate(&f, MergeObjectLimits::default()).is_err());
        f.objects.bodies.insert(f.transient_blob, original);
        validate(&f, MergeObjectLimits::default()).unwrap();
    }
}

#[test]
fn budgets_cover_the_whole_series_and_every_checkpoint_can_cancel() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = fixture(format);
        let first = f.objects.commit(
            f.source_tree,
            &[f.merge.target_tip_before],
            &"a".repeat(2048),
        );
        f.merge.merge_commit = f.objects.commit(f.source_tree, &[first], &"b".repeat(2048));
        let aggregate =
            f.objects.bodies[&first].1.len() + f.objects.bodies[&f.merge.merge_commit].1.len();
        let narrow = MergeObjectLimits {
            max_total_bytes: aggregate - 1,
            ..MergeObjectLimits::default()
        };
        budget(validate(&f, narrow));
        f.merge.merge_commit = f.objects.commit(
            f.source_tree,
            &[f.merge.target_tip_before],
            &"b".repeat(2048),
        );
        validate(&f, narrow).unwrap();
        budget(validate(
            &f,
            MergeObjectLimits {
                max_objects: 1,
                ..MergeObjectLimits::default()
            },
        ));
        budget(validate(
            &f,
            MergeObjectLimits {
                max_edges: 1,
                ..MergeObjectLimits::default()
            },
        ));
        let calls = Cell::new(0usize);
        validate_rebase_objects_above(
            &f.objects,
            &f.merge,
            &f.selected,
            MergeObjectLimits::default(),
            &mut || {
                calls.set(calls.get() + 1);
                true
            },
        )
        .unwrap();
        for stop in 0..calls.get() {
            let mut count = 0;
            let result = validate_rebase_objects_above(
                &f.objects,
                &f.merge,
                &f.selected,
                MergeObjectLimits::default(),
                &mut || {
                    let live = count < stop;
                    count += 1;
                    live
                },
            );
            assert!(
                matches!(
                    result,
                    Err(ProjectionFailure::Unavailable(
                        RefusalCode::CancellationInProgress
                    ))
                ),
                "checkpoint {stop}: {result:?}"
            );
        }
    }
}

#[test]
fn rebase_seal_is_explicit_distinct_and_preserves_original_merge_bytes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = fixture(format);
        let rebase = NativeMergeIntent::rebase(
            PullRequestNumber::FIRST,
            AggregateVersion::FIRST,
            f.merge.clone(),
        )
        .unwrap();
        let squash = NativeMergeIntent::squash(
            PullRequestNumber::FIRST,
            AggregateVersion::FIRST,
            f.merge.clone(),
        )
        .unwrap();
        let legacy = NativeMergeIntent::new(
            PullRequestNumber::FIRST,
            ExpectedVersion::Exactly(AggregateVersion::FIRST),
            f.merge.clone(),
        )
        .unwrap();
        assert_eq!(rebase.method(), NativeMergeMethod::Rebase);
        assert_eq!(
            rebase.expected_version(),
            ExpectedVersion::Exactly(AggregateVersion::FIRST)
        );
        assert_eq!(rebase.event(), legacy.event());
        let context = AdmissionContext {
            head_key: HeadKey::new(b"rebase/head".to_vec()).unwrap(),
            tenant_id: TenantId::from_bytes([1; 16]),
            repository_id: RepositoryId::from_bytes([2; 16]),
            principal_id: PrincipalId::from_bytes([3; 16]),
            idempotency_key: IdempotencyKey::new(b"same-key".to_vec()).unwrap(),
            object_format: format,
        };
        let old = legacy.seal_attempt(&context).unwrap();
        let current = rebase.seal_attempt(&context).unwrap();
        let squashed = squash.seal_attempt(&context).unwrap();
        assert_ne!(current.derive().unwrap().0, old.derive().unwrap().0);
        assert_ne!(current.derive().unwrap().0, squashed.derive().unwrap().0);
        assert_eq!(old.request.scoped_entries().len(), 1);
        let mut entries = old.request.scoped_entries().to_vec();
        entries.push(
            ScopedEntry::new(
                AsciiSlug::from_static("forge"),
                AsciiSlug::from_static("merge.method"),
                b"rebase/v1",
            )
            .unwrap(),
        );
        let expected = SemanticRequest::build(
            old.request.request_schema(),
            old.request.object_format(),
            old.request.atomic(),
            old.request.ref_commands().to_vec(),
            old.request.push_options().to_vec(),
            entries,
        )
        .unwrap();
        assert_eq!(current.request, expected);
        assert_eq!(current, rebase.clone().seal_attempt(&context).unwrap());
        let bound = rebase
            .with_workspace_snapshot([7; 32])
            .seal_attempt(&context)
            .unwrap();
        assert_ne!(current.derive().unwrap().0, bound.derive().unwrap().0);
        let mut no_op = f.merge.clone();
        no_op.merge_commit = no_op.target_tip_before;
        assert!(
            NativeMergeIntent::rebase(PullRequestNumber::FIRST, AggregateVersion::FIRST, no_op)
                .is_err()
        );
    }
}

#[test]
fn series_path_witness_keeps_transient_changes_and_shares_every_budget() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = fixture(format);
        f.merge.merge_commit =
            f.objects
                .commit(f.target_tree, &[f.intermediate], "restore target tree");
        let final_only = verify_merge_paths(
            &f.objects,
            &f.merge,
            MergeObjectLimits::default(),
            &mut || true,
        )
        .unwrap();
        assert!(final_only.changed_paths().is_empty());
        let complete = verify_rebase_paths(
            &f.objects,
            &f.merge,
            MergeObjectLimits::default(),
            &mut || true,
        )
        .unwrap();
        assert_eq!(complete.changed_paths(), &[b"file".to_vec()]);
        assert_eq!(complete.merge(), &f.merge);
        // Each single comparison has two commits and two trees. Two steps
        // collectively exceed that ceiling; it cannot restart per commit.
        assert!(matches!(
            verify_rebase_paths(
                &f.objects,
                &f.merge,
                MergeObjectLimits {
                    max_objects: 4,
                    ..MergeObjectLimits::default()
                },
                &mut || true
            ),
            Err(ProjectionFailure::Unavailable(
                RefusalCode::ResourceBudgetExceeded
            ))
        ));
        assert!(matches!(
            verify_rebase_paths(
                &f.objects,
                &f.merge,
                MergeObjectLimits {
                    max_edges: 4,
                    ..MergeObjectLimits::default()
                },
                &mut || true
            ),
            Err(ProjectionFailure::Unavailable(
                RefusalCode::ResourceBudgetExceeded
            ))
        ));
        let mut calls = 0usize;
        verify_rebase_paths(
            &f.objects,
            &f.merge,
            MergeObjectLimits::default(),
            &mut || {
                calls += 1;
                true
            },
        )
        .unwrap();
        for stop in 0..calls {
            let mut current = 0usize;
            assert!(matches!(
                verify_rebase_paths(
                    &f.objects,
                    &f.merge,
                    MergeObjectLimits::default(),
                    &mut || {
                        let live = current < stop;
                        current += 1;
                        live
                    }
                ),
                Err(ProjectionFailure::Unavailable(
                    RefusalCode::CancellationInProgress
                ))
            ));
        }
        f.objects.bodies.remove(&f.intermediate);
        assert!(
            verify_rebase_paths(
                &f.objects,
                &f.merge,
                MergeObjectLimits::default(),
                &mut || true
            )
            .is_err()
        );
    }
}
