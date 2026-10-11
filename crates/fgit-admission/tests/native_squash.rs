#![forbid(unsafe_code)]
//! Native object fixtures for squash admission, not an authority substitute.
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use fgit_admission::merge::native::objects::{
    MergeObjectLimits, validate_merge_objects, validate_squash_objects,
    validate_workspace_objects,
};
use fgit_admission::merge::native::{NativeMergeIntent, NativeMergeMethod};
use fgit_admission::{AdmissionContext, ProjectionFailure};
use fgit_authority::{HeadKey, IdempotencyKey, ScopedEntry, SemanticRequest};
use fgit_crypto::{GitObjectKind, git_object_id};
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
    claimed: Vec<GitOid>,
}
impl Objects {
    fn add(&mut self, format: GitHashAlgorithm, kind: GitObjectKind, body: Vec<u8>) -> GitOid {
        let id = git_object_id(format, kind, &body);
        let kind = match kind {
            GitObjectKind::Commit => ObjectType::Commit,
            GitObjectKind::Tree => ObjectType::Tree,
            GitObjectKind::Blob => ObjectType::Blob,
            GitObjectKind::Tag => ObjectType::Tag,
        };
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
        self.add(tree.algorithm(), GitObjectKind::Commit, body.into_bytes())
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
            self.claimed.clone(),
            0,
            0,
        ))
    }
}

fn fixture(format: GitHashAlgorithm) -> (Objects, NativeMerge, GitOid, GitOid) {
    let mut objects = Objects::default();
    let tree = objects.add(format, GitObjectKind::Tree, Vec::new());
    let base = objects.commit(tree, &[], "base\n");
    let target = objects.commit(tree, &[base], "target\n");
    // Source-only content must still be validated when a squash chooses a
    // different reviewed tree, because source is not a candidate parent.
    let blob = objects.add(format, GitObjectKind::Blob, b"source-only\n".to_vec());
    let source_tree = objects.add(
        format,
        GitObjectKind::Tree,
        [b"100644 incoming\0".as_slice(), blob.as_bytes()].concat(),
    );
    let middle = objects.commit(source_tree, &[base], "source middle\n");
    let source = objects.commit(source_tree, &[middle], "source tip\n");
    let candidate = objects.commit(tree, &[target], "reviewed squash\n");
    let merge = NativeMerge {
        source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
        source_tip: source,
        base_tip: base,
        target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
        target_tip_before: target,
        merge_commit: candidate,
    };
    (objects, merge, tree, blob)
}

fn refused<T: std::fmt::Debug>(result: Result<T, ProjectionFailure>, code: RefusalCode) {
    assert!(matches!(result, Err(ProjectionFailure::Refuse(value)) if value == code), "{result:?}");
}
fn unavailable<T: std::fmt::Debug>(result: Result<T, ProjectionFailure>, code: RefusalCode) {
    assert!(matches!(result, Err(ProjectionFailure::Unavailable(value)) if value == code), "{result:?}");
}

#[test]
fn squash_walk_verifies_both_histories_and_source_only_content_once_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (objects, merge, _, blob) = fixture(format);
        let original = objects.bodies.clone();
        let result = validate_squash_objects(
            &objects,
            &merge,
            MergeObjectLimits::default(),
            &mut || true,
        )
        .unwrap();
        assert_eq!(result.objects, objects.bodies.keys().copied().collect::<BTreeSet<_>>());
        assert!(result.objects.contains(&blob));
        assert!(result.objects.contains(&merge.source_tip));
        assert_eq!(objects.reads.get(), result.objects.len());
        assert_eq!(objects.bodies, original);
        let candidate_only = validate_workspace_objects(
            &objects,
            merge.merge_commit,
            merge.target_tip_before,
            MergeObjectLimits::default(),
            &mut || true,
        )
        .unwrap();
        assert!(!candidate_only.objects.contains(&merge.source_tip));
        assert!(!candidate_only.objects.contains(&blob));
        assert_ne!(result.object_closure_root, candidate_only.object_closure_root);
    }
}

#[test]
fn squash_requires_exactly_the_target_parent_and_cannot_substitute_a_merge_commit() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut objects, merge, tree, _) = fixture(format);
        let joined = objects.commit(tree, &[merge.target_tip_before, merge.source_tip], "merge\n");
        for candidate in [
            joined,
            objects.commit(tree, &[], "root\n"),
            objects.commit(tree, &[merge.source_tip], "wrong parent\n"),
            objects.commit(tree, &[merge.target_tip_before, merge.target_tip_before], "duplicate\n"),
        ] {
            refused(
                validate_squash_objects(
                    &objects,
                    &NativeMerge { merge_commit: candidate, ..merge.clone() },
                    MergeObjectLimits::default(),
                    &mut || true,
                ),
                RefusalCode::EvidenceInvalid,
            );
        }
        refused(
            validate_merge_objects(&objects, &merge, MergeObjectLimits::default(), &mut || true),
            RefusalCode::EvidenceInvalid,
        );
        validate_merge_objects(
            &objects,
            &NativeMerge { merge_commit: joined, ..merge.clone() },
            MergeObjectLimits::default(),
            &mut || true,
        ).unwrap();
        validate_squash_objects(&objects, &merge, MergeObjectLimits::default(), &mut || true).unwrap();
    }
}

#[test]
fn common_base_is_proved_through_commit_edges_of_both_branches_not_claimed_metadata() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut objects, merge, tree, _) = fixture(format);
        let unrelated = objects.commit(tree, &[], "unrelated source\n");
        objects.claimed = vec![merge.base_tip, merge.source_tip, merge.target_tip_before];
        for bad in [
            NativeMerge { source_tip: unrelated, ..merge.clone() },
            NativeMerge { base_tip: merge.source_tip, ..merge.clone() },
            NativeMerge { base_tip: merge.target_tip_before, ..merge.clone() },
        ] {
            refused(
                validate_squash_objects(&objects, &bad, MergeObjectLimits::default(), &mut || true),
                RefusalCode::EvidenceInvalid,
            );
        }
        // The common base may occur through the source's second parent.
        let source = objects.commit(tree, &[unrelated, merge.source_tip], "joined source\n");
        validate_squash_objects(
            &objects,
            &NativeMerge { source_tip: source, ..merge.clone() },
            MergeObjectLimits::default(),
            &mut || true,
        ).unwrap();
        validate_squash_objects(&objects, &merge, MergeObjectLimits::default(), &mut || true).unwrap();
    }
}

#[test]
fn source_only_missing_tampered_or_wrong_kind_objects_never_return_partial_success() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut objects, merge, _, blob) = fixture(format);
        for id in [merge.source_tip, blob] {
            let held = objects.bodies.remove(&id).unwrap();
            unavailable(
                validate_squash_objects(&objects, &merge, MergeObjectLimits::default(), &mut || true),
                RefusalCode::EvidenceMissing,
            );
            let mut corrupt = held.clone();
            corrupt.1.push(b'!');
            objects.bodies.insert(id, corrupt);
            refused(
                validate_squash_objects(&objects, &merge, MergeObjectLimits::default(), &mut || true),
                RefusalCode::EvidenceInvalid,
            );
            objects.bodies.insert(id, (ObjectType::Tree, held.1.clone()));
            refused(
                validate_squash_objects(&objects, &merge, MergeObjectLimits::default(), &mut || true),
                RefusalCode::EvidenceInvalid,
            );
            objects.bodies.insert(id, held);
        }
        validate_squash_objects(&objects, &merge, MergeObjectLimits::default(), &mut || true).unwrap();
    }
}

#[test]
fn all_squash_roots_share_one_unique_object_byte_and_edge_budget() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (objects, merge, _, _) = fixture(format);
        let total: usize = objects.bodies.values().map(|(_, body)| body.len()).sum();
        let exact = MergeObjectLimits {
            max_objects: 8,
            // Five commit trees, four commit parents, one source-tree blob.
            max_edges: 10,
            max_total_bytes: total,
            ..MergeObjectLimits::default()
        };
        validate_squash_objects(&objects, &merge, exact, &mut || true).unwrap();
        for limits in [
            MergeObjectLimits { max_objects: 7, ..exact },
            MergeObjectLimits { max_edges: 9, ..exact },
            MergeObjectLimits { max_total_bytes: total - 1, ..exact },
            MergeObjectLimits { max_object_bytes: 1, ..exact },
        ] {
            unavailable(
                validate_squash_objects(&objects, &merge, limits, &mut || true),
                RefusalCode::ResourceBudgetExceeded,
            );
        }
    }
}

#[test]
fn malformed_coordinates_refuse_before_reading_and_unrelated_store_objects_stay_excluded() {
    let (mut objects, merge, tree, _) = fixture(GitHashAlgorithm::Sha1);
    let wrong_format = GitOid::from_hex(GitHashAlgorithm::Sha256, &"a".repeat(64)).unwrap();
    for bad in [
        NativeMerge { source_tip: wrong_format, ..merge.clone() },
        NativeMerge { source_tip: merge.target_tip_before, ..merge.clone() },
        NativeMerge { source_ref: merge.target_ref.clone(), ..merge.clone() },
        NativeMerge { merge_commit: merge.target_tip_before, ..merge.clone() },
    ] {
        refused(
            validate_squash_objects(&objects, &bad, MergeObjectLimits::default(), &mut || true),
            RefusalCode::EvidenceInvalid,
        );
        assert_eq!(objects.reads.get(), 0);
    }
    let unrelated = objects.commit(tree, &[], "unselected\n");
    objects.claimed = vec![unrelated];
    let closure = validate_squash_objects(&objects, &merge, MergeObjectLimits::default(), &mut || true).unwrap();
    assert!(!closure.objects.contains(&unrelated));
}

#[test]
fn equal_original_tips_refuse_but_identical_source_and_candidate_bytes_remain_valid() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut objects, merge, tree, _) = fixture(format);
        let equal_tips = NativeMerge {
            source_tip: merge.target_tip_before,
            ..merge.clone()
        };
        assert!(NativeMergeIntent::squash(
            PullRequestNumber::FIRST,
            AggregateVersion::FIRST,
            equal_tips.clone(),
        ).is_err());
        refused(
            validate_squash_objects(&objects, &equal_tips, MergeObjectLimits::default(), &mut || true),
            RefusalCode::EvidenceInvalid,
        );
        let source = objects.commit(tree, &[merge.target_tip_before], "identical squash bytes\n");
        let identical_bytes = NativeMerge {
            source_tip: source,
            merge_commit: source,
            base_tip: merge.target_tip_before,
            ..merge
        };
        let intent = NativeMergeIntent::squash(
            PullRequestNumber::FIRST,
            AggregateVersion::FIRST,
            identical_bytes.clone(),
        ).unwrap();
        assert_eq!(intent.method(), NativeMergeMethod::Squash);
        validate_squash_objects(&objects, &identical_bytes, MergeObjectLimits::default(), &mut || true).unwrap();
    }
}

#[test]
fn interruption_at_every_checkpoint_returns_no_closure_and_retry_is_deterministic() {
    let (objects, merge, _, _) = fixture(GitHashAlgorithm::Sha1);
    let mut calls = 0;
    let original = validate_squash_objects(&objects, &merge, MergeObjectLimits::default(), &mut || {
        calls += 1;
        true
    }).unwrap();
    for stop in 1..=calls {
        let mut seen = 0;
        unavailable(
            validate_squash_objects(&objects, &merge, MergeObjectLimits::default(), &mut || {
                seen += 1;
                seen != stop
            }),
            RefusalCode::CancellationInProgress,
        );
    }
    assert_eq!(original, validate_squash_objects(&objects, &merge, MergeObjectLimits::default(), &mut || true).unwrap());
}

#[test]
fn squash_method_is_explicit_and_distinct_without_changing_legacy_seals() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_, merge, _, _) = fixture(format);
        let squash = NativeMergeIntent::squash(
            PullRequestNumber::FIRST,
            AggregateVersion::FIRST,
            merge.clone(),
        ).unwrap();
        let legacy = NativeMergeIntent::new(
            PullRequestNumber::FIRST,
            ExpectedVersion::Exactly(AggregateVersion::FIRST),
            merge,
        ).unwrap();
        assert_eq!(squash.method(), NativeMergeMethod::Squash);
        assert_eq!(squash.expected_version(), ExpectedVersion::Exactly(AggregateVersion::FIRST));
        assert_eq!(squash.event(), legacy.event());
        let context = AdmissionContext {
            head_key: HeadKey::new(b"squash/head".to_vec()).unwrap(),
            tenant_id: TenantId::from_bytes([1; 16]),
            repository_id: RepositoryId::from_bytes([2; 16]),
            principal_id: PrincipalId::from_bytes([3; 16]),
            idempotency_key: IdempotencyKey::new(b"same-key".to_vec()).unwrap(),
            object_format: format,
        };
        let old = legacy.seal_attempt(&context).unwrap();
        let current = squash.seal_attempt(&context).unwrap();
        assert_ne!(old.derive().unwrap().0, current.derive().unwrap().0);
        assert_eq!(old.request.scoped_entries().len(), 1);
        let mut entries = old.request.scoped_entries().to_vec();
        entries.push(ScopedEntry::new(
            AsciiSlug::from_static("forge"),
            AsciiSlug::from_static("merge.method"),
            b"squash/v1",
        ).unwrap());
        let expected = SemanticRequest::build(
            old.request.request_schema(),
            old.request.object_format(),
            old.request.atomic(),
            old.request.ref_commands().to_vec(),
            old.request.push_options().to_vec(),
            entries,
        ).unwrap();
        assert_eq!(current.request, expected);
        assert_eq!(current, squash.clone().seal_attempt(&context).unwrap());
        let bound = squash.with_workspace_snapshot([7; 32]).seal_attempt(&context).unwrap();
        assert_ne!(current.derive().unwrap().0, bound.derive().unwrap().0);
    }
}
