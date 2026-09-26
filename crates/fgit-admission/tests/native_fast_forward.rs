#![forbid(unsafe_code)]
//! Native object fixtures, not authority or authorization substitutes.
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use fgit_admission::merge::native::objects::{
    MergeObjectLimits, validate_fast_forward_objects, validate_merge_objects,
};
use fgit_admission::merge::native::{NativeMergeIntent, NativeMergeMethod};
use fgit_admission::{AdmissionContext, ProjectionFailure};
use fgit_authority::{
    ExpectedOld, HeadKey, IdempotencyKey, ProposedNew, RefCommand, ScopedEntry, SemanticRequest,
};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::{AggregateVersion, ExpectedVersion, ForgeEventBatch, PullRequestNumber};
use fgit_forge::event::NativeMerge;
use fgit_git_object::ObjectType;
use fgit_pack::{CanonicalObjectSource, CanonicalPackObject, PackWriteError};
use fgit_types::{AsciiSlug, GitHashAlgorithm, GitOid, PrincipalId, RefName, RefusalCode, RepositoryId, TenantId};

#[derive(Default)]
struct Objects {
    objects: BTreeMap<GitOid, (ObjectType, Vec<u8>)>,
    reads: Cell<usize>,
    claimed: Vec<GitOid>,
}
impl Objects {
    fn add(&mut self, format: GitHashAlgorithm, kind: GitObjectKind, body: Vec<u8>) -> GitOid {
        let id = git_object_id(format, kind, &body);
        let object_type = match kind {
            GitObjectKind::Commit => ObjectType::Commit,
            GitObjectKind::Tree => ObjectType::Tree,
            GitObjectKind::Blob => ObjectType::Blob,
            GitObjectKind::Tag => ObjectType::Tag,
        };
        self.objects.insert(id, (object_type, body));
        id
    }
    fn commit(&mut self, format: GitHashAlgorithm, tree: GitOid, parents: &[GitOid], message: &str) -> GitOid {
        let mut body = format!("tree {tree}\n");
        for parent in parents { body.push_str(&format!("parent {parent}\n")); }
        body.push_str("author Fixture <test@example.invalid> 1 +0000\ncommitter Fixture <test@example.invalid> 1 +0000\n\n");
        body.push_str(message);
        self.add(format, GitObjectKind::Commit, body.into_bytes())
    }
}
impl CanonicalObjectSource for Objects {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        self.reads.set(self.reads.get() + 1);
        let (kind, body) = self.objects.get(id).ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        Ok(CanonicalPackObject::new(*id, *kind, body.clone(), self.claimed.clone(), 0, 0))
    }
}
fn coordinates(target: GitOid, source: GitOid) -> NativeMerge {
    NativeMerge {
        source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
        source_tip: source,
        base_tip: target,
        target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
        target_tip_before: target,
        merge_commit: source,
    }
}
fn fixture(format: GitHashAlgorithm) -> (Objects, GitOid, GitOid, GitOid) {
    let mut objects = Objects::default();
    let tree = objects.add(format, GitObjectKind::Tree, Vec::new());
    let base = objects.commit(format, tree, &[], "base\n");
    let middle = objects.commit(format, tree, &[base], "middle\n");
    let tip = objects.commit(format, tree, &[middle], "tip\n");
    (objects, tree, base, tip)
}
fn refused<T: std::fmt::Debug>(result: Result<T, ProjectionFailure>, expected: RefusalCode) {
    assert!(matches!(result, Err(ProjectionFailure::Refuse(code)) if code == expected), "{result:?}");
}
fn unavailable<T: std::fmt::Debug>(result: Result<T, ProjectionFailure>, expected: RefusalCode) {
    assert!(matches!(result, Err(ProjectionFailure::Unavailable(code)) if code == expected), "{result:?}");
}

#[test]
fn deep_fast_forward_preserves_source_identity_and_loads_each_dependency_once() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (objects, _, base, tip) = fixture(format);
        let original = objects.objects.clone();
        let result = validate_fast_forward_objects(&objects, &coordinates(base, tip), MergeObjectLimits::default(), &mut || true).unwrap();
        assert_eq!(result.objects, objects.objects.keys().copied().collect::<BTreeSet<_>>());
        assert_eq!(objects.reads.get(), result.objects.len());
        assert_eq!(objects.objects, original);
        assert!(result.objects.contains(&base));
        assert!(result.objects.contains(&tip));
    }
}

#[test]
fn a_merge_in_source_history_can_fast_forward_through_its_second_parent() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut objects, tree, base, target) = fixture(format);
        let other = objects.commit(format, tree, &[base], "other\n");
        let tip = objects.commit(format, tree, &[other, target], "joined history\n");
        validate_fast_forward_objects(&objects, &coordinates(target, tip), MergeObjectLimits::default(), &mut || true).unwrap();
        let unrelated = objects.commit(format, tree, &[base], "same tree, not a parent\n");
        refused(validate_fast_forward_objects(&objects, &coordinates(unrelated, tip), MergeObjectLimits::default(), &mut || true), RefusalCode::NonFastForwardRefused);
    }
}

#[test]
fn divergence_and_reverse_ancestry_do_not_become_force_updates() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut objects, tree, base, tip) = fixture(format);
        let divergent = objects.commit(format, tree, &[base], "divergent\n");
        // A store edge list is not evidence: only hashed parent headers count.
        objects.claimed = vec![divergent];
        for (target, source) in [(divergent, tip), (tip, base)] {
            refused(validate_fast_forward_objects(&objects, &coordinates(target, source), MergeObjectLimits::default(), &mut || true), RefusalCode::NonFastForwardRefused);
        }
        validate_fast_forward_objects(&objects, &coordinates(base, tip), MergeObjectLimits::default(), &mut || true).unwrap();
    }
}

#[test]
fn two_parent_and_fast_forward_methods_cannot_substitute_for_one_another() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut objects, tree, base, tip) = fixture(format);
        let fast = coordinates(base, tip);
        refused(validate_merge_objects(&objects, &fast, MergeObjectLimits::default(), &mut || true), RefusalCode::EvidenceInvalid);
        let candidate = objects.commit(format, tree, &[base, tip], "explicit no-ff\n");
        let merged = NativeMerge { merge_commit: candidate, ..fast };
        validate_merge_objects(&objects, &merged, MergeObjectLimits::default(), &mut || true).unwrap();
        refused(validate_fast_forward_objects(&objects, &merged, MergeObjectLimits::default(), &mut || true), RefusalCode::EvidenceInvalid);
    }
}

#[test]
fn malformed_coordinates_are_refused_before_source_reads() {
    let (objects, _, base, tip) = fixture(GitHashAlgorithm::Sha1);
    let good = coordinates(base, tip);
    let other_format = GitOid::from_hex(GitHashAlgorithm::Sha256, &"a".repeat(64)).unwrap();
    for bad in [
        NativeMerge { base_tip: tip, ..good.clone() },
        NativeMerge { source_ref: good.target_ref.clone(), ..good.clone() },
        coordinates(base, base),
        coordinates(base, other_format),
    ] {
        refused(validate_fast_forward_objects(&objects, &bad, MergeObjectLimits::default(), &mut || true), RefusalCode::EvidenceInvalid);
        assert_eq!(objects.reads.get(), 0);
    }
    validate_fast_forward_objects(&objects, &good, MergeObjectLimits::default(), &mut || true).unwrap();
}

#[test]
fn missing_and_corrupt_dependencies_never_yield_a_partial_closure() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut objects, tree, base, tip) = fixture(format);
        let original = objects.objects.remove(&tree).unwrap();
        unavailable(validate_fast_forward_objects(&objects, &coordinates(base, tip), MergeObjectLimits::default(), &mut || true), RefusalCode::EvidenceMissing);
        objects.objects.insert(tree, (ObjectType::Tree, b"wrong bytes".to_vec()));
        refused(validate_fast_forward_objects(&objects, &coordinates(base, tip), MergeObjectLimits::default(), &mut || true), RefusalCode::EvidenceInvalid);
        objects.objects.insert(tree, original);
        validate_fast_forward_objects(&objects, &coordinates(base, tip), MergeObjectLimits::default(), &mut || true).unwrap();
    }
}

#[test]
fn unique_objects_bytes_and_parent_edges_keep_their_exact_budgets() {
    let (objects, _, base, tip) = fixture(GitHashAlgorithm::Sha1);
    let total: usize = objects.objects.values().map(|(_, body)| body.len()).sum();
    let exact = MergeObjectLimits { max_objects: 4, max_edges: 5, max_total_bytes: total, ..MergeObjectLimits::default() };
    validate_fast_forward_objects(&objects, &coordinates(base, tip), exact, &mut || true).unwrap();
    for limits in [
        MergeObjectLimits { max_objects: 3, ..exact },
        MergeObjectLimits { max_edges: 4, ..exact },
        MergeObjectLimits { max_total_bytes: total - 1, ..exact },
        MergeObjectLimits { max_object_bytes: 1, ..exact },
        MergeObjectLimits { max_objects: 0, ..exact },
    ] {
        unavailable(validate_fast_forward_objects(&objects, &coordinates(base, tip), limits, &mut || true), RefusalCode::ResourceBudgetExceeded);
    }
}

#[test]
fn interruption_at_every_checkpoint_refuses_without_losing_the_success_twin() {
    let (objects, _, base, tip) = fixture(GitHashAlgorithm::Sha1);
    let mut calls = 0;
    validate_fast_forward_objects(&objects, &coordinates(base, tip), MergeObjectLimits::default(), &mut || { calls += 1; true }).unwrap();
    for stop in 1..=calls {
        let mut seen = 0;
        unavailable(validate_fast_forward_objects(&objects, &coordinates(base, tip), MergeObjectLimits::default(), &mut || { seen += 1; seen != stop }), RefusalCode::CancellationInProgress);
    }
    validate_fast_forward_objects(&objects, &coordinates(base, tip), MergeObjectLimits::default(), &mut || true).unwrap();
}

#[test]
fn merge_method_is_sealed_and_legacy_seal_bytes_remain_unchanged() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_, _, base, tip) = fixture(format);
        let merge = coordinates(base, tip);
        let ff = NativeMergeIntent::fast_forward_only(PullRequestNumber::FIRST, AggregateVersion::FIRST, merge.source_ref.clone(), tip, merge.target_ref.clone(), base).unwrap();
        let old = NativeMergeIntent::new(PullRequestNumber::FIRST, ExpectedVersion::Exactly(AggregateVersion::FIRST), merge.clone()).unwrap();
        assert_eq!(ff.event(), old.event());
        assert_eq!(ff.method(), NativeMergeMethod::FastForwardOnly);
        assert_eq!(old.method(), NativeMergeMethod::MergeCommit);
        let context = AdmissionContext {
            head_key: HeadKey::new(b"ff-test/head".to_vec()).unwrap(),
            tenant_id: TenantId::from_bytes([1; 16]), repository_id: RepositoryId::from_bytes([2; 16]),
            principal_id: PrincipalId::from_bytes([3; 16]), idempotency_key: IdempotencyKey::new(b"same-key".to_vec()).unwrap(), object_format: format,
        };
        let a = ff.seal_attempt(&context).unwrap();
        let b = old.seal_attempt(&context).unwrap();
        assert_ne!(a.derive().unwrap().0, b.derive().unwrap().0);
        assert_eq!(a, ff.clone().seal_attempt(&context).unwrap());
        let root = fgit_admission::evidence::evidence_root(&ForgeEventBatch::of_one(old.event().clone())).unwrap();
        let legacy_request = SemanticRequest::build(
            fgit_authority::RECEIVE_ADMISSION_SCHEMA, format, true,
            vec![RefCommand { name: merge.target_ref, expected_old: ExpectedOld::Exactly(base), proposed_new: ProposedNew::Update(tip), force: false }],
            Vec::new(),
            vec![ScopedEntry::new(AsciiSlug::from_static("forge"), AsciiSlug::from_static("merge.event-batch-root"), root.bytes().as_bytes()).unwrap()],
        ).unwrap();
        assert_eq!(b.request, legacy_request);
    }
}
