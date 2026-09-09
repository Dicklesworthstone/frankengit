#![forbid(unsafe_code)]
//! Canonical request compatibility and additive workspace identity bindings.
//! Fixed object identities are encoding inputs, not object-validation evidence.

use std::collections::BTreeSet;

use fgit_admission::evidence::evidence_root;
use fgit_admission::merge::native::{NativeMergeIntent, workspace_seal_attempt_for};
use fgit_admission::merge::{SealedMerge, seal_attempt_for};
use fgit_admission::{
    AdmissionContext, CommitEvidence, PermittedObjectClosure, ValidatedClosure,
    permitted_object_closure_root,
};
use fgit_authority::{
    ExpectedOld, HeadKey, IdempotencyKey, ProposedNew, RefCommand, ScopedEntry, SemanticRequest,
};
use fgit_codec::{CryptoBodyIdentity, encode_body, harness};
use fgit_forge::aggregate::{ExpectedVersion, PullRequestNumber};
use fgit_forge::event::{ForgeEventBatch, NativeMerge};
use fgit_forge::{MergeAttempt, MergeEffectPackage, RefIntent, WorkspaceEpoch};
use fgit_types::{
    AsciiSlug, GitHashAlgorithm, GitOid, PrincipalId, RefName, RepositoryId, TenantId,
};

struct Fixture {
    context: AdmissionContext,
    intent: NativeMergeIntent,
    package: MergeEffectPackage,
    attempt: MergeAttempt,
    closure: ValidatedClosure,
}

impl Fixture {
    fn new() -> Self {
        let oid = |byte| GitOid::Sha1(fgit_types::GitOidSha1::from_bytes([byte; 20]));
        let merge = NativeMerge {
            source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
            source_tip: oid(1),
            base_tip: oid(2),
            target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
            target_tip_before: oid(3),
            merge_commit: oid(4),
        };
        let pull_request = PullRequestNumber::try_new(1).unwrap();
        let intent =
            NativeMergeIntent::new(pull_request, ExpectedVersion::NewStream, merge.clone())
                .unwrap();
        let package = MergeEffectPackage {
            objects: vec![merge.merge_commit],
            ref_intent: RefIntent {
                name: merge.target_ref.as_bytes().to_vec(),
                expected_tip: merge.target_tip_before,
                new_tip: merge.merge_commit,
            },
            event: intent.event().clone(),
        };
        let attempt = MergeAttempt {
            pull_request,
            source_ref: merge.source_ref.as_bytes().to_vec(),
            target_ref: merge.target_ref.as_bytes().to_vec(),
            source_tip: merge.source_tip,
            target_tip: merge.target_tip_before,
            base_tip: merge.base_tip,
            workspace_epoch: WorkspaceEpoch::from_u64(9),
        };
        Self {
            context: AdmissionContext {
                head_key: HeadKey::new(b"workspace-binding/head".to_vec()).unwrap(),
                tenant_id: TenantId::from_bytes([1; 16]),
                repository_id: RepositoryId::from_bytes([2; 16]),
                principal_id: PrincipalId::from_bytes([3; 16]),
                idempotency_key: IdempotencyKey::new(b"workspace-binding".to_vec()).unwrap(),
                object_format: GitHashAlgorithm::Sha1,
            },
            intent,
            package,
            attempt,
            closure: ValidatedClosure {
                objects: BTreeSet::from([merge.merge_commit]),
                object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
                    BTreeSet::from([merge.merge_commit]),
                ))
                .unwrap(),
            },
        }
    }

    fn sealed(&self) -> SealedMerge<'_> {
        let record = harness::commit_record();
        SealedMerge {
            package: &self.package,
            attempt: &self.attempt,
            closure: &self.closure,
            evidence: CommitEvidence {
                principal_snapshot_id: record.principal_snapshot_id,
                forge_event_batch_root: record.forge_event_batch_root,
                policy_decision_root: record.policy_decision_root,
                invariant_evidence_root: record.invariant_evidence_root,
                outbox_effect_root: record.outbox_effect_root,
                retention_delta_root: record.retention_delta_root,
            },
            workspace_epoch_now: self.attempt.workspace_epoch,
        }
    }

    fn historical_request(&self, original_package: bool) -> SemanticRequest {
        let merge = self.intent.merge().unwrap();
        let roots = self.package.roots(&CryptoBodyIdentity).unwrap();
        let event_root =
            evidence_root(&ForgeEventBatch::of_one(self.package.event.clone())).unwrap();
        let mut entries = vec![
            ScopedEntry::new(
                AsciiSlug::from_static("forge"),
                AsciiSlug::from_static("merge.event-batch-root"),
                event_root.bytes().as_bytes(),
            )
            .unwrap(),
        ];
        if original_package {
            entries.extend([
                ScopedEntry::new(
                    AsciiSlug::from_static("forge"),
                    AsciiSlug::from_static("merge.ref-intent-root"),
                    roots.ref_intent_root.bytes().as_bytes(),
                )
                .unwrap(),
                ScopedEntry::new(
                    AsciiSlug::from_static("forge"),
                    AsciiSlug::from_static("merge.workspace-epoch"),
                    self.attempt.workspace_epoch.get().to_be_bytes(),
                )
                .unwrap(),
            ]);
        }
        SemanticRequest::build(
            fgit_authority::RECEIVE_ADMISSION_SCHEMA,
            self.context.object_format,
            true,
            vec![RefCommand {
                name: merge.target_ref.clone(),
                expected_old: ExpectedOld::Exactly(merge.target_tip_before),
                proposed_new: ProposedNew::Update(merge.merge_commit),
                force: false,
            }],
            Vec::new(),
            entries,
        )
        .unwrap()
    }
}

#[test]
fn unbound_native_and_original_package_keep_their_historical_canonical_request_bytes() {
    let fixture = Fixture::new();
    assert_eq!(fixture.intent.workspace_snapshot_digest(), None);
    let native = fixture.intent.seal_attempt(&fixture.context).unwrap();
    let original = seal_attempt_for(&fixture.context, &fixture.sealed()).unwrap();
    assert_eq!(
        encode_body(&native.request).unwrap(),
        encode_body(&fixture.historical_request(false)).unwrap()
    );
    assert_eq!(
        encode_body(&original.request).unwrap(),
        encode_body(&fixture.historical_request(true)).unwrap()
    );
    assert_eq!(native.request.scoped_entries().len(), 1);
    assert_eq!(original.request.scoped_entries().len(), 3);
}

#[test]
fn workspace_digest_changes_identity_and_identical_retries_keep_exact_bytes() {
    let fixture = Fixture::new();
    let bound = fixture.intent.clone().with_workspace_snapshot([5; 32]);
    assert_eq!(bound.workspace_snapshot_digest(), Some([5; 32]));
    let first = bound.seal_attempt(&fixture.context).unwrap();
    let retry = bound.seal_attempt(&fixture.context).unwrap();
    let changed = fixture
        .intent
        .clone()
        .with_workspace_snapshot([6; 32])
        .seal_attempt(&fixture.context)
        .unwrap();
    let original = fixture.intent.seal_attempt(&fixture.context).unwrap();
    assert_eq!(
        encode_body(&first.request).unwrap(),
        encode_body(&retry.request).unwrap()
    );
    assert_eq!(first.derive().unwrap(), retry.derive().unwrap());
    assert_ne!(first.derive().unwrap().0, original.derive().unwrap().0);
    assert_ne!(first.derive().unwrap().0, changed.derive().unwrap().0);
    assert_eq!(fixture.intent.workspace_snapshot_digest(), None);
}

#[test]
fn explicit_original_package_binding_preserves_every_original_scoped_entry() {
    let fixture = Fixture::new();
    let original = seal_attempt_for(&fixture.context, &fixture.sealed()).unwrap();
    let bound = workspace_seal_attempt_for(&fixture.context, &fixture.sealed(), [7; 32]).unwrap();
    let changed = workspace_seal_attempt_for(&fixture.context, &fixture.sealed(), [8; 32]).unwrap();
    assert_eq!(
        bound.request.scoped_entries().len(),
        original.request.scoped_entries().len() + 1
    );
    for entry in original.request.scoped_entries() {
        assert!(bound.request.scoped_entries().contains(entry));
    }
    let workspace = bound
        .request
        .scoped_entries()
        .iter()
        .find(|entry| entry.namespace == AsciiSlug::from_static("treefs"))
        .unwrap();
    assert_eq!(
        workspace.key,
        AsciiSlug::from_static("merge.workspace-snapshot-digest")
    );
    assert_eq!(workspace.value, [7; 32]);
    assert_eq!(
        bound.request.ref_commands(),
        original.request.ref_commands()
    );
    assert_eq!(
        bound.request.push_options(),
        original.request.push_options()
    );
    assert_eq!(
        bound.request.request_schema(),
        original.request.request_schema()
    );
    assert_eq!(bound.request.atomic(), original.request.atomic());
    assert_eq!(bound.tenant_id, original.tenant_id);
    assert_eq!(bound.repository_id, original.repository_id);
    assert_eq!(
        bound.authenticated_principal_id,
        original.authenticated_principal_id
    );
    assert_eq!(bound.idempotency_key, original.idempotency_key);
    assert_ne!(bound.derive().unwrap().0, original.derive().unwrap().0);
    assert_ne!(bound.derive().unwrap().0, changed.derive().unwrap().0);
    assert_eq!(
        encode_body(
            &seal_attempt_for(&fixture.context, &fixture.sealed())
                .unwrap()
                .request
        )
        .unwrap(),
        encode_body(&original.request).unwrap()
    );
}
