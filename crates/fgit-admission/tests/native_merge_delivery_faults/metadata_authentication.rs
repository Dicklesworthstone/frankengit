//! Host-established authentication through the real metadata publication loop.
//! The authority store is the parent's explicitly non-durable reference model;
//! this exercises canonical receipts and retries, not filesystem durability.

use super::*;
use fgit_admission::evidence::{
    AdmissionAuthentication, PolicyDecisionEvidence, PrincipalSnapshotRecord, RefusalEvidence,
};
use fgit_admission::merge::native::issues;
use fgit_forge::event::issue::{IssueAction, IssueCommand};
use fgit_forge::{AggregateVersion, IssueNumber};

const PRINCIPAL_NAMESPACE: &[u8] = b"frankengit/admission/principal-snapshot/v1/";
const POLICY_NAMESPACE: &[u8] = b"frankengit/admission/policy-decision/v1/";
const REFUSAL_NAMESPACE: &[u8] = b"frankengit/admission/refusal-evidence/v1/";
const METHODS: [Option<AdmissionAuthentication>; 4] = [
    None,
    Some(AdmissionAuthentication::OperatorAssertion),
    Some(AdmissionAuthentication::HttpToken),
    Some(AdmissionAuthentication::SshDeployKey),
];

struct AuthenticationProjection {
    inner: Projection,
    context: AdmissionContext,
    authentication: Option<AdmissionAuthentication>,
    preparation_available: bool,
}

impl AsyncAdmissionProjection<Model> for AuthenticationProjection {
    async fn snapshot_async<'a>(
        &'a self,
        store: &'a Model,
        cx: &'a (),
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
    ) -> Result<AdmissionSnapshot, ProjectionFailure> {
        if !self.preparation_available {
            return Err(ProjectionFailure::Unavailable(RefusalCode::EvidenceMissing));
        }
        self.inner
            .snapshot_async(store, cx, basis, authenticated)
            .await
    }

    async fn materialize_commit_async<'a>(
        &'a self,
        store: &'a Model,
        cx: &'a (),
        basis: &'a PublicationBasis,
        request: &'a TransactionRequest,
        fold: &'a fgit_txn::TransactionFoldReport,
        closure: &'a ValidatedClosure,
    ) -> Result<CommitMaterialization, ProjectionFailure> {
        self.inner
            .materialize_commit_async(store, cx, basis, request, fold, closure)
            .await
    }

    async fn materialize_refusal_async<'a>(
        &'a self,
        store: &'a Model,
        cx: &'a (),
        basis: &'a PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
    ) -> Result<RefusalMaterialization, ProjectionFailure> {
        let Some(authentication) = self.authentication else {
            return self
                .inner
                .materialize_refusal_async(store, cx, basis, tx_id, code)
                .await;
        };
        let bodies = RefusalEvidenceBodies::derive_with_authentication(
            &self.context,
            basis,
            tx_id,
            code,
            authentication,
        )
        .map_err(ProjectionFailure::Unavailable)?;
        store
            .stage_principal_snapshot(self.context.repository_id, bodies.principal_snapshot())
            .map_err(ProjectionFailure::Unavailable)?;
        Ok(RefusalMaterialization {
            policy_epoch: basis.body().policy_epoch,
            detail: format!("authenticated metadata model refusal: {code:?}"),
            evidence_root: store
                .stage(
                    self.context.repository_id,
                    REFUSAL_NAMESPACE,
                    bodies.refusal_evidence(),
                )
                .map_err(ProjectionFailure::Unavailable)?,
        })
    }
}

impl NativeMergeProjection<Model> for AuthenticationProjection {
    fn admission_authentication(&self) -> Option<AdmissionAuthentication> {
        self.authentication
    }

    async fn resolve_merge_basis_async<'a>(
        &'a self,
        store: &'a Model,
        cx: &'a (),
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
    ) -> Result<NativeMergeBasis, ProjectionFailure> {
        self.inner
            .resolve_merge_basis_async(store, cx, basis, authenticated)
            .await
    }

    async fn validate_merge_async<'a>(
        &'a self,
        store: &'a Model,
        cx: &'a (),
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
        intent: &'a NativeMergeIntent,
    ) -> Result<ValidatedClosure, ProjectionFailure> {
        self.inner
            .validate_merge_async(store, cx, basis, authenticated, intent)
            .await
    }
}

fn submit(
    fixture: &Fixture,
    command: &IssueCommand,
    authentication: Option<AdmissionAuthentication>,
    preparation_available: bool,
) -> TerminalOutcome {
    poll_ready(issues::admit_issue_async(
        fixture.store.as_ref(),
        &(),
        &fixture.context,
        command,
        AdmissionLimits::default(),
        &AuthenticationProjection {
            inner: fixture.projection(&fixture.context),
            context: fixture.context.clone(),
            authentication,
            preparation_available,
        },
    ))
    .unwrap()
}

fn read_principal(fixture: &Fixture, id: PrincipalSnapshotId) -> PrincipalSnapshotRecord {
    let identity = id.as_internal_object_id();
    let root = Digest::new(identity.algorithm(), *identity.digest());
    let ImmutableRead::Present(frame) = fixture
        .store
        .backend
        .read_immutable(&key(
            PRINCIPAL_NAMESPACE,
            fixture.context.repository_id,
            root,
        ))
        .unwrap()
    else {
        panic!("a terminal decision must stage its principal receipt");
    };
    let snapshot = PrincipalSnapshotRecord::decode(&frame, DecodeLimits::DEFAULT).unwrap();
    assert_eq!(snapshot.id().unwrap(), id);
    snapshot
}

fn replay_with_other_methods(fixture: &Fixture, command: &IssueCommand, original: TerminalOutcome) {
    let head = fixture.head();
    let publications = fixture.store.publications.lock().unwrap().len();
    for authentication in METHODS {
        // The current basis is deliberately unavailable. The original outcome
        // and its receipt must resolve before any attempt at fresh preparation.
        assert_eq!(submit(fixture, command, authentication, false), original);
        assert_eq!(fixture.head(), head);
        assert_eq!(
            fixture.store.publications.lock().unwrap().len(),
            publications
        );
    }
}

#[test]
fn metadata_commits_record_each_method_without_changing_the_seal_or_forge_effects() {
    let command = IssueCommand {
        number: IssueNumber::FIRST,
        expected_version: ExpectedVersion::NewStream,
        action: IssueAction::Open {
            title: "Authentication accompanies metadata".into(),
            body: "The issue command has the same meaning under every method.".into(),
            labels: Vec::new(),
        },
    };
    let mut original_seal = None;
    let mut principal_ids = BTreeSet::new();
    let mut policy_roots = BTreeSet::new();
    let mut invariant_roots = BTreeSet::new();
    let mut event_roots = BTreeSet::new();
    for authentication in METHODS {
        let fixture = Fixture::new();
        let seal = issues::proposal(&fixture.context, &command).unwrap().1;
        let (tx, sealed) = seal.derive().unwrap();
        assert_eq!(original_seal.get_or_insert_with(|| seal.clone()), &seal);
        let terminal = submit(&fixture, &command, authentication, true);
        assert!(matches!(
            terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert_eq!(fixture.outcome(tx), OutcomeLookup::Decided(terminal));
        let after = fixture.head();
        assert_eq!(after.ref_root, fixture.genesis.ref_root);
        assert_eq!(after.retention_root, fixture.genesis.retention_root);
        assert_eq!(after.policy_epoch, fixture.genesis.policy_epoch);
        assert_ne!(
            after.forge_position_root,
            fixture.genesis.forge_position_root
        );
        assert_ne!(after.outbox_root, fixture.genesis.outbox_root);
        let batch =
            read_decision_batch_body(&fixture.store.backend, after.decision_tail_id.unwrap())
                .unwrap();
        let [record] = batch.committed_rcrs.as_slice() else {
            panic!("one metadata command must publish one commit record");
        };
        assert_eq!(record.tx_id, tx);
        assert_eq!(
            record.canonical_request_digest,
            sealed.canonical_request_digest
        );
        assert_eq!(
            read_principal(&fixture, record.principal_snapshot_id).authentication(),
            authentication
        );
        // Metadata remains in its existing policy-evidence schema. Merely
        // recording authentication must not activate reference-policy checks.
        let _: PolicyDecisionEvidence = fixture
            .store
            .read(
                fixture.context.repository_id,
                POLICY_NAMESPACE,
                record.policy_decision_root,
            )
            .unwrap();
        principal_ids.insert(record.principal_snapshot_id);
        policy_roots.insert(record.policy_decision_root);
        invariant_roots.insert(record.invariant_evidence_root);
        event_roots.insert(record.forge_event_batch_root);
        replay_with_other_methods(&fixture, &command, terminal);
    }
    assert_eq!(principal_ids.len(), METHODS.len());
    assert_eq!(policy_roots.len(), METHODS.len());
    assert_eq!(invariant_roots.len(), 1);
    assert_eq!(event_roots.len(), 1);
}

#[test]
fn metadata_refusals_retain_the_original_host_receipt_across_method_changes() {
    let command = IssueCommand {
        number: IssueNumber::FIRST,
        expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
        action: IssueAction::Close,
    };
    let mut evidence_roots = BTreeSet::new();
    for authentication in METHODS {
        let fixture = Fixture::new();
        let seal = issues::proposal(&fixture.context, &command).unwrap().1;
        let tx = seal.derive().unwrap().0;
        let before = fixture.head();
        let basis = PublicationBasis::new(
            fgit_authority::authority_head_identity(&before).unwrap(),
            before.clone(),
        );
        let terminal = submit(&fixture, &command, authentication, true);
        let DecisionOutcome::Refused {
            code,
            refusal_record_id,
        } = terminal.outcome
        else {
            panic!("closing an absent issue must refuse");
        };
        let expected = match authentication {
            Some(authentication) => RefusalEvidenceBodies::derive_with_authentication(
                &fixture.context,
                &basis,
                tx,
                code,
                authentication,
            ),
            None => RefusalEvidenceBodies::derive(&fixture.context, &basis, tx, code),
        }
        .unwrap();
        let ImmutableRead::Present(frame) = fixture
            .store
            .backend
            .read_immutable(
                &fgit_authority::body_key_for_id(refusal_record_id.as_internal_object_id())
                    .unwrap(),
            )
            .unwrap()
        else {
            panic!("a terminal refusal must stage its record");
        };
        let record =
            decode_body::<fgit_codec::RefusalRecordBody>(&frame, DecodeLimits::DEFAULT).unwrap();
        assert_eq!(record.tx_id, tx);
        assert_eq!(
            record.evidence_root,
            evidence_root(expected.refusal_evidence()).unwrap()
        );
        let recorded: RefusalEvidence = fixture
            .store
            .read(
                fixture.context.repository_id,
                REFUSAL_NAMESPACE,
                record.evidence_root,
            )
            .unwrap();
        assert_eq!(&recorded, expected.refusal_evidence());
        let principal_id = expected.principal_snapshot().id().unwrap();
        assert_eq!(
            read_principal(&fixture, principal_id).authentication(),
            authentication
        );
        evidence_roots.insert(record.evidence_root);
        let after = fixture.head();
        assert_eq!(after.ref_root, before.ref_root);
        assert_eq!(after.forge_position_root, before.forge_position_root);
        assert_eq!(after.outbox_root, before.outbox_root);
        assert_eq!(after.retention_root, before.retention_root);
        assert_eq!(fixture.outcome(tx), OutcomeLookup::Decided(terminal));
        assert_eq!(
            issues::proposal(&fixture.context, &command).unwrap().1,
            seal
        );
        replay_with_other_methods(&fixture, &command, terminal);
    }
    assert_eq!(evidence_roots.len(), METHODS.len());
}
