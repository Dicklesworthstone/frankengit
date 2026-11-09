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

pub(super) fn sponsored(fixture: &Fixture) -> AdmissionAuthentication {
    use fgit_admission::evidence::AgentAuthentication;
    use fgit_forge::event::agent_credential::{AgentCredentialId, SponsorKind};
    AdmissionAuthentication::AgentCredential(
        AgentAuthentication::try_new(
            fixture.context.principal_id,
            PrincipalId::from_bytes([4; 16]),
            SponsorKind::Human,
            AgentCredentialId::try_new([5; 32]).unwrap(),
            digest(6),
            [7; 32],
            100,
            200,
        )
        .unwrap(),
    )
}

pub(super) fn declared_agent_fixture(revoked: bool) -> Fixture {
    use fgit_codec::{CanonicalForgePositionState, CanonicalOutboxState, ForgePositionStateEntry};
    use fgit_forge::event::agent_credential::{
        AgentCredentialAction, AgentCredentialCommand, AgentCredentialGrant, AgentCredentialId,
        ISSUES_WRITE, SponsorKind,
    };
    let mut fixture = Fixture::new();
    let id = AgentCredentialId::try_new([5; 32]).unwrap();
    let grant = AgentCredentialGrant {
        agent: fixture.context.principal_id,
        sponsor: PrincipalId::from_bytes([4; 16]),
        sponsor_kind: SponsorKind::Human,
        tenant: fixture.context.tenant_id,
        repository: fixture.context.repository_id,
        incarnation: fgit_types::RepositoryIncarnationId::from_bytes([8; 16]),
        issued_at: 100,
        expires_at: 200,
        operations: ISSUES_WRITE,
    };
    let mut events = vec![
        AgentCredentialCommand {
            id,
            expected_version: ExpectedVersion::NewStream,
            action: AgentCredentialAction::Issue(grant),
        }
        .proposed_event(grant.sponsor)
        .unwrap(),
    ];
    if revoked {
        events.push(
            AgentCredentialCommand {
                id,
                expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
                action: AgentCredentialAction::Revoke(grant),
            }
            .proposed_event(grant.sponsor)
            .unwrap(),
        );
    }
    let count = u32::try_from(events.len()).unwrap();
    let root = fixture
        .store
        .stage(
            fixture.context.repository_id,
            EVENT_NAMESPACE,
            &ForgeEventBatch { events },
        )
        .unwrap();
    let label = fgit_forge::AggregateId::AgentCredential(id).to_string();
    let positions = CanonicalForgePositionState::try_new(
        fixture.context.repository_id,
        vec![
            ForgePositionStateEntry::try_new(
                AsciiSlug::try_new("agent", label.as_bytes()).unwrap(),
                0,
                count,
                root,
            )
            .unwrap(),
        ],
    )
    .unwrap();
    fixture.genesis.forge_position_root = fixture
        .store
        .stage(
            fixture.context.repository_id,
            POSITION_NAMESPACE,
            &positions,
        )
        .unwrap();
    fixture.genesis.outbox_root = fixture
        .store
        .stage(
            fixture.context.repository_id,
            delivery::OUTBOX_NAMESPACE,
            &CanonicalOutboxState::try_new(fixture.context.repository_id, Vec::new()).unwrap(),
        )
        .unwrap();
    fixture.context.head_key = HeadKey::new(b"declared-agent/head".to_vec()).unwrap();
    initialize_repository(
        &fixture.store.backend,
        &fixture.context.head_key,
        &fixture.genesis,
    )
    .unwrap();
    fixture
}

#[test]
fn canonical_agent_role_cannot_be_downgraded_by_any_legacy_method_after_revocation() {
    use fgit_admission::merge::native::{protection, pull_request::reviews};
    use fgit_forge::event::review::{ReviewCommand, ReviewDecision, ReviewSubject};
    for revoked in [false, true] {
        for authentication in METHODS {
            let fixture = declared_agent_fixture(revoked);
            let before = fixture.head();
            let projection = AuthenticationProjection {
                inner: fixture.projection(&fixture.context),
                context: fixture.context.clone(),
                authentication,
                preparation_available: false,
            };
            let merged = poll_ready(admit_native_merge_async(
                fixture.store.as_ref(),
                &(),
                &fixture.context,
                &fixture.intent,
                AdmissionLimits::default(),
                &projection,
            ))
            .unwrap();
            assert!(matches!(
                merged.outcome,
                DecisionOutcome::Refused {
                    code: RefusalCode::CapabilityScopeViolation,
                    ..
                }
            ));

            let mut review_context = fixture.context.clone();
            review_context.idempotency_key =
                IdempotencyKey::new(b"declared-agent-review".to_vec()).unwrap();
            let merge = fixture.intent.merge().unwrap();
            let command = ReviewCommand {
                expected_version: ExpectedVersion::NewStream,
                subject: ReviewSubject {
                    pull_request: PullRequestNumber::FIRST,
                    pull_request_version: AggregateVersion::FIRST,
                    source_ref: merge.source_ref.clone(),
                    target_ref: merge.target_ref.clone(),
                    source_tip: merge.source_tip,
                    target_tip: merge.target_tip_before,
                    policy_epoch: PolicyEpoch::FIRST,
                },
                decision: ReviewDecision::Approve,
                reason: String::new(),
            };
            let review_projection = AuthenticationProjection {
                inner: fixture.projection(&review_context),
                context: review_context.clone(),
                authentication,
                preparation_available: false,
            };
            let reviewed = poll_ready(reviews::admit_review_async(
                fixture.store.as_ref(),
                &(),
                &review_context,
                &command,
                AdmissionLimits::default(),
                &review_projection,
            ))
            .unwrap();
            assert!(matches!(
                reviewed.outcome,
                DecisionOutcome::Refused {
                    code: RefusalCode::CapabilityScopeViolation,
                    ..
                }
            ));

            let basis = PublicationBasis::new(
                fgit_authority::authority_head_identity(&before).unwrap(),
                before.clone(),
            );
            let refs: CanonicalRefState = fixture
                .store
                .read(
                    fixture.context.repository_id,
                    REF_NAMESPACE,
                    before.ref_root,
                )
                .unwrap();
            let attempt = fixture.intent.seal_attempt(&fixture.context).unwrap();
            let (tx_id, seal) = attempt.derive().unwrap();
            let request = TransactionRequest {
                tx_id,
                tenant: fixture.context.tenant_id,
                repository: fixture.context.repository_id,
                principal: fixture.context.principal_id,
                schema: attempt.request.request_schema(),
                idempotency_key: ModelKey::new(AsciiSlug::from_static("test")),
                canonical_request_digest: seal.canonical_request_digest,
                statements: Vec::new(),
                promised_closure: BTreeSet::new(),
                atomic: true,
                durability: DurabilityProfile::CanonicalSource,
            };
            let fold = fgit_txn::IntentEvaluator::new().evaluate(
                FoldBasis {
                    refs: refs.refs(),
                    forge_positions: &BTreeMap::new(),
                    retention: &BTreeSet::new(),
                    outbox: &BTreeMap::new(),
                },
                &request,
            );
            let direct = match authentication {
                Some(authentication) => {
                    poll_ready(protection::direct_decision_evidence_with_authentication_at(
                        fixture.store.as_ref(),
                        &(),
                        &fixture.context,
                        &basis,
                        &refs,
                        RootLayoutVersion::LegacyWholeBody,
                        &request,
                        &fold,
                        authentication,
                        &|| false,
                    ))
                }
                None => poll_ready(protection::direct_decision_evidence_at(
                    fixture.store.as_ref(),
                    &(),
                    &fixture.context,
                    &basis,
                    &refs,
                    RootLayoutVersion::LegacyWholeBody,
                    &request,
                    &fold,
                    &|| false,
                )),
            };
            assert!(matches!(
                direct,
                Err(ProjectionFailure::Refuse(
                    RefusalCode::CapabilityScopeViolation
                ))
            ));
            let after = fixture.head();
            assert_eq!(after.ref_root, before.ref_root);
            assert_eq!(after.forge_position_root, before.forge_position_root);
            assert_eq!(after.outbox_root, before.outbox_root);
            assert_eq!(after.retention_root, before.retention_root);
        }
    }
}

#[test]
fn sponsored_agent_cannot_merge_without_protection_and_terminal_recovery_still_wins() {
    let fixture = Fixture::new();
    let before = fixture.head();
    let submit_merge = |authentication, preparation_available| {
        poll_ready(admit_native_merge_async(
            fixture.store.as_ref(),
            &(),
            &fixture.context,
            &fixture.intent,
            AdmissionLimits::default(),
            &AuthenticationProjection {
                inner: fixture.projection(&fixture.context),
                context: fixture.context.clone(),
                authentication,
                preparation_available,
            },
        ))
        .unwrap()
    };
    // No review-protection stream exists, and preparation is unavailable.
    // The canonical driver must still refuse before any candidate work.
    let refused = submit_merge(Some(sponsored(&fixture)), false);
    assert!(matches!(
        refused.outcome,
        DecisionOutcome::Refused {
            code: RefusalCode::CapabilityScopeViolation,
            ..
        }
    ));
    let after = fixture.head();
    assert_eq!(after.ref_root, before.ref_root);
    assert_eq!(after.forge_position_root, before.forge_position_root);
    assert_eq!(after.outbox_root, before.outbox_root);
    assert_eq!(after.retention_root, before.retention_root);
    for method in METHODS {
        assert_eq!(submit_merge(method, false), refused);
        assert_eq!(fixture.head(), after);
    }

    let permitted = Fixture::new();
    let terminal = poll_ready(admit_native_merge_async(
        permitted.store.as_ref(),
        &(),
        &permitted.context,
        &permitted.intent,
        AdmissionLimits::default(),
        &AuthenticationProjection {
            inner: permitted.projection(&permitted.context),
            context: permitted.context.clone(),
            authentication: Some(AdmissionAuthentication::HttpToken),
            preparation_available: true,
        },
    ))
    .unwrap();
    permitted.assert_committed(terminal);
    // A later agent attempt may recover this same already-decided identity;
    // it does not receive permission for a new merge or rewrite its receipt.
    let replay = poll_ready(admit_native_merge_async(
        permitted.store.as_ref(),
        &(),
        &permitted.context,
        &permitted.intent,
        AdmissionLimits::default(),
        &AuthenticationProjection {
            inner: permitted.projection(&permitted.context),
            context: permitted.context.clone(),
            authentication: Some(sponsored(&permitted)),
            preparation_available: false,
        },
    ))
    .unwrap();
    assert_eq!(replay, terminal);
}

impl fgit_admission::merge::native::pull_request::reviews::ReviewProjection<Model>
    for AuthenticationProjection
{
    async fn validate_review_async<'a>(
        &'a self,
        _: &'a Model,
        _: &'a (),
        _: &'a PublicationBasis,
        _: &'a AuthenticatedHead,
        _: &'a fgit_forge::event::review::ReviewCommand,
        _: Option<fgit_forge::event::review::CandidateBinding>,
    ) -> Result<ValidatedClosure, ProjectionFailure> {
        panic!("a refused sponsored review must never validate a candidate")
    }
}

#[test]
fn sponsored_agent_cannot_cast_review_without_installed_review_protection() {
    use fgit_admission::merge::native::pull_request::reviews;
    use fgit_forge::event::review::{ReviewCommand, ReviewDecision, ReviewSubject};
    let fixture = Fixture::new();
    let merge = fixture.intent.merge().unwrap();
    let command = ReviewCommand {
        expected_version: ExpectedVersion::NewStream,
        subject: ReviewSubject {
            pull_request: PullRequestNumber::FIRST,
            pull_request_version: AggregateVersion::FIRST,
            source_ref: merge.source_ref.clone(),
            target_ref: merge.target_ref.clone(),
            source_tip: merge.source_tip,
            target_tip: merge.target_tip_before,
            policy_epoch: PolicyEpoch::FIRST,
        },
        decision: ReviewDecision::Approve,
        reason: String::new(),
    };
    let before = fixture.head();
    let submit_review = |authentication| {
        poll_ready(reviews::admit_review_async(
            fixture.store.as_ref(),
            &(),
            &fixture.context,
            &command,
            AdmissionLimits::default(),
            &AuthenticationProjection {
                inner: fixture.projection(&fixture.context),
                context: fixture.context.clone(),
                authentication,
                preparation_available: false,
            },
        ))
        .unwrap()
    };
    let refused = submit_review(Some(sponsored(&fixture)));
    assert!(matches!(
        refused.outcome,
        DecisionOutcome::Refused {
            code: RefusalCode::CapabilityScopeViolation,
            ..
        }
    ));
    let after = fixture.head();
    assert_eq!(after.ref_root, before.ref_root);
    assert_eq!(after.forge_position_root, before.forge_position_root);
    assert_eq!(after.outbox_root, before.outbox_root);
    for method in METHODS {
        assert_eq!(submit_review(method), refused);
        assert_eq!(fixture.head(), after);
    }
}

#[test]
fn sponsored_direct_publication_refuses_ref_updates_and_noops_without_protection() {
    use fgit_admission::merge::native::protection;
    let fixture = Fixture::new();
    let head = fixture.head();
    let basis = PublicationBasis::new(
        fgit_authority::authority_head_identity(&head).unwrap(),
        head.clone(),
    );
    let current: CanonicalRefState = fixture
        .store
        .read(fixture.context.repository_id, REF_NAMESPACE, head.ref_root)
        .unwrap();
    let attempt = fixture.intent.seal_attempt(&fixture.context).unwrap();
    let (tx_id, sealed) = attempt.derive().unwrap();
    for with_ref in [false, true] {
        let request = TransactionRequest {
            tx_id,
            tenant: fixture.context.tenant_id,
            repository: fixture.context.repository_id,
            principal: fixture.context.principal_id,
            schema: attempt.request.request_schema(),
            idempotency_key: ModelKey::new(AsciiSlug::from_static("test")),
            canonical_request_digest: sealed.canonical_request_digest,
            statements: if with_ref {
                vec![Statement {
                    intents: vec![Intent::Ref(RefIntent::Update {
                        name: name(b"refs/tags/sponsored"),
                        expected: ExpectedRefState::Absent,
                        new: fixture.intent.merge().unwrap().source_tip,
                        force: false,
                    })],
                    mismatch_policy: MismatchPolicy::TxnAbort,
                }]
            } else {
                Vec::new()
            },
            promised_closure: BTreeSet::new(),
            atomic: true,
            durability: DurabilityProfile::CanonicalSource,
        };
        let fold = fgit_txn::IntentEvaluator::new().evaluate(
            FoldBasis {
                refs: current.refs(),
                forge_positions: &BTreeMap::new(),
                retention: &BTreeSet::new(),
                outbox: &BTreeMap::new(),
            },
            &request,
        );
        let evaluate = |authentication| {
            poll_ready(protection::direct_decision_evidence_with_authentication_at(
                fixture.store.as_ref(),
                &(),
                &fixture.context,
                &basis,
                &current,
                RootLayoutVersion::LegacyWholeBody,
                &request,
                &fold,
                authentication,
                &|| false,
            ))
        };
        assert!(matches!(
            evaluate(sponsored(&fixture)),
            Err(ProjectionFailure::Refuse(
                RefusalCode::CapabilityScopeViolation
            ))
        ));
        evaluate(AdmissionAuthentication::HttpToken)
            .unwrap()
            .verify_decision(&fixture.context, &basis, &request, &fold)
            .unwrap();
        assert_eq!(fixture.head(), head);
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
