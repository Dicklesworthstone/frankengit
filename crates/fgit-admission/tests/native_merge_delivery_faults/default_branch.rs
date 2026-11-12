//! Symbolic HEAD decisions through the real sealed authority/CAS driver and
//! faultable reference store. This is not filesystem crash-durability evidence.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use fgit_admission::default_branch::{self as api, CanonicalHeadChange, DefaultBranchCommand};
use fgit_admission::evidence::AdmissionAuthentication;
use fgit_admission::merge::native::{history, protection};
use fgit_forge::event::protection::{ProtectionCommand, ReviewProtection};

const HEAD_DELTA: &[u8] = b"frankengit/admission/head-delta/v1/";

struct HeadProjection {
    inner: Projection,
    context: AdmissionContext,
    authentication: Option<AdmissionAuthentication>,
    snapshots: AtomicUsize,
    targets: AtomicUsize,
    publication_checks: AtomicUsize,
    cancel_publication: Option<usize>,
    target_failure: Option<RefusalCode>,
}

impl HeadProjection {
    fn new(fixture: &Fixture, context: &AdmissionContext) -> Self {
        Self {
            inner: fixture.projection(context),
            context: context.clone(),
            authentication: Some(AdmissionAuthentication::OperatorAssertion),
            snapshots: AtomicUsize::new(0),
            targets: AtomicUsize::new(0),
            publication_checks: AtomicUsize::new(0),
            cancel_publication: None,
            target_failure: None,
        }
    }
}

fn refs_at(fixture: &Fixture, head: &RepositoryAuthorityHeadBody) -> CanonicalRefState {
    let ImmutableRead::Present(frame) = fixture
        .store
        .backend
        .read_immutable(&key(
            REF_NAMESPACE,
            fixture.context.repository_id,
            head.ref_root,
        ))
        .unwrap()
    else {
        panic!("selected ref state absent")
    };
    decode_body(&frame, DecodeLimits::DEFAULT).unwrap()
}

impl AsyncAdmissionProjection<Model> for HeadProjection {
    async fn snapshot_async<'a>(
        &'a self,
        store: &'a Model,
        _: &'a (),
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
    ) -> Result<AdmissionSnapshot, ProjectionFailure> {
        self.snapshots.fetch_add(1, Ordering::Relaxed);
        assert_eq!(authenticated.body().unwrap(), *basis.body());
        let configuration = store
            .configuration(basis.body().configuration_root)
            .map_err(ProjectionFailure::Unavailable)?;
        let ImmutableRead::Present(frame) = store
            .backend
            .read_immutable(&key(
                REF_NAMESPACE,
                basis.body().repository_id,
                basis.body().ref_root,
            ))
            .unwrap()
        else {
            return Err(ProjectionFailure::Unavailable(RefusalCode::EvidenceMissing));
        };
        let refs = decode_body::<CanonicalRefState>(&frame, DecodeLimits::DEFAULT).unwrap();
        assert_eq!(
            fgit_admission::ref_state_root(configuration.root_layout, &refs).unwrap(),
            basis.body().ref_root
        );
        let mut hidden_refs = RefVisibility::new();
        for rule in &configuration.hidden_ref_rules {
            hidden_refs
                .push_rule(rule, &fgit_wire::WireLimits::default())
                .unwrap();
        }
        Ok(AdmissionSnapshot {
            refs: refs.refs().clone(),
            head_target: refs.head_target().cloned(),
            forge_positions: BTreeMap::new(),
            retention: BTreeSet::new(),
            outbox: BTreeMap::new(),
            hidden_refs,
            tag_peels: BTreeMap::new(),
        })
    }

    async fn materialize_commit_async<'a>(
        &'a self,
        _: &'a Model,
        _: &'a (),
        _: &'a PublicationBasis,
        _: &'a TransactionRequest,
        _: &'a fgit_txn::TransactionFoldReport,
        _: &'a ValidatedClosure,
    ) -> Result<CommitMaterialization, ProjectionFailure> {
        panic!("HEAD must not be lowered to an ordinary direct-ref fold")
    }

    async fn materialize_refusal_async<'a>(
        &'a self,
        store: &'a Model,
        _: &'a (),
        basis: &'a PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
    ) -> Result<RefusalMaterialization, ProjectionFailure> {
        let bodies = match self.authentication {
            Some(authentication) => RefusalEvidenceBodies::derive_with_authentication(
                &self.context,
                basis,
                tx_id,
                code,
                authentication,
            ),
            None => RefusalEvidenceBodies::derive(&self.context, basis, tx_id, code),
        }
        .map_err(ProjectionFailure::Unavailable)?;
        store
            .stage_principal_snapshot(self.context.repository_id, bodies.principal_snapshot())
            .map_err(ProjectionFailure::Unavailable)?;
        Ok(RefusalMaterialization {
            policy_epoch: basis.body().policy_epoch,
            detail: "canonical HEAD model refusal".into(),
            evidence_root: store
                .stage(
                    self.context.repository_id,
                    b"frankengit/admission/refusal-evidence/v1/",
                    bodies.refusal_evidence(),
                )
                .map_err(ProjectionFailure::Unavailable)?,
        })
    }
}

impl NativeMergeProjection<Model> for HeadProjection {
    fn admission_authentication(&self) -> Option<AdmissionAuthentication> {
        self.authentication
    }

    fn merge_publication_checkpoint(&self, _: &()) -> Result<(), RefusalCode> {
        let at = self.publication_checks.fetch_add(1, Ordering::Relaxed) + 1;
        if self.cancel_publication == Some(at) {
            Err(RefusalCode::CancellationInProgress)
        } else {
            Ok(())
        }
    }

    async fn validate_default_branch_target_async<'a>(
        &'a self,
        _: &'a Model,
        _: &'a (),
        _: &'a PublicationBasis,
        _: &'a AuthenticatedHead,
        _: &'a RefName,
        expected_tip: GitOid,
    ) -> Result<(), ProjectionFailure> {
        self.targets.fetch_add(1, Ordering::Relaxed);
        if let Some(code) = self.target_failure {
            return Err(ProjectionFailure::Refuse(code));
        }
        let object =
            self.inner.objects.load(&expected_tip).map_err(|_| {
                ProjectionFailure::Unavailable(RefusalCode::ObjectClosureIncomplete)
            })?;
        if object.object_type() != ObjectType::Commit {
            return Err(ProjectionFailure::Refuse(
                RefusalCode::ObjectClosureIncomplete,
            ));
        }
        assert_eq!(
            git_object_id(
                expected_tip.algorithm(),
                GitObjectKind::Commit,
                object.body()
            ),
            expected_tip
        );
        Ok(())
    }

    async fn validate_merge_async<'a>(
        &'a self,
        _: &'a Model,
        _: &'a (),
        _: &'a PublicationBasis,
        _: &'a AuthenticatedHead,
        _: &'a NativeMergeIntent,
    ) -> Result<ValidatedClosure, ProjectionFailure> {
        panic!("default-branch commands cannot invoke merge validation")
    }
}

fn context(fixture: &Fixture, value: &[u8]) -> AdmissionContext {
    let mut context = fixture.context.clone();
    context.idempotency_key = IdempotencyKey::new(value.to_vec()).unwrap();
    context
}
fn command(fixture: &Fixture) -> DefaultBranchCommand {
    DefaultBranchCommand {
        expected_head: Some(name(b"refs/heads/main")),
        target: name(b"refs/heads/topic"),
        expected_target_tip: fixture.intent.merge().unwrap().source_tip,
    }
}
fn submit(
    fixture: &Fixture,
    context: &AdmissionContext,
    command: &DefaultBranchCommand,
    projection: &HeadProjection,
) -> Result<TerminalOutcome, AdmissionError> {
    poll_ready(api::admit_async(
        fixture.store.as_ref(),
        &(),
        context,
        command,
        AdmissionLimits::default(),
        projection,
    ))
}
fn committed(outcome: TerminalOutcome) {
    assert!(
        matches!(outcome.outcome, DecisionOutcome::Committed { .. }),
        "{outcome:?}"
    );
}
fn refused(outcome: TerminalOutcome, expected: RefusalCode) {
    assert!(
        matches!(outcome.outcome, DecisionOutcome::Refused { code, .. } if code == expected),
        "{outcome:?}"
    );
}

fn configured_fixture(
    format: GitHashAlgorithm,
    layout: RootLayoutVersion,
    old: Option<RefName>,
    hidden: Vec<Vec<u8>>,
) -> Fixture {
    let mut fixture = Fixture::new_for_format(format);
    let previous = refs_at(&fixture, &fixture.genesis);
    let refs = match old {
        Some(target) => {
            CanonicalRefState::new_with_head_target(previous.refs().clone(), target).unwrap()
        }
        None => CanonicalRefState::new(previous.refs().clone()),
    };
    fixture.genesis.ref_root = fgit_admission::ref_state_root(layout, &refs).unwrap();
    assert!(matches!(
        fixture
            .store
            .put(
                &key(
                    REF_NAMESPACE,
                    fixture.context.repository_id,
                    fixture.genesis.ref_root
                ),
                &encode_body(&refs).unwrap()
            )
            .unwrap(),
        PutOutcome::Created | PutOutcome::IdenticalRetry
    ));
    fixture.genesis.configuration_root = fgit_authority::stage_repository_configuration(
        &fixture.store.backend,
        &RepositoryConfigurationBody {
            root_layout: layout,
            object_format: format,
            hidden_ref_rules: hidden,
        },
    )
    .unwrap();
    fixture.context.head_key = HeadKey::new(b"default-branch-configured/head".to_vec()).unwrap();
    initialize_repository(
        &fixture.store.backend,
        &fixture.context.head_key,
        &fixture.genesis,
    )
    .unwrap();
    fixture
}

#[test]
fn default_branch_commits_real_head_delta_preserves_every_other_partition_and_retries_once() {
    for format in GitHashAlgorithm::ALL {
        for layout in [
            RootLayoutVersion::LegacyWholeBody,
            RootLayoutVersion::RefStateMerkleV2,
            RootLayoutVersion::RefStateAndObjectClosureMerkleV2,
        ] {
            for old in [
                None,
                Some(name(b"refs/heads/main")),
                Some(name(b"refs/heads/topic")),
            ] {
                let fixture = configured_fixture(*format, layout, old.clone(), Vec::new());
                let context = context(&fixture, b"default-branch");
                let mut command = command(&fixture);
                command.expected_head = old.clone();
                let projection = HeadProjection::new(&fixture, &context);
                let outcome = submit(&fixture, &context, &command, &projection).unwrap();
                committed(outcome);
                let head = fixture.head();
                let before = refs_at(&fixture, &fixture.genesis);
                let after = refs_at(&fixture, &head);
                assert_eq!(after.head_target(), Some(&command.target));
                assert_eq!(before.refs(), after.refs());
                assert_eq!(
                    head.ref_root == fixture.genesis.ref_root,
                    old.as_ref() == Some(&command.target)
                );
                assert_eq!(
                    (
                        head.forge_position_root,
                        head.outbox_root,
                        head.retention_root,
                        head.policy_epoch,
                        head.configuration_root,
                        head.format_registry_epoch,
                        head.last_checkpoint_id
                    ),
                    (
                        fixture.genesis.forge_position_root,
                        fixture.genesis.outbox_root,
                        fixture.genesis.retention_root,
                        fixture.genesis.policy_epoch,
                        fixture.genesis.configuration_root,
                        fixture.genesis.format_registry_epoch,
                        fixture.genesis.last_checkpoint_id
                    )
                );
                let batch = read_decision_batch_body(
                    &fixture.store.backend,
                    head.decision_tail_id.unwrap(),
                )
                .unwrap();
                let record = &batch.committed_rcrs[0];
                let delta: CanonicalHeadChange = fixture
                    .store
                    .read(context.repository_id, HEAD_DELTA, record.ref_delta_root)
                    .unwrap();
                assert_eq!(record.ref_delta_root, record.invariant_evidence_root);
                delta
                    .verify_transition(
                        &context,
                        &PublicationBasis::new(
                            fgit_authority::authority_head_identity(&fixture.genesis).unwrap(),
                            fixture.genesis.clone(),
                        ),
                        &before,
                        &after,
                        &command,
                        None,
                    )
                    .unwrap();
                assert_eq!(
                    poll_ready(history::verify_record_evidence(
                        fixture.store.as_ref(),
                        &(),
                        context.repository_id,
                        record,
                        &|| false
                    ))
                    .unwrap(),
                    history::OutboxRecordEvidence::Ordinary
                );
                assert!(
                    fixture
                        .store
                        .read::<fgit_admission::evidence::ForgeEventBatch>(
                            context.repository_id,
                            EVENT_NAMESPACE,
                            record.forge_event_batch_root
                        )
                        .unwrap()
                        .is_empty()
                        .unwrap()
                );
                assert_eq!(
                    submit(&fixture, &context, &command, &projection).unwrap(),
                    outcome
                );
                assert_eq!(fixture.head(), head);
                assert_eq!(projection.targets.load(Ordering::Relaxed), 1);
            }
        }
    }
}

#[test]
fn default_branch_stale_missing_and_hidden_targets_refuse_without_native_inspection() {
    for hidden in [
        b"refs/heads/main".to_vec(),
        b"refs/heads/topic".to_vec(),
        b"HEAD".to_vec(),
    ] {
        let fixture = configured_fixture(
            GitHashAlgorithm::Sha1,
            RootLayoutVersion::LegacyWholeBody,
            Some(name(b"refs/heads/main")),
            vec![hidden],
        );
        let context = context(&fixture, b"hidden");
        let projection = HeadProjection::new(&fixture, &context);
        refused(
            submit(&fixture, &context, &command(&fixture), &projection).unwrap(),
            RefusalCode::HiddenRefUnauthorized,
        );
        assert_eq!(projection.targets.load(Ordering::Relaxed), 0);
        assert_eq!(fixture.head().ref_root, fixture.genesis.ref_root);
    }
    for case in 0..3 {
        let fixture = Fixture::new();
        let context = context(&fixture, b"stale");
        let mut command = command(&fixture);
        match case {
            0 => command.expected_head = None,
            1 => command.expected_target_tip = fixture.intent.merge().unwrap().target_tip_before,
            _ => command.target = name(b"refs/heads/absent"),
        }
        let projection = HeadProjection::new(&fixture, &context);
        refused(
            submit(&fixture, &context, &command, &projection).unwrap(),
            RefusalCode::ExpectedOldRefMismatch,
        );
        assert_eq!(projection.targets.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn default_branch_remote_and_declared_agent_provenance_never_reaches_target_intake() {
    for method in [
        None,
        Some(AdmissionAuthentication::HttpToken),
        Some(AdmissionAuthentication::SshDeployKey),
    ] {
        let fixture = Fixture::new();
        let context = context(&fixture, b"not-operator");
        let mut projection = HeadProjection::new(&fixture, &context);
        projection.authentication = method;
        refused(
            submit(&fixture, &context, &command(&fixture), &projection).unwrap(),
            RefusalCode::CapabilityScopeViolation,
        );
        assert_eq!(projection.snapshots.load(Ordering::Relaxed), 0);
    }
    for revoked in [false, true] {
        let fixture = metadata_authentication::declared_agent_fixture(revoked);
        for (index, method) in [
            Some(AdmissionAuthentication::OperatorAssertion),
            Some(metadata_authentication::sponsored(&fixture)),
        ]
        .into_iter()
        .enumerate()
        {
            let context = context(&fixture, format!("declared-{index}").as_bytes());
            let mut projection = HeadProjection::new(&fixture, &context);
            projection.authentication = method;
            refused(
                submit(&fixture, &context, &command(&fixture), &projection).unwrap(),
                RefusalCode::CapabilityScopeViolation,
            );
            assert_eq!(projection.snapshots.load(Ordering::Relaxed), 0);
            assert_eq!(projection.targets.load(Ordering::Relaxed), 0);
        }
    }
}

#[test]
fn default_branch_rejects_historical_v1_and_unvalidated_native_commit() {
    for layout in [
        RootLayoutVersion::RefStateMerkleV1,
        RootLayoutVersion::RefStateAndObjectClosureMerkleV1,
    ] {
        let fixture = configured_fixture(
            GitHashAlgorithm::Sha1,
            layout,
            Some(name(b"refs/heads/main")),
            Vec::new(),
        );
        let context = context(&fixture, b"legacy-unauthenticated-head");
        let projection = HeadProjection::new(&fixture, &context);
        refused(
            submit(&fixture, &context, &command(&fixture), &projection).unwrap(),
            RefusalCode::SchemaUnsupported,
        );
        assert_eq!(projection.targets.load(Ordering::Relaxed), 0);
    }
    let fixture = Fixture::new();
    let context = context(&fixture, b"native-refusal");
    let mut projection = HeadProjection::new(&fixture, &context);
    projection.target_failure = Some(RefusalCode::ObjectClosureIncomplete);
    refused(
        submit(&fixture, &context, &command(&fixture), &projection).unwrap(),
        RefusalCode::ObjectClosureIncomplete,
    );
    assert_eq!(fixture.head().ref_root, fixture.genesis.ref_root);
}

#[test]
fn default_branch_cas_loser_rechecks_head_tip_and_preserves_concurrent_real_ref_and_forge_effects()
{
    for race in 0..3 {
        let fixture = Arc::new(Fixture::new());
        let context = context(&fixture, b"default-race");
        let mut command = command(&fixture);
        if race == 2 {
            command.target = name(b"refs/heads/main");
            command.expected_target_tip = fixture.intent.merge().unwrap().target_tip_before;
        }
        let competitor = fixture.clone();
        *fixture.store.before_publish.lock().unwrap() = Some(Box::new(move || {
            if race == 1 {
                let context = self::context(&competitor, b"competing-default");
                committed(
                    submit(
                        &competitor,
                        &context,
                        &self::command(&competitor),
                        &HeadProjection::new(&competitor, &context),
                    )
                    .unwrap(),
                );
            } else {
                committed(competitor.run().unwrap());
            }
        }));
        let projection = HeadProjection::new(&fixture, &context);
        let outcome = submit(&fixture, &context, &command, &projection).unwrap();
        if race == 0 {
            committed(outcome);
            assert_eq!(projection.targets.load(Ordering::Relaxed), 2);
            let head = fixture.head();
            let refs = refs_at(&fixture, &head);
            assert_eq!(refs.head_target(), Some(&name(b"refs/heads/topic")));
            assert_eq!(
                refs.refs().get(&name(b"refs/heads/main")),
                Some(&fixture.intent.merge().unwrap().merge_commit)
            );
            assert_ne!(
                head.forge_position_root,
                fixture.genesis.forge_position_root
            );
            assert_ne!(head.outbox_root, fixture.genesis.outbox_root);
        } else {
            refused(outcome, RefusalCode::ExpectedOldRefMismatch);
            assert_eq!(projection.targets.load(Ordering::Relaxed), 1);
        }
        assert!(
            fixture
                .store
                .publications
                .lock()
                .unwrap()
                .iter()
                .any(|(_, result)| matches!(result, CasOutcome::PredecessorMismatch))
        );
        let tx = api::proposal(&context, &command)
            .unwrap()
            .derive()
            .unwrap()
            .0;
        assert_eq!(fixture.outcome(tx), OutcomeLookup::Decided(outcome));
    }
}

#[test]
fn default_branch_cas_loser_rechecks_new_administrators_before_reinspection() {
    let fixture = Arc::new(Fixture::new());
    let context = context(&fixture, b"admin-race");
    let competitor = fixture.clone();
    *fixture.store.before_publish.lock().unwrap() = Some(Box::new(move || {
        let mut context = self::context(&competitor, b"install-policy");
        context.principal_id = PrincipalId::from_bytes([4; 16]);
        let command = ProtectionCommand {
            expected_version: ExpectedVersion::NewStream,
            expected_epoch: PolicyEpoch::FIRST,
            protection: ReviewProtection {
                administrators: vec![context.principal_id],
                branches: Vec::new(),
                ref_policy: None,
            },
        };
        committed(
            poll_ready(protection::admit_async(
                competitor.store.as_ref(),
                &(),
                &context,
                &command,
                AdmissionLimits::default(),
                &HeadProjection::new(&competitor, &context),
            ))
            .unwrap(),
        );
    }));
    let projection = HeadProjection::new(&fixture, &context);
    refused(
        submit(&fixture, &context, &command(&fixture), &projection).unwrap(),
        RefusalCode::PublicationPolicyRefused,
    );
    assert_eq!(projection.targets.load(Ordering::Relaxed), 1);
    assert_eq!(projection.snapshots.load(Ordering::Relaxed), 1);
    assert_eq!(fixture.head().ref_root, fixture.genesis.ref_root);
}

#[test]
fn default_branch_cancellation_and_staging_crashes_keep_undecided_then_retry_original_seal() {
    for check in [1, 2, 3] {
        let fixture = Fixture::new();
        let context = context(&fixture, b"cancel-head");
        let command = command(&fixture);
        let tx = api::proposal(&context, &command)
            .unwrap()
            .derive()
            .unwrap()
            .0;
        let mut projection = HeadProjection::new(&fixture, &context);
        projection.cancel_publication = Some(check);
        assert!(matches!(
            submit(&fixture, &context, &command, &projection),
            Err(AdmissionError::AsyncProjectionUnavailable(
                RefusalCode::CancellationInProgress
            ))
        ));
        assert_eq!(fixture.head(), fixture.genesis);
        assert_eq!(fixture.outcome(tx), OutcomeLookup::Undecided);
        committed(
            submit(
                &fixture,
                &context,
                &command,
                &HeadProjection::new(&fixture, &context),
            )
            .unwrap(),
        );
    }
    for namespace in [HEAD_DELTA, REF_NAMESPACE] {
        for position in [FaultPosition::BeforeEffect, FaultPosition::AfterEffect] {
            let fixture = Fixture::new();
            let context = context(&fixture, b"staging-head");
            let command = command(&fixture);
            let tx = api::proposal(&context, &command)
                .unwrap()
                .derive()
                .unwrap()
                .0;
            *fixture.store.put_fault.lock().unwrap() = Some(PutFault {
                namespace,
                position,
            });
            assert!(
                submit(
                    &fixture,
                    &context,
                    &command,
                    &HeadProjection::new(&fixture, &context)
                )
                .is_err()
            );
            fixture.store.backend.restart();
            fixture.store.backend.install_fault_plan(FaultPlan::none());
            assert_eq!(fixture.head(), fixture.genesis);
            assert_eq!(fixture.outcome(tx), OutcomeLookup::Undecided);
            committed(
                submit(
                    &fixture,
                    &context,
                    &command,
                    &HeadProjection::new(&fixture, &context),
                )
                .unwrap(),
            );
        }
    }
}

#[test]
fn default_branch_ambiguous_cas_and_key_reuse_preserve_one_terminal_identity() {
    for position in [FaultPosition::BeforeEffect, FaultPosition::AfterEffect] {
        let fixture = Fixture::new();
        let context = context(&fixture, b"crash-head-cas");
        let command = command(&fixture);
        let tx = api::proposal(&context, &command)
            .unwrap()
            .derive()
            .unwrap()
            .0;
        fixture
            .store
            .backend
            .install_fault_plan(FaultPlan::explicit(vec![FaultDirective::nth_of_kind(
                0,
                AuthorityOpKind::CompareExchangeHead,
                FaultKind::Crash { position },
            )]));
        assert!(
            submit(
                &fixture,
                &context,
                &command,
                &HeadProjection::new(&fixture, &context)
            )
            .is_err()
        );
        fixture.store.backend.restart();
        fixture.store.backend.install_fault_plan(FaultPlan::none());
        assert_eq!(
            matches!(fixture.outcome(tx), OutcomeLookup::Decided(_)),
            position == FaultPosition::AfterEffect
        );
        let terminal = submit(
            &fixture,
            &context,
            &command,
            &HeadProjection::new(&fixture, &context),
        )
        .unwrap();
        committed(terminal);
        let head = fixture.head();
        assert_eq!(head.generation, HeadGeneration::FIRST.next().unwrap());
        // A retry can recover its own result after source intake becomes unavailable.
        let mut retired = HeadProjection::new(&fixture, &context);
        retired.authentication = Some(AdmissionAuthentication::HttpToken);
        retired.target_failure = Some(RefusalCode::ObjectClosureIncomplete);
        assert_eq!(
            submit(&fixture, &context, &command, &retired).unwrap(),
            terminal
        );
        assert_eq!(retired.snapshots.load(Ordering::Relaxed), 0);
        let mut changed = command.clone();
        changed.expected_head = None;
        assert!(submit(&fixture, &context, &changed, &retired).is_err());
        assert_eq!(fixture.head(), head);
    }
}
