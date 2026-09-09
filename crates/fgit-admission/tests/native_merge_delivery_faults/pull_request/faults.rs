//! Faultable model-store coverage of the actual asynchronous native PR driver.
//! Cancellation is injected at its projection checkpoints; this is not node
//! request-context or file-backed process-crash evidence.
//! The projection reuses this harness's verified native object graph; it does
//! not exercise the production node's selected-closure adapter.

use std::sync::atomic::{AtomicU8, Ordering};

use super::*;
use fgit_admission::merge::native::pull_request::{
    PullRequestProjection, admit_pull_request_async, proposal,
};

const LIVE: u8 = 0;
const CANCEL_BEFORE_SEAL: u8 = 1;
const CANCEL_BEFORE_PUBLICATION: u8 = 2;

struct PrProjection {
    inner: Projection,
    source_graph: NativeMergeIntent,
    cancellation: AtomicU8,
}

impl PrProjection {
    fn new(fixture: &Fixture) -> Self {
        Self {
            inner: fixture.projection(&fixture.context),
            source_graph: fixture.intent.clone(),
            cancellation: AtomicU8::new(LIVE),
        }
    }
}

impl AsyncAdmissionProjection<Model> for PrProjection {
    fn snapshot_async<'a>(
        &'a self,
        store: &'a Model,
        cx: &'a (),
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
    ) -> impl Future<Output = Result<AdmissionSnapshot, ProjectionFailure>> + Send + 'a {
        self.inner.snapshot_async(store, cx, basis, authenticated)
    }
    fn materialize_commit_async<'a>(
        &'a self,
        store: &'a Model,
        cx: &'a (),
        basis: &'a PublicationBasis,
        request: &'a TransactionRequest,
        fold: &'a fgit_txn::TransactionFoldReport,
        closure: &'a ValidatedClosure,
    ) -> impl Future<Output = Result<CommitMaterialization, ProjectionFailure>> + Send + 'a {
        self.inner
            .materialize_commit_async(store, cx, basis, request, fold, closure)
    }
    fn materialize_refusal_async<'a>(
        &'a self,
        store: &'a Model,
        cx: &'a (),
        basis: &'a PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
    ) -> impl Future<Output = Result<RefusalMaterialization, ProjectionFailure>> + Send + 'a {
        self.inner
            .materialize_refusal_async(store, cx, basis, tx_id, code)
    }
}

impl NativeMergeProjection<Model> for PrProjection {
    fn merge_checkpoint(&self, _: &()) -> Result<(), RefusalCode> {
        if self.cancellation.load(Ordering::SeqCst) == CANCEL_BEFORE_SEAL {
            Err(RefusalCode::CancellationInProgress)
        } else {
            Ok(())
        }
    }
    fn merge_publication_checkpoint(&self, cx: &()) -> Result<(), RefusalCode> {
        self.merge_checkpoint(cx)?;
        if self.cancellation.load(Ordering::SeqCst) == CANCEL_BEFORE_PUBLICATION {
            Err(RefusalCode::CancellationInProgress)
        } else {
            Ok(())
        }
    }
    fn resolve_merge_basis_async<'a>(
        &'a self,
        store: &'a Model,
        cx: &'a (),
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
    ) -> impl Future<Output = Result<NativeMergeBasis, ProjectionFailure>> + Send + 'a {
        self.inner
            .resolve_merge_basis_async(store, cx, basis, authenticated)
    }
    fn validate_merge_async<'a>(
        &'a self,
        store: &'a Model,
        cx: &'a (),
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
        intent: &'a NativeMergeIntent,
    ) -> impl Future<Output = Result<ValidatedClosure, ProjectionFailure>> + Send + 'a {
        self.inner
            .validate_merge_async(store, cx, basis, authenticated, intent)
    }
}

impl PullRequestProjection<Model> for PrProjection {
    fn validate_pull_request_async<'a>(
        &'a self,
        _: &'a Model,
        _: &'a (),
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
        command: &'a PullRequestCommand,
    ) -> impl Future<Output = Result<ValidatedClosure, ProjectionFailure>> + Send + 'a {
        std::future::ready((|| {
            let selected = self.inner.resolved_basis(basis, authenticated)?;
            if selected.refs.refs().get(&command.data.source_ref) != Some(&command.data.source_tip)
                || selected.refs.refs().get(&command.data.target_ref)
                    != Some(&command.data.target_tip)
            {
                return Err(ProjectionFailure::Refuse(RefusalCode::TargetRefMoved));
            }
            let merge = self.source_graph.merge().unwrap();
            let mut closure = validate_merge_objects(
                self.inner.objects.as_ref(),
                merge,
                MergeObjectLimits::default(),
                &mut || true,
            )?;
            // The reused fixture has two selected branch tips plus one
            // unselected candidate whose only parents are those tips. Native
            // traversal verified every dependency; excluding that candidate
            // leaves exactly the selected parents' closure for metadata work.
            assert!(closure.objects.remove(&merge.merge_commit));
            assert!(closure.objects.contains(&command.data.source_tip));
            assert!(closure.objects.contains(&command.data.target_tip));
            closure.object_closure_root = fgit_admission::permitted_object_closure_root(
                &PermittedObjectClosure::new(closure.objects.clone()),
            )
            .map_err(ProjectionFailure::Unavailable)?;
            Ok(closure)
        })())
    }
}

struct PrFixture {
    fixture: Fixture,
    command: PullRequestCommand,
    projection: PrProjection,
}

impl PrFixture {
    fn new(format: GitHashAlgorithm, action: PullRequestAction) -> Self {
        let mut fixture = Fixture::new_for_format(format);
        fixture.context.idempotency_key = IdempotencyKey::new(b"native-pr-open".to_vec()).unwrap();
        let merge = fixture.intent.merge().unwrap();
        let mut command = PullRequestCommand {
            number: PullRequestNumber::FIRST,
            expected_version: ExpectedVersion::NewStream,
            action: PullRequestAction::Open,
            data: PullRequestData {
                source_ref: merge.source_ref.clone(),
                target_ref: merge.target_ref.clone(),
                source_tip: merge.source_tip,
                target_tip: merge.target_tip_before,
                title: "Native PR under authority faults".into(),
                body: "Untrusted metadata".into(),
            },
        };
        if action != PullRequestAction::Open {
            let projection = PrProjection::new(&fixture);
            let opened = poll_ready(admit_pull_request_async(
                fixture.store.as_ref(),
                &(),
                &fixture.context,
                &command,
                AdmissionLimits::default(),
                &projection,
            ))
            .unwrap();
            assert!(matches!(opened.outcome, DecisionOutcome::Committed { .. }));
            command.expected_version =
                ExpectedVersion::Exactly(fgit_forge::AggregateVersion::FIRST);
            command.action = action;
            if action == PullRequestAction::Update {
                command.data.body.push_str("\nUpdated metadata");
            }
            fixture.context.idempotency_key =
                IdempotencyKey::new(format!("native-pr-{action:?}").into_bytes()).unwrap();
        }
        let projection = PrProjection::new(&fixture);
        Self {
            fixture,
            command,
            projection,
        }
    }
    fn with_key(&self, key: &[u8]) -> Self {
        let mut context = self.fixture.context.clone();
        context.idempotency_key = IdempotencyKey::new(key.to_vec()).unwrap();
        let fixture = Fixture {
            store: self.fixture.store.clone(),
            objects: self.fixture.objects.clone(),
            context,
            intent: self.fixture.intent.clone(),
            genesis: self.fixture.genesis.clone(),
        };
        let projection = PrProjection::new(&fixture);
        Self {
            fixture,
            command: self.command.clone(),
            projection,
        }
    }
    fn run(&self) -> Result<TerminalOutcome, AdmissionError> {
        poll_ready(admit_pull_request_async(
            self.fixture.store.as_ref(),
            &(),
            &self.fixture.context,
            &self.command,
            AdmissionLimits::default(),
            &self.projection,
        ))
    }
    fn tx_id(&self) -> TxId {
        proposal(&self.fixture.context, &self.command)
            .unwrap()
            .1
            .derive()
            .unwrap()
            .0
    }
    fn event_root(&self) -> Digest {
        let event = proposal(&self.fixture.context, &self.command).unwrap().0;
        evidence_root(&ForgeEventBatch::of_one(event)).unwrap()
    }
    fn assert_committed(
        &self,
        before: &RepositoryAuthorityHeadBody,
        terminal: TerminalOutcome,
    ) -> RepositoryAuthorityHeadBody {
        assert!(
            matches!(terminal.outcome, DecisionOutcome::Committed { .. }),
            "{terminal:?}"
        );
        let head = self.fixture.head();
        assert_eq!(head.generation, before.generation.next().unwrap());
        assert_eq!(head.ref_root, before.ref_root);
        assert_eq!(head.retention_root, before.retention_root);
        assert_ne!(head.forge_position_root, before.forge_position_root);
        assert_ne!(head.outbox_root, before.outbox_root);
        let (refs, delivery) = selected_state(&self.fixture);
        let old_refs: CanonicalRefState = self
            .fixture
            .store
            .read(
                self.fixture.context.repository_id,
                REF_NAMESPACE,
                before.ref_root,
            )
            .unwrap();
        assert_eq!(
            refs, old_refs,
            "metadata publication preserves every ref and symbolic HEAD"
        );
        let event = proposal(&self.fixture.context, &self.command).unwrap().0;
        assert_eq!(delivery.forge.entries().len(), 1);
        let position = &delivery.forge.entries()[0];
        assert_eq!(position.successor_position(), event.version.get());
        assert_eq!(position.event_batch_root(), self.event_root());
        assert_eq!(
            delivery.outbox.entries().len(),
            usize::try_from(event.version.get()).unwrap()
        );
        let deliveries: Vec<_> = delivery
            .outbox
            .entries()
            .iter()
            .filter(|entry| entry.tx_id() == self.tx_id())
            .collect();
        assert_eq!(
            deliveries.len(),
            1,
            "one delivery belongs to this exact original transaction"
        );
        assert_eq!(deliveries[0].payload_root(), self.event_root());
        let batch =
            read_decision_batch_body(&self.fixture.store.backend, head.decision_tail_id.unwrap())
                .unwrap();
        assert_eq!(batch.committed_rcrs.len(), 1);
        let record = &batch.committed_rcrs[0];
        assert_eq!(record.tx_id, self.tx_id());
        assert_eq!(record.parent_rcr_id, before.latest_committed_rcr_id);
        assert_eq!(record.resulting_ref_root, before.ref_root);
        assert_eq!(record.forge_event_batch_root, self.event_root());
        assert_eq!(
            record.resulting_forge_position_root,
            head.forge_position_root
        );
        assert_eq!(batch.resulting_outbox_root, head.outbox_root);
        let stored: ForgeEventBatch = self
            .fixture
            .store
            .read(
                self.fixture.context.repository_id,
                EVENT_NAMESPACE,
                self.event_root(),
            )
            .unwrap();
        assert_eq!(stored.events, vec![event]);
        assert_eq!(
            self.fixture.outcome(self.tx_id()),
            OutcomeLookup::Decided(terminal)
        );
        head
    }
    fn assert_retry(&self, before: &RepositoryAuthorityHeadBody) -> TerminalOutcome {
        let terminal = self.run().unwrap();
        let after = self.assert_committed(before, terminal);
        assert_eq!(self.run().unwrap(), terminal);
        assert_eq!(self.fixture.head(), after);
        terminal
    }
}

#[test]
fn native_pr_checkpoint_cancellation_retains_old_roots_and_exact_retry() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for action in [
            PullRequestAction::Open,
            PullRequestAction::Update,
            PullRequestAction::Close,
        ] {
            for boundary in [CANCEL_BEFORE_SEAL, CANCEL_BEFORE_PUBLICATION] {
                let case = PrFixture::new(format, action);
                let before = case.fixture.head();
                case.projection
                    .cancellation
                    .store(boundary, Ordering::SeqCst);
                assert!(matches!(
                    case.run(),
                    Err(AdmissionError::AsyncProjectionUnavailable(
                        RefusalCode::CancellationInProgress
                    ))
                ));
                assert_eq!(case.fixture.head(), before);
                assert_eq!(case.fixture.outcome(case.tx_id()), OutcomeLookup::Undecided);
                let stored = case
                    .fixture
                    .store
                    .backend
                    .read_immutable(&key(
                        EVENT_NAMESPACE,
                        case.fixture.context.repository_id,
                        case.event_root(),
                    ))
                    .unwrap();
                assert_eq!(
                    matches!(stored, ImmutableRead::Present(_)),
                    boundary == CANCEL_BEFORE_PUBLICATION
                );
                let seal = poll_ready(fgit_authority::read_seal_async(
                    case.fixture.store.as_ref(),
                    &(),
                    case.fixture.context.tenant_id,
                    case.fixture.context.repository_id,
                    case.tx_id(),
                ))
                .unwrap();
                assert_eq!(seal.is_some(), boundary == CANCEL_BEFORE_PUBLICATION);
                case.projection.cancellation.store(LIVE, Ordering::SeqCst);
                case.assert_retry(&before);
            }
        }
    }
}

#[test]
fn native_pr_interrupted_immutable_stages_remain_unpublished_until_retry() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for action in [
            PullRequestAction::Open,
            PullRequestAction::Update,
            PullRequestAction::Close,
        ] {
            for namespace in [
                EVENT_NAMESPACE,
                POSITION_NAMESPACE,
                delivery::EFFECT_NAMESPACE,
                delivery::OUTBOX_NAMESPACE,
            ] {
                for position in [FaultPosition::BeforeEffect, FaultPosition::AfterEffect] {
                    let case = PrFixture::new(format, action);
                    let before = case.fixture.head();
                    *case.fixture.store.put_fault.lock().unwrap() = Some(PutFault {
                        namespace,
                        position,
                    });
                    assert!(matches!(case.run(), Err(AdmissionError::Authority(_))));
                    let faults = case.fixture.store.backend.fault_log();
                    assert_eq!(faults.records().len(), 1);
                    assert_eq!(faults.records()[0].op_kind, AuthorityOpKind::PutIfAbsent);
                    assert_eq!(
                        faults.records()[0].effect_reached,
                        position == FaultPosition::AfterEffect
                    );
                    assert!(case.fixture.store.backend.is_crashed());
                    case.fixture.store.backend.restart();
                    case.fixture
                        .store
                        .backend
                        .install_fault_plan(FaultPlan::none());
                    let interrupted = case
                        .fixture
                        .store
                        .interrupted_key
                        .lock()
                        .unwrap()
                        .clone()
                        .unwrap();
                    let staged = case
                        .fixture
                        .store
                        .backend
                        .read_immutable(&interrupted)
                        .unwrap();
                    assert_eq!(
                        matches!(staged, ImmutableRead::Present(_)),
                        position == FaultPosition::AfterEffect
                    );
                    assert_eq!(case.fixture.head(), before);
                    assert_eq!(case.fixture.outcome(case.tx_id()), OutcomeLookup::Undecided);
                    case.assert_retry(&before);
                }
            }
        }
    }
}

#[test]
fn native_pr_lost_cas_request_or_response_recovers_the_original_outcome_once() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for action in [
            PullRequestAction::Open,
            PullRequestAction::Update,
            PullRequestAction::Close,
        ] {
            for fault in [FaultKind::LoseRequest, FaultKind::LoseResponse] {
                let case = PrFixture::new(format, action);
                let before = case.fixture.head();
                case.fixture
                    .store
                    .backend
                    .install_fault_plan(FaultPlan::explicit(vec![FaultDirective::nth_of_kind(
                        0,
                        AuthorityOpKind::CompareExchangeHead,
                        fault,
                    )]));
                let first = case.run();
                let Err(AdmissionError::Outcome(error)) = &first else {
                    panic!("lost CAS must report ambiguity: {first:?}");
                };
                let fgit_authority::OutcomeFailure::Seal(error) = error.as_ref() else {
                    panic!("expected authority seal failure: {error:?}");
                };
                assert!(matches!(
                    error.as_ref(),
                    fgit_authority::SealFailure::Store(AuthorityFailure::Ambiguous(_))
                ));
                let faults = case.fixture.store.backend.fault_log();
                assert_eq!(faults.records().len(), 1);
                assert_eq!(faults.records()[0].kind, fault);
                assert_eq!(
                    faults.records()[0].effect_reached,
                    fault == FaultKind::LoseResponse
                );
                let recovered = if fault == FaultKind::LoseRequest {
                    assert_eq!(case.fixture.head(), before);
                    assert_eq!(case.fixture.outcome(case.tx_id()), OutcomeLookup::Undecided);
                    None
                } else {
                    let OutcomeLookup::Decided(terminal) = case.fixture.outcome(case.tx_id())
                    else {
                        panic!("lost response cannot erase committed PR transition");
                    };
                    case.assert_committed(&before, terminal);
                    Some(terminal)
                };
                case.fixture
                    .store
                    .backend
                    .install_fault_plan(FaultPlan::none());
                let retry = case.assert_retry(&before);
                if let Some(recovered) = recovered {
                    assert_eq!(retry, recovered);
                }
            }
        }
    }
}

#[test]
fn native_pr_cas_loser_revalidates_original_version_without_another_forge_effect() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for action in [
            PullRequestAction::Open,
            PullRequestAction::Update,
            PullRequestAction::Close,
        ] {
            let case = PrFixture::new(format, action);
            let competitor = Arc::new(case.with_key(b"native-pr-competing-key"));
            let before = case.fixture.head();
            let initial_publications = case.fixture.store.publications.lock().unwrap().len();
            let observed = Arc::new(Mutex::new(None));
            let competing = competitor.clone();
            let observed_winner = observed.clone();
            let before_winner = before.clone();
            // This hook runs the same production driver immediately before
            // the first caller's actual CAS, after its immutable preparation.
            *case.fixture.store.before_publish.lock().unwrap() = Some(Box::new(move || {
                let terminal = competing.run().unwrap();
                let head = competing.assert_committed(&before_winner, terminal);
                *observed_winner.lock().unwrap() = Some((terminal, head));
            }));
            let loser = case.run().unwrap();
            let (winner, winning_head) = observed.lock().unwrap().clone().unwrap();
            assert!(
                matches!(
                    loser.outcome,
                    DecisionOutcome::Refused {
                        code: RefusalCode::EvidenceStale,
                        ..
                    }
                ),
                "{loser:?}"
            );
            assert_ne!(case.tx_id(), competitor.tx_id());
            assert_ne!(loser.decision_sequence, winner.decision_sequence);
            let publications = case.fixture.store.publications.lock().unwrap().clone();
            let publications = &publications[initial_publications..];
            assert_eq!(publications.len(), 3, "winner CAS, stale CAS, refusal CAS");
            assert!(matches!(publications[0].1, CasOutcome::Committed(_)));
            assert!(matches!(publications[1].1, CasOutcome::PredecessorMismatch));
            assert!(matches!(publications[2].1, CasOutcome::Committed(_)));
            assert_eq!(publications[0].0, publications[1].0);
            assert_ne!(publications[1].0, publications[2].0);

            let head = case.fixture.head();
            assert_eq!(head.generation, winning_head.generation.next().unwrap());
            assert_eq!(head.ref_root, before.ref_root);
            assert_eq!(head.ref_root, winning_head.ref_root);
            assert_eq!(head.forge_position_root, winning_head.forge_position_root);
            assert_eq!(head.outbox_root, winning_head.outbox_root);
            assert_eq!(head.retention_root, winning_head.retention_root);
            assert_eq!(
                head.latest_committed_rcr_id,
                winning_head.latest_committed_rcr_id
            );
            let predecessor = fgit_authority::read_authority_head_body(
                &case.fixture.store.backend,
                head.predecessor_head_id.unwrap(),
            )
            .unwrap();
            assert_eq!(predecessor, winning_head);
            let batch = read_decision_batch_body(
                &case.fixture.store.backend,
                head.decision_tail_id.unwrap(),
            )
            .unwrap();
            assert!(
                batch.committed_rcrs.is_empty(),
                "the losing request adds no RCR"
            );
            let (_, delivery) = selected_state(&case.fixture);
            assert_eq!(delivery.forge.entries().len(), 1);
            assert_eq!(
                delivery.forge.entries()[0].event_batch_root(),
                competitor.event_root()
            );
            assert_eq!(
                delivery.outbox.entries().len(),
                usize::try_from(
                    proposal(&case.fixture.context, &case.command)
                        .unwrap()
                        .0
                        .version
                        .get(),
                )
                .unwrap()
            );
            assert_eq!(
                delivery
                    .outbox
                    .entries()
                    .iter()
                    .filter(|entry| entry.tx_id() == competitor.tx_id())
                    .count(),
                1
            );
            assert!(
                delivery
                    .outbox
                    .entries()
                    .iter()
                    .all(|entry| entry.tx_id() != case.tx_id())
            );
            assert_eq!(
                case.fixture.outcome(case.tx_id()),
                OutcomeLookup::Decided(loser)
            );
            assert_eq!(
                case.fixture.outcome(competitor.tx_id()),
                OutcomeLookup::Decided(winner)
            );
            assert_eq!(case.run().unwrap(), loser);
            assert_eq!(competitor.run().unwrap(), winner);
            assert_eq!(case.fixture.head(), head);
            assert_eq!(
                case.fixture.store.publications.lock().unwrap().len(),
                initial_publications + 3
            );
        }
    }
}
