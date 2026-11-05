//! Native retained-outcome recovery with unavailable pre-checkpoint history.
//! The ordinary admission, checkpoint fabric, original run and durable journal
//! are real; the read wrapper only makes selected history unavailable.

use super::*;

use crate::{FsqliteCx, outcome_checkpoint::OutcomeCheckpointReceipt};
use fgit_agent::ref_publication::observe_ref_transaction_async;
use fgit_authority::{
    AmbiguityReason, AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityLimits,
    AuthorityRefusal, AuthorityVersionToken, CasOutcome, HeadInit, HeadKey, HeadRead, ImmutableKey,
    ImmutableRead, OutcomeFailure, PutOutcome, StoreInstanceId, TerminalOutcome, body_key_for_id,
    outcome_key,
};
use fgit_chronicle::load_verified_outcome_index_checkpoint_async;
use fgit_codec::CryptoBodyIdentity;
use fgit_object_fabric::fabric::ImmutableObjectFabric;
use std::sync::{Mutex, atomic::AtomicUsize};

struct ReadView<'a> {
    node: &'a OneNode,
    reads: Mutex<Vec<ImmutableKey>>,
    operations: AtomicUsize,
    head_reads: AtomicUsize,
    missing: Option<ImmutableKey>,
    cancel_after: Option<ImmutableKey>,
    absent_head_from: Option<usize>,
}

impl<'a> ReadView<'a> {
    fn new(node: &'a OneNode) -> Self {
        Self {
            node,
            reads: Mutex::new(Vec::new()),
            operations: AtomicUsize::new(0),
            head_reads: AtomicUsize::new(0),
            missing: None,
            cancel_after: None,
            absent_head_from: None,
        }
    }

    fn reads_of(&self, key: &ImmutableKey) -> usize {
        self.reads
            .lock()
            .unwrap()
            .iter()
            .filter(|found| *found == key)
            .count()
    }

    fn decision_reads(&self) -> usize {
        let domain = b"frankengit/decision-batch/v1";
        self.reads
            .lock()
            .unwrap()
            .iter()
            .filter(|key| {
                key.as_bytes()
                    .windows(domain.len())
                    .any(|window| window == domain)
            })
            .count()
    }
}

impl AsyncAuthorityStore for ReadView<'_> {
    type Context = FsqliteCx;

    fn instance_id(&self) -> StoreInstanceId {
        AsyncAuthorityStore::instance_id(&self.node.authority)
    }

    fn limits(&self) -> AuthorityLimits {
        AsyncAuthorityStore::limits(&self.node.authority)
    }

    async fn read_immutable(
        &self,
        cx: &FsqliteCx,
        key: &ImmutableKey,
    ) -> Result<ImmutableRead, AuthorityFailure> {
        self.operations.fetch_add(1, Ordering::Relaxed);
        self.reads.lock().unwrap().push(key.clone());
        if self.missing.as_ref() == Some(key) {
            return Ok(ImmutableRead::Absent);
        }
        let result = AsyncAuthorityStore::read_immutable(&self.node.authority, cx, key).await;
        if self.cancel_after.as_ref() == Some(key) {
            cx.cancel();
        }
        result
    }

    async fn read_head(&self, cx: &FsqliteCx, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        self.operations.fetch_add(1, Ordering::Relaxed);
        let read = self.head_reads.fetch_add(1, Ordering::Relaxed) + 1;
        if self.absent_head_from.is_some_and(|first| read >= first) {
            return Ok(HeadRead::Absent);
        }
        AsyncAuthorityStore::read_head(&self.node.authority, cx, key).await
    }

    async fn authenticate_head_receipt(
        &self,
        cx: &FsqliteCx,
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure> {
        self.operations.fetch_add(1, Ordering::Relaxed);
        AsyncAuthorityStore::authenticate_head_receipt(&self.node.authority, cx, receipt).await
    }

    async fn put_if_absent(
        &self,
        _: &FsqliteCx,
        _: &ImmutableKey,
        _: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        panic!("observing original responsibility must not stage new authority");
    }

    async fn initialize_head(
        &self,
        _: &FsqliteCx,
        _: &HeadKey,
        _: HeadGeneration,
        _: &[u8],
    ) -> Result<HeadInit, AuthorityFailure> {
        panic!("observing original responsibility must not initialize authority");
    }

    async fn compare_exchange_head(
        &self,
        _: &FsqliteCx,
        _: &HeadKey,
        _: AuthorityVersionToken,
        _: HeadGeneration,
        _: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        panic!("observing original responsibility must not publish another head");
    }
}

fn selected_head(node: &OneNode) -> AuthenticatedHead {
    node.runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap()
}

fn decision_key(head: &AuthenticatedHead) -> ImmutableKey {
    body_key_for_id(
        head.body()
            .unwrap()
            .decision_tail_id
            .unwrap()
            .as_internal_object_id(),
    )
    .unwrap()
}

fn maintain_checkpoint(node: &OneNode) -> OutcomeCheckpointReceipt {
    node.runtime()
        .block_on(node.checkpoint_outcomes_in(&node.request_context(), Default::default()))
        .unwrap()
}

fn observe<Authority>(
    node: &OneNode,
    authority: &Authority,
    request: &NodeRequestContext,
    run: &IntentRun,
    binding: &RefTransactionBinding,
) -> Result<Option<ObservedRefTransaction>, RefTransactionObservationRefusal>
where
    Authority: AsyncAuthorityStore<Context = FsqliteCx>,
{
    node.runtime()
        .block_on(super::super::observation::observe_checkpointed(
            authority,
            &node.head_key,
            &node.outcome_checkpoint_fabric,
            request,
            run,
            binding,
        ))
}

/// Stop at the same production boundary as an admission whose ACK is lost.
/// Native object validation and ordinary admission both run; only the following
/// responsibility reconciliation is left for each test to invoke.
fn admit_without_ack<A: GitHashAlgorithm>(
    node: &OneNode,
    change: &Prepared<A>,
    approved: &TrustedLocalAgentPublicationApproval,
    chain: &VerifiedCapabilityChain,
    broker: &mut CurrentAuthorityRevocationCheckedEffectBroker,
) -> (PendingRefTransactionSubmission, TerminalOutcome) {
    let clock = node
        .trusted_local_agent_publication_clock(LogicalTime::new(20), Duration::from_secs(1))
        .unwrap();
    let request = node.command_request_context(Some(
        crate::GitDaemonSessionTimeout::try_new(Duration::from_secs(30)).unwrap(),
    ));
    let prepared = node
        .runtime()
        .block_on(node.prepare_agent_ref_transaction_trusted_local_in(
            &request,
            broker,
            &clock,
            input(change, approved, chain),
        ))
        .unwrap();
    let PreparedNativeAgentPublication::Ready(publication) = prepared else {
        panic!("a new publication must retain native object custody");
    };
    let admission = node
        .runtime()
        .block_on(node.admit_basis_bound_loopback_receive_publishing_in(
            &request,
            &publication.session,
            &publication.validated,
            AdmissionLimits::default(),
            Some(&publication.staging),
        ))
        .unwrap();
    assert_eq!(admission.session.tx_ids, [publication.binding().tx_id()]);
    assert_eq!(admission.commands.len(), 1);
    (publication.into_pending(), admission.commands[0].terminal)
}

fn original_observation(
    node: &OneNode,
    pending: &PendingRefTransactionSubmission,
) -> ObservedRefTransaction {
    let request = node.request_context();
    node.runtime()
        .block_on(observe_ref_transaction_async(
            &node.authority,
            request.authority(),
            &node.head_key,
            pending.run(),
            pending.binding(),
        ))
        .unwrap()
        .unwrap()
}

fn assert_missing_history(error: RefTransactionObservationRefusal) {
    assert!(
        matches!(error, RefTransactionObservationRefusal::Outcome(ref reason)
            if matches!(**reason, OutcomeFailure::StreamBodyMissing { .. })),
        "missing authority history must remain a refusal: {error:?}"
    );
}

fn assert_cancelled(error: RefTransactionObservationRefusal) {
    assert!(
        matches!(error, RefTransactionObservationRefusal::Outcome(ref reason)
        if **reason == OutcomeFailure::from(AuthorityFailure::Ambiguous(
            AmbiguityReason::Cancelled
        ))),
        "cancellation must not be reinterpreted as an undecided answer: {error:?}"
    );
}

fn checkpointed_native_recovery<A: GitHashAlgorithm>(refused: bool) {
    let scratch = Scratch::new();
    let (node, source) = node(&scratch, A::OBJECT_FORMAT, true);
    let branch = if refused {
        b"refs/heads/absent".as_slice()
    } else {
        b"refs/heads/main".as_slice()
    };
    let change = prepared::<A>(&node, &source, branch, false);
    let approved = approval(&change, b"checkpoint-original-agent-submission");
    let chain = chain(10_000, true);
    let directory = scratch.journal("journal");
    let mut broker = broker(&node, &change, &directory);
    let (pending, terminal) = admit_without_ack(&node, &change, &approved, &chain, &mut broker);
    assert_eq!(
        matches!(terminal.outcome, DecisionOutcome::Refused { .. }),
        refused
    );
    let binding = pending.binding().clone();
    let run = pending.run().clone();
    let before = broker.records();
    let original_tail = broker.durable_position().unwrap().unwrap();
    let expected = original_observation(&node, &pending);
    assert_eq!(expected.binding(), &binding);
    assert_eq!(expected.terminal(), &terminal);
    let old_batch = decision_key(&selected_head(&node));
    let checkpoint = maintain_checkpoint(&node);
    assert!(checkpoint.published);
    let head = selected_head(&node);

    {
        let old_walk = ReadView {
            missing: Some(old_batch.clone()),
            ..ReadView::new(&node)
        };
        let request = node.request_context();
        assert_missing_history(
            node.runtime()
                .block_on(observe_ref_transaction_async(
                    &old_walk,
                    request.authority(),
                    &node.head_key,
                    &run,
                    &binding,
                ))
                .unwrap_err(),
        );
        assert_eq!(old_walk.reads_of(&old_batch), 1);

        let retained = ReadView {
            missing: Some(old_batch.clone()),
            ..ReadView::new(&node)
        };
        let observed = observe(&node, &retained, &request, &run, &binding)
            .unwrap()
            .unwrap();
        assert_eq!(observed, expected);
        assert_eq!(retained.reads_of(&old_batch), 0);
        assert_eq!(retained.decision_reads(), 0);
        assert_eq!(broker.records(), before);
        assert_eq!(broker.durable_position().unwrap().unwrap(), original_tail);

        let substituted = IntentRun::new_authenticated(
            run.run_id(),
            run.authority_read_receipt().unwrap().clone(),
            run.allowed_operation_classes(),
            run.resource_budget(),
            LogicalTime::new(run.expiry().value() + 1),
        )
        .unwrap();
        assert!(matches!(
            observe(&node, &retained, &request, &substituted, &binding),
            Err(RefTransactionObservationRefusal::Binding)
        ));
    }

    // Retrying the public entry point after expiry observes only. Even the
    // transport bytes and a publication-capable chain are no longer supplied.
    let expired = node
        .trusted_local_agent_publication_clock(LogicalTime::new(10_001), Duration::from_secs(1))
        .unwrap();
    let prepare_only = super::chain(10_000, false);
    let mut retry = input(&change, &approved, &prepare_only);
    retry.bundle = b"original transport is unavailable";
    let NativeAgentPublicationResult::Recovered(replayed) = node
        .runtime()
        .block_on(node.publish_agent_ref_transaction_trusted_local_in(
            &node.request_context(),
            &mut broker,
            &expired,
            retry,
        ))
        .unwrap()
    else {
        panic!("a retained original submission must never be dispatched again");
    };
    assert_eq!(replayed, expected);
    assert_eq!(broker.records(), before);
    assert_eq!(broker.durable_position().unwrap().unwrap(), original_tail);
    assert_eq!(broker.authorizations().len(), 1);
    assert_eq!(broker.dispatch_authorizations().len(), 1);
    assert_eq!(broker.generic_dispatch_authorizations().len(), 1);
    drop(expired);

    let cancelled = node.request_context();
    cancelled.cancel();
    let RefTransactionReconciliationRefused::Pending { pending, reason } = node
        .runtime()
        .block_on(node.reconcile_agent_ref_transaction_in(&cancelled, pending))
        .unwrap_err()
    else {
        panic!("cancelled observation must retain the original pending owner");
    };
    assert_cancelled(reason);
    let pending = *pending;
    assert_eq!(pending.binding(), &binding);
    assert_eq!(pending.run(), &run);
    assert_eq!(broker.records(), before);
    assert_eq!(broker.durable_position().unwrap().unwrap(), original_tail);
    assert_eq!(selected_head(&node).receipt(), head.receipt());

    let tail = if refused {
        // Closing a live owner with debt is explicitly nonquiescent. Only the
        // independently anchored journal survives for cold cleanup below.
        drop(pending);
        assert!(!broker.close().is_quiescent());
        original_tail
    } else {
        let RefTransactionResolution::Decided(settled) = node
            .runtime()
            .block_on(node.reconcile_agent_ref_transaction_in(&node.request_context(), pending))
            .unwrap()
        else {
            panic!("live reconciliation must acknowledge the retained terminal");
        };
        assert_eq!(settled.observation(), &expected);
        assert_eq!(
            broker.records()[0].budget_consumed,
            before[0].budget_consumed
        );
        assert_eq!(
            broker.records()[0].budget_reserved,
            before[0].budget_reserved
        );
        assert_eq!(broker.dispatch_authorizations().len(), 1);
        let tail = broker.durable_position().unwrap().unwrap();
        assert!(broker.close().is_quiescent());
        tail
    };
    let run_id = run.run_id();
    let run_pin = *run.commitment().unwrap().as_bytes();
    let effect = binding.effect_id();
    drop(change);
    node.shutdown().unwrap();

    let node = OneNode::open_existing(scratch.config(A::OBJECT_FORMAT)).unwrap();
    let request = node.request_context();
    let recovered = node
        .runtime()
        .block_on(node.recover_agent_journal_in(&request, &directory, run_id, &run_pin, tail))
        .unwrap();
    assert_eq!(recovered.original_run(), &run);
    let now = LogicalTime::new(10_001);
    let report = recovered.reconciliation_report(now).unwrap();
    assert_eq!(report.has_unsettled_effects(), refused);
    assert_eq!(
        report.cumulative_budget_consumed(),
        before[0].budget_consumed
    );
    assert_eq!(
        node.runtime()
            .block_on(node.observe_recovered_agent_ref_transaction_in(&request, &recovered, effect))
            .unwrap()
            .unwrap(),
        expected
    );
    assert_eq!(recovered.journal().position(), tail);
    let path = directory.join(format!("{:032x}.fg-agent-journal", run_id.value()));
    let original_bytes = fs::read(&path).unwrap();
    let NativeRecoveredRefTransactionSettlement::Acknowledged {
        observation,
        recovered,
        already_acknowledged,
    } = node
        .runtime()
        .block_on(node.settle_recovered_agent_ref_transaction_in(
            &request, &directory, run_id, &run_pin, tail, effect, now,
        ))
        .unwrap()
    else {
        panic!("cold cleanup must acknowledge the original terminal only");
    };
    assert_eq!(observation, expected);
    assert_eq!(already_acknowledged, !refused);
    assert_eq!(recovered.original_run(), &run);
    let report = recovered.reconciliation_report(now).unwrap();
    assert!(!report.has_unsettled_effects());
    assert_eq!(
        report.cumulative_budget_consumed(),
        before[0].budget_consumed
    );
    let settled_tail = recovered.journal().position();
    if refused {
        assert!(settled_tail.entries > tail.entries);
        assert!(settled_tail.bytes > tail.bytes);
    } else {
        assert_eq!(settled_tail, tail);
        assert_eq!(fs::read(&path).unwrap(), original_bytes);
    }
    let settled_bytes = fs::read(&path).unwrap();
    let NativeRecoveredRefTransactionSettlement::Acknowledged {
        observation,
        recovered,
        already_acknowledged,
    } = node
        .runtime()
        .block_on(node.settle_recovered_agent_ref_transaction_in(
            &request,
            &directory,
            run_id,
            &run_pin,
            settled_tail,
            effect,
            now,
        ))
        .unwrap()
    else {
        panic!("the exact durable acknowledgement must be idempotent");
    };
    assert_eq!(observation, expected);
    assert!(already_acknowledged);
    assert_eq!(recovered.journal().position(), settled_tail);
    assert_eq!(fs::read(&path).unwrap(), settled_bytes);
    assert_eq!(selected_head(&node).receipt(), head.receipt());
    node.shutdown().unwrap();
}

#[test]
fn native_commit_and_refusal_recover_from_checkpoint_in_both_object_formats() {
    for refused in [false, true] {
        checkpointed_native_recovery::<Sha1>(refused);
        checkpointed_native_recovery::<Sha256>(refused);
    }
}

fn retained_leaf_paths(node: &OneNode, checkpoint: &OutcomeCheckpointReceipt) -> Vec<PathBuf> {
    let request = node.request_context();
    let (body, _) = node
        .runtime()
        .block_on(load_verified_outcome_index_checkpoint_async(
            &node.authority,
            request.authority(),
            &CryptoBodyIdentity,
            &node.outcome_checkpoint_fabric,
            checkpoint.checkpoint_root,
        ))
        .unwrap();
    let manifest = node
        .outcome_checkpoint_fabric
        .read_manifest(body.leaf_archive_manifest)
        .unwrap();
    assert!(!manifest.entries().is_empty());
    let hex = fgit_crypto::lowercase_hex;
    manifest
        .entries()
        .iter()
        .map(|entry| {
            let identity = entry.object_identity();
            node.storage_root
                .join("objects")
                .join(hex(manifest.namespace()))
                .join(hex(&identity.algorithm().code_point().to_be_bytes()))
                .join(hex(identity.as_bytes()))
        })
        .collect()
}

#[test]
fn cancellation_and_damaged_checkpoints_never_invent_absence_or_settle_pending_debt() {
    let scratch = Scratch::new();
    let (node, source) = node(&scratch, Format::Sha256, true);
    let source_batch = decision_key(&selected_head(&node));
    let change = prepared::<Sha256>(&node, &source, reference().as_bytes(), false);
    let approved = approval(&change, b"checkpoint-fallback-original-submission");
    let chain = chain(10_000, true);
    let mut broker = broker(&node, &change, &scratch.journal("journal"));
    let (pending, _) = admit_without_ack(&node, &change, &approved, &chain, &mut broker);
    let expected = original_observation(&node, &pending);
    let agent_batch = decision_key(&selected_head(&node));
    assert_ne!(agent_batch, source_batch);
    let before = broker.records();
    let tail = broker.durable_position().unwrap().unwrap();
    let run = pending.run();
    let binding = pending.binding();
    let request = node.request_context();

    let before_checkpoint = selected_head(&node);
    assert!(
        before_checkpoint
            .body()
            .unwrap()
            .last_checkpoint_id
            .is_none()
    );
    {
        // Before the first checkpoint a recent terminal still stops the
        // ordinary walk before older, unavailable history is needed.
        let no_checkpoint = ReadView {
            missing: Some(source_batch.clone()),
            ..ReadView::new(&node)
        };
        assert_eq!(
            observe(&node, &no_checkpoint, &request, run, binding)
                .unwrap()
                .unwrap(),
            expected
        );
        assert_eq!(no_checkpoint.reads_of(&source_batch), 0);
        assert_eq!(no_checkpoint.decision_reads(), 1);

        let hint = outcome_key(node.tenant_id(), node.repository_id(), binding.tx_id()).unwrap();
        for absent_head_from in [1, 2] {
            // A missing hint makes this the dangerous case: an absent head
            // in ordinary replay would otherwise produce an undecided answer.
            // Historical run authentication still succeeds through issuance.
            let disappeared = ReadView {
                missing: Some(hint.clone()),
                absent_head_from: Some(absent_head_from),
                ..ReadView::new(&node)
            };
            let error = observe(&node, &disappeared, &request, run, binding).unwrap_err();
            if absent_head_from == 1 {
                assert!(matches!(
                    error,
                    RefTransactionObservationRefusal::StaleOutcomeBasis
                ));
                assert_eq!(disappeared.reads_of(&hint), 0);
            } else {
                assert!(
                    matches!(error, RefTransactionObservationRefusal::Outcome(reason)
                    if *reason == OutcomeFailure::from(AuthorityFailure::Refused(
                        AuthorityRefusal::HeadAbsent
                    )))
                );
                assert_eq!(disappeared.reads_of(&hint), 1);
            }
            assert_eq!(
                disappeared.head_reads.load(Ordering::Relaxed),
                absent_head_from
            );
            assert_eq!(disappeared.decision_reads(), 0);
            assert_eq!(broker.records(), before);
            assert_eq!(broker.durable_position().unwrap().unwrap(), tail);
            assert_eq!(selected_head(&node).receipt(), before_checkpoint.receipt());
        }
    }

    let checkpoint = maintain_checkpoint(&node);
    let paths = retained_leaf_paths(&node, &checkpoint);
    let head = selected_head(&node);

    {
        let retained = ReadView {
            missing: Some(agent_batch.clone()),
            ..ReadView::new(&node)
        };
        assert_eq!(
            observe(&node, &retained, &request, run, binding)
                .unwrap()
                .unwrap(),
            expected
        );
        assert_eq!(retained.decision_reads(), 0);

        let cancelled = node.request_context();
        cancelled.cancel();
        let no_io = ReadView::new(&node);
        assert_cancelled(observe(&node, &no_io, &cancelled, run, binding).unwrap_err());
        assert_eq!(no_io.operations.load(Ordering::Relaxed), 0);

        let capsule_key = body_key_for_id(checkpoint.capsule_id.as_internal_object_id()).unwrap();
        let cancel_during_read = ReadView {
            cancel_after: Some(capsule_key.clone()),
            ..ReadView::new(&node)
        };
        let cancelled = node.request_context();
        assert_cancelled(
            observe(&node, &cancel_during_read, &cancelled, run, binding).unwrap_err(),
        );
        assert_eq!(cancel_during_read.reads_of(&capsule_key), 1);
        assert_eq!(cancel_during_read.decision_reads(), 0);
    }
    assert_eq!(broker.records(), before);
    assert_eq!(broker.durable_position().unwrap().unwrap(), tail);

    for path in paths {
        fs::write(path, b"damaged retained outcome leaf").unwrap();
    }
    {
        let replay = ReadView::new(&node);
        assert_eq!(
            observe(&node, &replay, &request, run, binding)
                .unwrap()
                .unwrap(),
            expected
        );
        assert!(replay.decision_reads() > 0);

        let unavailable_terminal = ReadView {
            missing: Some(agent_batch.clone()),
            ..ReadView::new(&node)
        };
        assert_missing_history(
            observe(&node, &unavailable_terminal, &request, run, binding).unwrap_err(),
        );
        assert!(unavailable_terminal.reads_of(&agent_batch) > 0);

        // Complete history is unavailable, but this newer terminal is still
        // reachable. Only that positive fact may survive the short fallback.
        let recent_terminal = ReadView {
            missing: Some(source_batch.clone()),
            ..ReadView::new(&node)
        };
        assert_eq!(
            observe(&node, &recent_terminal, &request, run, binding)
                .unwrap()
                .unwrap(),
            expected
        );
        assert!(recent_terminal.reads_of(&source_batch) > 0);
        let undecided = RefTransactionBinding::derive(
            &change.transaction,
            node.tenant_id(),
            OWNER,
            IdempotencyKey::new(b"never-submitted-checkpoint-query".to_vec()).unwrap(),
        )
        .unwrap()
        .with_custody_commitment(binding.custody_commitment().unwrap())
        .unwrap();
        assert_missing_history(
            observe(&node, &recent_terminal, &request, run, &undecided).unwrap_err(),
        );
    }
    assert_eq!(broker.records(), before);
    assert_eq!(broker.durable_position().unwrap().unwrap(), tail);
    assert_eq!(selected_head(&node).receipt(), head.receipt());

    // The public live path also uses the bounded fallback, and the retained
    // pending owner remains usable after every failed observation above.
    let RefTransactionResolution::Decided(settled) = node
        .runtime()
        .block_on(node.reconcile_agent_ref_transaction_in(&request, pending))
        .unwrap()
    else {
        panic!("available native history must settle the original responsibility");
    };
    assert_eq!(settled.observation(), &expected);
    assert_eq!(
        broker.records()[0].budget_consumed,
        before[0].budget_consumed
    );
    assert_eq!(
        broker.records()[0].budget_reserved,
        before[0].budget_reserved
    );
    assert_eq!(broker.dispatch_authorizations().len(), 1);
    assert_eq!(selected_head(&node).receipt(), head.receipt());
    assert!(broker.close().is_quiescent());
    node.shutdown().unwrap();
}
