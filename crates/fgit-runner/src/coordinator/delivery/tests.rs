//! Custody state-machine tests; the fixture sink is not durable storage.
use super::*;
use crate::{CoordinatorLimits, ResourceCeilings, RunStatus, TriggerContext};
use fgit_schema::workflow::{Limits, compile};
use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};

const SOURCE: &str = "name: delivery\non: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: true\n  b:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: true\n";
fn coordinator() -> WorkflowCoordinator {
    WorkflowCoordinator::new(
        CoordinatorLimits::default(),
        ResourceCeilings::new(100, 1024, 1024, 0, 1, 1000).unwrap(),
        1,
    )
    .unwrap()
}
fn enqueue(c: &mut WorkflowCoordinator, tenant: u8, repo: u8, sequence: u64) -> WorkflowRunId {
    c.enqueue_run(
        TenantId::from_bytes([tenant; 16]),
        RepositoryId::from_bytes([repo; 16]),
        Commitment::of_bytes(b"head"),
        GitOid::Sha1(GitOidSha1::from_bytes([3; 20])),
        compile(SOURCE, &Limits::default()).unwrap(),
        TriggerContext::trusted_push("operator"),
        sequence,
        10,
    )
    .unwrap()
}
fn batch(c: &WorkflowCoordinator) -> CheckDeliveryBatch {
    c.prepare_check_delivery(MAX_BATCH_FACTS, MAX_BATCH_BYTES)
        .unwrap()
        .unwrap()
}
struct Sink<'a> {
    fail: bool,
    panic: bool,
    accepted: Vec<Vec<u8>>,
    live: Option<&'a Cell<bool>>,
}
impl CheckDeliverySink for Sink<'_> {
    fn accept(
        &mut self,
        batch: &CheckDeliveryBatch,
    ) -> Result<CheckDeliveryAcknowledgement, CheckDeliveryRefusal> {
        self.accepted.push(batch.body().to_vec());
        assert!(!self.panic, "injected sink unwind");
        if self.fail {
            return Err(CheckDeliveryRefusal::StorageUnavailable);
        }
        if let Some(live) = self.live {
            live.set(false);
        }
        Ok(CheckDeliveryAcknowledgement::after_durable_acceptance(
            batch,
            Commitment::of_bytes(b"fixture-custody-only"),
        ))
    }
}
fn sink() -> Sink<'static> {
    Sink {
        fail: false,
        panic: false,
        accepted: Vec::new(),
        live: None,
    }
}

#[test]
fn preparing_and_reading_never_settle_or_remove_pending_facts() {
    let mut c = coordinator();
    enqueue(&mut c, 1, 2, 1);
    let before = c.obligations.clone();
    let first = batch(&c);
    assert_eq!(first, batch(&c));
    assert_eq!(c.pending_check_fact_count(), 2);
    assert_eq!(c.obligations, before);
    assert!(c.verify_quiescence().is_err());
    assert_eq!(CheckDeliveryBatch::decode(first.body()).unwrap(), first);
}

#[test]
fn exact_acknowledgement_settles_only_frozen_prefix() {
    let mut c = coordinator();
    enqueue(&mut c, 1, 2, 1);
    let first = c
        .prepare_check_delivery(1, MAX_BATCH_BYTES)
        .unwrap()
        .unwrap();
    enqueue(&mut c, 1, 3, 2);
    let ack = CheckDeliveryAcknowledgement::after_durable_acceptance(
        &first,
        Commitment::of_bytes(b"receipt"),
    );
    c.acknowledge_check_delivery(&first, ack).unwrap();
    assert_eq!(c.pending_check_fact_count(), 3);
    assert_eq!(c.obligations.check_publications_settled, 1);
    assert_eq!(batch(&c).facts()[0].job_id, "b");
    assert_eq!(batch(&c).ordinal(), 1);
}

#[test]
fn wrong_and_duplicate_acknowledgements_cannot_drop_other_facts() {
    let mut c = coordinator();
    enqueue(&mut c, 1, 2, 1);
    let first = c
        .prepare_check_delivery(1, MAX_BATCH_BYTES)
        .unwrap()
        .unwrap();
    let other = batch(&c);
    let wrong = CheckDeliveryAcknowledgement::after_durable_acceptance(
        &other,
        Commitment::of_bytes(b"receipt"),
    );
    assert_eq!(
        c.acknowledge_check_delivery(&first, wrong),
        Err(CheckDeliveryRefusal::AcknowledgementMismatch)
    );
    assert_eq!(c.pending_check_fact_count(), 2);
    let correct =
        CheckDeliveryAcknowledgement::after_durable_acceptance(&first, wrong.receipt_root());
    c.acknowledge_check_delivery(&first, correct).unwrap();
    assert_eq!(
        c.acknowledge_check_delivery(&first, correct),
        Err(CheckDeliveryRefusal::StaleBatch)
    );
    assert_eq!(c.pending_check_fact_count(), 1);
}

#[test]
fn failed_or_ambiguous_sink_submission_retains_identical_retry_bytes() {
    let mut c = coordinator();
    enqueue(&mut c, 1, 2, 1);
    let original = batch(&c);
    let mut s = sink();
    s.fail = true;
    assert_eq!(
        c.deliver_check_facts(&mut s, MAX_BATCH_FACTS, MAX_BATCH_BYTES, &|| true),
        Err(CheckDeliveryRefusal::StorageUnavailable)
    );
    assert_eq!(batch(&c), original);
    s.fail = false;
    c.deliver_check_facts(&mut s, MAX_BATCH_FACTS, MAX_BATCH_BYTES, &|| true)
        .unwrap();
    assert_eq!(s.accepted, vec![original.body().to_vec(); 2]);
    assert_eq!(c.pending_check_fact_count(), 0);
    c.verify_quiescence().unwrap();
}

#[test]
fn sink_unwind_leaves_every_proposal_owned_by_the_coordinator() {
    let mut c = coordinator();
    enqueue(&mut c, 1, 2, 1);
    let original = batch(&c);
    let mut s = sink();
    s.panic = true;
    assert!(
        catch_unwind(AssertUnwindSafe(|| c.deliver_check_facts(
            &mut s,
            128,
            MAX_BATCH_BYTES,
            &|| true
        )))
        .is_err()
    );
    assert_eq!(batch(&c), original);
    assert_eq!(c.obligations.check_publications_settled, 0);
}

#[test]
fn cancellation_before_submission_has_no_effect_but_accepted_custody_settles() {
    let mut c = coordinator();
    enqueue(&mut c, 1, 2, 1);
    let mut s = sink();
    assert_eq!(
        c.deliver_check_facts(&mut s, 128, MAX_BATCH_BYTES, &|| false),
        Err(CheckDeliveryRefusal::Cancelled)
    );
    assert!(s.accepted.is_empty());
    let live = Cell::new(true);
    let mut s = Sink {
        live: Some(&live),
        ..sink()
    };
    c.deliver_check_facts(&mut s, 128, MAX_BATCH_BYTES, &|| live.get())
        .unwrap();
    assert!(!live.get());
    assert_eq!(c.pending_check_fact_count(), 0);
}

#[test]
fn batches_do_not_cross_run_or_repository_boundaries() {
    let mut c = coordinator();
    let first = enqueue(&mut c, 1, 2, 1);
    let second = enqueue(&mut c, 1, 3, 2);
    let a = batch(&c);
    assert_eq!(a.run_id(), first);
    assert_eq!(a.facts().len(), 2);
    c.deliver_check_facts(&mut sink(), 128, MAX_BATCH_BYTES, &|| true)
        .unwrap();
    let b = batch(&c);
    assert_eq!(b.run_id(), second);
    assert_eq!(b.repository(), RepositoryId::from_bytes([3; 16]));
    assert_ne!(a.id(), b.id());
}

#[test]
fn hard_and_requested_envelopes_are_checked_without_changing_ownership() {
    let mut c = coordinator();
    enqueue(&mut c, 1, 2, 1);
    for (count, bytes) in [(0, 1), (129, 1), (1, 0), (1, MAX_BATCH_BYTES + 1)] {
        assert_eq!(
            c.prepare_check_delivery(count, bytes),
            Err(CheckDeliveryRefusal::InvalidLimits)
        );
    }
    assert_eq!(
        c.prepare_check_delivery(1, 1),
        Err(CheckDeliveryRefusal::BatchTooLarge)
    );
    let one = c
        .prepare_check_delivery(1, MAX_BATCH_BYTES)
        .unwrap()
        .unwrap();
    assert_eq!(
        c.prepare_check_delivery(128, one.body().len())
            .unwrap()
            .unwrap(),
        one
    );
    assert_eq!(c.pending_check_fact_count(), 2);
}

#[test]
fn every_truncated_prefix_and_trailing_bytes_are_refused() {
    let mut c = coordinator();
    enqueue(&mut c, 1, 2, 1);
    let a = batch(&c);
    for end in 0..a.body().len() {
        assert!(
            CheckDeliveryBatch::decode(&a.body()[..end]).is_err(),
            "accepted prefix {end}"
        );
    }
    let mut bytes = a.body().to_vec();
    bytes.push(0);
    assert_eq!(
        CheckDeliveryBatch::decode(&bytes),
        Err(CheckDeliveryRefusal::InvalidBatch)
    );
}

#[test]
fn profile_fence_and_receipt_shape_are_checked_during_encoding_and_decode() {
    let mut c = coordinator();
    enqueue(&mut c, 1, 2, 1);
    let mut a = batch(&c);
    a.facts[0].status = CheckRunStatus::Completed;
    a.facts[0].conclusion = Some(CheckRunConclusion::Success);
    assert_eq!(a.encode(), Err(CheckDeliveryRefusal::InvalidBatch));
    a.facts[0].receipt_commitment = Some(Commitment::of_bytes(b"evidence-reference-not-proof"));
    assert!(a.encode().is_ok());
    a.profile = CoordinatorExecutionProfile::TrustedWorkflow {
        source: Commitment::of_bytes(b"workflow"),
        limits: crate::workflow::WorkflowLimits::default(),
    };
    assert_eq!(a.encode(), Err(CheckDeliveryRefusal::InvalidBatch));
    a.facts[0].conclusion = Some(CheckRunConclusion::ActionRequired);
    let bytes = a.encode().unwrap();
    assert_eq!(
        CheckDeliveryBatch::decode(&bytes)
            .unwrap()
            .execution_profile(),
        a.profile
    );
}

#[test]
fn native_domains_and_submillisecond_limits_survive_round_trip() {
    let mut c = coordinator();
    enqueue(&mut c, 1, 2, 1);
    let mut a = batch(&c);
    let original = a.id();
    a.source = GitOid::Sha256(GitOidSha256::from_bytes([3; 32]));
    a.profile = CoordinatorExecutionProfile::TrustedWorkflow {
        source: Commitment::of_bytes(b"script"),
        limits: crate::workflow::WorkflowLimits {
            step_timeout: Duration::new(1, 17),
            ..crate::workflow::WorkflowLimits::default()
        },
    };
    a.body = a.encode().unwrap();
    assert_eq!(CheckDeliveryBatch::decode(a.body()).unwrap(), a);
    assert_ne!(a.id(), original);
}

#[test]
fn oversized_job_id_is_refused_before_batch_copy() {
    let mut c = coordinator();
    let run = enqueue(&mut c, 1, 2, 1);
    c.outbox_facts[0].job_id = "x".repeat(MAX_JOB_BYTES + 1);
    assert_eq!(
        c.prepare_check_delivery(1, MAX_BATCH_BYTES),
        Err(CheckDeliveryRefusal::BatchTooLarge)
    );
    assert_eq!(c.pending_check_fact_count(), 2);
    assert_eq!(c.active_runs[&run].status, RunStatus::Queued);
}
