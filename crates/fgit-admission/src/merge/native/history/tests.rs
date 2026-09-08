//! These tests exercise the production history-order and evidence decoders.
//! They do not establish durable-store or concurrent-publication behavior.

use core::num::NonZeroU32;

use fgit_codec::encode_body;
use fgit_codec::harness::{commit_record, digest_of, repository_id, tx_id};
use fgit_resource::settlement::{Observation, ProbeVerdict};
use fgit_resource::{LifecycleEvent, ReconcilePolicy};

use super::*;

fn fixture() -> (CanonicalOutboxEffectState, CanonicalOutboxProgress) {
    let key =
        AsciiSlug::from_static("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    let deferred =
        CanonicalOutboxEffectState::committed(repository_id(), key, tx_id(), digest_of(91))
            .transition(LifecycleEvent::Defer, None)
            .expect("legal deferred effect");
    let progress = CanonicalOutboxProgress::start(
        repository_id(),
        key,
        AsciiSlug::from_static("forge-projection"),
        deferred.payload_root(),
        deferred.root().expect("effect root"),
        ReconcilePolicy::new(NonZeroU32::new(4).expect("positive budget")),
    )
    .expect("initial reconciliation");
    (deferred, progress)
}

#[test]
fn latest_requires_the_complete_canonical_progress_order_and_deferred_origin() {
    let (deferred, initial) = fixture();
    let delivered = initial
        .observe(
            Observation::Probe(ProbeVerdict::Delivered),
            b"destination receipt".to_vec(),
        )
        .expect("probe observed delivery");
    let mut history = ReverseProgress::new(initial.delivery_key());
    history.progress(delivered.clone()).expect("latest first");
    history.progress(initial).expect("exact predecessor next");
    history
        .effect(&deferred)
        .expect("canonical deferred origin");
    assert_eq!(history.finish().expect("complete history"), Some(delivered));
}

#[test]
fn staged_predecessor_does_not_excuse_a_missing_canonical_transition() {
    let (deferred, initial) = fixture();
    let pending = initial
        .observe(Observation::Probe(ProbeVerdict::NotDelivered), Vec::new())
        .expect("probe permits later attempt");
    let dispatched = pending
        .mark_dispatch()
        .expect("persist dispatch responsibility");
    let mut history = ReverseProgress::new(initial.delivery_key());
    history.progress(dispatched).expect("latest");
    assert!(history.progress(initial).is_err());

    let mut incomplete = ReverseProgress::new(deferred.delivery_key());
    incomplete.progress(pending).expect("latest");
    assert!(incomplete.effect(&deferred).is_err());
}

#[test]
fn competing_progress_fork_cannot_be_selected_by_root_order() {
    let (_, initial) = fixture();
    let delivered = initial
        .observe(
            Observation::Probe(ProbeVerdict::Delivered),
            b"observed".to_vec(),
        )
        .expect("delivered fork");
    let pending = initial
        .observe(Observation::Probe(ProbeVerdict::NotDelivered), Vec::new())
        .expect("pending fork");
    let mut history = ReverseProgress::new(initial.delivery_key());
    history
        .progress(delivered)
        .expect("newest canonical record");
    assert!(history.progress(pending).is_err());
}

#[test]
fn duplicate_or_misordered_initial_record_is_rejected() {
    let (deferred, initial) = fixture();
    let mut duplicate = ReverseProgress::new(initial.delivery_key());
    duplicate.progress(initial.clone()).expect("first record");
    assert!(duplicate.progress(initial.clone()).is_err());

    let mut older_than_origin = ReverseProgress::new(initial.delivery_key());
    older_than_origin
        .effect(&deferred)
        .expect("deferred with no later progress");
    assert!(older_than_origin.progress(initial).is_err());
}

#[test]
fn absence_is_not_inferred_from_an_unresolved_progress_origin() {
    let (deferred, initial) = fixture();
    assert_eq!(
        ReverseProgress::new(initial.delivery_key())
            .finish()
            .expect("no progress"),
        None
    );
    let mut missing = ReverseProgress::new(initial.delivery_key());
    missing.progress(initial).expect("valid body");
    assert!(missing.finish().is_err());

    let mut only_deferred = ReverseProgress::new(deferred.delivery_key());
    only_deferred
        .effect(&deferred)
        .expect("canonical unattempted obligation");
    assert_eq!(only_deferred.finish().expect("no progress yet"), None);
}

#[test]
fn record_decoder_binds_type_root_repository_and_equal_invariant_root() {
    let (deferred, initial) = fixture();
    let mut record = commit_record();
    record.repository_id = repository_id();
    record.outbox_effect_root = initial.root().expect("root");
    record.invariant_evidence_root = record.outbox_effect_root;
    let frame = encode_body(&initial).expect("canonical frame");
    assert_eq!(
        decode_record_effect(repository_id(), &record, &frame).expect("typed progress"),
        OutboxRecordEvidence::Progress(initial)
    );
    record.invariant_evidence_root = digest_of(99);
    assert!(decode_record_effect(repository_id(), &record, &frame).is_err());
    record.invariant_evidence_root = record.outbox_effect_root;
    record.repository_id = RepositoryId::from_bytes([99; 16]);
    assert!(decode_record_effect(repository_id(), &record, &frame).is_err());

    record.repository_id = repository_id();
    record.outbox_effect_root = deferred.root().expect("root");
    record.invariant_evidence_root = record.outbox_effect_root;
    let effect_frame = encode_body(&deferred).expect("effect frame");
    assert_eq!(
        decode_record_effect(repository_id(), &record, &effect_frame).expect("typed effect"),
        OutboxRecordEvidence::Effect(deferred)
    );
    assert!(decode_record_effect(repository_id(), &record, &frame).is_err());
    assert!(decode_record_effect(repository_id(), &record, b"malformed body").is_err());
}

fn acknowledged(
    deferred: &CanonicalOutboxEffectState,
    progress: &CanonicalOutboxProgress,
    destination: AsciiSlug,
    evidence: Vec<u8>,
) -> (CanonicalOutboxEffectState, CanonicalOutboxDeliveryReceipt) {
    let receipt = CanonicalOutboxDeliveryReceipt::try_new(
        deferred.repository_id(),
        deferred.delivery_key(),
        destination,
        deferred.payload_root(),
        progress.origin_effect_root(),
        OutboxDeliveryDisposition::Acknowledged,
        evidence,
    )
    .expect("bounded receipt");
    let effect = deferred
        .transition(
            LifecycleEvent::Acknowledge,
            Some(storage::root(&receipt).expect("receipt root")),
        )
        .expect("acknowledged lifecycle");
    (effect, receipt)
}

#[test]
fn terminal_receipt_must_quote_the_newest_preceding_terminal_progress() {
    let (deferred, initial) = fixture();
    let delivered = initial
        .observe(
            Observation::Probe(ProbeVerdict::Delivered),
            b"destination receipt".to_vec(),
        )
        .expect("delivery observed");
    let (effect, receipt) = acknowledged(
        &deferred,
        &delivered,
        delivered.destination(),
        delivered.evidence().to_vec(),
    );
    let mut matching = ReverseProgress::new(initial.delivery_key());
    matching
        .terminal(&effect, receipt)
        .expect("latest lifecycle result");
    matching
        .progress(delivered.clone())
        .expect("matching terminal observation");
    matching
        .progress(initial.clone())
        .expect("initial progress");
    matching.effect(&deferred).expect("deferred origin");
    assert_eq!(
        matching.finish().expect("complete history"),
        Some(delivered.clone())
    );

    for (destination, bytes) in [
        (
            AsciiSlug::from_static("different-destination"),
            delivered.evidence().to_vec(),
        ),
        (delivered.destination(), b"different evidence".to_vec()),
    ] {
        let (effect, receipt) = acknowledged(&deferred, &delivered, destination, bytes);
        let mut mismatch = ReverseProgress::new(initial.delivery_key());
        mismatch
            .terminal(&effect, receipt)
            .expect("codec-valid lifecycle");
        assert!(mismatch.progress(delivered.clone()).is_err());
    }

    let (effect, receipt) = acknowledged(
        &deferred,
        &delivered,
        delivered.destination(),
        delivered.evidence().to_vec(),
    );
    let mut nonterminal = ReverseProgress::new(initial.delivery_key());
    nonterminal
        .terminal(&effect, receipt)
        .expect("latest terminal record");
    assert!(nonterminal.progress(initial).is_err());
}

#[test]
fn lifecycle_only_history_is_compatible_but_progress_cannot_reopen_it() {
    let (deferred, initial) = fixture();
    let (effect, receipt) = acknowledged(
        &deferred,
        &initial,
        initial.destination(),
        b"legacy destination evidence".to_vec(),
    );
    let mut legacy = ReverseProgress::new(initial.delivery_key());
    legacy
        .terminal(&effect, receipt.clone())
        .expect("historical acknowledgement");
    legacy.effect(&deferred).expect("deferred origin");
    assert_eq!(
        legacy
            .finish()
            .expect("explicit lifecycle-only compatibility"),
        None
    );

    let mut reopened = ReverseProgress::new(initial.delivery_key());
    reopened.progress(initial).expect("latest progress");
    assert!(reopened.terminal(&effect, receipt).is_err());
}
