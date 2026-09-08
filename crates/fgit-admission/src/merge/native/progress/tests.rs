//! Codec and shared-reconciler tests, not durable-node or publication evidence.

use fgit_codec::harness::digest_of;
use fgit_codec::{DecodeLimits, decode_body, encode_body};

use super::*;

fn policy(attempts: u32) -> ReconcilePolicy {
    ReconcilePolicy::new(NonZeroU32::new(attempts).expect("nonzero policy"))
}

fn start(attempts: u32) -> CanonicalOutboxProgress {
    CanonicalOutboxProgress::start(
        RepositoryId::from_bytes([1; 16]),
        AsciiSlug::from_static("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        AsciiSlug::from_static("forge-projection"),
        digest_of(2),
        digest_of(3),
        policy(attempts),
    )
    .expect("bounded initial reconciliation")
}

fn reload(body: &CanonicalOutboxProgress) -> CanonicalOutboxProgress {
    let frame = encode_body(body).expect("canonical body encodes");
    let decoded = decode_body::<CanonicalOutboxProgress>(&frame, DecodeLimits::DEFAULT)
        .expect("canonical body decodes");
    assert_eq!(&decoded, body);
    assert_eq!(encode_body(&decoded).expect("stable re-encoding"), frame);
    assert_eq!(
        decoded.root().expect("decoded root"),
        body.root().expect("root")
    );
    decoded
}

fn pending(attempts: u32) -> CanonicalOutboxProgress {
    let initial = start(attempts);
    let pending = initial
        .observe(
            Observation::Probe(ProbeVerdict::NotDelivered),
            b"absent".to_vec(),
        )
        .expect("definite probe permits next attempt");
    pending
        .verify_successor_of(&initial)
        .expect("exact predecessor");
    assert_eq!(pending.state(), ReconcileState::Pending { attempt: 2 });
    pending
}

#[test]
fn persisted_dispatch_recovers_by_probe_without_resetting_attempt_or_losing_evidence() {
    let pending = pending(3);
    assert!(
        pending
            .observe(
                Observation::Delivery(DeliveryVerdict::Accepted),
                b"accepted".to_vec()
            )
            .is_err()
    );
    let marker = pending
        .mark_dispatch()
        .expect("persist responsibility before dispatch");
    marker
        .verify_successor_of(&pending)
        .expect("marker predecessor");
    assert!(marker.dispatch_in_flight());
    assert!(marker.mark_dispatch().is_err());
    let restarted = reload(&marker);
    let acknowledged = restarted
        .observe(
            Observation::Probe(ProbeVerdict::Delivered),
            b"stable-key receipt".to_vec(),
        )
        .expect("restart probe reconciles the in-flight attempt");
    acknowledged
        .verify_successor_of(&marker)
        .expect("observation predecessor");
    assert_eq!(
        acknowledged.state(),
        ReconcileState::Delivered { attempt: 2 }
    );
    assert_eq!(acknowledged.attempt(), 2);
    assert!(!acknowledged.dispatch_in_flight());
    assert_eq!(acknowledged.evidence(), b"stable-key receipt");
    let recovered_terminal = reload(&acknowledged);
    assert!(recovered_terminal.mark_dispatch().is_err());
    assert!(
        recovered_terminal
            .observe(
                Observation::Probe(ProbeVerdict::Delivered),
                b"again".to_vec()
            )
            .is_err()
    );
}

#[test]
fn restarted_attempt_three_exhausts_the_original_budget_instead_of_starting_over() {
    let second = pending(3).mark_dispatch().expect("attempt two marker");
    let third = second
        .observe(
            Observation::Delivery(DeliveryVerdict::TransientFailure),
            b"retryable".to_vec(),
        )
        .expect("one remaining dispatch");
    assert_eq!(third.state(), ReconcileState::Pending { attempt: 3 });
    let in_flight = reload(&third.mark_dispatch().expect("attempt three marker"));
    let exhausted = in_flight
        .observe(
            Observation::Probe(ProbeVerdict::NotDelivered),
            b"still absent".to_vec(),
        )
        .expect("recovery consumes the persisted final attempt");
    assert_eq!(
        exhausted.state(),
        ReconcileState::Indeterminate {
            reason: EscalationReason::RetryBudgetExhausted
        }
    );
    assert_eq!(exhausted.max_attempts(), 3);
    assert_eq!(exhausted.attempt(), 3);
    assert!(exhausted.mark_dispatch().is_err());
    reload(&exhausted);
    let one = start(1)
        .observe(Observation::Probe(ProbeVerdict::NotDelivered), Vec::new())
        .expect("resource policy one has no spare dispatch after recovery");
    assert_eq!(
        one.state(),
        ReconcileState::Indeterminate {
            reason: EscalationReason::RetryBudgetExhausted
        }
    );
}

#[test]
fn actual_delivery_and_probe_verdicts_keep_the_existing_resource_meanings() {
    let marker = pending(4).mark_dispatch().expect("dispatch marker");
    for (verdict, expected) in [
        (
            DeliveryVerdict::Accepted,
            ReconcileState::Delivered { attempt: 2 },
        ),
        (
            DeliveryVerdict::DuplicateSuppressed,
            ReconcileState::Delivered { attempt: 2 },
        ),
        (
            DeliveryVerdict::TransientFailure,
            ReconcileState::Pending { attempt: 3 },
        ),
        (
            DeliveryVerdict::PermanentRejection,
            ReconcileState::Undeliverable {
                reason: TerminalFailureReason::PermanentDownstreamRejection,
            },
        ),
        (
            DeliveryVerdict::AmbiguousTimeout,
            ReconcileState::Probing { attempt: 2 },
        ),
    ] {
        let next = marker
            .observe(
                Observation::Delivery(verdict),
                b"actual transport evidence".to_vec(),
            )
            .expect("resource delivery verdict");
        assert_eq!(next.state(), expected);
        next.verify_successor_of(&marker)
            .expect("same immutable predecessor");
        reload(&next);
    }
    let ambiguous = marker
        .observe(
            Observation::Delivery(DeliveryVerdict::AmbiguousTimeout),
            b"timeout".to_vec(),
        )
        .expect("ambiguous");
    assert!(
        ambiguous
            .observe(
                Observation::Delivery(DeliveryVerdict::Accepted),
                b"invalid order".to_vec()
            )
            .is_err()
    );
    for (verdict, expected) in [
        (
            ProbeVerdict::Delivered,
            ReconcileState::Delivered { attempt: 2 },
        ),
        (
            ProbeVerdict::NotDelivered,
            ReconcileState::Pending { attempt: 3 },
        ),
        (
            ProbeVerdict::Unknown,
            ReconcileState::Indeterminate {
                reason: EscalationReason::ProbeContractViolation,
            },
        ),
    ] {
        let next = ambiguous
            .observe(Observation::Probe(verdict), b"probe evidence".to_vec())
            .expect("probe verdict");
        assert_eq!(next.state(), expected);
        reload(&next);
    }
    assert!(
        marker
            .observe(Observation::Delivery(DeliveryVerdict::Accepted), Vec::new())
            .is_err()
    );
    assert!(
        marker
            .observe(
                Observation::Delivery(DeliveryVerdict::PermanentRejection),
                Vec::new()
            )
            .is_err()
    );
}

/// Encodes planted malformed histories without calling their production writer
/// validation, so assertions exercise the decoder's independent refusal path.
struct Unchecked(CanonicalOutboxProgress);
impl CanonicalBody for Unchecked {
    const DOMAIN: DomainTag = CanonicalOutboxProgress::DOMAIN;
    const SCHEMA_FAMILY: SchemaFamily = CanonicalOutboxProgress::SCHEMA_FAMILY;
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;
    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.0.write_fields(out)
    }
    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        CanonicalOutboxProgress::read_payload(input).map(Self)
    }
}

fn refuses_decode(body: CanonicalOutboxProgress) {
    let planted = encode_body(&Unchecked(body)).expect("encode planted wire fields");
    assert!(decode_body::<CanonicalOutboxProgress>(&planted, DecodeLimits::DEFAULT).is_err());
}

#[test]
fn decoder_refuses_planted_illegal_history_state_pairs_and_fabricated_terminal_evidence() {
    let marker = pending(4).mark_dispatch().expect("valid marker");
    let mut invalid_key = marker.clone();
    invalid_key.delivery_key = AsciiSlug::from_static("not-a-canonical-delivery-key");
    refuses_decode(invalid_key);
    let valid = marker
        .observe(
            Observation::Delivery(DeliveryVerdict::Accepted),
            b"accepted".to_vec(),
        )
        .expect("valid terminal");
    reload(&valid);
    let mut missing_marker = valid.clone();
    missing_marker
        .predecessor
        .as_mut()
        .expect("predecessor")
        .dispatch_in_flight = false;
    refuses_decode(missing_marker);
    let mut wrong_result = valid.clone();
    wrong_result.state = ReconcileState::Pending { attempt: 2 };
    refuses_decode(wrong_result);
    let mut skipped_attempt = valid.clone();
    skipped_attempt.attempt = 3;
    skipped_attempt.state = ReconcileState::Delivered { attempt: 3 };
    refuses_decode(skipped_attempt);
    let mut skipped_ordinal = valid.clone();
    skipped_ordinal.ordinal += 1;
    refuses_decode(skipped_ordinal);
    let mut missing_evidence = valid;
    missing_evidence.evidence.clear();
    refuses_decode(missing_evidence);
    let mut false_genesis = start(4);
    false_genesis.state = ReconcileState::Delivered { attempt: 1 };
    false_genesis.evidence = b"not observed".to_vec();
    refuses_decode(false_genesis);
}

#[test]
fn exact_predecessor_verification_refuses_cross_obligation_and_changed_policy_histories() {
    let previous = pending(4);
    let valid = previous.mark_dispatch().expect("valid marker");
    valid
        .verify_successor_of(&previous)
        .expect("authentic predecessor");
    let mut changed_policy = valid.clone();
    changed_policy.max_attempts = 5;
    reload(&changed_policy); // Local transition is legal; chain binding is not.
    assert!(changed_policy.verify_successor_of(&previous).is_err());
    let mut substituted_root = valid.clone();
    substituted_root
        .predecessor
        .as_mut()
        .expect("predecessor")
        .root = digest_of(99);
    reload(&substituted_root);
    assert!(substituted_root.verify_successor_of(&previous).is_err());
    let mut other_obligation = valid;
    other_obligation.origin_effect_root = digest_of(98);
    reload(&other_obligation);
    assert!(other_obligation.verify_successor_of(&previous).is_err());
}

#[test]
fn stable_identity_covers_every_semantic_binding_and_actual_observation() {
    let initial = start(4);
    let original = initial.root().expect("initial root");
    let mut variants = Vec::new();
    let mut changed = initial.clone();
    changed.repository_id = RepositoryId::from_bytes([9; 16]);
    variants.push(changed);
    let mut changed = initial.clone();
    changed.delivery_key =
        AsciiSlug::from_static("1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    variants.push(changed);
    let mut changed = initial.clone();
    changed.destination = AsciiSlug::from_static("other-projection");
    variants.push(changed);
    let mut changed = initial.clone();
    changed.payload_root = digest_of(12);
    variants.push(changed);
    let mut changed = initial.clone();
    changed.origin_effect_root = digest_of(13);
    variants.push(changed);
    let mut changed = initial.clone();
    changed.max_attempts = 5;
    variants.push(changed);
    for changed in variants {
        assert_ne!(changed.root().expect("changed root"), original);
        reload(&changed);
    }
    let marker = pending(4).mark_dispatch().expect("marker");
    let accepted = marker
        .observe(
            Observation::Delivery(DeliveryVerdict::Accepted),
            b"receipt one".to_vec(),
        )
        .expect("accepted");
    let duplicate = marker
        .observe(
            Observation::Delivery(DeliveryVerdict::DuplicateSuppressed),
            b"receipt one".to_vec(),
        )
        .expect("duplicate");
    let other_evidence = marker
        .observe(
            Observation::Delivery(DeliveryVerdict::Accepted),
            b"receipt two".to_vec(),
        )
        .expect("different evidence");
    assert_eq!(accepted.state(), duplicate.state());
    assert_ne!(
        accepted.root().expect("root"),
        duplicate.root().expect("observation root")
    );
    assert_ne!(
        accepted.root().expect("root"),
        other_evidence.root().expect("evidence root")
    );
    assert_eq!(
        accepted,
        marker
            .observe(
                Observation::Delivery(DeliveryVerdict::Accepted),
                b"receipt one".to_vec()
            )
            .expect("identical retry")
    );
    let frame = encode_body(&accepted).expect("frame");
    assert!(
        decode_body::<fgit_codec::CanonicalOutboxDeliveryReceipt>(&frame, DecodeLimits::DEFAULT)
            .is_err()
    );
}

#[test]
fn counts_and_declared_evidence_are_bounded_before_reading_unavailable_bytes() {
    reload(&start(MAX_OUTBOX_PROGRESS_ATTEMPTS));
    let mut oversized = start(4);
    oversized.max_attempts = MAX_OUTBOX_PROGRESS_ATTEMPTS + 1;
    refuses_decode(oversized);
    let mut zero = start(4);
    zero.max_attempts = 0;
    refuses_decode(zero);
    let mut too_long = pending(4).mark_dispatch().expect("marker");
    too_long.ordinal = MAX_OUTBOX_PROGRESS_TRANSITIONS + 1;
    too_long.predecessor.as_mut().expect("predecessor").ordinal = MAX_OUTBOX_PROGRESS_TRANSITIONS;
    refuses_decode(too_long);
    let marker = pending(4).mark_dispatch().expect("marker");
    let full = marker
        .observe(
            Observation::Delivery(DeliveryVerdict::Accepted),
            vec![7; MAX_OUTBOX_PROGRESS_EVIDENCE_BYTES],
        )
        .expect("exact evidence ceiling");
    reload(&full);
    assert!(
        marker
            .observe(
                Observation::Delivery(DeliveryVerdict::Accepted),
                vec![7; MAX_OUTBOX_PROGRESS_EVIDENCE_BYTES + 1]
            )
            .is_err()
    );
    let mut payload = Encoder::new();
    full.write_fields(&mut payload).expect("payload fields");
    let mut bytes = payload.into_bytes();
    let length_offset = bytes.len() - MAX_OUTBOX_PROGRESS_EVIDENCE_BYTES - 4;
    bytes.truncate(length_offset);
    bytes.extend_from_slice(&((MAX_OUTBOX_PROGRESS_EVIDENCE_BYTES + 1) as u32).to_be_bytes());
    let mut input = Decoder::new(&bytes, DecodeLimits::DEFAULT);
    assert!(matches!(
        CanonicalOutboxProgress::read_payload(&mut input),
        Err(CodecRefusal::LengthBoundExceeded {
            field: "outbox_progress_evidence",
            ..
        })
    ));
}

#[test]
fn state_and_observation_wire_tags_are_closed() {
    let mut state = Encoder::new();
    state.write_scalar(5_u16);
    state.write_scalar(1_u32);
    assert!(read_state(&mut Decoder::new(state.as_bytes(), DecodeLimits::DEFAULT)).is_err());
    let mut reason = Encoder::new();
    reason.write_scalar(4_u16);
    reason.write_scalar(4_u32);
    assert!(read_state(&mut Decoder::new(reason.as_bytes(), DecodeLimits::DEFAULT)).is_err());
    let mut observation = Encoder::new();
    observation.write_scalar(8_u16);
    assert!(
        read_observation(&mut Decoder::new(
            observation.as_bytes(),
            DecodeLimits::DEFAULT
        ))
        .is_err()
    );
}
