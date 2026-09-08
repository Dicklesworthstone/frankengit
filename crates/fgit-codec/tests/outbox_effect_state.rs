#![forbid(unsafe_code)]
//! Canonical-body and shared-lifecycle evidence only, not node delivery proof.

use fgit_codec::{
    CanonicalBody, CanonicalOutboxEffectState, CanonicalOutboxState, CodecRefusal,
    DecodeLimits, Decoder, Encoder, MAX_OUTBOX_EFFECT_TRANSITIONS, decode_body, encode_body,
};
use fgit_resource::{LifecycleEvent, ObligationState};
use fgit_types::{
    AsciiSlug, CANONICAL_CODEC_VERSION, Digest, DigestAlgorithmId, DigestBytes, RepositoryId, TxId,
};

fn digest(byte: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(2).expect("registered SHA-256"),
        DigestBytes::try_new(&[byte; 32]).expect("SHA-256 width"),
    )
}

fn tx(byte: u8) -> TxId {
    let digest = digest(byte);
    TxId::from_digest(digest.algorithm(), CANONICAL_CODEC_VERSION, *digest.bytes())
}

fn committed() -> CanonicalOutboxEffectState {
    CanonicalOutboxEffectState::committed(
        RepositoryId::from_bytes([1; 16]), AsciiSlug::from_static("delivery"), tx(2), digest(3),
    )
}

fn roundtrip(body: &CanonicalOutboxEffectState) {
    let frame = encode_body(body).expect("valid canonical body encodes");
    let decoded = decode_body::<CanonicalOutboxEffectState>(&frame, DecodeLimits::DEFAULT)
        .expect("valid canonical body strictly decodes");
    assert_eq!(&decoded, body);
    assert_eq!(encode_body(&decoded).expect("re-encode"), frame);
    assert_eq!(decoded.root().expect("decoded root"), body.root().expect("root"));
}

#[test]
fn committed_and_acknowledged_bodies_round_trip_with_exact_predecessor_identity() {
    let initial = committed();
    assert_eq!(initial.state(), ObligationState::Committed);
    assert_eq!(initial.transition_ordinal(), 0);
    assert_eq!(initial.predecessor_root(), None);
    assert_eq!(initial.predecessor_state(), None);
    assert_eq!(initial.event(), None);
    assert_eq!(initial.evidence_root(), None);
    roundtrip(&initial);

    let acknowledged = initial.transition(LifecycleEvent::Acknowledge, Some(digest(4)))
        .expect("committed obligation accepts observation evidence");
    assert_eq!(acknowledged.state(), ObligationState::Acknowledged);
    assert_eq!(acknowledged.transition_ordinal(), 1);
    assert_eq!(acknowledged.predecessor_root(), Some(initial.root().expect("initial root")));
    assert_eq!(acknowledged.predecessor_state(), Some(ObligationState::Committed));
    assert_eq!(acknowledged.event(), Some(LifecycleEvent::Acknowledge));
    assert_eq!(acknowledged.evidence_root(), Some(digest(4)));
    assert_eq!(acknowledged.repository_id(), initial.repository_id());
    assert_eq!(acknowledged.delivery_key(), initial.delivery_key());
    assert_eq!(acknowledged.tx_id(), initial.tx_id());
    assert_eq!(acknowledged.payload_root(), initial.payload_root());
    assert_ne!(acknowledged.root().expect("ack root"), initial.root().expect("initial root"));
    roundtrip(&acknowledged);
    assert_eq!(
        initial.transition(LifecycleEvent::Acknowledge, Some(digest(4))).expect("identical retry"),
        acknowledged,
    );
}

#[test]
fn deferred_escalated_and_terminal_paths_use_the_shared_lifecycle() {
    let initial = committed();
    let deferred = initial.transition(LifecycleEvent::Defer, None).expect("defer");
    let escalated = deferred.transition(LifecycleEvent::Escalate, Some(digest(8))).expect("escalate");
    assert_eq!(deferred.state(), ObligationState::DeferredExternally);
    assert_eq!(escalated.state(), ObligationState::Escalated);
    assert_eq!(escalated.predecessor_root(), Some(deferred.root().expect("root")));
    roundtrip(&deferred);
    roundtrip(&escalated);
    for source in [&initial, &deferred, &escalated] {
        for (event, evidence) in [
            (LifecycleEvent::Acknowledge, Some(digest(9))),
            (LifecycleEvent::FailTerminally, Some(digest(10))),
            (LifecycleEvent::Leak, None),
        ] {
            let shared = source.state().apply(event);
            let persisted = source.transition(event, evidence);
            match shared {
                Ok(expected) => {
                    let actual = persisted.expect("shared legal transition persists");
                    assert_eq!(actual.state(), expected);
                    roundtrip(&actual);
                    assert!(actual.transition(LifecycleEvent::Acknowledge, Some(digest(11))).is_err());
                }
                Err(_) => assert!(persisted.is_err()),
            }
        }
    }
    let terminal = escalated.transition(LifecycleEvent::Acknowledge, Some(digest(12))).expect("settle");
    assert_eq!(terminal.transition_ordinal(), MAX_OUTBOX_EFFECT_TRANSITIONS);
    assert!(initial.transition(LifecycleEvent::Acknowledge, None).is_err());
    assert!(initial.transition(LifecycleEvent::Commit, None).is_err());
    assert!(initial.transition(LifecycleEvent::Abort, None).is_err());
    assert!(initial.transition(LifecycleEvent::Escalate, None).is_err());
}

#[test]
fn semantic_inputs_history_and_acknowledgement_evidence_change_identity() {
    let initial = committed();
    let variants = [
        CanonicalOutboxEffectState::committed(RepositoryId::from_bytes([2; 16]), initial.delivery_key(), initial.tx_id(), initial.payload_root()),
        CanonicalOutboxEffectState::committed(initial.repository_id(), AsciiSlug::from_static("other-delivery"), initial.tx_id(), initial.payload_root()),
        CanonicalOutboxEffectState::committed(initial.repository_id(), initial.delivery_key(), tx(4), initial.payload_root()),
        CanonicalOutboxEffectState::committed(initial.repository_id(), initial.delivery_key(), initial.tx_id(), digest(5)),
    ];
    for changed in variants {
        assert_ne!(initial.root().expect("root"), changed.root().expect("changed root"));
        roundtrip(&changed);
    }
    let direct = initial.transition(LifecycleEvent::Acknowledge, Some(digest(6))).expect("ack");
    let changed_evidence = initial.transition(LifecycleEvent::Acknowledge, Some(digest(7))).expect("ack");
    let deferred = initial.transition(LifecycleEvent::Defer, Some(digest(8))).expect("defer");
    let via_deferred = deferred.transition(LifecycleEvent::Acknowledge, Some(digest(6))).expect("ack");
    let changed_predecessor = initial.transition(LifecycleEvent::Defer, Some(digest(9))).expect("defer")
        .transition(LifecycleEvent::Acknowledge, Some(digest(6))).expect("ack");
    assert_ne!(direct.root().expect("root"), changed_evidence.root().expect("changed evidence root"));
    assert_ne!(direct.root().expect("root"), via_deferred.root().expect("changed history root"));
    assert_eq!(via_deferred.state(), changed_predecessor.state());
    assert_eq!(via_deferred.event(), changed_predecessor.event());
    assert_eq!(via_deferred.evidence_root(), changed_predecessor.evidence_root());
    assert_ne!(via_deferred.predecessor_root(), changed_predecessor.predecessor_root());
    assert_ne!(via_deferred.root().expect("root"), changed_predecessor.root().expect("changed predecessor root"));
    let encoded = encode_body(&initial).expect("frame");
    assert!(matches!(decode_body::<CanonicalOutboxState>(&encoded, DecodeLimits::DEFAULT),
        Err(CodecRefusal::SchemaFamilyUnexpected { .. })));
}

/// Independent wire constructor for adversarial states the public API cannot
/// build. Tags below pin schema v1 rather than using its private encoding map.
struct WireState {
    ordinal: u32,
    state: u16,
    predecessor_root: Option<Digest>,
    predecessor_state: Option<u16>,
    event: Option<u16>,
    evidence: Option<Digest>,
}

impl WireState {
    fn acknowledged() -> Self {
        Self { ordinal: 1, state: 4, predecessor_root: Some(committed().root().expect("root")),
            predecessor_state: Some(1), event: Some(2), evidence: Some(digest(4)) }
    }

    fn payload(&self) -> Vec<u8> {
        let initial = committed();
        let mut out = Encoder::new();
        out.write_opaque_id(initial.repository_id().as_bytes());
        out.write_bytes("delivery_key", initial.delivery_key().as_bytes()).expect("slug");
        out.write_internal_object_id(initial.tx_id().as_internal_object_id()).expect("tx");
        out.write_digest(&initial.payload_root()).expect("payload");
        out.write_scalar(self.ordinal);
        out.write_scalar(self.state);
        out.write_option(self.predecessor_root.as_ref(), Encoder::write_digest).expect("predecessor");
        out.write_option(self.predecessor_state.as_ref(), |out, state| { out.write_scalar(*state); Ok(()) }).expect("state");
        out.write_option(self.event.as_ref(), |out, event| { out.write_scalar(*event); Ok(()) }).expect("event");
        out.write_option(self.evidence.as_ref(), Encoder::write_digest).expect("evidence");
        out.into_bytes()
    }

    fn decode(&self) -> Result<CanonicalOutboxEffectState, CodecRefusal> {
        let payload = self.payload();
        let mut decoder = Decoder::new(&payload, DecodeLimits::DEFAULT);
        let body = CanonicalOutboxEffectState::read_payload(&mut decoder)?;
        decoder.finish()?;
        Ok(body)
    }
}

#[test]
fn schema_v1_wire_layout_matches_the_public_acknowledgement() {
    let wire = WireState::acknowledged();
    let body = committed().transition(LifecycleEvent::Acknowledge, Some(digest(4))).expect("ack");
    let mut encoded = Encoder::new();
    body.write_payload(&mut encoded).expect("payload");
    assert_eq!(wire.payload(), encoded.into_bytes());
    assert_eq!(wire.decode().expect("independent wire reads"), body);
}

#[test]
fn planted_illegal_and_incomplete_histories_are_refused_by_the_real_decoder() {
    let mutations: &[fn(&mut WireState)] = &[
        |wire| wire.predecessor_state = Some(0), // acknowledge before commit
        |wire| wire.predecessor_state = Some(4), // terminal state cannot advance
        |wire| wire.state = 1, // acknowledged event claims committed result
        |wire| wire.event = Some(0), // second commit
        |wire| wire.event = Some(99), // closed event vocabulary
        |wire| wire.state = 99, // closed state vocabulary
        |wire| wire.predecessor_root = None,
        |wire| wire.predecessor_state = None,
        |wire| wire.event = None,
        |wire| wire.evidence = None,
        |wire| wire.ordinal = 0, // genesis cannot already be acknowledged
        |wire| wire.ordinal = 2, // committed predecessor must have ordinal zero
    ];
    for (index, mutate) in mutations.iter().enumerate() {
        let mut wire = WireState::acknowledged();
        mutate(&mut wire);
        assert!(wire.decode().is_err(), "planted invalid history {index} must refuse");
        assert!(WireState::acknowledged().decode().is_ok(), "adjacent legal history remains accepted");
    }
    let mut bounded = WireState::acknowledged();
    bounded.ordinal = MAX_OUTBOX_EFFECT_TRANSITIONS + 1;
    assert!(matches!(bounded.decode(), Err(CodecRefusal::CountBoundExceeded {
        field: "outbox_effect_transition_ordinal", observed: 4, limit: 3,
    })));
    let mut payload = WireState::acknowledged().payload();
    payload.pop();
    assert!(matches!(CanonicalOutboxEffectState::read_payload(&mut Decoder::new(&payload, DecodeLimits::DEFAULT)),
        Err(CodecRefusal::InputTruncated { .. })));
}
