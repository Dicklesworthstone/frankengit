use super::tests::{actor, policy};
use super::*;
use fgit_codec::{DecodeLimits, decode_body, encode_body};

const AGENT: &str = "policy release { rule agent { when actor.kind == agent and actor.authentication >= single_factor then allow } default deny \"authenticated agent required\" }";

fn installed(source: &str) -> ReviewProtection {
    let mut value = policy();
    value.ref_policy = Some(compile_ref_policy(source).unwrap());
    value
}

fn event(protection: ReviewProtection) -> ForgeEvent {
    ProtectionCommand {
        expected_version: ExpectedVersion::NewStream,
        expected_epoch: PolicyEpoch::FIRST,
        protection,
    }
    .proposed_event(actor(1))
    .unwrap()
}

#[test]
fn principal_kind_policy_requires_kind_28_and_exact_canonical_snapshot() {
    let policy = compile_ref_policy(AGENT).unwrap();
    assert_eq!(
        ref_policy_profile_name(&policy).unwrap(),
        "reference_principal_kind_v1"
    );
    assert_eq!(
        decode_ref_policy(&policy.encode().unwrap()).unwrap(),
        policy
    );
    let event = event(installed(AGENT));
    assert_eq!(event.payload.kind(), 28);
    let frame = encode_body(&event).unwrap();
    let decoded = decode_body::<ForgeEvent>(&frame, DecodeLimits::DEFAULT).unwrap();
    assert_eq!(decoded, event);
    assert_eq!(encode_body(&decoded).unwrap(), frame);
    for size in [0, 1, frame.len() / 2, frame.len() - 1] {
        assert!(decode_body::<ForgeEvent>(&frame[..size], DecodeLimits::DEFAULT).is_err());
    }
    let mut suffix = frame;
    suffix.push(0);
    assert!(decode_body::<ForgeEvent>(&suffix, DecodeLimits::DEFAULT).is_err());

    let ForgeEventPayload::ReviewProtectionChanged(change) = &event.payload else {
        panic!("protection")
    };
    let mut payload = Encoder::new();
    change.write(&mut payload).unwrap();
    let payload = payload.into_bytes();
    assert!(
        NativeProtectionEvent::read_with_policy(&mut Decoder::new(&payload, DecodeLimits::DEFAULT))
            .is_err()
    );
    assert!(
        NativeProtectionEvent::read_with_actor_policy(&mut Decoder::new(
            &payload,
            DecodeLimits::DEFAULT
        ))
        .is_err()
    );
    assert!(
        NativeProtectionEvent::read_with_authentication_policy(&mut Decoder::new(
            &payload,
            DecodeLimits::DEFAULT
        ))
        .is_err()
    );
    let mut input = Decoder::new(&payload, DecodeLimits::DEFAULT);
    assert_eq!(
        NativeProtectionEvent::read_with_principal_kind_policy(&mut input).unwrap(),
        *change,
    );
    input.finish().unwrap();
}

#[test]
fn historical_profiles_cannot_be_relabelled_as_principal_kind_events() {
    for (source, kind) in [
        ("policy p { default allow }", 16),
        (
            "policy p { rule r { when actor.id == \"33333333333333333333333333333333\" then allow } default deny \"owner\" }",
            17,
        ),
        (
            "policy p { rule r { when actor.authentication >= single_factor then allow } default deny \"credential\" }",
            18,
        ),
    ] {
        let event = event(installed(source));
        assert_eq!(event.payload.kind(), kind);
        let frame = encode_body(&event).unwrap();
        assert_eq!(
            encode_body(&decode_body::<ForgeEvent>(&frame, DecodeLimits::DEFAULT).unwrap())
                .unwrap(),
            frame,
        );
        let ForgeEventPayload::ReviewProtectionChanged(change) = &event.payload else {
            panic!("protection")
        };
        let mut payload = Encoder::new();
        change.write(&mut payload).unwrap();
        assert!(
            NativeProtectionEvent::read_with_principal_kind_policy(&mut Decoder::new(
                &payload.into_bytes(),
                DecodeLimits::DEFAULT
            ))
            .is_err()
        );
    }
}

#[test]
fn principal_kind_activation_preserves_administrator_epoch_and_fact_boundaries() {
    let previous = event(policy());
    let epoch = PolicyEpoch::FIRST.next().unwrap();
    let command = ProtectionCommand {
        expected_version: ExpectedVersion::Exactly(previous.version),
        expected_epoch: epoch,
        protection: installed(AGENT),
    };
    let next = command.proposed_event(actor(1)).unwrap();
    validate_transition(Some(&previous), &next, epoch).unwrap();
    assert_eq!(
        validate_transition(Some(&previous), &next, PolicyEpoch::FIRST),
        Err(RefusalCode::EvidenceStale),
    );
    assert_eq!(
        validate_transition(
            Some(&previous),
            &command.proposed_event(actor(9)).unwrap(),
            epoch
        ),
        Err(RefusalCode::ProtectedRefTransitionDenied),
    );
    for predicate in [
        "actor.teams contains release",
        "actor.capabilities contains release",
        "actor.snapshot == \"unknown\"",
        "ref.update == fast_forward",
        "ref.force_requested",
    ] {
        let source = format!(
            "policy p {{ rule r {{ when actor.kind == human and not ({predicate}) then allow }} default allow }}"
        );
        assert!(compile_ref_policy(&source).is_err());
        let frame = fgit_policy::compile_and_seal(&source)
            .unwrap()
            .encode()
            .unwrap();
        assert!(decode_ref_policy(&frame).is_err());
    }
}
