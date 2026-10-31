use super::tests::{actor, policy};
use super::*;
use fgit_codec::{DecodeLimits, decode_body, encode_body};

const AUTHENTICATED: &str = "policy release { rule credential { when actor.id == \"33333333333333333333333333333333\" and actor.authentication >= single_factor then allow } default deny \"verified credential required\" }";

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
fn authenticated_policy_requires_kind_18_and_exact_canonical_snapshot() {
    let policy = compile_ref_policy(AUTHENTICATED).unwrap();
    assert_eq!(
        ref_policy_profile_name(&policy).unwrap(),
        "reference_authentication_v1"
    );
    assert_eq!(
        decode_ref_policy(&policy.encode().unwrap()).unwrap(),
        policy
    );
    let event = event(installed(AUTHENTICATED));
    assert_eq!(event.payload.kind(), 18);
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
    let mut input = Decoder::new(&payload, DecodeLimits::DEFAULT);
    assert_eq!(
        NativeProtectionEvent::read_with_authentication_policy(&mut input).unwrap(),
        *change
    );
    input.finish().unwrap();
}

#[test]
fn historical_profiles_cannot_be_relabelled_as_authentication_events() {
    for (source, kind) in [
        ("policy p { default allow }", 16),
        (
            "policy p { rule owner { when actor.id == \"33333333333333333333333333333333\" then allow } default deny \"owner\" }",
            17,
        ),
    ] {
        let event = event(installed(source));
        assert_eq!(event.payload.kind(), kind);
        let frame = encode_body(&event).unwrap();
        assert_eq!(
            encode_body(&decode_body::<ForgeEvent>(&frame, DecodeLimits::DEFAULT).unwrap())
                .unwrap(),
            frame
        );
        let ForgeEventPayload::ReviewProtectionChanged(change) = &event.payload else {
            panic!("protection")
        };
        let mut payload = Encoder::new();
        change.write(&mut payload).unwrap();
        assert!(
            NativeProtectionEvent::read_with_authentication_policy(&mut Decoder::new(
                &payload.into_bytes(),
                DecodeLimits::DEFAULT
            ))
            .is_err()
        );
    }
}

#[test]
fn authentication_activation_keeps_administrator_epoch_and_fact_boundaries() {
    let previous = event(policy());
    let epoch = PolicyEpoch::FIRST.next().unwrap();
    let command = ProtectionCommand {
        expected_version: ExpectedVersion::Exactly(previous.version),
        expected_epoch: epoch,
        protection: installed(AUTHENTICATED),
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
        "actor.kind == human",
        "actor.teams contains release",
        "actor.snapshot == \"unknown\"",
        "ref.update == fast_forward",
    ] {
        let source = format!(
            "policy p {{ rule r {{ when actor.authentication >= single_factor and not ({predicate}) then allow }} default allow }}"
        );
        assert!(compile_ref_policy(&source).is_err());
        let raw = fgit_policy::compile_and_seal(&source)
            .unwrap()
            .encode()
            .unwrap();
        assert!(decode_ref_policy(&raw).is_err());
    }
}
