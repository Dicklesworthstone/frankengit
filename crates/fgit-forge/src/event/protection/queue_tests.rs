//! Required queues extend canonical protection without reinterpreting old bytes.
use super::tests::{actor, policy, required_check};
use super::*;
use fgit_codec::{DecodeLimits, decode_body, encode_body};

const PROFILES: [(u32, &str); 3] = [
    (16, "policy p { default allow }"),
    (
        17,
        "policy p { rule owner { when actor.id == \"33333333333333333333333333333333\" then allow } default deny \"owner\" }",
    ),
    (
        18,
        "policy p { rule verified { when actor.authentication >= single_factor then allow } default deny \"credential\" }",
    ),
];

fn event(protection: ReviewProtection) -> ForgeEvent {
    ProtectionCommand {
        expected_version: ExpectedVersion::NewStream,
        expected_epoch: PolicyEpoch::FIRST,
        protection,
    }
    .proposed_event(actor(1))
    .unwrap()
}

fn change(event: &ForgeEvent) -> &NativeProtectionEvent {
    let ForgeEventPayload::ReviewProtectionChanged(value) = &event.payload else {
        panic!("expected protection");
    };
    value
}

fn payload(event: &ForgeEvent) -> Vec<u8> {
    let mut out = Encoder::new();
    change(event).write(&mut out).unwrap();
    out.into_bytes()
}

fn read_payload(kind: u32, bytes: &[u8]) -> Result<NativeProtectionEvent, CodecRefusal> {
    let mut input = Decoder::new(bytes, DecodeLimits::DEFAULT);
    let value = match kind {
        9 => NativeProtectionEvent::read(&mut input, false, false, false),
        13 => NativeProtectionEvent::read(&mut input, true, false, false),
        14 => NativeProtectionEvent::read(&mut input, true, true, false),
        16 => NativeProtectionEvent::read_with_policy(&mut input),
        17 => NativeProtectionEvent::read_with_actor_policy(&mut input),
        18 => NativeProtectionEvent::read_with_authentication_policy(&mut input),
        19 => NativeProtectionEvent::read(&mut input, true, true, true),
        _ => panic!("test kind"),
    }?;
    input.finish()?;
    Ok(value)
}

fn hex(text: &str) -> Vec<u8> {
    let (pairs, suffix) = text.as_bytes().as_chunks::<2>();
    assert!(suffix.is_empty());
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn queue_only() -> ReviewProtection {
    let mut value = policy();
    value.branches[0].reviewers.clear();
    value.branches[0].required_approvals = 0;
    value.branches[0].require_merge_queue = true;
    value
}

#[test]
fn every_historical_protection_kind_keeps_its_body_and_defaults_queue_to_false() {
    // Frozen historical body fields, independent of the production writer.
    const PREFIX: &str = concat!(
        "01010101010101010101010101010101", // actor
        "0000000000000001",                 // epoch
        "00000001",
        "01010101010101010101010101010101", // administrator
        "00000001",
        "0000000f726566732f68656164732f6d61696e", // main
    );
    const REVIEWERS: &str = concat!(
        "03030303030303030303030303030303",
        "04040404040404040404040404040404",
    );
    const CHECK: &str = concat!(
        "00000001",
        "00000017726566732f68656164732f63692d63616e646964617465",
        "07070707070707070707070707070707",
        "5151515151515151515151515151515151515151515151515151515151515151",
        "0000000e6275696c643a6c696e757820cebb",
    );
    let unanimous = policy();
    let mut checked = policy();
    checked.branches[0].required_checks.push(required_check());
    let mut quorum = policy();
    quorum.branches[0].reviewers.push(actor(5));
    let frozen = [
        (
            9_u32,
            unanimous,
            hex(&format!("{PREFIX}00000002{REVIEWERS}")),
        ),
        (
            13,
            checked,
            hex(&format!("{PREFIX}00000002{REVIEWERS}{CHECK}")),
        ),
        (
            14,
            quorum,
            hex(&format!(
                "{PREFIX}00000003{REVIEWERS}05050505050505050505050505050505000200000000"
            )),
        ),
    ];
    for (base, settings, original) in frozen {
        let plain = event(settings.clone());
        assert_eq!(plain.payload.kind(), base);
        assert_eq!(payload(&plain), original);
        assert_eq!(read_payload(base, &original).unwrap(), *change(&plain));
        for (outer, source) in PROFILES {
            let mut wrapped = settings.clone();
            let snapshot = compile_ref_policy(source).unwrap();
            let frame = snapshot.encode().unwrap();
            wrapped.ref_policy = Some(snapshot);
            let expected = event(wrapped);
            assert_eq!(expected.payload.kind(), outer);
            let mut historical = base.to_be_bytes().to_vec();
            historical.extend_from_slice(&original);
            historical.extend_from_slice(&(frame.len() as u32).to_be_bytes());
            historical.extend_from_slice(&frame);
            assert_eq!(payload(&expected), historical);
            let decoded = read_payload(outer, &historical).unwrap();
            assert_eq!(decoded, *change(&expected));
            assert!(!decoded.protection.has_required_merge_queue());
            assert!(
                decoded
                    .protection
                    .branches
                    .iter()
                    .all(|branch| !branch.require_merge_queue)
            );
            let encoded = encode_body(&expected).unwrap();
            let roundtrip = decode_body::<ForgeEvent>(&encoded, DecodeLimits::DEFAULT).unwrap();
            assert_eq!(encode_body(&roundtrip).unwrap(), encoded);
        }
    }
}

#[test]
fn queue_only_policy_is_a_required_new_kind_with_complete_bounded_roundtrip() {
    let expected = event(queue_only());
    assert_eq!(expected.payload.kind(), 19);
    assert!(!change(&expected).protection.has_required_checks());
    assert!(!change(&expected).protection.has_review_quorum());
    assert!(change(&expected).protection.has_required_merge_queue());
    let body = payload(&expected);
    // Empty reviewers, explicit zero approvals/checks, then canonical true.
    assert!(body.ends_with(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
    assert_eq!(read_payload(19, &body).unwrap(), *change(&expected));
    let frame = encode_body(&expected).unwrap();
    assert_eq!(
        decode_body::<ForgeEvent>(&frame, DecodeLimits::DEFAULT).unwrap(),
        expected
    );
    for length in 0..frame.len() {
        assert!(decode_body::<ForgeEvent>(&frame[..length], DecodeLimits::DEFAULT).is_err());
    }
    let mut extra = frame;
    extra.push(0);
    assert!(decode_body::<ForgeEvent>(&extra, DecodeLimits::DEFAULT).is_err());
    for old_kind in [9, 13, 14] {
        assert!(
            read_payload(old_kind, &body).is_err(),
            "kind {old_kind} accepted a queue body"
        );
    }
}

#[test]
fn mixed_queue_quorum_check_and_raw_ref_rules_keep_every_restriction() {
    let mut settings = policy();
    settings.branches[0].require_merge_queue = true;
    settings.branches[0].reviewers.push(actor(5));
    settings.branches[0].required_checks.push(required_check());
    settings.branches.push(ProtectedBranch {
        name: RefName::try_new(b"refs/heads/release").unwrap(),
        reviewers: Vec::new(),
        required_approvals: 0,
        required_checks: vec![required_check()],
        require_merge_queue: false,
    });
    settings.branches.push(ProtectedBranch {
        name: RefName::try_new(b"refs/heads/\xffqueue").unwrap(),
        reviewers: Vec::new(),
        required_approvals: 0,
        required_checks: Vec::new(),
        require_merge_queue: true,
    });
    let expected = event(settings);
    assert_eq!(expected.payload.kind(), 19);
    let encoded = encode_body(&expected).unwrap();
    let decoded = decode_body::<ForgeEvent>(&encoded, DecodeLimits::DEFAULT).unwrap();
    assert_eq!(decoded, expected);
    assert_eq!(encode_body(&decoded).unwrap(), encoded);
    let branches = &change(&decoded).protection.branches;
    assert_eq!(
        branches
            .iter()
            .map(|rule| rule.require_merge_queue)
            .collect::<Vec<_>>(),
        [true, false, true]
    );
    assert_eq!(branches[0].required_approvals, 2);
    assert_eq!(branches[0].reviewers.len(), 3);
    assert_eq!(branches[0].required_checks, vec![required_check()]);
    assert_eq!(branches[2].name.as_bytes(), b"refs/heads/\xffqueue");
    let mut changed = change(&expected).protection.clone();
    changed.branches[1].require_merge_queue = true;
    let changed = event(changed);
    assert_eq!(changed.payload.kind(), 19);
    assert_ne!(encode_body(&changed).unwrap(), encoded);
}

#[test]
fn queue_flag_changes_identity_and_redundant_or_non_boolean_encodings_refuse() {
    let old = event(policy());
    let mut settings = policy();
    settings.branches[0].require_merge_queue = true;
    let required = event(settings);
    assert_ne!(encode_body(&old).unwrap(), encode_body(&required).unwrap());
    let body = payload(&required);
    assert_eq!(body.last(), Some(&1));
    for byte in [0, 2, 255] {
        let mut invalid = body.clone();
        *invalid.last_mut().unwrap() = byte;
        assert!(read_payload(19, &invalid).is_err(), "accepted flag {byte}");
    }
    // Dropping an explicit true cannot manufacture a historical quorum: this
    // underlying rule is unanimous, so kind 14 remains noncanonical too.
    assert!(read_payload(14, &body[..body.len() - 1]).is_err());
    assert!(read_payload(19, &body[..body.len() - 1]).is_err());
}

#[test]
fn queue_wrappers_bind_the_exact_base_and_existing_dsl_profile() {
    for (kind, source) in PROFILES {
        let mut settings = queue_only();
        settings.ref_policy = Some(compile_ref_policy(source).unwrap());
        let expected = event(settings);
        assert_eq!(expected.payload.kind(), kind);
        let body = payload(&expected);
        assert_eq!(&body[..4], &19_u32.to_be_bytes());
        assert_eq!(read_payload(kind, &body).unwrap(), *change(&expected));
        let flag_offset = 4 + payload(&event(queue_only())).len() - 1;
        assert_eq!(body[flag_offset], 1);
        for flag in [0, 2, 255] {
            let mut invalid = body.clone();
            invalid[flag_offset] = flag;
            assert!(read_payload(kind, &invalid).is_err());
        }
        for (other, _) in PROFILES {
            if other != kind {
                assert!(
                    read_payload(other, &body).is_err(),
                    "profile {kind} relabelled {other}"
                );
            }
        }
        for base in [9_u32, 13, 14, 20, u32::MAX] {
            let mut invalid = body.clone();
            invalid[..4].copy_from_slice(&base.to_be_bytes());
            assert!(
                read_payload(kind, &invalid).is_err(),
                "accepted base {base}"
            );
        }
        let frame = encode_body(&expected).unwrap();
        let decoded = decode_body::<ForgeEvent>(&frame, DecodeLimits::DEFAULT).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(encode_body(&decoded).unwrap(), frame);
    }
}

#[test]
fn queue_only_rules_do_not_weaken_review_check_or_branch_bounds() {
    let mut settings = queue_only();
    settings.validate().unwrap();
    settings.branches[0].require_merge_queue = false;
    assert!(settings.validate().is_err());
    settings = queue_only();
    settings.branches[0].required_approvals = 1;
    assert!(settings.validate().is_err());
    settings = queue_only();
    settings.branches[0].reviewers.push(actor(3));
    assert!(settings.validate().is_err());
    settings.branches[0].required_approvals = 1;
    settings.validate().unwrap();
    settings.branches[0].required_approvals = 2;
    assert!(settings.validate().is_err());
    settings = queue_only();
    settings.branches[0].required_checks.push(required_check());
    settings.branches[0].required_checks[0].job.clear();
    assert!(settings.validate().is_err());
    settings = queue_only();
    settings.branches.push(settings.branches[0].clone());
    assert!(settings.validate().is_err());
    settings = queue_only();
    settings.branches[0].name = RefName::try_new(b"refs/tags/release").unwrap();
    assert!(settings.validate().is_err());
}

#[test]
fn only_current_administrators_can_install_or_remove_queue_requirements() {
    let first = event(policy());
    let mut settings = policy();
    settings.branches[0].require_merge_queue = true;
    let command = ProtectionCommand {
        expected_version: ExpectedVersion::Exactly(first.version),
        expected_epoch: PolicyEpoch::try_new(2).unwrap(),
        protection: settings,
    };
    let required = command.proposed_event(actor(1)).unwrap();
    validate_transition(Some(&first), &required, command.expected_epoch).unwrap();
    assert_eq!(
        validate_transition(
            Some(&first),
            &command.proposed_event(actor(3)).unwrap(),
            command.expected_epoch
        ),
        Err(RefusalCode::ProtectedRefTransitionDenied)
    );
    assert_eq!(
        validate_transition(Some(&first), &required, PolicyEpoch::FIRST),
        Err(RefusalCode::EvidenceStale)
    );
    let mut remove = ProtectionCommand {
        expected_version: ExpectedVersion::Exactly(required.version),
        expected_epoch: PolicyEpoch::try_new(3).unwrap(),
        protection: policy(),
    };
    let restored = remove.proposed_event(actor(1)).unwrap();
    validate_transition(Some(&required), &restored, remove.expected_epoch).unwrap();
    assert_eq!(restored.payload.kind(), 9);
    remove.protection.administrators = vec![actor(9)];
    assert_eq!(
        validate_transition(
            Some(&required),
            &remove.proposed_event(actor(9)).unwrap(),
            remove.expected_epoch
        ),
        Err(RefusalCode::ProtectedRefTransitionDenied)
    );
}
