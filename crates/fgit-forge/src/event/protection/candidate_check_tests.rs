//! Candidate requirements are an explicit additive trust mode. Old policy
//! kinds keep their canonical bytes and cannot silently acquire this mode.
use super::tests::{actor, policy, required_check};
use super::*;
use fgit_codec::{DecodeLimits, decode_body, encode_body};

fn selector(index: u8) -> RequiredCandidateWorkflowCheck {
    RequiredCandidateWorkflowCheck {
        publisher: actor(index),
        graph_root: [0x51; 32],
        job: "build:linux λ".into(),
    }
}
fn candidate_only() -> ReviewProtection {
    let mut settings = policy();
    let rule = &mut settings.branches[0];
    rule.reviewers.clear();
    rule.required_approvals = 0;
    rule.required_candidate_checks.push(selector(7));
    settings
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
fn change(event: &ForgeEvent) -> &NativeProtectionEvent {
    let ForgeEventPayload::ReviewProtectionChanged(change) = &event.payload else {
        panic!("protection fixture")
    };
    change
}
fn payload(event: &ForgeEvent) -> Vec<u8> {
    let mut out = Encoder::new();
    change(event).write(&mut out).unwrap();
    out.into_bytes()
}
fn read(bytes: &[u8]) -> Result<NativeProtectionEvent, CodecRefusal> {
    let mut input = Decoder::new(bytes, DecodeLimits::DEFAULT);
    let value = NativeProtectionEvent::read_with_candidate_checks(&mut input)?;
    input.finish()?;
    Ok(value)
}
fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn candidate_only_policy_has_one_required_encoding_with_frozen_field_order() {
    let expected = event(candidate_only());
    assert_eq!(expected.payload.kind(), 21);
    assert!(!change(&expected).protection.has_required_checks());
    assert!(!change(&expected).protection.has_required_merge_queue());
    assert!(change(&expected).protection.has_required_candidate_checks());
    let original = hex(concat!(
        "01010101010101010101010101010101", // actor
        "0000000000000001",                 // policy epoch
        "00000001",
        "01010101010101010101010101010101", // administrator
        "00000001",
        "0000000f726566732f68656164732f6d61696e", // main
        "00000000",                               // reviewers
        "0000",                                   // approvals
        "00000000",                               // ordinary checks
        "00",                                     // queue flag
        "00000001",                               // candidate checks
        "07070707070707070707070707070707",       // publisher
        "5151515151515151515151515151515151515151515151515151515151515151",
        "0000000e6275696c643a6c696e757820cebb", // exact job bytes
    ));
    assert_eq!(payload(&expected), original);
    assert_eq!(read(&original).unwrap(), *change(&expected));
    let frame = encode_body(&expected).unwrap();
    let decoded = decode_body::<ForgeEvent>(&frame, DecodeLimits::DEFAULT).unwrap();
    assert_eq!(decoded, expected);
    assert_eq!(encode_body(&decoded).unwrap(), frame);
    for end in 0..frame.len() {
        assert!(decode_body::<ForgeEvent>(&frame[..end], DecodeLimits::DEFAULT).is_err());
    }
    let mut extra = frame;
    extra.push(0);
    assert!(decode_body::<ForgeEvent>(&extra, DecodeLimits::DEFAULT).is_err());
}

#[test]
fn mixed_candidate_ordinary_quorum_queue_and_raw_ref_rules_keep_every_restriction() {
    let mut settings = policy();
    settings.branches[0].reviewers.push(actor(5));
    settings.branches[0].required_checks.push(required_check());
    settings.branches[0]
        .required_candidate_checks
        .push(selector(7));
    settings.branches[0].require_merge_queue = true;
    settings.branches.push(ProtectedBranch {
        name: RefName::try_new(b"refs/heads/release").unwrap(),
        reviewers: Vec::new(),
        required_approvals: 0,
        required_checks: vec![required_check()],
        required_candidate_checks: Vec::new(),
        path_reviews: Vec::new(),
        require_merge_queue: false,
    });
    settings.branches.push(ProtectedBranch {
        name: RefName::try_new(b"refs/heads/\xffcandidate").unwrap(),
        reviewers: Vec::new(),
        required_approvals: 0,
        required_checks: Vec::new(),
        required_candidate_checks: vec![selector(9)],
        path_reviews: Vec::new(),
        require_merge_queue: false,
    });
    let expected = event(settings);
    let bytes = encode_body(&expected).unwrap();
    let decoded = decode_body::<ForgeEvent>(&bytes, DecodeLimits::DEFAULT).unwrap();
    assert_eq!(decoded, expected);
    let rules = &change(&decoded).protection.branches;
    assert_eq!(rules[0].reviewers.len(), 3);
    assert_eq!(rules[0].required_approvals, 2);
    assert_eq!(rules[0].required_checks, [required_check()]);
    assert_eq!(rules[0].required_candidate_checks, [selector(7)]);
    assert!(rules[0].require_merge_queue);
    assert!(rules[1].required_candidate_checks.is_empty());
    assert_eq!(rules[2].name.as_bytes(), b"refs/heads/\xffcandidate");
    for field in 0..3 {
        let mut settings = change(&expected).protection.clone();
        let selected = &mut settings.branches[0].required_candidate_checks[0];
        match field {
            0 => selected.publisher = actor(8),
            1 => selected.graph_root[31] ^= 1,
            _ => selected.job.push('x'),
        }
        assert_ne!(encode_body(&event(settings)).unwrap(), bytes);
    }
}

#[test]
fn ordinary_and_candidate_selectors_share_one_total_bound_and_each_is_a_sorted_set() {
    let mut settings = candidate_only();
    settings.branches[0].required_candidate_checks = (1..=31).map(selector).collect();
    settings.branches[0].required_checks.push(required_check());
    settings.validate().unwrap();
    let expected = event(settings.clone());
    assert_eq!(
        decode_body::<ForgeEvent>(&encode_body(&expected).unwrap(), DecodeLimits::DEFAULT).unwrap(),
        expected
    );
    settings.branches[0]
        .required_candidate_checks
        .push(selector(32));
    assert!(
        settings.validate().is_err(),
        "33 combined selectors were accepted"
    );
    settings.branches[0].required_checks.clear();
    settings.validate().unwrap();
    settings.branches[0]
        .required_candidate_checks
        .push(selector(33));
    assert!(settings.validate().is_err());
    for invalid in [
        vec![selector(7), selector(7)],
        vec![selector(8), selector(7)],
    ] {
        let mut settings = candidate_only();
        settings.branches[0].required_candidate_checks = invalid;
        assert!(settings.validate().is_err());
    }
    let mut invalid = candidate_only();
    invalid.branches[0].required_checks = vec![required_check(), required_check()];
    assert!(invalid.validate().is_err());
    let mut empty = candidate_only();
    empty.branches[0].required_candidate_checks.clear();
    assert!(
        empty.validate().is_err(),
        "empty rule must not grant protection"
    );
}

#[test]
fn candidate_selector_job_validation_and_decode_count_limits_precede_allocation() {
    let mut good = selector(7);
    good.job = "x".repeat(super::super::workflow_check::MAX_CHECK_JOB_BYTES);
    good.validate().unwrap();
    good.job.push('x');
    assert!(good.validate().is_err());
    for name in ["", "bad\njob", "bad\0job"] {
        let mut invalid = selector(7);
        invalid.job = name.into();
        assert!(invalid.validate().is_err());
    }
    // Candidate-only fixture: principal, epoch, admins, branches, branch name,
    // reviewers, approval threshold, ordinary count, then the queue boolean.
    let offset = 16 + 8 + 4 + 16 + 4 + 4 + 15 + 4 + 2 + 4 + 1;
    let mut body = payload(&event(candidate_only()));
    assert_eq!(&body[offset..offset + 4], &1_u32.to_be_bytes());
    body[offset..offset + 4].copy_from_slice(&33_u32.to_be_bytes());
    assert!(matches!(
        read(&body),
        Err(CodecRefusal::ValueUnrepresentable {
            field: "review_protection.required_candidate_checks",
            ..
        })
    ));
    for value in [2, 255] {
        let mut body = payload(&event(candidate_only()));
        body[offset - 1] = value;
        assert!(read(&body).is_err());
    }
}

#[test]
fn kind21_without_candidate_selectors_is_noncanonical_and_kind19_stays_frozen() {
    let mut settings = policy();
    settings.branches[0].require_merge_queue = true;
    let old = event(settings);
    assert_eq!(old.payload.kind(), 19);
    let original = hex(concat!(
        "01010101010101010101010101010101",
        "0000000000000001",
        "00000001",
        "01010101010101010101010101010101",
        "00000001",
        "0000000f726566732f68656164732f6d61696e",
        "00000002",
        "03030303030303030303030303030303",
        "04040404040404040404040404040404",
        "0002",
        "00000000",
        "01",
    ));
    assert_eq!(payload(&old), original);
    let mut input = Decoder::new(&original, DecodeLimits::DEFAULT);
    let decoded = NativeProtectionEvent::read(&mut input, true, true, true).unwrap();
    input.finish().unwrap();
    assert!(
        decoded.protection.branches[0]
            .required_candidate_checks
            .is_empty()
    );
    let mut redundant = original;
    redundant.extend_from_slice(&0_u32.to_be_bytes());
    assert!(read(&redundant).is_err());
    let body = payload(&event(candidate_only()));
    for (checks, quorum, queue) in [
        (false, false, false),
        (true, false, false),
        (true, true, false),
        (true, true, true),
    ] {
        let mut input = Decoder::new(&body, DecodeLimits::DEFAULT);
        assert!(
            NativeProtectionEvent::read(&mut input, checks, quorum, queue)
                .and_then(|_| input.finish())
                .is_err()
        );
    }
}

#[test]
fn all_dsl_wrappers_accept_exact_base21_and_keep_their_authentication_profile() {
    let profiles = [
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
    for (kind, source) in profiles {
        let mut settings = candidate_only();
        settings.ref_policy = Some(compile_ref_policy(source).unwrap());
        let expected = event(settings);
        assert_eq!(expected.payload.kind(), kind);
        let body = payload(&expected);
        assert_eq!(&body[..4], &21_u32.to_be_bytes());
        let bytes = encode_body(&expected).unwrap();
        let decoded = decode_body::<ForgeEvent>(&bytes, DecodeLimits::DEFAULT).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(encode_body(&decoded).unwrap(), bytes);
        let mut wrong_base = body.clone();
        wrong_base[..4].copy_from_slice(&19_u32.to_be_bytes());
        let mut input = Decoder::new(&wrong_base, DecodeLimits::DEFAULT);
        let result = match kind {
            16 => NativeProtectionEvent::read_with_policy(&mut input),
            17 => NativeProtectionEvent::read_with_actor_policy(&mut input),
            18 => NativeProtectionEvent::read_with_authentication_policy(&mut input),
            _ => unreachable!(),
        };
        assert!(result.and_then(|_| input.finish()).is_err());
    }
}

#[test]
fn candidate_trust_replacement_still_needs_original_owner_version_and_epoch() {
    let previous = event(policy());
    let next = ProtectionCommand {
        expected_version: ExpectedVersion::Exactly(previous.version),
        expected_epoch: PolicyEpoch::FIRST.next().unwrap(),
        protection: candidate_only(),
    }
    .proposed_event(actor(1))
    .unwrap();
    validate_transition(Some(&previous), &next, PolicyEpoch::FIRST.next().unwrap()).unwrap();
    assert_eq!(
        validate_transition(Some(&previous), &next, PolicyEpoch::FIRST),
        Err(RefusalCode::EvidenceStale)
    );
    let mut unauthorized = next.clone();
    let ForgeEventPayload::ReviewProtectionChanged(change) = &mut unauthorized.payload else {
        panic!("protection fixture")
    };
    change.actor = actor(9);
    assert_eq!(
        validate_transition(
            Some(&previous),
            &unauthorized,
            PolicyEpoch::FIRST.next().unwrap()
        ),
        Err(RefusalCode::ProtectedRefTransitionDenied)
    );
}
