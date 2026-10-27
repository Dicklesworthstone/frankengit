use super::tests::{actor, policy};
use super::*;
use fgit_codec::{DecodeLimits, decode_body, encode_body};

fn event(
    protection: ReviewProtection,
    version: ExpectedVersion,
    epoch: PolicyEpoch,
    actor: PrincipalId,
) -> ForgeEvent {
    ProtectionCommand {
        expected_version: version,
        expected_epoch: epoch,
        protection,
    }
    .proposed_event(actor)
    .unwrap()
}
fn installed(source: &str) -> ReviewProtection {
    let mut protection = policy();
    protection.ref_policy = Some(compile_ref_policy(source).unwrap());
    protection
}

#[test]
fn activated_snapshot_is_a_required_new_kind_and_preserves_each_old_profile() {
    for quorum in [false, true] {
        for checks in [false, true] {
            let mut settings = policy();
            if quorum {
                settings.branches[0].required_approvals = 1;
            }
            if checks {
                settings.branches[0]
                    .required_checks
                    .push(super::tests::required_check());
            }
            let old = event(
                settings.clone(),
                ExpectedVersion::NewStream,
                PolicyEpoch::FIRST,
                actor(1),
            );
            let old_frame = encode_body(&old).unwrap();
            settings.ref_policy = Some(compile_ref_policy("policy p { default allow }").unwrap());
            let new = event(
                settings.clone(),
                ExpectedVersion::NewStream,
                PolicyEpoch::FIRST,
                actor(1),
            );
            assert_eq!(new.payload.kind(), 16);
            let frame = encode_body(&new).unwrap();
            let decoded = decode_body::<ForgeEvent>(&frame, DecodeLimits::DEFAULT).unwrap();
            assert_eq!(decoded, new);
            assert_eq!(encode_body(&decoded).unwrap(), frame);
            settings.ref_policy = None;
            assert_eq!(
                encode_body(&event(
                    settings,
                    ExpectedVersion::NewStream,
                    PolicyEpoch::FIRST,
                    actor(1)
                ))
                .unwrap(),
                old_frame
            );
        }
    }
}

#[test]
fn activation_replacement_and_removal_require_current_admin_version_and_epoch() {
    let first = event(
        installed("policy deny { default deny \"maintenance\" }"),
        ExpectedVersion::NewStream,
        PolicyEpoch::FIRST,
        actor(1),
    );
    validate_transition(None, &first, PolicyEpoch::FIRST).unwrap();
    let next_epoch = PolicyEpoch::FIRST.next().unwrap();
    for replacement in [installed("policy allow { default allow }"), policy()] {
        let next = event(
            replacement.clone(),
            ExpectedVersion::Exactly(first.version),
            next_epoch,
            actor(1),
        );
        validate_transition(Some(&first), &next, next_epoch).unwrap();
        assert_eq!(
            validate_transition(Some(&first), &next, PolicyEpoch::FIRST),
            Err(RefusalCode::EvidenceStale)
        );
        let mut self_enrolled = replacement;
        self_enrolled.administrators = vec![actor(9)];
        let next = event(
            self_enrolled,
            ExpectedVersion::Exactly(first.version),
            next_epoch,
            actor(9),
        );
        assert_eq!(
            validate_transition(Some(&first), &next, next_epoch),
            Err(RefusalCode::ProtectedRefTransitionDenied)
        );
    }
}

#[test]
fn source_and_frame_paths_share_strict_profile_and_exact_bytes() {
    let snapshot = compile_ref_policy("policy p { rule protect { when ref.update == delete then deny \"immutable\" } default allow }").unwrap();
    let frame = snapshot.encode().unwrap();
    assert_eq!(decode_ref_policy(&frame).unwrap(), snapshot);
    for size in 0..frame.len() {
        assert!(decode_ref_policy(&frame[..size]).is_err());
    }
    let mut suffix = frame.clone();
    suffix.push(0);
    assert!(decode_ref_policy(&suffix).is_err());
    assert!(compile_ref_policy("policy p { rule protected { when ref.update == fast_forward then allow } default allow }").is_err());
    let unsupported = fgit_policy::compile_and_seal(
        "policy p { rule protected { when ref.update == fast_forward then allow } default allow }",
    )
    .unwrap();
    assert!(decode_ref_policy(&unsupported.encode().unwrap()).is_err());
    let mut bad = policy();
    bad.ref_policy = Some(unsupported);
    assert!(bad.validate().is_err());
    assert!(decode_ref_policy(&vec![0; MAX_REF_POLICY_FRAME_BYTES + 1]).is_err());

    let mut source = String::from("policy large { ");
    for index in 0..40 {
        source.push_str(&format!(
            "rule r{index:02} {{ when ref.name == \"{}\" then deny \"retained\" }} ",
            "a".repeat(900)
        ));
    }
    source.push_str("default allow }");
    let snapshot = compile_ref_policy(&source).unwrap();
    let frame = snapshot.encode().unwrap();
    assert!(frame.len() > 32 * 1024);
    assert_eq!(decode_ref_policy(&frame).unwrap(), snapshot);
    assert!(
        decode_ref_policy_with_limits(
            &frame,
            DecodeLimits {
                byte_string_bytes: 4096,
                ..DecodeLimits::DEFAULT
            },
        )
        .is_err()
    );
    let event = event(
        installed(&source),
        ExpectedVersion::NewStream,
        PolicyEpoch::FIRST,
        actor(1),
    );
    let frame = encode_body(&event).unwrap();
    assert_eq!(
        decode_body::<ForgeEvent>(&frame, DecodeLimits::DEFAULT).unwrap(),
        event
    );
}
