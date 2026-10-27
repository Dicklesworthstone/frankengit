//! Wire compatibility and policy semantics for administrator-selected quorums.
use super::tests::{actor, initial, policy, required_check};
use super::*;
use fgit_codec::{DecodeLimits, decode_body, encode_body};

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn quorum_policy() -> ReviewProtection {
    let mut value = policy();
    value.branches[0].reviewers.push(actor(5));
    value.branches[0].required_approvals = 2;
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
fn historical_unanimity_and_check_encodings_keep_exact_bytes_and_effective_counts() {
    // Frozen pre-quorum frames. Counts are inferred on read, with no new bytes
    // added to either historical kind's canonical identity.
    const V9: &str = "4647433100010000000000196672616e6b656e6769742f666f7267652d6576656e742f76310000000b666f7267652d6576656e74000100000000007f0000000000000000000000050000000000000001000000090101010101010101010101010101010100000000000000010000000101010101010101010101010101010101000000010000000f726566732f68656164732f6d61696e000000020303030303030303030303030303030304040404040404040404040404040404";
    const V13: &str = "4647433100010000000000196672616e6b656e6769742f666f7267652d6576656e742f76310000000b666f7267652d6576656e7400010000000000e000000000000000000000000500000000000000010000000d0101010101010101010101010101010100000000000000010000000101010101010101010101010101010101000000010000000f726566732f68656164732f6d61696e0000000203030303030303030303030303030303040404040404040404040404040404040000000100000017726566732f68656164732f63692d63616e6469646174650707070707070707070707070707070751515151515151515151515151515151515151515151515151515151515151510000000e6275696c643a6c696e757820cebb";
    let old = initial();
    let mut checked = policy();
    checked.branches[0].required_checks.push(required_check());
    for (expected, frame, kind) in [(old, hex(V9), 9), (event(checked), hex(V13), 13)] {
        assert_eq!(encode_body(&expected).unwrap(), frame);
        let decoded = decode_body::<ForgeEvent>(&frame, DecodeLimits::DEFAULT).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(decoded.payload.kind(), kind);
        let ForgeEventPayload::ReviewProtectionChanged(change) = decoded.payload else {
            panic!()
        };
        assert!(!change.protection.has_review_quorum());
        assert_eq!(change.protection.branches[0].required_approvals, 2);
    }
}

#[test]
fn quorum_is_a_required_new_kind_and_mixed_rules_keep_all_counts_and_checks() {
    let mut settings = quorum_policy();
    settings.branches[0].required_checks.push(required_check());
    settings.branches.push(ProtectedBranch {
        name: RefName::try_new(b"refs/heads/release").unwrap(),
        reviewers: vec![actor(8)],
        required_approvals: 1,
        required_checks: Vec::new(),
    });
    settings.branches.push(ProtectedBranch {
        name: RefName::try_new(b"refs/heads/staging").unwrap(),
        reviewers: Vec::new(),
        required_approvals: 0,
        required_checks: vec![required_check()],
    });
    for expected in [event(settings), event(quorum_policy())] {
        assert_eq!(expected.payload.kind(), 14);
        let frame = encode_body(&expected).unwrap();
        assert_eq!(
            decode_body::<ForgeEvent>(&frame, DecodeLimits::DEFAULT).unwrap(),
            expected
        );
        for length in 0..frame.len() {
            assert!(decode_body::<ForgeEvent>(&frame[..length], DecodeLimits::DEFAULT).is_err());
        }
        let mut trailing = frame;
        trailing.push(0);
        assert!(decode_body::<ForgeEvent>(&trailing, DecodeLimits::DEFAULT).is_err());
    }
}

#[test]
fn count_bounds_preserve_a_real_approval_requirement_and_check_only_zero() {
    for count in [1, 2, 3] {
        let mut settings = quorum_policy();
        settings.branches[0].required_approvals = count;
        settings.validate().unwrap();
    }
    for count in [0, 4, u16::MAX] {
        let mut settings = quorum_policy();
        settings.branches[0].required_approvals = count;
        assert!(settings.validate().is_err());
    }
    let mut checked = quorum_policy();
    checked.branches[0].reviewers.clear();
    checked.branches[0].required_approvals = 0;
    checked.branches[0].required_checks.push(required_check());
    checked.validate().unwrap();
    assert_eq!(event(checked.clone()).payload.kind(), 13);
    checked.branches[0].required_approvals = 1;
    assert!(checked.validate().is_err());
    checked.branches[0].required_approvals = 0;
    checked.branches[0].required_checks.clear();
    assert!(checked.validate().is_err());
}

#[test]
fn quorum_count_is_identity_material_and_redundant_or_invalid_wire_counts_refuse() {
    let settings = quorum_policy();
    let frame = encode_body(&event(settings.clone())).unwrap();
    let reviewers = [
        actor(3).as_bytes().as_slice(),
        actor(4).as_bytes().as_slice(),
        actor(5).as_bytes().as_slice(),
    ]
    .concat();
    let offset = frame
        .windows(reviewers.len())
        .position(|bytes| bytes == reviewers)
        .unwrap()
        + reviewers.len();
    assert_eq!(&frame[offset..offset + 2], &2_u16.to_be_bytes());
    let mut lower = settings.clone();
    lower.branches[0].required_approvals = 1;
    assert_ne!(encode_body(&event(lower)).unwrap(), frame);
    let mut unanimous = settings;
    unanimous.branches[0].required_approvals = 3;
    assert_eq!(event(unanimous).payload.kind(), 9);
    for count in [0_u16, 3, 4, u16::MAX] {
        let mut invalid = frame.clone();
        invalid[offset..offset + 2].copy_from_slice(&count.to_be_bytes());
        assert!(
            decode_body::<ForgeEvent>(&invalid, DecodeLimits::DEFAULT).is_err(),
            "{count}"
        );
    }
}

#[test]
fn only_current_administrators_can_lower_the_quorum_in_a_new_policy_epoch() {
    let first = event(quorum_policy());
    validate_transition(None, &first, PolicyEpoch::FIRST).unwrap();
    let mut lower = quorum_policy();
    lower.branches[0].required_approvals = 1;
    let command = ProtectionCommand {
        expected_version: ExpectedVersion::Exactly(first.version),
        expected_epoch: PolicyEpoch::try_new(2).unwrap(),
        protection: lower,
    };
    let authorized = command.proposed_event(actor(1)).unwrap();
    validate_transition(Some(&first), &authorized, command.expected_epoch).unwrap();
    assert_eq!(
        validate_transition(
            Some(&first),
            &command.proposed_event(actor(3)).unwrap(),
            command.expected_epoch
        ),
        Err(RefusalCode::ProtectedRefTransitionDenied)
    );
    assert_eq!(
        validate_transition(Some(&first), &authorized, PolicyEpoch::FIRST),
        Err(RefusalCode::EvidenceStale)
    );
}
