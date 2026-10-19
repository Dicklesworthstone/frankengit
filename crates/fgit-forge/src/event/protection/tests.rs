use super::*;
use fgit_codec::{DecodeLimits, decode_body, encode_body};
pub(super) fn actor(n: u8) -> PrincipalId {
    PrincipalId::from_bytes([n; 16])
}
pub(super) fn policy() -> ReviewProtection {
    ReviewProtection {
        administrators: vec![actor(1)],
        branches: vec![ProtectedBranch {
            required_checks: Vec::new(),
            name: RefName::try_new(b"refs/heads/main").unwrap(),
            reviewers: vec![actor(3), actor(4)],
            required_approvals: 2,
        }],
    }
}
pub(super) fn initial() -> ForgeEvent {
    ProtectionCommand {
        expected_version: ExpectedVersion::NewStream,
        expected_epoch: PolicyEpoch::FIRST,
        protection: policy(),
    }
    .proposed_event(actor(1))
    .unwrap()
}
fn after(previous: &ForgeEvent, administrator: u8, protection: ReviewProtection) -> ForgeEvent {
    let ForgeEventPayload::ReviewProtectionChanged(change) = &previous.payload else {
        unreachable!()
    };
    ProtectionCommand {
        expected_version: ExpectedVersion::Exactly(previous.version),
        expected_epoch: change.resulting_epoch().unwrap(),
        protection,
    }
    .proposed_event(actor(administrator))
    .unwrap()
}
#[test]
fn bootstrap_rotation_disable_and_reenable_remain_versioned_owned_events() {
    let mut previous = initial();
    validate_transition(None, &previous, PolicyEpoch::FIRST).unwrap();
    let mut rotated = policy();
    rotated.administrators = vec![actor(2)];
    for (who, settings) in [
        (1, rotated.clone()),
        (
            2,
            ReviewProtection {
                branches: vec![],
                ..rotated.clone()
            },
        ),
        (2, rotated),
    ] {
        let next = after(&previous, who, settings);
        let ForgeEventPayload::ReviewProtectionChanged(change) = &next.payload else {
            unreachable!()
        };
        validate_transition(Some(&previous), &next, change.expected_epoch).unwrap();
        let bytes = encode_body(&next).unwrap();
        assert_eq!(
            decode_body::<ForgeEvent>(&bytes, DecodeLimits::DEFAULT).unwrap(),
            next
        );
        previous = next;
    }
    assert_eq!(previous.version.get(), 4);
    let ForgeEventPayload::ReviewProtectionChanged(last) = previous.payload else {
        unreachable!()
    };
    assert_eq!(last.resulting_epoch().unwrap().get(), 5);
    assert_eq!(last.protection.administrators, vec![actor(2)]);
}
#[test]
fn proposed_administrators_cannot_authorize_their_own_enrolment_or_disabled_policy_takeover() {
    let first = initial();
    let mut takeover = policy();
    takeover.administrators = vec![actor(2)];
    let illegal = after(&first, 2, takeover.clone());
    assert_eq!(
        validate_transition(Some(&first), &illegal, PolicyEpoch::try_new(2).unwrap()),
        Err(RefusalCode::ProtectedRefTransitionDenied)
    );
    let disabled = after(
        &first,
        1,
        ReviewProtection {
            administrators: vec![actor(1)],
            branches: vec![],
        },
    );
    let illegal = after(&disabled, 2, takeover);
    assert_eq!(
        validate_transition(Some(&disabled), &illegal, PolicyEpoch::try_new(3).unwrap()),
        Err(RefusalCode::ProtectedRefTransitionDenied)
    );
    let mut first = initial();
    let ForgeEventPayload::ReviewProtectionChanged(change) = &mut first.payload else {
        unreachable!()
    };
    change.actor = actor(9);
    assert_eq!(
        validate_transition(None, &first, PolicyEpoch::FIRST),
        Err(RefusalCode::ProtectedRefTransitionDenied)
    );
}
#[test]
fn stale_policy_versions_and_epochs_never_refresh_themselves() {
    let first = initial();
    let next = after(&first, 1, policy());
    assert_eq!(
        validate_transition(Some(&first), &next, PolicyEpoch::FIRST),
        Err(RefusalCode::EvidenceStale)
    );
    assert_eq!(
        validate_transition(Some(&next), &next, PolicyEpoch::try_new(3).unwrap()),
        Err(RefusalCode::EvidenceStale)
    );
    let mut gap = next.clone();
    gap.version = AggregateVersion::try_new(3).unwrap();
    assert_eq!(
        validate_transition(Some(&first), &gap, PolicyEpoch::try_new(2).unwrap()),
        Err(RefusalCode::EvidenceStale)
    );
    assert_eq!(
        validate_transition(None, &next, PolicyEpoch::try_new(2).unwrap()),
        Err(RefusalCode::EvidenceStale)
    );
}
#[test]
fn policy_order_duplicates_namespace_and_capacity_are_checked_before_use() {
    let mut p = policy();
    p.administrators.clear();
    assert!(p.validate().is_err());
    p = policy();
    p.administrators.push(actor(1));
    assert!(p.validate().is_err());
    p = policy();
    p.branches[0].reviewers.reverse();
    assert!(p.validate().is_err());
    p = policy();
    p.branches[0].reviewers.clear();
    assert!(p.validate().is_err());
    p = policy();
    p.branches[0].name = RefName::try_new(b"refs/tags/main").unwrap();
    assert!(p.validate().is_err());
    p = policy();
    p.branches.push(p.branches[0].clone());
    assert!(p.validate().is_err());
    p = policy();
    p.administrators = (1..=MAX_POLICY_ADMINISTRATORS)
        .map(|i| actor(i as u8))
        .collect();
    p.validate().unwrap();
    p.administrators.push(actor(100));
    assert!(p.validate().is_err());
    p = policy();
    p.branches = (0..MAX_PROTECTED_BRANCHES)
        .map(|i| ProtectedBranch {
            required_checks: Vec::new(),
            name: RefName::try_new(format!("refs/heads/b{i:02}").as_bytes()).unwrap(),
            reviewers: vec![actor(2)],
            required_approvals: 1,
        })
        .collect();
    p.validate().unwrap();
    p.branches.push(ProtectedBranch {
        required_checks: Vec::new(),
        name: RefName::try_new(b"refs/heads/zz").unwrap(),
        reviewers: vec![actor(2)],
        required_approvals: 1,
    });
    assert!(p.validate().is_err());
    p = policy();
    p.branches[0].reviewers = (1..=MAX_BRANCH_REVIEWERS).map(|i| actor(i as u8)).collect();
    p.branches[0].required_approvals = MAX_BRANCH_REVIEWERS as u16;
    p.validate().unwrap();
    p.branches[0].reviewers.push(actor(200));
    assert!(p.validate().is_err());
}
#[test]
fn truncations_wrong_aggregates_unknown_actions_and_exhausted_epochs_refuse() {
    let first = initial();
    let frame = encode_body(&first).unwrap();
    for n in 0..frame.len() {
        assert!(
            decode_body::<ForgeEvent>(&frame[..n], DecodeLimits::DEFAULT).is_err(),
            "{n}"
        );
    }
    let mut wrong = first.clone();
    wrong.aggregate = AggregateId::PullRequest(crate::PullRequestNumber::FIRST);
    assert!(encode_body(&wrong).is_err());
    let mut wrong = first.clone();
    wrong.payload = ForgeEventPayload::PullRequestClosed { withdrawn: false };
    assert!(encode_body(&wrong).is_err());
    let ForgeEventPayload::ReviewProtectionChanged(mut change) = first.payload else {
        unreachable!()
    };
    change.expected_epoch = PolicyEpoch::try_new(u64::MAX).unwrap();
    assert!(change.validate().is_err());
}
#[test]
fn every_administrator_reviewer_branch_and_epoch_is_identity_material() {
    let first = initial();
    let bytes = encode_body(&first).unwrap();
    for i in 0..5 {
        let mut changed = first.clone();
        let ForgeEventPayload::ReviewProtectionChanged(change) = &mut changed.payload else {
            unreachable!()
        };
        match i {
            0 => change.actor = actor(2),
            1 => change.expected_epoch = PolicyEpoch::try_new(2).unwrap(),
            2 => change.protection.administrators = vec![actor(2)],
            3 => {
                change.protection.branches[0].reviewers = vec![actor(5)];
                change.protection.branches[0].required_approvals = 1;
            }
            _ => {
                change.protection.branches[0].name = RefName::try_new(b"refs/heads/other").unwrap();
            }
        }
        assert_ne!(encode_body(&changed).unwrap(), bytes);
    }
    assert_eq!(
        AggregateId::ReviewProtection.to_string(),
        "review-protection"
    );
}

pub(super) fn required_check() -> RequiredWorkflowCheck {
    RequiredWorkflowCheck {
        source_ref: RefName::try_new(b"refs/heads/ci-candidate").unwrap(),
        publisher: actor(7),
        graph_root: [0x51; 32],
        job: "build:linux λ".into(),
    }
}
#[test]
fn required_checks_have_a_required_wire_kind_and_preserve_review_only_encoding() {
    let old = initial();
    assert_eq!(old.payload.kind(), 9);
    let original = encode_body(&old).unwrap();
    let mut new = old.clone();
    let ForgeEventPayload::ReviewProtectionChanged(change) = &mut new.payload else {
        panic!()
    };
    change.protection.branches[0]
        .required_checks
        .push(required_check());
    assert_eq!(new.payload.kind(), 13);
    let frame = encode_body(&new).unwrap();
    assert_eq!(
        decode_body::<ForgeEvent>(&frame, DecodeLimits::DEFAULT).unwrap(),
        new
    );
    for length in 0..frame.len() {
        assert!(decode_body::<ForgeEvent>(&frame[..length], DecodeLimits::DEFAULT).is_err());
    }
    let ForgeEventPayload::ReviewProtectionChanged(change) = &mut new.payload else {
        panic!()
    };
    change.protection.branches[0].required_checks.clear();
    assert_eq!(encode_body(&new).unwrap(), original);
}
#[test]
fn check_only_policies_are_explicit_bounded_and_canonical() {
    let mut p = policy();
    p.branches[0].reviewers.clear();
    p.branches[0].required_approvals = 0;
    assert!(p.validate().is_err());
    p.branches[0].required_checks.push(required_check());
    p.validate().unwrap();
    let mut invalid = p.clone();
    invalid.branches[0].required_checks.push(required_check());
    assert!(invalid.validate().is_err());
    for job in [
        "".to_owned(),
        "a\nb".to_owned(),
        "\u{85}".to_owned(),
        "λ".repeat(513),
    ] {
        let mut invalid = p.clone();
        invalid.branches[0].required_checks[0].job = job;
        assert!(invalid.validate().is_err());
    }
    let mut invalid = p.clone();
    invalid.branches[0].required_checks[0].source_ref = RefName::try_new(b"refs/tags/ci").unwrap();
    assert!(invalid.validate().is_err());
    p.branches[0].required_checks = (0..MAX_BRANCH_REQUIRED_CHECKS)
        .map(|n| RequiredWorkflowCheck {
            job: format!("job-{n:02}"),
            ..required_check()
        })
        .collect();
    p.validate().unwrap();
    p.branches[0].required_checks.reverse();
    assert!(p.validate().is_err());
    p.branches[0].required_checks.reverse();
    p.branches[0].required_checks.push(RequiredWorkflowCheck {
        job: "zz".into(),
        ..required_check()
    });
    assert!(p.validate().is_err());
}
#[test]
fn publishers_do_not_authorize_their_own_policy_and_every_selector_is_identity_material() {
    let first = initial();
    let mut p = policy();
    p.branches[0].required_checks.push(required_check());
    let authorized = after(&first, 1, p.clone());
    validate_transition(Some(&first), &authorized, PolicyEpoch::try_new(2).unwrap()).unwrap();
    assert_eq!(
        validate_transition(
            Some(&first),
            &after(&first, 7, p.clone()),
            PolicyEpoch::try_new(2).unwrap()
        ),
        Err(RefusalCode::ProtectedRefTransitionDenied)
    );
    let bytes = encode_body(&authorized).unwrap();
    for field in 0..4 {
        let mut changed = p.clone();
        let check = &mut changed.branches[0].required_checks[0];
        match field {
            0 => check.source_ref = RefName::try_new(b"refs/heads/other").unwrap(),
            1 => check.publisher = actor(8),
            2 => check.graph_root[0] ^= 1,
            _ => check.job.push_str("-other"),
        }
        assert_ne!(encode_body(&after(&first, 1, changed)).unwrap(), bytes);
    }
}
