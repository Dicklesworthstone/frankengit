#![forbid(unsafe_code)]
//! Regression for frankengit-root-doctrine-x2mv.4.6 acceptance 4.
//! These are evaluator/input-boundary tests, not authenticated runner evidence.

use fgit_policy::basis::MAX_RECEIPTS;
use fgit_policy::{
    AuthenticationStrength, Decision, EvidenceKind, EvidenceReceipt, IssuerLabel,
    MAX_REQUIRED_CHECKS, PolicyInputRefusal, PolicyInputRoot, PolicyInstant, PrincipalFacts,
    PrincipalKind, ProtectedRefEvaluation, ProtectedRefRule, ProtectionBits, RefPattern,
    RefUpdateFact, RefUpdateKind, StatusCheckConclusion, StatusCheckReceipt,
    StatusCheckRequirement, evaluate_protected_ref,
};
use fgit_types::{
    AsciiSlug, CodecVersion, DigestAlgorithmId, DigestBytes, GitHashAlgorithm, GitOid, GitOidSha1,
    GitOidSha256, PrincipalId, PrincipalSnapshotId, RefName,
};

fn name(text: &str) -> AsciiSlug {
    AsciiSlug::try_new("test check name", text.as_bytes()).unwrap()
}

fn reference(text: &[u8]) -> RefName {
    RefName::try_new(text).unwrap()
}

fn target() -> RefName {
    reference(b"refs/heads/main")
}

const fn oid(format: GitHashAlgorithm, byte: u8) -> GitOid {
    match format {
        GitHashAlgorithm::Sha1 => GitOid::Sha1(GitOidSha1::from_bytes([byte; 20])),
        GitHashAlgorithm::Sha256 => GitOid::Sha256(GitOidSha256::from_bytes([byte; 32])),
    }
}

fn principal() -> PrincipalFacts {
    PrincipalFacts::try_new(
        PrincipalId::from_bytes([1; 16]),
        PrincipalSnapshotId::from_digest(
            DigestAlgorithmId::try_new(2).unwrap(),
            CodecVersion::new(1, 0),
            DigestBytes::try_new(&[1; 32]).unwrap(),
        ),
        PrincipalKind::Human,
        AuthenticationStrength::HardwareBacked,
        &[],
        &[],
    )
    .unwrap()
}

fn input(format: GitHashAlgorithm, instant: u64, generic: &[EvidenceReceipt]) -> PolicyInputRoot {
    PolicyInputRoot::try_new(
        principal(),
        vec![
            RefUpdateFact::try_new(
                target(),
                Some(oid(format, 1)),
                Some(oid(format, 2)),
                RefUpdateKind::FastForward,
                false,
            )
            .unwrap(),
        ],
        generic,
        &[],
        PolicyInstant::from_seconds(instant),
    )
    .unwrap()
}

fn check(
    subject: &RefName,
    commit: GitOid,
    check_name: &str,
    conclusion: StatusCheckConclusion,
    issued: u64,
    expires: u64,
) -> StatusCheckReceipt {
    StatusCheckReceipt::try_new(
        name(check_name),
        IssuerLabel::from_static("verified-ci"),
        subject.clone(),
        commit,
        conclusion,
        PolicyInstant::from_seconds(issued),
        PolicyInstant::from_seconds(expires),
    )
    .unwrap()
}

fn passed(format: GitHashAlgorithm, check_name: &str) -> StatusCheckReceipt {
    check(
        &target(),
        oid(format, 2),
        check_name,
        StatusCheckConclusion::Success,
        50,
        200,
    )
}

fn rule(names: &[&str], strict_up_to_date: bool) -> ProtectedRefRule {
    let mut rule = ProtectedRefRule::strict_branch(RefPattern::compile("refs/heads/main").unwrap());
    rule.reviews = None;
    rule.flags = ProtectionBits::empty();
    rule.checks = Some(StatusCheckRequirement {
        required_checks: names.iter().map(|text| name(text)).collect(),
        strict_up_to_date,
    });
    rule
}

fn evaluate(rule: &ProtectedRefRule, input: &PolicyInputRoot) -> ProtectedRefEvaluation {
    evaluate_protected_ref(std::slice::from_ref(rule), input, &target())
}

#[test]
fn wrong_name_ref_commit_or_hash_domain_cannot_satisfy_build() {
    for &format in GitHashAlgorithm::ALL {
        let other_format = match format {
            GitHashAlgorithm::Sha1 => GitHashAlgorithm::Sha256,
            GitHashAlgorithm::Sha256 => GitHashAlgorithm::Sha1,
        };
        for strict in [false, true] {
            let protection = rule(&["build"], strict);
            let good = passed(format, "build");
            let allowed = input(format, 100, &[]).with_status_checks(&[good]).unwrap();
            assert_eq!(evaluate(&protection, &allowed).decision, Decision::Allow);
            let wrong = [
                passed(format, "lint"),
                check(
                    &reference(b"refs/heads/other"),
                    oid(format, 2),
                    "build",
                    StatusCheckConclusion::Success,
                    50,
                    200,
                ),
                check(
                    &target(),
                    oid(format, 1),
                    "build",
                    StatusCheckConclusion::Success,
                    50,
                    200,
                ),
                check(
                    &target(),
                    oid(format, 3),
                    "build",
                    StatusCheckConclusion::Success,
                    50,
                    200,
                ),
                check(
                    &target(),
                    oid(other_format, 2),
                    "build",
                    StatusCheckConclusion::Success,
                    50,
                    200,
                ),
            ];
            for wrong in wrong {
                let refused = input(format, 100, &[])
                    .with_status_checks(&[wrong])
                    .unwrap();
                let result = evaluate(&protection, &refused);
                assert_eq!(result.decision, Decision::Deny);
                assert!(
                    result
                        .denial_reason
                        .unwrap()
                        .contains("missing required CI status check `build`")
                );
            }
        }
    }
}

#[test]
fn all_required_names_must_succeed_and_one_receipt_cannot_cover_two_names() {
    for &format in GitHashAlgorithm::ALL {
        let protection = rule(&["lint", "build"], true);
        let build = passed(format, "build");
        let lint = passed(format, "lint");
        for missing in [vec![], vec![build.clone()], vec![lint.clone()]] {
            let incomplete = input(format, 100, &[])
                .with_status_checks(&missing)
                .unwrap();
            assert_eq!(evaluate(&protection, &incomplete).decision, Decision::Deny);
        }
        let complete = input(format, 100, &[])
            .with_status_checks(&[build, lint])
            .unwrap();
        assert_eq!(evaluate(&protection, &complete).decision, Decision::Allow);
    }
}

#[test]
fn only_explicit_success_is_accepted() {
    let format = GitHashAlgorithm::Sha1;
    let protection = rule(&["build"], true);
    for conclusion in [
        StatusCheckConclusion::Success,
        StatusCheckConclusion::Failure,
        StatusCheckConclusion::Cancelled,
        StatusCheckConclusion::TimedOut,
        StatusCheckConclusion::ActionRequired,
    ] {
        let receipt = check(&target(), oid(format, 2), "build", conclusion, 50, 200);
        let facts = input(format, 100, &[])
            .with_status_checks(&[receipt])
            .unwrap();
        assert_eq!(
            evaluate(&protection, &facts).decision,
            if conclusion == StatusCheckConclusion::Success {
                Decision::Allow
            } else {
                Decision::Deny
            },
        );
    }
}

#[test]
fn validity_is_half_open_at_the_pinned_evaluation_instant() {
    let format = GitHashAlgorithm::Sha256;
    let protection = rule(&["build"], true);
    for (instant, expected) in [
        (49, Decision::Deny),
        (50, Decision::Allow),
        (199, Decision::Allow),
        (200, Decision::Deny),
    ] {
        let facts = input(format, instant, &[])
            .with_status_checks(&[passed(format, "build")])
            .unwrap();
        assert_eq!(evaluate(&protection, &facts).decision, expected);
    }
}

#[test]
fn generic_ci_receipt_does_not_imply_any_named_success() {
    let format = GitHashAlgorithm::Sha1;
    let generic = EvidenceReceipt::try_new(
        EvidenceKind::from_static("ci_check"),
        IssuerLabel::from_static("build"),
        target(),
        PolicyInstant::from_seconds(50),
        PolicyInstant::from_seconds(200),
    )
    .unwrap();
    let original = input(format, 100, std::slice::from_ref(&generic));
    assert_eq!(original.receipts(), &[generic]);
    assert!(original.status_checks().is_empty());
    let protection = rule(&["build"], true);
    assert_eq!(evaluate(&protection, &original).decision, Decision::Deny);
    let complete = original
        .clone()
        .with_status_checks(&[passed(format, "build")])
        .unwrap();
    assert_eq!(complete.receipts(), original.receipts());
    assert_eq!(evaluate(&protection, &complete).decision, Decision::Allow);
    assert_eq!(
        evaluate(&rule(&[], true), &original).decision,
        Decision::Allow
    );
}

#[test]
fn duplicate_slots_refuse_identical_or_conflicting_results_without_order_dependence() {
    let format = GitHashAlgorithm::Sha1;
    let good = passed(format, "build");
    let other_issuer = StatusCheckReceipt::try_new(
        good.name(),
        IssuerLabel::from_static("other-ci"),
        target(),
        good.commit(),
        StatusCheckConclusion::Success,
        good.issued_at(),
        good.expires_at(),
    )
    .unwrap();
    let rivals = [
        good.clone(),
        other_issuer,
        check(
            &target(),
            good.commit(),
            "build",
            StatusCheckConclusion::Failure,
            50,
            200,
        ),
        check(
            &target(),
            good.commit(),
            "build",
            StatusCheckConclusion::Success,
            100,
            300,
        ),
    ];
    for rival in rivals {
        for values in [[good.clone(), rival.clone()], [rival, good.clone()]] {
            assert_eq!(
                input(format, 100, &[]).with_status_checks(&values),
                Err(PolicyInputRefusal::DuplicateStatusCheck {
                    subject: target().as_bytes().to_vec(),
                    commit: good.commit(),
                    name: name("build"),
                }),
            );
        }
    }
    // Different commits, refs and names are distinct facts, not duplicate slots.
    let distinct = [
        good,
        passed(format, "lint"),
        check(
            &target(),
            oid(format, 1),
            "build",
            StatusCheckConclusion::Failure,
            50,
            200,
        ),
        check(
            &reference(b"refs/heads/other"),
            oid(format, 2),
            "build",
            StatusCheckConclusion::Failure,
            50,
            200,
        ),
    ];
    let facts = input(format, 100, &[])
        .with_status_checks(&distinct)
        .unwrap();
    assert_eq!(
        evaluate(&rule(&["build"], true), &facts).decision,
        Decision::Allow
    );
}

#[test]
fn facts_and_verdicts_are_identical_for_every_receipt_permutation() {
    let format = GitHashAlgorithm::Sha256;
    let protection = rule(&["lint", "build"], true);
    for build_conclusion in [
        StatusCheckConclusion::Success,
        StatusCheckConclusion::Failure,
    ] {
        let values = [
            check(
                &target(),
                oid(format, 2),
                "build",
                build_conclusion,
                50,
                200,
            ),
            passed(format, "lint"),
            passed(format, "unrequired"),
        ];
        let expected = input(format, 100, &[]).with_status_checks(&values).unwrap();
        let verdict = evaluate(&protection, &expected);
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let permuted = order.map(|index| values[index].clone());
            let facts = input(format, 100, &[])
                .with_status_checks(&permuted)
                .unwrap();
            assert_eq!(facts, expected);
            assert_eq!(evaluate(&protection, &facts), verdict);
        }
    }
}

#[test]
fn zero_commit_and_empty_intervals_are_typed_refusals() {
    for &format in GitHashAlgorithm::ALL {
        let construct = |commit, issued, expires| {
            StatusCheckReceipt::try_new(
                name("build"),
                IssuerLabel::from_static("verified-ci"),
                target(),
                commit,
                StatusCheckConclusion::Success,
                PolicyInstant::from_seconds(issued),
                PolicyInstant::from_seconds(expires),
            )
        };
        assert_eq!(
            construct(oid(format, 0), 1, 2),
            Err(PolicyInputRefusal::StatusCheckCommitZero {
                name: name("build")
            })
        );
        for (issued, expires) in [(1, 1), (2, 1)] {
            assert!(matches!(
                construct(oid(format, 2), issued, expires),
                Err(PolicyInputRefusal::StatusCheckWindowEmpty { .. })
            ));
        }
        assert!(construct(oid(format, 2), 1, 2).is_ok());
    }
}

#[test]
fn a_deletion_cannot_reuse_the_old_commits_success() {
    let format = GitHashAlgorithm::Sha1;
    let mut protection = rule(&["build"], true);
    protection.flags = ProtectionBits::ALLOW_DELETIONS;
    let deleted = PolicyInputRoot::try_new(
        principal(),
        vec![
            RefUpdateFact::try_new(
                target(),
                Some(oid(format, 2)),
                None,
                RefUpdateKind::Delete,
                false,
            )
            .unwrap(),
        ],
        &[],
        &[],
        PolicyInstant::from_seconds(100),
    )
    .unwrap()
    .with_status_checks(&[passed(format, "build")])
    .unwrap();
    assert_eq!(evaluate(&protection, &deleted).decision, Decision::Deny);
    let updated = input(format, 100, &[])
        .with_status_checks(&[passed(format, "build")])
        .unwrap();
    assert_eq!(evaluate(&protection, &updated).decision, Decision::Allow);
}

#[test]
fn required_name_count_refuses_above_the_bound_with_an_admitted_boundary_twin() {
    let format = GitHashAlgorithm::Sha1;
    let names: Vec<_> = (0..=MAX_REQUIRED_CHECKS)
        .map(|index| format!("check-{index}"))
        .collect();
    let checks: Vec<_> = names.iter().map(|text| passed(format, text)).collect();
    let facts = input(format, 100, &[]).with_status_checks(&checks).unwrap();
    let names: Vec<_> = names.iter().map(String::as_str).collect();
    assert_eq!(
        evaluate(&rule(&names[..MAX_REQUIRED_CHECKS], true), &facts).decision,
        Decision::Allow
    );
    assert_eq!(
        evaluate(&rule(&names, true), &facts).decision,
        Decision::Deny
    );
}

#[test]
fn generic_and_named_receipts_share_one_checked_allocation_bound() {
    let format = GitHashAlgorithm::Sha1;
    let checks: Vec<_> = (0..MAX_RECEIPTS)
        .map(|index| passed(format, &format!("check-{index}")))
        .collect();
    let maximum = input(format, 100, &[]).with_status_checks(&checks).unwrap();
    assert_eq!(maximum.status_checks().len(), MAX_RECEIPTS);
    let generic = EvidenceReceipt::try_new(
        EvidenceKind::from_static("code_review"),
        IssuerLabel::from_static("reviewer"),
        target(),
        PolicyInstant::from_seconds(1),
        PolicyInstant::from_seconds(200),
    )
    .unwrap();
    let basis = input(format, 100, &[generic]);
    assert!(
        basis
            .clone()
            .with_status_checks(&checks[..MAX_RECEIPTS - 1])
            .is_ok()
    );
    assert_eq!(
        basis.with_status_checks(&checks),
        Err(PolicyInputRefusal::CountExceeded {
            field: "receipts",
            observed: MAX_RECEIPTS + 1,
            limit: MAX_RECEIPTS,
        })
    );
}
