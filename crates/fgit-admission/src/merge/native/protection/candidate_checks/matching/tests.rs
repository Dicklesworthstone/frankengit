use super::*;
use fgit_forge::event::workflow_check::candidate::{
    CandidateWorkflowCheckRecord, NativeCandidateWorkflowCheck,
};
use fgit_forge::event::workflow_check::{NativeWorkflowCheck, WorkflowCheckRecord};
use fgit_forge::{AggregateVersion, PullRequestNumber};
use fgit_types::{GitHashAlgorithm, GitOid, PolicyEpoch, PrincipalId, RefName};

fn oid(format: GitHashAlgorithm, digit: &str) -> GitOid {
    GitOid::from_hex(format, &digit.repeat(format.digest_len() * 2)).unwrap()
}
fn setup(
    format: GitHashAlgorithm,
) -> (
    ReviewSubject,
    CandidateBinding,
    RequiredCandidateWorkflowCheck,
) {
    (
        ReviewSubject {
            pull_request: PullRequestNumber::FIRST,
            pull_request_version: AggregateVersion::FIRST,
            source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
            target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
            source_tip: oid(format, "1"),
            target_tip: oid(format, "2"),
            policy_epoch: PolicyEpoch::FIRST,
        },
        CandidateBinding {
            merge_base: oid(format, "3"),
            commit: oid(format, "4"),
        },
        RequiredCandidateWorkflowCheck {
            publisher: PrincipalId::from_bytes([7; 16]),
            graph_root: [8; 32],
            job: "test".into(),
        },
    )
}
fn candidate_event(
    subject: &ReviewSubject,
    binding: CandidateBinding,
    required: &RequiredCandidateWorkflowCheck,
    conclusion: WorkflowCheckConclusion,
) -> ForgeEventPayload {
    ForgeEventPayload::CandidateWorkflowCheckObservedNative(NativeCandidateWorkflowCheck {
        actor: required.publisher,
        record: CandidateWorkflowCheckRecord {
            subject: subject.clone(),
            candidate: binding,
            bundle_sha256: [9; 32],
            check: WorkflowCheckRecord {
                source_ref: subject.target_ref.clone(),
                source_commit: binding.commit,
                run_id: [10; 32],
                attempt_id: [11; 32],
                graph_root: required.graph_root,
                job: required.job.clone(),
                conclusion,
                evidence: vec![12],
            },
        },
    })
}

#[test]
fn every_exact_subject_coordinate_and_configured_selector_is_required() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (subject, binding, required) = setup(format);
        let requirements = [required.clone()];
        let valid = candidate_event(
            &subject,
            binding,
            &required,
            WorkflowCheckConclusion::Success,
        );
        for field in 0..13 {
            let mut altered = valid.clone();
            let ForgeEventPayload::CandidateWorkflowCheckObservedNative(observation) = &mut altered
            else {
                unreachable!()
            };
            let record = &mut observation.record;
            match field {
                0 => record.subject.pull_request = PullRequestNumber::try_new(2).unwrap(),
                1 => record.subject.pull_request_version = AggregateVersion::try_new(2).unwrap(),
                2 => record.subject.source_ref = RefName::try_new(b"refs/heads/other").unwrap(),
                3 => {
                    record.subject.target_ref =
                        RefName::try_new(b"refs/heads/other-target").unwrap()
                }
                4 => record.subject.source_tip = oid(format, "5"),
                5 => record.subject.target_tip = oid(format, "6"),
                6 => record.subject.policy_epoch = PolicyEpoch::try_new(2).unwrap(),
                7 => record.candidate.merge_base = oid(format, "7"),
                8 => record.candidate.commit = oid(format, "8"),
                9 => observation.actor = PrincipalId::from_bytes([13; 16]),
                10 => record.check.graph_root = [14; 32],
                11 => record.check.job = "another".into(),
                12 => record.subject.source_tip = subject.target_tip,
                _ => unreachable!(),
            }
            let mut selected = ExactChecks::new(subject.clone(), binding, &[], &requirements);
            assert!(!selected.observe(&altered).unwrap(), "field {field}");
            assert!(selected.observe(&valid).unwrap(), "valid twin {field}");
        }
    }
}

#[test]
fn every_non_success_latest_exact_observation_refuses() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (subject, binding, required) = setup(format);
        let requirements = [required.clone()];
        for conclusion in [
            WorkflowCheckConclusion::ActionRequired,
            WorkflowCheckConclusion::Failure,
            WorkflowCheckConclusion::Cancelled,
            WorkflowCheckConclusion::TimedOut,
        ] {
            let mut selected = ExactChecks::new(subject.clone(), binding, &[], &requirements);
            assert_eq!(
                selected.observe(&candidate_event(&subject, binding, &required, conclusion)),
                Err(RefusalCode::ProtectedRefTransitionDenied)
            );
        }
    }
}

#[test]
fn older_failures_do_not_override_a_resolved_newer_green_while_other_jobs_are_pending() {
    let (subject, binding, first) = setup(GitHashAlgorithm::Sha1);
    let mut second = first.clone();
    second.job = "lint".into();
    let requirements = [first.clone(), second.clone()];
    let mut selected = ExactChecks::new(subject.clone(), binding, &[], &requirements);
    assert!(
        !selected
            .observe(&candidate_event(
                &subject,
                binding,
                &first,
                WorkflowCheckConclusion::Success
            ))
            .unwrap()
    );
    assert!(
        !selected
            .observe(&candidate_event(
                &subject,
                binding,
                &first,
                WorkflowCheckConclusion::Failure
            ))
            .unwrap()
    );
    assert!(
        selected
            .observe(&candidate_event(
                &subject,
                binding,
                &second,
                WorkflowCheckConclusion::Success
            ))
            .unwrap()
    );
}

#[test]
fn ordinary_and_candidate_profiles_are_both_required_and_never_substitute_for_each_other() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (subject, binding, required) = setup(format);
        let ordinary = [RequiredWorkflowCheck {
            source_ref: RefName::try_new(b"refs/heads/ci").unwrap(),
            publisher: required.publisher,
            graph_root: required.graph_root,
            job: required.job.clone(),
        }];
        let candidates = [required.clone()];
        let exact = candidate_event(
            &subject,
            binding,
            &required,
            WorkflowCheckConclusion::Success,
        );
        let ForgeEventPayload::CandidateWorkflowCheckObservedNative(observation) = &exact else {
            unreachable!()
        };
        let mut check = observation.record.check.clone();
        check.source_ref = ordinary[0].source_ref.clone();
        let branch = ForgeEventPayload::WorkflowCheckObservedNative(NativeWorkflowCheck {
            actor: required.publisher,
            record: check,
        });
        for sequence in [[&exact, &branch], [&branch, &exact]] {
            let mut selected = ExactChecks::new(subject.clone(), binding, &ordinary, &candidates);
            assert!(!selected.observe(sequence[0]).unwrap());
            assert!(selected.observe(sequence[1]).unwrap());
        }
        let mut selected = ExactChecks::new(subject.clone(), binding, &ordinary, &[]);
        assert!(!selected.observe(&exact).unwrap());
        assert!(selected.observe(&branch).unwrap());
        let mut selected = ExactChecks::new(subject.clone(), binding, &[], &candidates);
        assert!(!selected.observe(&branch).unwrap());
        assert!(selected.observe(&exact).unwrap());
    }
}

#[test]
fn candidate_evidence_does_not_depend_on_a_mutable_head_or_bundle_pack_spelling() {
    let (subject, binding, required) = setup(GitHashAlgorithm::Sha256);
    let candidates = [required.clone()];
    let mut observation = candidate_event(
        &subject,
        binding,
        &required,
        WorkflowCheckConclusion::Success,
    );
    let ForgeEventPayload::CandidateWorkflowCheckObservedNative(change) = &mut observation else {
        unreachable!()
    };
    // Once admitted, native candidate identity governs applicability. The
    // accepted bundle and run remain audit provenance, not current-head leases.
    change.record.bundle_sha256 = [99; 32];
    change.record.check.run_id = [100; 32];
    change.record.check.attempt_id = [101; 32];
    let mut selected = ExactChecks::new(subject, binding, &[], &candidates);
    assert!(selected.observe(&observation).unwrap());
}

#[test]
fn cloned_candidate_matchers_preserve_only_the_ordered_suffix_resolution() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (subject, binding, build) = setup(format);
        let mut lint = build.clone();
        lint.job = "lint".into();
        let required = [build.clone(), lint.clone()];
        let initial = ExactChecks::new(subject.clone(), binding, &[], &required);
        let build_success =
            candidate_event(&subject, binding, &build, WorkflowCheckConclusion::Success);
        let build_failure =
            candidate_event(&subject, binding, &build, WorkflowCheckConclusion::Failure);
        let lint_success =
            candidate_event(&subject, binding, &lint, WorkflowCheckConclusion::Success);

        let mut suffix = initial.clone();
        assert!(!suffix.observe(&build_success).unwrap());
        // The known newer success settles build, while lint remains mandatory.
        let mut remaining = suffix.clone();
        assert!(!remaining.observe(&build_failure).unwrap());
        assert!(remaining.observe(&lint_success).unwrap());

        // A fresh pre-suffix clone must still see the same failure. Cloning
        // neither shares mutable resolution nor erases a pending selector.
        let mut independent = initial.clone();
        assert_eq!(
            independent.observe(&build_failure),
            Err(RefusalCode::ProtectedRefTransitionDenied),
        );
        let mut another = initial;
        assert!(!another.observe(&lint_success).unwrap());
        assert!(another.observe(&build_success).unwrap());
    }
}
