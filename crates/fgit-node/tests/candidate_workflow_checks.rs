#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Actual unpublished merge execution -> canonical evidence -> protected queue landing.
//! Both native hash domains exercise real disk authority, runner custody and imports.
#[path = "candidate_workflow_checks/support.rs"]
mod support;
use support::*;

use fgit_crypto::sha256_digest;
use fgit_forge::event::protection::RequiredWorkflowCheck;
use fgit_forge::event::workflow_check::WorkflowCheckConclusion;
use fgit_forge::{AggregateVersion, PullRequestNumber, QueueNumber};
use fgit_node::OneNode;
use fgit_pack::full_bundle::retarget::RetargetedBundle;
use fgit_types::{DecisionOutcome, GitHashAlgorithm, RefusalCode};
use fgit_wire::visibility::RefVisibility;
use std::fs;

fn formats() -> [GitHashAlgorithm; 2] {
    [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256]
}

#[test]
fn unpublished_candidate_checks_gate_real_queue_landing_and_latest_failure_wins() {
    for format in formats() {
        let mut case = Case::new(format);
        let original_refs = refs(case.node());
        assert_eq!(original_refs.len(), 2);
        assert!(case.node().read_git_object(case.binding.commit).is_err());

        let saved = case.execute(1, 8192);
        let seed = saved.record(&case);
        assert_eq!(seed.check.conclusion, WorkflowCheckConclusion::Success);
        assert_eq!(seed.check.source_commit, case.binding.commit);
        assert_ne!(seed.check.source_commit, case.f.source);
        assert_ne!(seed.check.source_commit, case.f.target);
        assert_eq!(seed.check.source_ref, target_ref());
        assert_eq!(refs(case.node()), original_refs);
        case.protect(
            vec![required(&seed)],
            Vec::new(),
            true,
            b"require-candidate",
        );
        let green = saved.record(&case);
        case.approve(b"review-exact-unpublished-candidate");

        let missing = case
            .land(b"missing-canonical-candidate-check", &case.bundle)
            .unwrap();
        assert!(matches!(
            missing.1.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::ProtectedRefTransitionDenied,
                ..
            }
        ));
        let before_publication = generation(case.node());
        let published = committed(
            case.publish(&green, OWNER, b"original-candidate-green", &case.bundle)
                .unwrap(),
        );
        assert_eq!(generation(case.node()), before_publication + 1);
        assert_eq!(
            refs(case.node()),
            original_refs,
            "checks never move any ref"
        );
        assert!(
            case.node().read_git_object(case.binding.commit).is_err(),
            "check publication retains verified evidence without staging candidate objects"
        );

        let id = candidate_id(&green, OWNER);
        let (_, selected) = case
            .node()
            .runtime()
            .block_on(case.node().read_candidate_workflow_check_in(
                &case.node().request_context(),
                id,
                &RefVisibility::new(),
            ))
            .unwrap()
            .unwrap();
        assert_eq!(selected.record, green);
        assert_eq!(selected.actor, OWNER);
        assert_eq!(selected.id(), id);
        for hidden in [source_ref(), target_ref()] {
            let mut visibility = RefVisibility::new();
            visibility
                .push_rule(hidden.as_bytes(), &Default::default())
                .unwrap();
            assert!(
                case.node()
                    .runtime()
                    .block_on(case.node().read_candidate_workflow_check_in(
                        &case.node().request_context(),
                        id,
                        &visibility,
                    ))
                    .unwrap()
                    .is_none(),
                "either hidden subject branch must suppress the candidate observation"
            );
        }

        let failed_saved = case.execute(2, 2);
        let failed = failed_saved.record(&case);
        assert_eq!(failed.check.conclusion, WorkflowCheckConclusion::Failure);
        assert_eq!(failed.check.graph_root, green.check.graph_root);
        assert_eq!(failed.check.job, green.check.job);
        committed(
            case.publish(&failed, OWNER, b"newer-candidate-failure", &case.bundle)
                .unwrap(),
        );
        let denied = case.land(b"newest-candidate-failed", &case.bundle).unwrap();
        assert!(matches!(
            denied.1.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::ProtectedRefTransitionDenied,
                ..
            }
        ));
        let after_failure = generation(case.node());
        assert_eq!(
            case.publish(&green, OWNER, b"original-candidate-green", b"")
                .unwrap(),
            published,
            "an old successful publication retry must resolve its original transaction"
        );
        assert_eq!(generation(case.node()), after_failure);
        refused(case.land(b"replayed-green-is-not-new-green", &case.bundle));

        let latest_saved = case.execute(3, 8192);
        let latest = latest_saved.record(&case);
        assert_eq!(latest.check.conclusion, WorkflowCheckConclusion::Success);
        assert_ne!(latest.check.run_id, green.check.run_id);
        assert_ne!(latest.check.attempt_id, green.check.attempt_id);
        committed(
            case.publish(&latest, OWNER, b"fresh-candidate-success", &case.bundle)
                .unwrap(),
        );
        // An unconfigured actor's later failure cannot override the named publisher.
        committed(
            case.publish(
                &failed,
                OTHER_PUBLISHER,
                b"other-publisher-failure",
                &case.bundle,
            )
            .unwrap(),
        );
        assert_eq!(
            case.land(b"missing-canonical-candidate-check", b"")
                .unwrap(),
            missing,
            "a later success cannot rewrite an earlier terminal refusal"
        );
        assert_eq!(case.land(b"newest-candidate-failed", b"").unwrap(), denied);

        let before_landing = generation(case.node());
        let landed = committed(
            case.land(b"land-checked-unpublished-candidate", &case.bundle)
                .unwrap(),
        );
        assert_eq!(generation(case.node()), before_landing + 1);
        let final_refs = refs(case.node());
        assert_eq!(
            final_refs.len(),
            2,
            "no CI branch was ever required or created"
        );
        assert_eq!(final_refs[&source_ref()], case.f.source);
        assert_eq!(final_refs[&target_ref()], case.binding.commit);
        let queue = case
            .node()
            .runtime()
            .block_on(case.node().read_queue_in(
                &case.node().request_context(),
                &RefVisibility::new(),
                QueueNumber::FIRST,
                None,
            ))
            .unwrap()
            .queue
            .unwrap();
        assert!(queue.is_empty());
        let report = fs::read(saved.directory.join("report.json")).unwrap();
        let runs_before = fs::read_dir(case.f.parent()).unwrap().count();
        case.f.reopen();
        let after_restart = generation(case.node());
        assert_eq!(
            case.publish(&green, OWNER, b"original-candidate-green", b"")
                .unwrap(),
            published,
            "merged PR and moved target do not change original check outcome recovery"
        );
        assert_eq!(
            case.land(b"land-checked-unpublished-candidate", b"")
                .unwrap(),
            landed
        );
        assert_eq!(generation(case.node()), after_restart);
        assert_eq!(fs::read_dir(case.f.parent()).unwrap().count(), runs_before);
        assert_eq!(
            fs::read(saved.directory.join("report.json")).unwrap(),
            report
        );
        assert_eq!(
            case.node()
                .runtime()
                .block_on(case.node().read_candidate_workflow_check_in(
                    &case.node().request_context(),
                    id,
                    &RefVisibility::new(),
                ))
                .unwrap()
                .unwrap()
                .1
                .record,
            green
        );
    }
}

#[test]
fn ordinary_and_candidate_checks_are_independent_requirements_and_share_execution_identity() {
    for format in formats() {
        for candidate_first in [true, false] {
            let mut case = Case::new(format);
            let saved = case.execute(11, 8192);
            let seed = saved.record(&case);
            let ordinary_requirement = RequiredWorkflowCheck {
                source_ref: ci_ref(),
                publisher: OWNER,
                graph_root: seed.check.graph_root,
                job: seed.check.job.clone(),
            };
            // This branch exists solely to exercise the OLD profile's permitted twin.
            // The independent queue campaign above never creates it.
            case.import_candidate(ci_ref(), b"ordinary-profile-canonical-input");
            case.protect(
                vec![required(&seed)],
                vec![ordinary_requirement],
                false,
                b"both-check-profiles-required",
            );
            let candidate = saved.record(&case);
            let ordinary = saved.ordinary(ci_ref());
            assert_eq!(ordinary.conclusion, WorkflowCheckConclusion::Success);
            assert_eq!(
                candidate_id(&candidate, OWNER),
                ordinary_id(&ordinary, OWNER),
                "changing the profile or reporting ref must not mint another execution identity"
            );

            let (published_candidate, published_ordinary) = if candidate_first {
                committed(
                    case.publish(&candidate, OWNER, b"candidate-profile-first", &case.bundle)
                        .unwrap(),
                );
                refused(case.land(b"ordinary-profile-still-missing", &case.bundle));
                refused(case.publish_ordinary(&ordinary, b"cannot-relabel-candidate-as-ordinary"));
                let independent = case.execute_ref(&ci_ref(), case.binding.commit, 12);
                let fresh_ordinary = independent.ordinary(ci_ref());
                committed(
                    case.publish_ordinary(&fresh_ordinary, b"independent-ordinary-success")
                        .unwrap(),
                );
                (candidate, fresh_ordinary)
            } else {
                committed(
                    case.publish_ordinary(&ordinary, b"ordinary-profile-first")
                        .unwrap(),
                );
                refused(case.land(b"candidate-profile-still-missing", &case.bundle));
                refused(case.publish(
                    &candidate,
                    OWNER,
                    b"cannot-relabel-ordinary-as-candidate",
                    &case.bundle,
                ));
                let independent = case.execute(12, 8192);
                let fresh_candidate = independent.record(&case);
                committed(
                    case.publish(
                        &fresh_candidate,
                        OWNER,
                        b"independent-candidate-success",
                        &case.bundle,
                    )
                    .unwrap(),
                );
                (fresh_candidate, ordinary)
            };
            let candidate_check = candidate_id(&published_candidate, OWNER);
            let ordinary_check = ordinary_id(&published_ordinary, OWNER);
            assert_ne!(candidate_check, ordinary_check);
            assert_eq!(
                case.node()
                    .runtime()
                    .block_on(case.node().read_candidate_workflow_check_in(
                        &case.node().request_context(),
                        candidate_check,
                        &RefVisibility::new(),
                    ))
                    .unwrap()
                    .unwrap()
                    .1
                    .record,
                published_candidate
            );
            assert!(
                case.node()
                    .runtime()
                    .block_on(case.node().read_candidate_workflow_check_in(
                        &case.node().request_context(),
                        ordinary_check,
                        &RefVisibility::new(),
                    ))
                    .unwrap()
                    .is_none(),
                "ordinary canonical evidence must not be mislabeled as a candidate observation"
            );

            // A genuine parent execution fails the combined-tree test. It remains
            // visible on the existing PR SOURCE page, unlike candidate/CI observations.
            let source_execution = case.execute_ref(&source_ref(), case.f.source, 13);
            let source_check = source_execution.ordinary(source_ref());
            assert_eq!(source_check.conclusion, WorkflowCheckConclusion::Failure);
            committed(
                case.publish_ordinary(&source_check, b"ordinary-source-failure")
                    .unwrap(),
            );
            let page = case
                .node()
                .runtime()
                .block_on(case.node().read_pull_request_checks_in(
                    &case.node().request_context(),
                    &RefVisibility::new(),
                    PullRequestNumber::FIRST,
                    None,
                    10,
                    None,
                ))
                .unwrap()
                .unwrap();
            assert!(page.source_current);
            assert_eq!(page.source_tip, case.f.source);
            assert_eq!(page.checks.len(), 1);
            assert_eq!(page.checks[0].id, ordinary_id(&source_check, OWNER));
            assert_eq!(page.checks[0].conclusion, WorkflowCheckConclusion::Failure);
            committed(
                case.land(b"both-independent-check-profiles-satisfied", &case.bundle)
                    .unwrap(),
            );
        }
    }
}

#[test]
fn original_check_receipts_recover_after_real_pr_ref_and_policy_changes_but_fresh_requests_refuse()
{
    for format in formats() {
        for changed in ["pull-request", "source", "target", "policy"] {
            let mut case = Case::new(format);
            let saved = case.execute(21, 8192);
            let original = saved.record(&case);
            let receipt = committed(
                case.publish(
                    &original,
                    OWNER,
                    b"original-before-state-change",
                    &case.bundle,
                )
                .unwrap(),
            );
            match changed {
                "pull-request" => case.update_pull(),
                "source" => case.import_candidate(source_ref(), b"advance-original-source"),
                "target" => case.import_candidate(target_ref(), b"advance-original-target"),
                "policy" => {
                    case.protect(Vec::new(), Vec::new(), false, b"replace-original-policy");
                }
                _ => unreachable!(),
            }
            let changed_refs = refs(case.node());
            refused(case.publish(
                &original,
                OWNER,
                b"fresh-stale-subject-request",
                &case.bundle,
            ));
            assert_eq!(refs(case.node()), changed_refs);
            case.f.reopen();
            let generation_before = generation(case.node());
            let run_count = fs::read_dir(case.f.parent()).unwrap().count();
            assert_eq!(
                case.publish(&original, OWNER, b"original-before-state-change", b"")
                    .unwrap(),
                receipt,
                "historical outcome lookup precedes fresh input validation after {changed}"
            );
            assert_eq!(generation(case.node()), generation_before);
            assert_eq!(refs(case.node()), changed_refs);
            assert_eq!(fs::read_dir(case.f.parent()).unwrap().count(), run_count);
            assert_eq!(
                case.node()
                    .runtime()
                    .block_on(case.node().read_candidate_workflow_check_in(
                        &case.node().request_context(),
                        candidate_id(&original, OWNER),
                        &RefVisibility::new(),
                    ))
                    .unwrap()
                    .unwrap()
                    .1
                    .record,
                original,
                "reading a retained observation is not fresh merge authorization"
            );
        }
    }
}

#[test]
fn altered_candidate_bundle_subject_and_execution_evidence_cannot_be_published() {
    for format in formats() {
        let case = Case::new(format);
        let saved = case.execute(31, 8192);
        let original = saved.record(&case);
        let original_refs = refs(case.node());

        let from_batch = OneNode::candidate_workflow_check_record_from_batch(
            case.subject.clone(),
            case.binding.clone(),
            sha256_digest(&case.bundle),
            &saved.batch,
            saved.index,
            &saved.evidence,
            &|| true,
        )
        .unwrap();
        assert_eq!(
            from_batch, original,
            "saved and live selection bind the same actual job"
        );

        let mut variants = Vec::new();
        let mut changed = original.clone();
        changed.bundle_sha256[0] ^= 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.subject.source_tip = case.f.target;
        variants.push(changed);
        let mut changed = original.clone();
        changed.subject.target_tip = case.f.base;
        variants.push(changed);
        let mut changed = original.clone();
        changed.subject.pull_request_version = AggregateVersion::FIRST.next().unwrap();
        variants.push(changed);
        let mut changed = original.clone();
        changed.subject.policy_epoch = changed.subject.policy_epoch.next().unwrap();
        variants.push(changed);
        let mut changed = original.clone();
        changed.candidate.merge_base = case.f.target;
        variants.push(changed);
        let mut changed = original.clone();
        changed.candidate.commit = case.f.source;
        changed.check.source_commit = case.f.source;
        variants.push(changed);
        let mut changed = original.clone();
        changed.check.evidence[0] ^= 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.check.run_id[0] ^= 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.check.attempt_id[0] ^= 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.check.graph_root[0] ^= 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.check.job.push_str("-another-job");
        variants.push(changed);
        for (index, record) in variants.iter().enumerate() {
            refused(case.publish(
                record,
                OWNER,
                format!("altered-candidate-record-{index}").as_bytes(),
                &case.bundle,
            ));
            assert_eq!(refs(case.node()), original_refs);
        }

        let mut corrupt = case.bundle.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        let mut matching_digest = original.clone();
        matching_digest.bundle_sha256 = sha256_digest(&corrupt);
        refused(case.publish(
            &matching_digest,
            OWNER,
            b"bad-pack-even-with-matching-envelope-digest",
            &corrupt,
        ));
        let wrong_advertisement = RetargetedBundle::parse(
            &case.bundle,
            &target_ref(),
            &ci_ref(),
            case.binding.commit,
            Default::default(),
            &mut || true,
        )
        .unwrap();
        let wrong_advertisement = [
            wrong_advertisement.header_bytes(),
            wrong_advertisement.pack_bytes(),
        ]
        .concat();
        let mut matching_digest = original.clone();
        matching_digest.bundle_sha256 = sha256_digest(&wrong_advertisement);
        refused(case.publish(
            &matching_digest,
            OWNER,
            b"wrong-advertised-ref-even-with-matching-digest",
            &wrong_advertisement,
        ));
        assert_eq!(refs(case.node()), original_refs);

        let parent = case.execute_ref(&source_ref(), case.f.source, 32);
        assert!(
            OneNode::candidate_workflow_check_record_from_batch(
                case.subject.clone(),
                case.binding.clone(),
                sha256_digest(&case.bundle),
                &parent.batch,
                parent.index,
                &parent.evidence,
                &|| true,
            )
            .is_err(),
            "executing the PR source cannot establish execution of its merge candidate"
        );
        let accepted = committed(
            case.publish(
                &original,
                OWNER,
                b"unaltered-permitted-candidate",
                &case.bundle,
            )
            .unwrap(),
        );
        assert_eq!(refs(case.node()), original_refs);
        let before = generation(case.node());
        assert_eq!(
            case.publish(&original, OWNER, b"unaltered-permitted-candidate", b"")
                .unwrap(),
            accepted
        );
        assert_eq!(generation(case.node()), before);
    }
}

#[test]
fn saved_candidate_check_selection_honors_journal_pins_and_canonical_evidence_survives_local_loss()
{
    for format in formats() {
        let case = Case::new(format);
        let saved = case.execute(41, 8192);
        let record = saved.record(&case);
        let load = |minimum, fact_index, live: &dyn Fn() -> bool| {
            OneNode::trusted_candidate_workflow_check_record(
                &saved.directory,
                (TENANT, REPOSITORY, saved.journal),
                minimum,
                saved.batch.id().digest(),
                fact_index,
                case.subject.clone(),
                case.binding.clone(),
                sha256_digest(&case.bundle),
                live,
            )
        };
        assert!(load(Some((saved.pin.0 - 1, saved.pin.1)), saved.index, &|| true).is_err());
        assert!(load(Some(saved.pin), usize::MAX, &|| true).is_err());
        assert!(load(Some(saved.pin), saved.index, &|| false).is_err());
        assert_eq!(
            load(Some(saved.pin), saved.index, &|| true).unwrap(),
            record
        );
        let receipt = committed(
            case.publish(&record, OWNER, b"retained-canonical-job", &case.bundle)
                .unwrap(),
        );

        // Damage only this test's retained journal; canonical publication already
        // retained the verified evidence and must not consult mutable local custody.
        let path = saved.directory.join("check-proposals.journal");
        let mut bytes = fs::read(&path).unwrap();
        bytes[0] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(load(Some(saved.pin), saved.index, &|| true).is_err());
        let before = generation(case.node());
        assert_eq!(
            case.publish(&record, OWNER, b"retained-canonical-job", b"")
                .unwrap(),
            receipt
        );
        let (_, canonical) = case
            .node()
            .runtime()
            .block_on(case.node().read_candidate_workflow_check_in(
                &case.node().request_context(),
                candidate_id(&record, OWNER),
                &RefVisibility::new(),
            ))
            .unwrap()
            .unwrap();
        assert_eq!(canonical.record.check.evidence, saved.evidence);
        assert_eq!(canonical.record, record);
        assert_eq!(generation(case.node()), before);
    }
}

#[test]
fn a_candidate_check_requires_the_guarded_merge_path_even_without_review_or_queue_rules() {
    for format in formats() {
        let mut case = Case::new(format);
        let saved = case.execute(51, 8192);
        let seed = saved.record(&case);
        case.protect_with_queue(
            vec![required(&seed)],
            Vec::new(),
            false,
            false,
            b"candidate-protection-without-other-gates",
        );
        let record = saved.record(&case);
        committed(
            case.publish(
                &record,
                OWNER,
                b"checked-before-direct-bypass",
                &case.bundle,
            )
            .unwrap(),
        );
        let original_refs = refs(case.node());
        let node = case.node();
        let imported = node
            .runtime()
            .block_on(node.import_incremental_git_bundle_durable_in(
                &node.request_context(),
                &session(OWNER, b"cannot-bypass-candidate-subject-through-import"),
                &case.bundle,
                &[(target_ref(), Some(case.f.target))],
                Default::default(),
            ))
            .unwrap();
        assert_eq!(imported.commands.len(), 1);
        assert!(matches!(
            imported.commands[0].terminal.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::ProtectedRefTransitionDenied,
                ..
            }
        ));
        assert_eq!(refs(case.node()), original_refs);
        committed(
            case.land(b"permitted-exact-subject-landing", &case.bundle)
                .unwrap(),
        );
        assert_eq!(refs(case.node())[&target_ref()], case.binding.commit);
    }
}

#[test]
fn candidate_check_publication_does_not_inherit_the_human_diff_rendering_budget() {
    for format in formats() {
        let maximum_review_blob = fgit_forge::review::ReviewOptions::default()
            .limits
            .max_blob_bytes;
        let mut case = Case::new(format).with_large_candidate_file(maximum_review_blob + 1);
        let before = generation(case.node());
        let original_refs = refs(case.node());
        let inspection = case
            .node()
            .runtime()
            .block_on(case.node().inspect_merge_bundle_in(
                &case.node().request_context(),
                &case.merge,
                &case.bundle,
                &RefVisibility::new(),
                None,
                &fgit_forge::review::ReviewOptions::default(),
            ));
        assert!(matches!(
            inspection,
            Err(fgit_node::BundleInspectionRefusal::Review(error))
                if matches!(*error, fgit_forge::review::ReviewError::Budget("blob bytes"))
        ));
        assert_eq!(generation(case.node()), before);
        let saved = case.execute(61, 8192);
        let seed = saved.record(&case);
        assert_eq!(seed.check.conclusion, WorkflowCheckConclusion::Success);
        case.protect(
            vec![required(&seed)],
            Vec::new(),
            false,
            b"large-candidate-policy",
        );
        let record = saved.record(&case);
        committed(
            case.publish(&record, OWNER, b"large-candidate-check", &case.bundle)
                .unwrap(),
        );
        assert_eq!(refs(case.node()), original_refs);
        assert!(case.node().read_git_object(case.binding.commit).is_err());
        // The permitted publication path validates the full native bundle; its
        // success does not weaken the unchanged public review-rendering limit.
        assert!(
            case.node()
                .runtime()
                .block_on(case.node().inspect_merge_bundle_in(
                    &case.node().request_context(),
                    &case.merge,
                    &case.bundle,
                    &RefVisibility::new(),
                    None,
                    &fgit_forge::review::ReviewOptions::default(),
                ))
                .is_err()
        );
        committed(
            case.land(b"land-valid-large-candidate", &case.bundle)
                .unwrap(),
        );
        assert_eq!(refs(case.node())[&target_ref()], case.binding.commit);
    }
}
