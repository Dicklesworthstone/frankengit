//! Pure production fold/search/receipt checks with real canonical codec types.
//! These fixtures do not claim an authority-store or native OneNode execution.
use super::{Error, MAX_EVENTS, MAX_PROBES, Predicate, Query, Report, fold, receipt};
use fgit_codec::{
    CryptoBodyIdentity, DecodeLimits, RepositoryAuthorityHeadBody, RepositoryCommitRecord,
    RepositoryDecision, RepositoryDecisionBatchBody, body_id, decode_body, encode_body,
};
use fgit_crypto::DigestAlgorithm;
use fgit_forge::aggregate::{AggregateId, AggregateVersion};
use fgit_forge::bisection::{
    BisectionRange, BisectionRefusal, BisectionTermination, MonotonicityShape, PredicateOutcome,
    ProbeObservation, search_published_positions,
};
use fgit_forge::event::workflow_check::{
    MAX_CHECK_JOB_BYTES, NativeWorkflowCheck, WorkflowCheckConclusion, WorkflowCheckId,
    WorkflowCheckRecord,
};
use fgit_forge::event::{ForgeEvent, ForgeEventBatch, ForgeEventPayload};
use fgit_forge::snapshot::HistoricalBatch;
use fgit_types::{
    CodecVersion, DecisionOutcome, DecisionSequence, Digest, DigestBytes, GitHashAlgorithm, GitOid,
    HeadGeneration, PolicyEpoch, PrincipalId, PrincipalSnapshotId, RefName, RegistryEpoch,
    RepositoryAuthorityHeadId, RepositoryCommitId, RepositoryDecisionBatchId, RepositoryId,
    RepositoryIncarnationId, RepositorySequence, TenantId, TxId,
};

fn seq(value: u64) -> DecisionSequence {
    DecisionSequence::try_new(value).unwrap()
}
fn repository() -> RepositoryId {
    RepositoryId::from_bytes([0x22; 16])
}
fn publisher() -> PrincipalId {
    PrincipalId::from_bytes([0x33; 16])
}
fn oid(format: GitHashAlgorithm, byte: char) -> GitOid {
    GitOid::from_hex(format, &byte.to_string().repeat(format.digest_len() * 2)).unwrap()
}
fn digest(seed: u64) -> Digest {
    Digest::new(
        DigestAlgorithm::Sha256.id(),
        DigestBytes::try_new(&fgit_crypto::sha256_digest(&seed.to_be_bytes())).unwrap(),
    )
}
fn record(
    format: GitHashAlgorithm,
    run: u8,
    conclusion: WorkflowCheckConclusion,
) -> WorkflowCheckRecord {
    WorkflowCheckRecord {
        source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
        source_commit: oid(format, '1'),
        run_id: [run; 32],
        attempt_id: [0x45; 32],
        graph_root: [0x56; 32],
        job: "build/linux".into(),
        conclusion,
        evidence: format!("original evidence for run {run}").into_bytes(),
    }
}
fn event(format: GitHashAlgorithm, run: u8, conclusion: WorkflowCheckConclusion) -> ForgeEvent {
    record(format, run, conclusion)
        .proposed_event(publisher(), format)
        .unwrap()
}
fn observation(event: &ForgeEvent) -> &NativeWorkflowCheck {
    let ForgeEventPayload::WorkflowCheckObservedNative(value) = &event.payload else {
        panic!("check fixture");
    };
    value
}
fn observation_mut(event: &mut ForgeEvent) -> &mut NativeWorkflowCheck {
    let ForgeEventPayload::WorkflowCheckObservedNative(value) = &mut event.payload else {
        panic!("check fixture");
    };
    value
}
fn query(format: GitHashAlgorithm, conclusion: WorkflowCheckConclusion) -> Query {
    let record = record(format, 1, conclusion);
    Query::new(
        seq(1),
        Predicate::WorkflowCheck {
            source_ref: record.source_ref,
            source_commit: record.source_commit,
            publisher: publisher(),
            graph_root: record.graph_root,
            job: record.job,
            conclusion,
        },
    )
}
fn genesis() -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: repository(),
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: digest(1),
        forge_position_root: digest(2),
        outcome_index_root: digest(3),
        retention_root: digest(4),
        outbox_root: digest(5),
        configuration_root: digest(6),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}
fn head_id(head: &RepositoryAuthorityHeadBody) -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_internal_object_id(body_id(&CryptoBodyIdentity, head).unwrap())
        .unwrap()
}

/// Each group is one atomic publication. Multiple decisions expose only their
/// final position; its ordered check events belong to the final committed RCR.
fn history(
    groups: Vec<(usize, Vec<ForgeEvent>)>,
) -> (Vec<HistoricalBatch>, RepositoryAuthorityHeadBody) {
    let mut head = genesis();
    let mut history = Vec::new();
    let mut position = 0u64;
    for (width, events) in groups {
        assert!(width > 0);
        let first = seq(position + 1);
        let mut decisions = Vec::new();
        let mut records = Vec::new();
        let framed = encode_body(&ForgeEventBatch { events }).unwrap();
        let events = decode_body::<ForgeEventBatch>(&framed, DecodeLimits::DEFAULT)
            .unwrap()
            .events;
        let event_root = Digest::new(
            DigestAlgorithm::Sha256.id(),
            DigestBytes::try_new(&fgit_crypto::sha256_digest(&framed)).unwrap(),
        );
        let mut parent = head.latest_committed_rcr_id;
        for ordinal in 0..width {
            position += 1;
            let tx_id = TxId::from_digest(
                digest(position + 100).algorithm(),
                CodecVersion::new(1, 0),
                *digest(position + 100).bytes(),
            );
            let record = RepositoryCommitRecord {
                repository_id: repository(),
                repository_sequence: RepositorySequence::try_new(position).unwrap(),
                parent_rcr_id: parent,
                tx_id,
                principal_snapshot_id: PrincipalSnapshotId::from_digest(
                    digest(77).algorithm(),
                    CodecVersion::new(1, 0),
                    *digest(77).bytes(),
                ),
                canonical_request_digest: digest(position + 200),
                ref_delta_root: digest(11),
                resulting_ref_root: head.ref_root,
                object_closure_root: digest(12),
                forge_event_batch_root: if ordinal + 1 == width {
                    event_root
                } else {
                    digest(13)
                },
                resulting_forge_position_root: event_root,
                policy_epoch: head.policy_epoch,
                policy_decision_root: digest(14),
                invariant_evidence_root: digest(15),
                outbox_effect_root: digest(16),
                retention_delta_root: digest(17),
            };
            let id = RepositoryCommitId::from_internal_object_id(
                body_id(&CryptoBodyIdentity, &record).unwrap(),
            )
            .unwrap();
            decisions.push(RepositoryDecision {
                tx_id,
                decision_sequence: seq(position),
                outcome: DecisionOutcome::Committed {
                    repository_commit_id: id,
                },
            });
            parent = Some(id);
            records.push(record);
        }
        let previous = head_id(&head);
        let batch = RepositoryDecisionBatchBody {
            repository_id: repository(),
            predecessor_head_id: previous,
            predecessor_head_generation: head.generation,
            first_decision_sequence: first,
            decisions,
            committed_rcrs: records,
            resulting_ref_root: head.ref_root,
            resulting_forge_position_root: event_root,
            resulting_outcome_index_root: digest(position + 300),
            resulting_retention_root: head.retention_root,
            resulting_outbox_root: head.outbox_root,
            resulting_policy_epoch: head.policy_epoch,
            batch_evidence_root: digest(position + 400),
            compaction_generation_link: None,
        };
        let batch = decode_body::<RepositoryDecisionBatchBody>(
            &encode_body(&batch).unwrap(),
            DecodeLimits::DEFAULT,
        )
        .unwrap();
        let batch_id = RepositoryDecisionBatchId::from_internal_object_id(
            body_id(&CryptoBodyIdentity, &batch).unwrap(),
        )
        .unwrap();
        head.generation = HeadGeneration::try_new(head.generation.get() + 1).unwrap();
        head.predecessor_head_id = Some(previous);
        head.decision_tail_id = Some(batch_id);
        head.latest_decision_sequence = Some(seq(position));
        head.latest_committed_rcr_id = parent;
        head.latest_repository_sequence = Some(RepositorySequence::try_new(position).unwrap());
        head.forge_position_root = event_root;
        head.outcome_index_root = batch.resulting_outcome_index_root;
        history.push(HistoricalBatch {
            batch_id,
            resulting_head_id: head_id(&head),
            resulting_head_generation: head.generation,
            batch,
            forge_events: events,
            ref_updates: Vec::new(),
        });
    }
    (history, head)
}
fn fold_values(
    history: &[HistoricalBatch],
    head: &RepositoryAuthorityHeadBody,
    query: &Query,
) -> Result<Vec<bool>, Error> {
    query.validate(match &query.predicate {
        Predicate::WorkflowCheck { source_commit, .. } => source_commit.algorithm(),
        _ => GitHashAlgorithm::Sha1,
    })?;
    let range = BisectionRange::new(
        query.start,
        query.end.or(head.latest_decision_sequence).unwrap(),
    )
    .unwrap();
    let (points, _) = fold::points(history, head, query, range, None, &mut || Ok(()))?;
    Ok(points
        .iter()
        .map(|point| point.evaluate(&query.predicate) == PredicateOutcome::Satisfied)
        .collect())
}
fn report(
    format: GitHashAlgorithm,
    history: &[HistoricalBatch],
    head: &RepositoryAuthorityHeadBody,
    query: &Query,
) -> Report {
    query.validate(format).unwrap();
    let range = BisectionRange::new(
        query.start,
        query.end.or(head.latest_decision_sequence).unwrap(),
    )
    .unwrap();
    let (points, events) = fold::points(history, head, query, range, None, &mut || Ok(())).unwrap();
    let positions: Vec<_> = points.iter().map(|point| point.sequence).collect();
    let search = search_published_positions(
        repository(),
        range,
        MonotonicityShape::LinearOnly {
            max_steps: query.max_probes,
        },
        &positions,
        |sequence| {
            let point = &points[positions.binary_search(&sequence).unwrap()];
            Ok(ProbeObservation {
                outcome: Ok(point.evaluate(&query.predicate)),
                head_id: point.head,
                policy_epoch: point.epoch,
                replayed_batches: point.replayed,
            })
        },
        &mut || true,
    );
    Report {
        tenant: TenantId::from_bytes([0x11; 16]),
        repository: repository(),
        incarnation: RepositoryIncarnationId::from_bytes([0x44; 16]),
        format,
        source_head: head_id(head),
        source_generation: head.generation.get(),
        current_policy_epoch: head.policy_epoch,
        query: query.clone(),
        history_batches: history.len(),
        history_events: events,
        published_positions: points.len(),
        positions_digest: receipt::positions_digest(&points),
        search,
    }
}

#[test]
fn success_failure_success_uses_latest_exact_check_without_a_monotonicity_assumption() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (history, head) = history(vec![
            (1, Vec::new()),
            (1, vec![event(format, 1, WorkflowCheckConclusion::Success)]),
            (1, vec![event(format, 2, WorkflowCheckConclusion::Failure)]),
            (1, vec![event(format, 3, WorkflowCheckConclusion::Success)]),
        ]);
        let query = query(format, WorkflowCheckConclusion::Failure);
        assert_eq!(
            fold_values(&history, &head, &query).unwrap(),
            [false, false, true, false]
        );
        let report = report(format, &history, &head, &query);
        assert!(report.complete());
        assert!(report.matched());
        assert_eq!(report.search.transition_found, Some(seq(3)));
        assert_eq!(report.search.steps_taken, 3);
        assert!(matches!(
            report.search.monotonicity_shape,
            MonotonicityShape::LinearOnly { .. }
        ));
    }
}

#[test]
fn every_conclusion_has_an_exact_selector_and_absence_is_not_success() {
    let conclusions = [
        WorkflowCheckConclusion::ActionRequired,
        WorkflowCheckConclusion::Success,
        WorkflowCheckConclusion::Failure,
        WorkflowCheckConclusion::Cancelled,
        WorkflowCheckConclusion::TimedOut,
    ];
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut groups = vec![(1, Vec::new())];
        groups.extend(
            conclusions
                .iter()
                .enumerate()
                .map(|(index, conclusion)| (1, vec![event(format, index as u8 + 1, *conclusion)])),
        );
        let (history, head) = history(groups);
        for (index, conclusion) in conclusions.iter().enumerate() {
            let mut expected = vec![false; 6];
            expected[index + 1] = true;
            assert_eq!(
                fold_values(&history, &head, &query(format, *conclusion)).unwrap(),
                expected
            );
        }
    }
}

#[test]
fn competing_subjects_publishers_graphs_and_jobs_do_not_replace_the_selected_check() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for field in 0..5 {
            let good = event(format, 1, WorkflowCheckConclusion::Success);
            let mut other = record(format, 2, WorkflowCheckConclusion::Failure);
            let mut actor = publisher();
            match field {
                0 => other.source_ref = RefName::try_new(b"refs/heads/other").unwrap(),
                1 => other.source_commit = oid(format, '2'),
                2 => actor = PrincipalId::from_bytes([0x34; 16]),
                3 => other.graph_root[0] ^= 1,
                _ => other.job.push('x'),
            }
            let other = other.proposed_event(actor, format).unwrap();
            let (history, head) = history(vec![(1, vec![good]), (1, vec![other])]);
            assert_eq!(
                fold_values(
                    &history,
                    &head,
                    &query(format, WorkflowCheckConclusion::Success)
                )
                .unwrap(),
                [true, true],
                "selector field {field}"
            );
            assert_eq!(
                fold_values(
                    &history,
                    &head,
                    &query(format, WorkflowCheckConclusion::Failure)
                )
                .unwrap(),
                [false, false]
            );
        }
    }
}

#[test]
fn later_attempts_and_runs_replace_the_observation_for_the_same_exact_selector() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let original = event(format, 1, WorkflowCheckConclusion::Success);
        let mut retry = record(format, 1, WorkflowCheckConclusion::Failure);
        retry.attempt_id[0] ^= 1;
        let retry = retry.proposed_event(publisher(), format).unwrap();
        let last = event(format, 2, WorkflowCheckConclusion::TimedOut);
        let (history, head) = history(vec![(1, vec![original]), (1, vec![retry]), (1, vec![last])]);
        assert_eq!(
            fold_values(
                &history,
                &head,
                &query(format, WorkflowCheckConclusion::Failure)
            )
            .unwrap(),
            [false, true, false]
        );
        assert_eq!(
            fold_values(
                &history,
                &head,
                &query(format, WorkflowCheckConclusion::TimedOut)
            )
            .unwrap(),
            [false, false, true]
        );
    }
}

#[test]
fn last_event_in_one_publication_wins_even_when_immutable_ids_are_reverse_sorted() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let first = event(format, 1, WorkflowCheckConclusion::Success);
        let first_id = observation(&first).id();
        let later = (2..=255)
            .map(|run| event(format, run, WorkflowCheckConclusion::Failure))
            .find(|event| observation(event).id() < first_id)
            .expect("deterministic reverse-ID twin");
        let (history, head) = history(vec![(2, vec![first, later])]);
        let mut query = query(format, WorkflowCheckConclusion::Failure);
        query.start = seq(2);
        assert_eq!(fold_values(&history, &head, &query).unwrap(), [true]);
        assert_eq!(
            report(format, &history, &head, &query)
                .search
                .transition_found,
            Some(seq(2))
        );
        query.start = seq(1);
        let interior = report(format, &history, &head, &query);
        assert!(!interior.complete());
        assert!(!interior.matched());
    }
}

#[test]
fn exact_duplicate_observations_follow_literal_canonical_order_but_conflicts_refuse() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let first = event(format, 1, WorkflowCheckConclusion::Success);
        let second = event(format, 2, WorkflowCheckConclusion::Failure);
        let (history, head) = history(vec![
            (1, vec![first.clone()]),
            (1, vec![second]),
            (1, vec![first.clone()]),
        ]);
        assert_eq!(
            fold_values(
                &history,
                &head,
                &query(format, WorkflowCheckConclusion::Success)
            )
            .unwrap(),
            [true, false, true]
        );
        for changed in 0..4 {
            let mut broken = history.clone();
            let mutation = observation_mut(&mut broken[2].forge_events[0]);
            match changed {
                0 => mutation.record.conclusion = WorkflowCheckConclusion::Failure,
                1 => mutation.record.evidence.push(0),
                2 => mutation.record.source_commit = oid(format, '3'),
                _ => mutation.record.graph_root[0] ^= 1,
            }
            assert_eq!(
                fold_values(
                    &broken,
                    &head,
                    &query(format, WorkflowCheckConclusion::Success)
                )
                .unwrap_err()
                .code,
                "corrupt_workflow_check_history"
            );
        }
    }
}

#[test]
fn state_before_requested_range_is_carried_forward_and_missing_checks_remain_false() {
    let format = GitHashAlgorithm::Sha256;
    let (history, head) = history(vec![
        (1, vec![event(format, 1, WorkflowCheckConclusion::Failure)]),
        (2, Vec::new()),
        (1, Vec::new()),
    ]);
    let mut query = query(format, WorkflowCheckConclusion::Failure);
    query.start = seq(3);
    assert_eq!(fold_values(&history, &head, &query).unwrap(), [true, true]);
    let report = report(format, &history, &head, &query);
    assert_eq!(report.search.transition_found, Some(seq(3)));
    assert_eq!(report.search.probes[0].replayed_batches, 2);
    if let Predicate::WorkflowCheck { job, .. } = &mut query.predicate {
        *job = "missing".into();
    }
    assert_eq!(
        fold_values(&history, &head, &query).unwrap(),
        [false, false]
    );
}

#[test]
fn malformed_check_history_refuses_before_unrelated_selector_filtering() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (valid, head) = history(vec![(
            1,
            vec![event(format, 1, WorkflowCheckConclusion::Failure)],
        )]);
        let mut query = query(format, WorkflowCheckConclusion::Success);
        if let Predicate::WorkflowCheck { job, .. } = &mut query.predicate {
            *job = "unrelated".into();
        }
        for mutation in 0..8 {
            let mut broken = valid.clone();
            let event = &mut broken[0].forge_events[0];
            match mutation {
                0 => event.version = AggregateVersion::try_new(2).unwrap(),
                1 => {
                    event.aggregate =
                        AggregateId::WorkflowCheck(WorkflowCheckId::from_bytes([0xff; 32]))
                }
                2 => event.aggregate = AggregateId::Issue(fgit_forge::IssueNumber::FIRST),
                3 => observation_mut(event).record.job.clear(),
                4 => observation_mut(event).record.evidence.clear(),
                5 => {
                    observation_mut(event).record.source_ref =
                        RefName::try_new(b"refs/tags/release").unwrap()
                }
                6 => observation_mut(event).record.source_commit = oid(format, '0'),
                _ => {
                    observation_mut(event).record.source_commit = oid(
                        if format == GitHashAlgorithm::Sha1 {
                            GitHashAlgorithm::Sha256
                        } else {
                            GitHashAlgorithm::Sha1
                        },
                        '1',
                    )
                }
            }
            assert_eq!(
                fold_values(&broken, &head, &query).unwrap_err().code,
                "corrupt_workflow_check_history",
                "mutation {mutation}"
            );
        }
        let mut wrong_payload = valid.clone();
        wrong_payload[0].forge_events[0].payload = ForgeEventPayload::PullRequestHeadAdvanced {
            source_tip: digest(1),
        };
        assert_eq!(
            fold_values(&wrong_payload, &head, &query).unwrap_err().code,
            "corrupt_workflow_check_history"
        );
    }
}

#[test]
fn query_checks_native_domain_branch_job_bytes_and_finite_probe_budget() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let accepted = query(format, WorkflowCheckConclusion::Failure);
        assert!(accepted.validate(format).is_ok());
        for value in [0, MAX_PROBES + 1] {
            let mut bad = accepted.clone();
            bad.max_probes = value;
            assert_eq!(bad.validate(format).unwrap_err().code, "probe_limit");
        }
        for bad_job in [
            String::new(),
            "newline\n".into(),
            "nul\0".into(),
            "é".repeat(MAX_CHECK_JOB_BYTES / 2 + 1),
        ] {
            let mut bad = accepted.clone();
            if let Predicate::WorkflowCheck { job, .. } = &mut bad.predicate {
                *job = bad_job;
            }
            assert_eq!(
                bad.validate(format).unwrap_err().code,
                "workflow_check_selector"
            );
        }
        let mut boundary = accepted.clone();
        if let Predicate::WorkflowCheck { job, .. } = &mut boundary.predicate {
            *job = "é".repeat(MAX_CHECK_JOB_BYTES / 2);
        }
        assert!(boundary.validate(format).is_ok());
        for wrong in [
            oid(format, '0'),
            oid(
                if format == GitHashAlgorithm::Sha1 {
                    GitHashAlgorithm::Sha256
                } else {
                    GitHashAlgorithm::Sha1
                },
                '1',
            ),
        ] {
            let mut bad = accepted.clone();
            if let Predicate::WorkflowCheck { source_commit, .. } = &mut bad.predicate {
                *source_commit = wrong;
            }
            assert_eq!(bad.validate(format).unwrap_err().code, "object_format");
        }
        let mut bad = accepted.clone();
        if let Predicate::WorkflowCheck { source_ref, .. } = &mut bad.predicate {
            *source_ref = RefName::try_new(b"refs/tags/v1").unwrap();
        }
        assert_eq!(
            bad.validate(format).unwrap_err().code,
            "workflow_check_selector"
        );
        let mut reversed = accepted;
        reversed.start = seq(3);
        reversed.end = Some(seq(2));
        assert_eq!(reversed.validate(format).unwrap_err().code, "invalid_range");
    }
}

#[test]
fn probe_exhaustion_never_reports_a_later_check_as_a_completed_match() {
    let format = GitHashAlgorithm::Sha256;
    let (history, head) = history(vec![
        (1, Vec::new()),
        (1, vec![event(format, 1, WorkflowCheckConclusion::Success)]),
        (1, vec![event(format, 2, WorkflowCheckConclusion::Failure)]),
    ]);
    let mut query = query(format, WorkflowCheckConclusion::Failure);
    query.max_probes = 2;
    let limited = report(format, &history, &head, &query);
    assert!(!limited.complete());
    assert!(!limited.matched());
    assert_eq!(limited.search.steps_taken, 2);
    assert_eq!(limited.search.transition_found, None);
    assert!(matches!(
        limited.search.termination,
        BisectionTermination::Refused {
            reason: BisectionRefusal::BudgetExhausted {
                steps_taken: 2,
                max_budget: 2
            }
        }
    ));
    query.max_probes = 3;
    let complete = report(format, &history, &head, &query);
    assert!(complete.complete());
    assert_eq!(complete.search.transition_found, Some(seq(3)));
}

#[test]
fn every_observed_fold_checkpoint_cancels_without_mutating_history() {
    let format = GitHashAlgorithm::Sha1;
    let (history, head) = history(vec![
        (1, vec![event(format, 1, WorkflowCheckConclusion::Success)]),
        (
            1,
            vec![
                event(format, 2, WorkflowCheckConclusion::Failure),
                event(format, 3, WorkflowCheckConclusion::TimedOut),
            ],
        ),
    ]);
    let original = history.clone();
    let query = query(format, WorkflowCheckConclusion::Failure);
    let range = BisectionRange::new(seq(1), seq(2)).unwrap();
    let mut checkpoints = 0usize;
    fold::points(&history, &head, &query, range, None, &mut || {
        checkpoints += 1;
        Ok(())
    })
    .unwrap();
    assert!(checkpoints >= 6);
    for stop in 1..=checkpoints {
        let mut seen = 0usize;
        let result = fold::points(&history, &head, &query, range, None, &mut || {
            seen += 1;
            if seen == stop {
                Err(Error::new("request_stopped", "injected cancellation"))
            } else {
                Ok(())
            }
        });
        assert_eq!(
            result.err().expect("cancelled fold must refuse").code,
            "request_stopped"
        );
        assert_eq!(seen, stop);
        assert_eq!(history, original);
    }
}

#[test]
fn event_count_history_gaps_and_final_head_mismatch_still_refuse() {
    let format = GitHashAlgorithm::Sha1;
    let (original, head) = history(vec![
        (1, vec![event(format, 1, WorkflowCheckConclusion::Success)]),
        (1, Vec::new()),
    ]);
    let query = query(format, WorkflowCheckConclusion::Success);
    let mut excessive = original.clone();
    excessive[0].forge_events = vec![excessive[0].forge_events[0].clone(); MAX_EVENTS + 1];
    assert_eq!(
        fold_values(&excessive, &head, &query).unwrap_err().code,
        "history_limit"
    );
    let mut gap = original.clone();
    gap[1].batch.first_decision_sequence = seq(3);
    assert_eq!(
        fold_values(&gap, &head, &query).unwrap_err().code,
        "corrupt_history"
    );
    let mut moved = head;
    moved.latest_decision_sequence = Some(seq(3));
    assert_eq!(
        fold_values(&original, &moved, &query).unwrap_err().code,
        "snapshot_changed"
    );
}

fn verify_json_digest(json: &str) -> String {
    let (payload, suffix) = json.rsplit_once(",\"receipt_sha256\":\"").unwrap();
    let expected = fgit_crypto::sha256_digest(format!("{payload}}}").as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(suffix, format!("{expected}\"}}"));
    expected
}

#[test]
fn diagnostic_receipt_binds_every_check_coordinate_conclusion_and_probe() {
    let format = GitHashAlgorithm::Sha256;
    let (history, head) = history(vec![(
        1,
        vec![event(format, 1, WorkflowCheckConclusion::Failure)],
    )]);
    let original = report(
        format,
        &history,
        &head,
        &query(format, WorkflowCheckConclusion::Failure),
    );
    let json = original.to_json();
    let digest = verify_json_digest(&json);
    assert!(json.contains("\"kind\":\"workflow_check\""));
    assert!(json.contains("\"conclusion\":\"failure\""));
    assert!(json.contains("\"strategy\":\"exhaustive_published_states\""));
    for field in 0..7 {
        let mut changed = original.clone();
        let Predicate::WorkflowCheck {
            source_ref,
            source_commit,
            publisher,
            graph_root,
            job,
            conclusion,
        } = &mut changed.query.predicate
        else {
            unreachable!()
        };
        match field {
            0 => *source_ref = RefName::try_new(b"refs/heads/other").unwrap(),
            1 => *source_commit = oid(format, '2'),
            2 => *publisher = PrincipalId::from_bytes([0x34; 16]),
            3 => graph_root[0] ^= 1,
            4 => *job = "build/\"quoted\\é".into(),
            5 => *conclusion = WorkflowCheckConclusion::Cancelled,
            _ => changed.search.probes[0].outcome = Ok(PredicateOutcome::Unsatisfied),
        }
        let changed_json = changed.to_json();
        assert_ne!(
            verify_json_digest(&changed_json),
            digest,
            "unbound field {field}"
        );
        if field == 4 {
            assert!(changed_json.contains("\"job\":\"build/\\\"quoted\\\\é\""));
        }
    }
    assert_eq!(original.to_json(), json);
}

#[test]
fn existing_predicate_json_encodings_remain_in_the_original_v1_profile() {
    let (history, head) = history(vec![(1, Vec::new())]);
    let cases = [
        (
            Predicate::RefAbsent {
                name: RefName::try_new(b"refs/heads/a").unwrap(),
            },
            "{\"kind\":\"ref_absent\",\"ref_hex\":\"726566732f68656164732f61\"}".to_owned(),
        ),
        (
            Predicate::RefEquals {
                name: RefName::try_new(b"refs/heads/a").unwrap(),
                target: oid(GitHashAlgorithm::Sha1, '1'),
            },
            format!(
                "{{\"kind\":\"ref_equals\",\"ref_hex\":\"726566732f68656164732f61\",\"oid\":\"{}\"}}",
                oid(GitHashAlgorithm::Sha1, '1')
            ),
        ),
        (
            Predicate::PolicyAtLeast(PolicyEpoch::FIRST),
            "{\"kind\":\"policy_at_least\",\"epoch\":\"1\"}".to_owned(),
        ),
        (
            Predicate::IssueState {
                number: fgit_forge::IssueNumber::FIRST,
                state: fgit_forge::event::issue::IssueState::Closed,
            },
            "{\"kind\":\"issue_state\",\"number\":\"1\",\"state\":\"closed\"}".to_owned(),
        ),
        (
            Predicate::PullRequestState {
                number: fgit_forge::PullRequestNumber::FIRST,
                state: super::PullState::Merged,
            },
            "{\"kind\":\"pull_request_state\",\"number\":\"1\",\"state\":\"merged\"}".to_owned(),
        ),
    ];
    for (predicate, expected) in cases {
        let report = report(
            GitHashAlgorithm::Sha1,
            &history,
            &head,
            &Query::new(seq(1), predicate),
        );
        let json = report.to_json();
        assert!(
            json.contains(&format!("\"predicate\":{expected},\"requested_start\"")),
            "{json}"
        );
        assert!(json.contains("\"schema_version\":1,\"profile\":\"forge-state-bisect-local-v1\""));
        assert!(!json.contains("workflow_check"));
        verify_json_digest(&json);
    }
}
