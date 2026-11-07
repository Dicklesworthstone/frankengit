//! Real queued candidates, explicit refresh authority and original-command custody.
use super::*;
use fgit_admission::merge::native::pull_request::PullRequestView;
use fgit_forge::ForgeEventPayload;
use fgit_forge::merge_queue::{DequeueReason, MergeQueueSnapshot};
use fgit_node::workflow_watch::{
    QueueRefreshMode, TrustedQueueLanding, TrustedQueueRefresh, WorkflowWatchConfig,
    WorkflowWatchControl, run_service_with_ready,
};
use fgit_types::{PrincipalId, RepositoryAuthorityHeadId};
use std::time::Duration;

// The original queue fixture filters on "right". Once a sibling lands, its
// successor's incoming diff need not include that path. Use an unfiltered PR
// workflow so both real candidates must execute, while checking their actual
// merged files before writing the external execution marker.
fn continuing_fixture(format: GitHashAlgorithm) -> (Fixture, GitOid) {
    let mut f = Fixture::new(format, WORKFLOW);
    let mut objects = Objects(BTreeMap::new());
    let definition = format!(
        "name: queue-check\non: pull_request\njobs:\n  check:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: test \"$(cat left)\" = target && test \"$(cat right)\" = source || exit 7; printf x >> '{}'\n",
        f.root.join("executed").display(),
    );
    let workflow = objects.put(format, GitObjectKind::Blob, definition.into_bytes());
    let ci = objects.put(
        format,
        GitObjectKind::Tree,
        [b"100644 check.yml\0".as_slice(), workflow.as_bytes()].concat(),
    );
    let left = objects.put(format, GitObjectKind::Blob, b"base\n".to_vec());
    let right = objects.put(format, GitObjectKind::Blob, b"source\n".to_vec());
    let tree = objects.put(
        format,
        GitObjectKind::Tree,
        [
            b"40000 ci\0".as_slice(),
            ci.as_bytes(),
            b"100644 left\0",
            left.as_bytes(),
            b"100644 right\0",
            right.as_bytes(),
            b"100644 workflow.yml\0",
            f.workflow.as_bytes(),
        ]
        .concat(),
    );
    let first = objects.put(
        format,
        GitObjectKind::Commit,
        commit_bytes(tree, &[f.source], "first refreshable queued source"),
    );
    let second = objects.put(
        format,
        GitObjectKind::Commit,
        commit_bytes(tree, &[f.source], "second refreshable queued source"),
    );
    let limits = PackLimits::default();
    let plan = PackPlanner::new(
        format,
        PackWriteProfile::COMPRESSED_NO_DELTA_V1,
        limits.clone(),
    )
    .plan_selected(
        &objects,
        &objects.0.keys().copied().collect::<Vec<_>>(),
        &mut || true,
    )
    .unwrap();
    let (pack, _) = PackWriter::new(limits).write(&plan, &mut || true).unwrap();
    let mut bundle = match format {
        GitHashAlgorithm::Sha1 => b"# v2 git bundle\n".to_vec(),
        GitHashAlgorithm::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".to_vec(),
    };
    bundle.extend_from_slice(
        format!(
            "-{} original incoming\n{first} refs/heads/topic\n{second} refs/heads/topic-two\n\n",
            f.source
        )
        .as_bytes(),
    );
    bundle.extend_from_slice(&pack);
    let node = f.node();
    let imported = node
        .runtime()
        .block_on(node.import_incremental_git_bundle_durable_in(
            &node.request_context(),
            &session(b"automatic-refresh-ci-definitions"),
            &bundle,
            &[(source_ref(), Some(f.source)), (second_ref(), None)],
            Default::default(),
        ))
        .unwrap();
    assert!(
        imported.commands.iter().all(|row| matches!(
            row.terminal.outcome,
            DecisionOutcome::Committed { .. }
        ))
    );
    f.source = first;
    for (number, source, tip, priority) in [
        (1, source_ref(), first, 7),
        (2, second_ref(), second, 11),
    ] {
        open_with_body(&f, number, source.clone(), tip);
        change_queue(
            &f,
            number - 1,
            QueueCommandAction::Enqueue {
                pull_request: pull_number(number),
                expected_pull_request_version: AggregateVersion::FIRST,
                source_ref: source,
                head_tip: tip,
                expected_target_tip: f.target,
                priority,
            },
            format!("automatic-refresh-enqueue-{number}").as_bytes(),
        );
    }
    (f, second)
}

fn refresh(
    f: &Fixture,
    merge: &PullRequestMergeWatchConfig,
    principal: PrincipalId,
    mode: QueueRefreshMode,
    observe: impl FnMut(&str) -> Result<(), String>,
) -> TrustedQueueRefresh {
    let node = f.node();
    node.runtime()
        .block_on(node.refresh_trusted_queue_head_merge_workflows_in(
            &node.request_context(),
            &target_ref(),
            1,
            b"ci",
            &f.parent(),
            merge,
            OWNER,
            OWNER,
            principal,
            mode,
            observe,
        ))
}

fn land(f: &Fixture, merge: &PullRequestMergeWatchConfig) -> TrustedQueueLanding {
    let node = f.node();
    node.runtime()
        .block_on(node.land_trusted_queue_head_merge_workflows_in(
            &node.request_context(),
            &target_ref(),
            1,
            b"ci",
            &f.parent(),
            OWNER,
            merge,
            OWNER,
            |_| Ok(()),
        ))
}

fn checks(f: &Fixture, merge: &PullRequestMergeWatchConfig) -> usize {
    let node = f.node();
    let report = node.runtime().block_on(
        node.publish_trusted_queue_head_merge_workflow_checks_in(
            &node.request_context(),
            &target_ref(),
            1,
            b"ci",
            &f.parent(),
            OWNER,
            merge,
            |_| Ok(()),
        ),
    );
    assert!(report.error.is_none(), "{:?}", report.error);
    assert!(!report.request_stopped);
    assert_eq!(report.refused, 0);
    report.committed
}

fn queue(f: &Fixture) -> MergeQueueSnapshot {
    let node = f.node();
    node.runtime()
        .block_on(node.read_queue_in(
            &node.request_context(),
            &Default::default(),
            QueueNumber::FIRST,
            None,
        ))
        .unwrap()
        .queue
        .unwrap()
}

fn pull(f: &Fixture, number: u64) -> PullRequestView {
    let node = f.node();
    node.runtime()
        .block_on(node.read_pull_requests_in(
            &node.request_context(),
            &Default::default(),
            0,
            100,
            None,
        ))
        .unwrap()
        .pull_requests
        .into_iter()
        .find(|row| row.number == pull_number(number))
        .unwrap()
}

fn position(f: &Fixture) -> RepositoryAuthorityHeadId {
    let node = f.node();
    node.runtime()
        .block_on(node.materialize_admission())
        .unwrap()
        .basis()
        .id()
}

fn refs(f: &Fixture) -> BTreeMap<RefName, GitOid> {
    let node = f.node();
    node.runtime()
        .block_on(node.materialize_admission())
        .unwrap()
        .snapshot()
        .refs
        .clone()
}

fn candidate(format: GitHashAlgorithm, observed: &str) -> GitOid {
    let candidate = observed.split_once("\"merge_candidate\":").unwrap().1;
    GitOid::from_hex(format, json_string(candidate, "commit")).unwrap()
}

fn attempts(f: &Fixture) -> Vec<PathBuf> {
    let mut records = Vec::new();
    for entry in fs::read_dir(f.parent()).unwrap().map(Result::unwrap) {
        if !entry.file_name().to_str().is_some_and(|name| name.starts_with("watch-")) {
            continue;
        }
        let root = entry.path().join("queue-refresh");
        if root.exists() {
            for record in fs::read_dir(root).unwrap().map(Result::unwrap) {
                if record.file_name().to_str().is_some_and(|name| name.starts_with("attempt-")) {
                    records.push(record.path());
                }
            }
        }
    }
    records.sort();
    records
}

fn acknowledgment(attempt: &std::path::Path) -> PathBuf {
    let name = attempt.file_name().unwrap().to_str().unwrap();
    attempt.with_file_name(name.replacen("attempt-", "outcome-", 1))
}

fn service_config(
    f: &Fixture,
    merge: &PullRequestMergeWatchConfig,
) -> WorkflowWatchConfig {
    WorkflowWatchConfig::try_new(
        f.source.algorithm(),
        target_ref(),
        b"ci".to_vec(),
        f.parent(),
        read_inputs(),
        Duration::from_millis(10),
    )
    .unwrap()
    .with_merge_queue(1)
    .unwrap()
    .with_merge_candidate(merge.clone())
    .unwrap()
    .with_publisher(OWNER)
    .with_landing_principal(OWNER)
}

fn first_landing(f: &Fixture, merge: &PullRequestMergeWatchConfig) -> GitOid {
    let observed = poll(f, merge).unwrap();
    assert!(observed.contains("\"succeeded\":true"), "{observed}");
    let tested = candidate(f.source.algorithm(), &observed);
    assert_eq!(checks(f, merge), 1);
    let landed = land(f, merge);
    assert!(landed.error.is_none(), "{landed:?}");
    assert_eq!(landed.committed, 1);
    assert_eq!(queue(f).version, version(4));
    assert_eq!(queue(f).deterministic_order(), vec![pull_number(1)]);
    assert_eq!(refs(f)[&target_ref()], tested);
    tested
}

fn require_check(f: &Fixture, observed: &str) {
    let node = f.node();
    let (_, outcome) = node.runtime().block_on(node.admit_review_protection_durable_in(
        &node.request_context(),
        &session(b"automatic-refresh-required-check"),
        &ProtectionCommand {
            expected_version: ExpectedVersion::NewStream,
            expected_epoch: PolicyEpoch::FIRST,
            protection: ReviewProtection {
                administrators: vec![OWNER],
                ref_policy: None,
                branches: vec![ProtectedBranch {
                    path_reviews: Vec::new(),
                    name: target_ref(),
                    reviewers: Vec::new(),
                    required_approvals: 0,
                    required_candidate_checks: Vec::new(),
                    require_merge_queue: true,
                    required_checks: vec![RequiredWorkflowCheck {
                        source_ref: ci_ref(),
                        publisher: OWNER,
                        graph_root: hex32(json_string(observed, "graph_sha256")),
                        job: "check".into(),
                    }],
                }],
            },
        },
        Default::default(),
    )).unwrap();
    assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }));
}

fn open_with_body(f: &Fixture, number: u64, source: RefName, tip: GitOid) {
    let node = f.node();
    let (_, outcome) = node.runtime().block_on(node.admit_pull_request_durable_in(
        &node.request_context(),
        &session(format!("automatic-refresh-open-{number}").as_bytes()),
        &PullRequestCommand {
            number: pull_number(number),
            expected_version: ExpectedVersion::NewStream,
            action: PullRequestAction::Open,
            data: PullRequestData {
                source_ref: source,
                target_ref: target_ref(),
                source_tip: tip,
                target_tip: f.target,
                title: format!("Queue candidate {number}"),
                body: "Original PR text é\nThis text grants no authority.\n".into(),
            },
        },
        Default::default(),
    )).unwrap();
    assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }));
}

#[test]
fn two_heads_execute_fresh_checks_and_land_with_one_target_only_refresh_between_them() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut f, second) = continuing_fixture(format);
        let merge = config();
        let original = poll(&f, &merge).unwrap();
        require_check(&f, &original);
        let first_run = poll(&f, &merge).unwrap();
        assert!(first_run.contains("\"succeeded\":true"), "{first_run}");
        let first_candidate = candidate(format, &first_run);
        assert_eq!(checks(&f, &merge), 2);
        let first = land(&f, &merge);
        assert!(first.error.is_none(), "{first:?}");
        assert_eq!(first.committed, 1);
        assert_eq!(queue(&f).version, version(4));
        assert_eq!(queue(&f).deterministic_order(), vec![pull_number(1)]);
        assert_eq!(refs(&f)[&target_ref()], first_candidate);
        assert_eq!(pull(&f, 2).event.version, version(2));

        // Existing execution/landing grants do not silently add refresh authority.
        assert!(service_config(&f, &merge).queue_refresh_principal().is_none());
        let before = position(&f);
        let before_queue = queue(&f);
        let before_pull = pull(&f, 1);
        let before_refs = refs(&f);
        assert!(
            poll(&f, &merge).unwrap().contains("\"state\":\"queue_head_stale\"")
        );
        assert_eq!(position(&f), before);
        assert!(attempts(&f).is_empty());
        assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"xx");

        let mut decisions = Vec::new();
        let refreshed = refresh(&f, &merge, OWNER, QueueRefreshMode::RecoverAndSelect, |row| {
            if row.contains("\"type\":\"workflow_queue_refresh_decision\"") {
                decisions.push(row.to_owned());
            }
            Ok(())
        });
        assert!(refreshed.error.is_none(), "{refreshed:?}");
        assert_eq!(refreshed.committed, 1);
        assert_eq!(refreshed.refused, 0);
        assert_eq!(decisions.len(), 1);
        assert_eq!(queue(&f), before_queue);
        assert_eq!(refs(&f), before_refs);
        let changed = pull(&f, 1);
        assert_eq!(changed.event.version, version(2));
        let mut expected_data = before_pull.data.unwrap();
        expected_data.target_tip = first_candidate;
        assert_eq!(changed.data.as_ref(), Some(&expected_data));
        assert_eq!(changed.opened_by, before_pull.opened_by);
        let ForgeEventPayload::PullRequestChangedNative(event) = &changed.event.payload else {
            panic!("refresh must preserve the open PR metadata stream");
        };
        assert_eq!(event.action, PullRequestAction::Update);
        assert_eq!(event.actor, OWNER);
        assert_eq!(attempts(&f).len(), 1);

        let second_run = poll(&f, &merge).unwrap();
        assert!(second_run.contains("\"state\":\"dispatched\""), "{second_run}");
        assert!(second_run.contains("\"succeeded\":true"), "{second_run}");
        assert!(second_run.contains("\"pull_request\":\"1\""), "{second_run}");
        assert!(second_run.contains("\"pull_request_version\":\"2\""), "{second_run}");
        let second_candidate = candidate(format, &second_run);
        assert_ne!(second_candidate, first_candidate);
        assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"xxx");

        // The first candidate's successful checks cannot authorize the successor.
        let held = position(&f);
        let waiting = land(&f, &merge);
        assert!(waiting.error.is_none(), "{waiting:?}");
        assert_eq!(waiting.committed, 0);
        assert!(waiting.waiting > 0);
        assert_eq!(position(&f), held);
        assert_eq!(refs(&f)[&target_ref()], first_candidate);
        assert_eq!(checks(&f, &merge), 1);
        let landed = land(&f, &merge);
        assert!(landed.error.is_none(), "{landed:?}");
        assert_eq!(landed.committed, 1);
        assert_eq!(landed.refused, 0);
        let completed = queue(&f);
        assert_eq!(completed.version, version(6));
        assert!(completed.entries.is_empty());
        assert!(completed.active_batch.is_none());
        let final_refs = refs(&f);
        assert_eq!(final_refs[&target_ref()], second_candidate);
        assert_eq!(final_refs[&source_ref()], f.source);
        assert_eq!(final_refs[&second_ref()], second);
        assert_eq!(pull(&f, 1).event.version, version(3));
        assert_eq!(pull(&f, 2).event.version, version(2));
        let held = position(&f);
        f.reopen();
        let recovered = refresh(&f, &merge, OWNER, QueueRefreshMode::RecoverOnly, |_| Ok(()));
        assert!(recovered.error.is_none(), "{recovered:?}");
        assert_eq!(recovered.committed, 0);
        assert_eq!(recovered.previously_decided, 1);
        assert_eq!(position(&f), held);
        assert_eq!(refs(&f), final_refs);
        assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"xxx");
    }
}

#[test]
fn service_readiness_and_controller_ready_output_precede_every_fresh_refresh() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut f, _) = continuing_fixture(format);
        let merge = config();
        first_landing(&f, &merge);
        let before = position(&f);
        let before_pull = pull(&f, 1);
        let before_queue = queue(&f);
        let before_refs = refs(&f);
        let service = service_config(&f, &merge).with_queue_refresh_principal(OWNER);
        assert_eq!(service.queue_refresh_principal(), Some(OWNER));
        f.node.take().unwrap().shutdown().unwrap();
        let ready = std::cell::Cell::new(false);
        let error = run_service_with_ready(
            f.config.clone(),
            service,
            WorkflowWatchControl::default(),
            || {
                ready.set(true);
                Err(std::io::Error::other("test refresh readiness output unavailable"))
            },
        )
        .unwrap_err();
        assert!(ready.get());
        let receipt = error.receipt().unwrap();
        assert!(receipt.node_closed);
        assert_eq!(receipt.refreshes_committed, 0);
        assert_eq!(receipt.refreshes_refused, 0);
        assert_eq!(receipt.landings_committed, 0);
        assert_eq!(receipt.dispatched, 0);
        f.reopen();
        assert_eq!(position(&f), before);
        assert_eq!(pull(&f, 1).event, before_pull.event);
        assert_eq!(queue(&f), before_queue);
        assert_eq!(refs(&f), before_refs);
        assert!(attempts(&f).is_empty());

        let mut offered = false;
        let rejected = refresh(&f, &merge, OWNER, QueueRefreshMode::RecoverAndSelect, |row| {
            if row.contains("\"type\":\"workflow_queue_refresh_ready\"") {
                offered = true;
                Err("test refresh proposal observer failed".into())
            } else {
                Ok(())
            }
        });
        assert!(offered);
        assert!(rejected.error.is_some(), "{rejected:?}");
        assert_eq!(rejected.committed, 0);
        assert_eq!(rejected.refused, 0);
        assert_eq!(position(&f), before);
        assert_eq!(queue(&f), before_queue);
        assert_eq!(refs(&f), before_refs);
        assert!(attempts(&f).is_empty(), "failed ready output must not retain an intent");
        assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"x");
    }
}

#[test]
fn lost_refresh_observer_keeps_original_command_and_blocks_a_restart_without_its_grant() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut f, _) = continuing_fixture(format);
        let merge = config();
        first_landing(&f, &merge);
        let mut lost_decision = None;
        let lost = refresh(&f, &merge, OWNER, QueueRefreshMode::RecoverAndSelect, |row| {
            if row.contains("\"type\":\"workflow_queue_refresh_decision\"") {
                lost_decision = Some(row.to_owned());
                Err("test consumer lost the refresh decision".into())
            } else {
                Ok(())
            }
        });
        assert_eq!(lost.committed, 1);
        assert!(lost.error.as_deref().unwrap().contains("lost the refresh decision"));
        let lost_decision = lost_decision.unwrap();
        let records = attempts(&f);
        assert_eq!(records.len(), 1);
        let retained = fs::read(&records[0]).unwrap();
        assert!(!acknowledgment(&records[0]).exists());
        assert_eq!(pull(&f, 1).event.version, version(2));
        let held = position(&f);
        assert!(
            poll(&f, &merge).is_err(),
            "unacknowledged refresh must fence ordinary execution without a refresh flag"
        );
        let blocked_landing = land(&f, &merge);
        assert!(blocked_landing.error.is_some(), "{blocked_landing:?}");
        assert_eq!(blocked_landing.committed, 0);
        assert_eq!(position(&f), held);

        // A matching grant validates custody before readiness but cannot replay
        // the original request until readiness succeeds. Failed output retains
        // both the original bytes and visible reconciliation responsibility.
        let authorized = service_config(&f, &merge).with_queue_refresh_principal(OWNER);
        f.node.take().unwrap().shutdown().unwrap();
        let ready = std::cell::Cell::new(false);
        let error = run_service_with_ready(
            f.config.clone(),
            authorized,
            WorkflowWatchControl::default(),
            || {
                ready.set(true);
                Err(std::io::Error::other("pending refresh readiness output unavailable"))
            },
        )
        .unwrap_err();
        assert!(ready.get());
        let receipt = error.receipt().unwrap();
        assert!(receipt.node_closed);
        assert!(receipt.requires_reconciliation);
        assert_eq!(receipt.refreshes_committed, 0);
        assert_eq!(receipt.refreshes_refused, 0);
        assert_eq!(receipt.landings_committed, 0);
        assert_eq!(receipt.dispatched, 0);
        f.reopen();
        assert_eq!(position(&f), held);
        assert_eq!(fs::read(&records[0]).unwrap(), retained);
        assert!(!acknowledgment(&records[0]).exists());

        // A differently configured service cannot infer sponsorship from disk.
        f.node.take().unwrap().shutdown().unwrap();
        let ready = std::cell::Cell::new(false);
        let error = run_service_with_ready(
            f.config.clone(),
            service_config(&f, &merge),
            WorkflowWatchControl::default(),
            || {
                ready.set(true);
                Err(std::io::Error::other("missing refresh grant reached readiness"))
            },
        )
        .unwrap_err();
        assert!(!ready.get(), "unacknowledged refresh must fail before readiness");
        assert!(error.receipt().unwrap().node_closed);
        assert_eq!(error.receipt().unwrap().refreshes_committed, 0);
        assert_eq!(error.receipt().unwrap().landings_committed, 0);
        f.reopen();
        assert_eq!(position(&f), held);
        let changed_actor = refresh(
            &f,
            &merge,
            PrincipalId::from_bytes([0x7f; 16]),
            QueueRefreshMode::RecoverOnly,
            |_| Ok(()),
        );
        assert!(changed_actor.error.is_some(), "{changed_actor:?}");
        assert_eq!(position(&f), held);

        // Advance current metadata and remove the head after the lost reply.
        // Recovery must submit the retained command, not rebuild it from this PR.
        let mut later = pull(&f, 1).data.unwrap();
        later.title = "A later independent metadata edit".into();
        later.body = "Retain this later body verbatim.\n".into();
        let node = f.node();
        let (_, outcome) = node.runtime().block_on(node.admit_pull_request_durable_in(
            &node.request_context(),
            &session(b"metadata-after-lost-refresh"),
            &PullRequestCommand {
                number: pull_number(1),
                expected_version: ExpectedVersion::Exactly(version(2)),
                action: PullRequestAction::Update,
                data: later.clone(),
            },
            Default::default(),
        )).unwrap();
        assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }));
        change_queue(
            &f,
            4,
            QueueCommandAction::Dequeue {
                pull_request: pull_number(1),
                reason: DequeueReason::Withdrawn,
            },
            b"dequeue-after-lost-refresh",
        );
        assert!(queue(&f).entries.is_empty());
        let held = position(&f);
        let current_refs = refs(&f);
        f.reopen();
        let mut recovered_decisions = Vec::new();
        let recovered = refresh(&f, &merge, OWNER, QueueRefreshMode::RecoverOnly, |row| {
            if row.contains("\"type\":\"workflow_queue_refresh_decision\"") {
                recovered_decisions.push(row.to_owned());
            }
            Ok(())
        });
        assert!(recovered.error.is_none(), "{recovered:?}");
        assert_eq!(recovered.committed, 1);
        assert_eq!(recovered.refused, 0);
        assert_eq!(recovered_decisions, vec![lost_decision]);
        assert_eq!(position(&f), held);
        assert_eq!(refs(&f), current_refs);
        assert_eq!(pull(&f, 1).event.version, version(3));
        assert_eq!(pull(&f, 1).data.as_ref(), Some(&later));
        assert!(queue(&f).entries.is_empty());
        assert_eq!(fs::read(&records[0]).unwrap(), retained);
        assert!(acknowledgment(&records[0]).is_file());

        // Once canonically checked and acknowledged, recovery without submission
        // authority is a read-only custody validation and changes nothing.
        let node = f.node();
        node.runtime().block_on(node.validate_trusted_queue_head_refresh_custody_in(
            &node.request_context(),
            &target_ref(),
            1,
            b"ci",
            &f.parent(),
            &merge,
            None,
        )).unwrap();
        let again = refresh(&f, &merge, OWNER, QueueRefreshMode::RecoverOnly, |_| Ok(()));
        assert!(again.error.is_none(), "{again:?}");
        assert_eq!(again.previously_decided, 1);
        assert_eq!(again.committed, 0);
        assert_eq!(position(&f), held);
        assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"x");
    }
}

#[test]
fn corrupt_or_forged_refresh_acknowledgments_never_release_execution_or_landing() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut f, _) = continuing_fixture(format);
        let merge = config();
        first_landing(&f, &merge);
        let accepted = refresh(&f, &merge, OWNER, QueueRefreshMode::RecoverAndSelect, |_| Ok(()));
        assert!(accepted.error.is_none(), "{accepted:?}");
        assert_eq!(accepted.committed, 1);
        let records = attempts(&f);
        assert_eq!(records.len(), 1);
        let path = acknowledgment(&records[0]);
        let original = fs::read(&path).unwrap();
        assert_eq!(original.len(), 81);
        let mut wrong_outcome = original.clone();
        assert_eq!(wrong_outcome[40], 1, "the actual canonical refresh committed");
        wrong_outcome[40] = 2;
        let checksum = sha256_digest(&wrong_outcome[..49]);
        wrong_outcome[49..].copy_from_slice(&checksum);
        let held = position(&f);
        let before_pull = pull(&f, 1);
        let before_queue = queue(&f);
        let before_refs = refs(&f);

        // The second case has a valid local checksum and original command digest.
        // Only canonical terminal lookup can reject its false refusal tag.
        for bytes in [b"truncated local acknowledgement".to_vec(), wrong_outcome] {
            fs::write(&path, bytes).unwrap();
            f.reopen();
            for principal in [None, Some(OWNER)] {
                let node = f.node();
                assert!(node.runtime().block_on(
                    node.validate_trusted_queue_head_refresh_custody_in(
                        &node.request_context(),
                        &target_ref(),
                        1,
                        b"ci",
                        &f.parent(),
                        &merge,
                        principal,
                    )
                ).is_err());
            }
            let recovering = refresh(&f, &merge, OWNER, QueueRefreshMode::RecoverOnly, |_| Ok(()));
            assert!(recovering.error.is_some(), "{recovering:?}");
            assert_eq!(recovering.committed, 0);
            assert_eq!(recovering.refused, 0);
            assert!(poll(&f, &merge).is_err());
            let landing = land(&f, &merge);
            assert!(landing.error.is_some(), "{landing:?}");
            assert_eq!(landing.committed, 0);
            assert_eq!(position(&f), held);
            assert_eq!(pull(&f, 1).event, before_pull.event);
            assert_eq!(queue(&f), before_queue);
            assert_eq!(refs(&f), before_refs);
            assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"x");
        }
    }
}

#[test]
fn recover_only_never_selects_a_new_refresh_for_a_stale_unreserved_head() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (f, _) = continuing_fixture(format);
        let merge = config();
        first_landing(&f, &merge);
        let held = position(&f);
        let before = pull(&f, 1);
        let report = refresh(&f, &merge, OWNER, QueueRefreshMode::RecoverOnly, |_| {
            panic!("recovery with no retained request must not propose or decide fresh work");
        });
        assert!(report.error.is_none(), "{report:?}");
        assert_eq!(report.committed, 0);
        assert_eq!(report.refused, 0);
        assert_eq!(report.previously_decided, 0);
        assert_eq!(position(&f), held);
        assert_eq!(pull(&f, 1).event, before.event);
        assert!(attempts(&f).is_empty());
        assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"x");
    }
}

#[test]
fn missing_first_refresh_marker_recovers_only_with_the_original_explicit_grant() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut f, _) = continuing_fixture(format);
        let merge = config();
        first_landing(&f, &merge);
        let mut original_decision = None;
        let lost = refresh(&f, &merge, OWNER, QueueRefreshMode::RecoverAndSelect, |row| {
            if row.contains("\"type\":\"workflow_queue_refresh_decision\"") {
                original_decision = Some(row.to_owned());
                Err("test lost first refresh decision".into())
            } else {
                Ok(())
            }
        });
        assert_eq!(lost.committed, 1);
        assert!(lost.error.is_some());
        let records = attempts(&f);
        assert_eq!(records.len(), 1);
        let retained = fs::read(&records[0]).unwrap();
        let marker = records[0].parent().unwrap().parent().unwrap().join("refresh-principal");
        let marker_bytes = fs::read(&marker).unwrap();
        fs::remove_file(&marker).unwrap();
        let held = position(&f);
        let before = pull(&f, 1).event;
        f.reopen();

        let node = f.node();
        for principal in [None, Some(PrincipalId::from_bytes([0x7e; 16]))] {
            assert!(node.runtime().block_on(
                node.validate_trusted_queue_head_refresh_custody_in(
                    &node.request_context(), &target_ref(), 1, b"ci", &f.parent(),
                    &merge, principal,
                )
            ).is_err());
        }
        assert!(node.runtime().block_on(
            node.validate_trusted_queue_head_refresh_custody_in(
                &node.request_context(), &target_ref(), 1, b"ci", &f.parent(),
                &merge, Some(OWNER),
            )
        ).unwrap());
        assert!(!marker.exists(), "startup validation must not repair custody");
        assert!(!acknowledgment(&records[0]).exists());
        assert_eq!(position(&f), held);

        let mut recovered_decisions = Vec::new();
        let recovered = refresh(&f, &merge, OWNER, QueueRefreshMode::RecoverOnly, |row| {
            if row.contains("\"type\":\"workflow_queue_refresh_decision\"") {
                recovered_decisions.push(row.to_owned());
            }
            Ok(())
        });
        assert!(recovered.error.is_none(), "{recovered:?}");
        assert_eq!(recovered.committed, 1);
        assert_eq!(recovered_decisions, vec![original_decision.unwrap()]);
        assert_eq!(fs::read(&marker).unwrap(), marker_bytes);
        assert_eq!(fs::read(&records[0]).unwrap(), retained);
        assert!(acknowledgment(&records[0]).exists());
        assert_eq!(position(&f), held);
        assert_eq!(pull(&f, 1).event, before);
        assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"x");
    }
}
