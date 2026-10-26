//! Real trusted processes produce immutable binary logs before durable check
//! proposals are accepted. Artifact custody never changes execution success.
use super::*;
use fgit_node::TrustedWorkflowLogStream;
use fgit_object_fabric::ArtifactPayloadKind;
use fgit_runner::workflow::{StepOutcome, WorkflowLimits};

fn logs_config(f: &Fixture, selections: Vec<Selection>, maximum: usize, total: usize) -> Config {
    Config::new_with_logs(private(f, "artifacts"), selections, maximum, total).unwrap()
}

fn execute_limited(
    f: &Fixture,
    contract: &Config,
    id: u8,
    limits: WorkflowLimits,
) -> TrustedWorkflowRun {
    f.node()
        .runtime()
        .block_on(f.node().run_trusted_workflow_with_artifacts_in(
            &f.node().command_request_context(None),
            &reference(),
            b"workflow.yml",
            [id; 16],
            &f.parent(),
            &inputs(),
            (None, Some(f.tip)),
            limits,
            Some(contract),
        ))
        .unwrap()
}

fn retained_non_green_jobs_match_report(run: &TrustedWorkflowRun) {
    use fgit_runner::coordinator::CheckRunStatus;
    use fgit_runner::coordinator::delivery::journal::history::MAX_OBSERVATION_BYTES;

    let mut journal = run.open_check_journal(None, &|| true).unwrap();
    let page = journal
        .read_history(None, None, MAX_HISTORY_BATCHES, MAX_HISTORY_BYTES, &|| true)
        .unwrap();
    assert!(
        page.next_after().is_none(),
        "fixture exceeds one bounded history page"
    );
    let mut retained = std::collections::BTreeSet::new();
    for entry in page.entries() {
        let batch = entry.batch();
        for (index, fact) in batch.facts().iter().enumerate() {
            if fact.status != CheckRunStatus::Completed {
                continue;
            }
            let expected = run
                .execution
                .jobs
                .iter()
                .find(|job| job.id == fact.job_id)
                .expect("a retained terminal proposal must name an observed job");
            assert_ne!(expected.outcome, JobOutcome::Succeeded);
            // Raw proposal conclusions intentionally label even successful local
            // executions ActionRequired. Verify the actual retained evidence
            // instead: this reads an accepted batch's bounded body at one exact
            // journal snapshot, verifies its commitments, and decodes the job.
            let observed = journal
                .read_trusted_job(
                    page.snapshot(),
                    batch.id(),
                    index,
                    MAX_OBSERVATION_BYTES,
                    &|| true,
                )
                .unwrap();
            assert_eq!(observed.report().source, run.execution.source);
            assert_eq!(observed.report().graph, run.execution.graph);
            assert_eq!(observed.report().limits, run.execution.limits);
            assert_eq!(
                observed.report().jobs.as_slice(),
                std::slice::from_ref(expected)
            );
            assert!(
                retained.insert(fact.job_id.clone()),
                "duplicate terminal observation"
            );
        }
    }
    let expected = run
        .execution
        .jobs
        .iter()
        .map(|job| job.id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(!expected.is_empty());
    assert_eq!(
        retained, expected,
        "every observed job must have retained exact evidence"
    );
}

fn verify_logs(contract: &Config, run: &TrustedWorkflowRun) {
    let live = || true;
    let op = ArtifactOperation::new(1024 * 1024, Duration::from_secs(30), &live).unwrap();
    let artifacts = store(contract, run);
    for captured in &run.artifact_logs {
        let (job_index, job) = run
            .execution
            .jobs
            .iter()
            .enumerate()
            .find(|(_, job)| job.id == captured.job_id)
            .unwrap();
        assert_eq!(captured.observed_outcome, job.outcome);
        assert_eq!(captured.logs.len(), 2 * job.steps.len());
        for (step, pair) in job.steps.iter().zip(captured.logs.chunks_exact(2)) {
            for (log, stream, bytes) in [
                (
                    &pair[0],
                    TrustedWorkflowLogStream::Stdout,
                    &step.observation.stdout,
                ),
                (
                    &pair[1],
                    TrustedWorkflowLogStream::Stderr,
                    &step.observation.stderr,
                ),
            ] {
                assert_eq!(log.step_index, step.index);
                assert_eq!(log.step_name, step.name);
                assert_eq!(log.script, step.script);
                assert_eq!(log.stream, stream);
                assert_eq!(log.observed_outcome, step.observation.outcome);
                assert_eq!(log.exit_code, step.observation.exit_code);
                assert_eq!(log.output_complete, step.observation.output_complete);
                assert_eq!(log.payload_bytes, bytes.len());
                let (identity, retained) = artifacts.read_payload(&log.artifact_id, &op).unwrap();
                assert_eq!(retained, *bytes);
                assert_eq!(identity.payload_kind(), ArtifactPayloadKind::BuildLog);
                assert_eq!(identity.payload_digest(), &log.payload_sha256);
                assert_eq!(identity.payload_len(), bytes.len() as u64);
                assert!(identity.build_capsule_id().is_none());
                assert!(identity.check_receipt_id().is_none());
            }
        }
        let (identity, manifest) = artifacts.read_payload(&captured.manifest_id, &op).unwrap();
        assert_eq!(identity.payload_kind(), ArtifactPayloadKind::Provenance);
        let manifest = String::from_utf8(manifest).unwrap();
        assert!(manifest.contains("\"type\":\"trusted_workflow_log_provenance\""));
        assert!(manifest.contains("\"job_success_asserted\":false"));
        assert!(manifest.contains("\"cache_reuse_authorized\":false"));
        assert!(manifest.contains(&format!("\"source_commit\":\"{}\"", run.source_commit)));
        for log in &captured.logs {
            assert!(manifest.contains(&hex(log.artifact_id.bytes().as_bytes())));
        }
        let receipt = fs::read_to_string(
            run.run_directory
                .join(format!("job-{job_index:03}-logs.json")),
        )
        .unwrap();
        assert_eq!(
            receipt,
            format!(
                "{{\"type\":\"trusted_workflow_log_receipt\",\"manifest_id_sha256\":\"{}\",\"manifest\":{manifest}}}",
                hex(captured.manifest_id.bytes().as_bytes())
            )
        );
    }
    assert!(!fs::read_dir(&run.run_directory).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".pending")
    }));
    assert_eq!(
        fs::read_to_string(run.run_directory.join("report.json")).unwrap(),
        run.to_json()
    );
}

#[test]
fn failed_binary_streams_and_diagnostics_survive_cleanup_reopen_and_selected_outputs() {
    let workflow = "name: failed binary logs\non: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - name: failing producer\n        run: printf selected > out.bin; printf 'stdout\\000\\377'; printf 'stderr\\000\\376' >&2; exit 7\n      - if: failure()\n        name: postmortem\n        run: printf diagnosis; printf detail >&2\n      - if: always()\n        run: true\n  b:\n    runs-on: fgit-trusted-local\n    needs: a\n    steps:\n      - run: printf forbidden\n";
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, workflow);
        let contract = logs_config(
            &f,
            vec![Selection::new(b"workflow.yml", "a", b"out.bin").unwrap()],
            1024,
            4096,
        );
        assert!(contract.capture_logs());
        let before = generation(f.node());
        let run = execute_limited(&f, &contract, 0x71, WorkflowLimits::default());
        assert!(!run.succeeded());
        assert!(run.workspaces_closed);
        assert_eq!(run.execution.jobs[0].outcome, JobOutcome::Failed);
        assert_eq!(run.execution.jobs[1].outcome, JobOutcome::Skipped);
        assert_eq!(run.execution.jobs[0].steps.len(), 3);
        assert_eq!(
            run.execution.jobs[0].steps[0].observation.stdout,
            b"stdout\0\xff"
        );
        assert_eq!(
            run.execution.jobs[0].steps[0].observation.stderr,
            b"stderr\0\xfe"
        );
        assert_eq!(run.artifact_logs.len(), 1);
        assert_eq!(run.artifact_logs[0].logs.len(), 6);
        assert_ne!(
            run.artifact_logs[0].logs[0].artifact_id,
            run.artifact_logs[0].logs[1].artifact_id
        );
        assert!(
            run.artifact_logs[0]
                .logs
                .iter()
                .all(|log| log.output_complete)
        );
        assert_eq!(run.artifacts.len(), 1);
        let op = ArtifactOperation::new(4096, Duration::from_secs(30), &|| true).unwrap();
        assert_eq!(
            store(&contract, &run)
                .read_payload(&run.artifacts[0].outputs[0].artifact_id, &op)
                .unwrap()
                .1,
            b"selected"
        );
        verify_logs(&contract, &run);
        retained_non_green_jobs_match_report(&run);
        assert!(!run.run_directory.join("job-000").exists());
        assert!(!run.run_directory.join("job-001-logs.json").exists());
        assert_eq!(generation(f.node()), before);
        f.reopen();
        verify_logs(&contract, &run);
        assert_eq!(generation(f.node()), before);
    }
}

#[test]
fn output_limit_archives_only_normalized_bounded_bytes_and_never_asserts_completeness() {
    let f = Fixture::new(
        GitHashAlgorithm::Sha256,
        &workflow("printf 0123456789; printf abcdefghij >&2"),
    );
    let contract = logs_config(&f, vec![], 4, 8);
    let run = execute_limited(
        &f,
        &contract,
        0x72,
        WorkflowLimits {
            stream_bytes: 4,
            total_output_bytes: 8,
            ..Default::default()
        },
    );
    assert!(!run.succeeded());
    assert_eq!(run.execution.jobs[0].steps.len(), 1);
    assert!(run.execution.jobs[1].steps.is_empty());
    assert_eq!(
        run.execution.jobs[0].steps[0].observation.outcome,
        StepOutcome::OutputLimit
    );
    assert_eq!(run.artifact_logs.len(), 1);
    assert!(
        run.artifact_logs[0]
            .logs
            .iter()
            .all(|log| !log.output_complete && log.payload_bytes <= 4)
    );
    assert!(
        run.artifact_logs[0]
            .logs
            .iter()
            .any(|log| log.payload_bytes != 0)
    );
    verify_logs(&contract, &run);
    retained_non_green_jobs_match_report(&run);
}

#[test]
fn log_budget_failure_refuses_success_after_selected_output_with_an_exact_permitted_twin() {
    let f = Fixture::new(
        GitHashAlgorithm::Sha1,
        "on: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf file > out.bin; printf out1; printf err2 >&2\n",
    );
    let selections = vec![Selection::new(b"workflow.yml", "a", b"out.bin").unwrap()];
    let contract = logs_config(&f, selections.clone(), 4, 11);
    let run = execute_limited(&f, &contract, 0x73, WorkflowLimits::default());
    assert!(!run.succeeded());
    assert!(run.workspaces_closed);
    assert_eq!(run.execution.jobs[0].outcome, JobOutcome::Refused);
    assert_eq!(run.artifacts.len(), 1);
    assert!(run.artifact_logs.is_empty());
    assert!(!run.run_directory.join("job-000-logs.json").exists());
    retained_non_green_jobs_match_report(&run);
    let exact = Config::new_with_logs(contract.root().to_path_buf(), selections, 4, 12).unwrap();
    let permitted = execute_limited(&f, &exact, 0x74, WorkflowLimits::default());
    assert!(permitted.succeeded());
    assert!(permitted.workspaces_closed);
    assert_eq!(permitted.artifacts.len(), 1);
    assert_eq!(permitted.artifact_logs.len(), 1);
    verify_logs(&exact, &permitted);
}

#[test]
fn cancellation_stops_execution_but_finalizes_partial_logs_without_a_success_proposal() {
    let f = Fixture::new(
        GitHashAlgorithm::Sha1,
        "on: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf '%s' \"$$\" >&2; printf 'ready\\000\\377'; while true; do true; done\n      - if: always()\n        run: printf forbidden-step\n  b:\n    runs-on: fgit-trusted-local\n    needs: a\n    if: always()\n    steps:\n      - run: printf forbidden-job\n",
    );
    let contract = logs_config(&f, vec![], 1024, 2048);
    let request = f.node().command_request_context(None);
    let capture = f
        .parent()
        .join(format!("workflow-{}", "75".repeat(16)))
        .join("job-000-step-000-stdout");
    let run = std::thread::scope(|scope| {
        let observer = scope.spawn(|| {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            let mut started = false;
            while std::time::Instant::now() < deadline {
                if fs::metadata(&capture).is_ok_and(|metadata| metadata.len() >= 7) {
                    started = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            request.cancel();
            assert!(
                started,
                "the real child must emit its binary prefix before cancellation"
            );
        });
        let run = f
            .node()
            .runtime()
            .block_on(f.node().run_trusted_workflow_with_artifacts_in(
                &request,
                &reference(),
                b"workflow.yml",
                [0x75; 16],
                &f.parent(),
                &inputs(),
                (None, Some(f.tip)),
                WorkflowLimits {
                    step_timeout: Duration::from_secs(20),
                    run_timeout: Duration::from_secs(25),
                    ..Default::default()
                },
                Some(&contract),
            ))
            .unwrap();
        observer.join().unwrap();
        run
    });
    assert!(!run.succeeded());
    assert!(run.request_interrupted);
    assert_eq!(run.execution.jobs[0].steps.len(), 1);
    assert_eq!(
        run.execution.jobs[0].steps[0].observation.stdout,
        b"ready\0\xff"
    );
    assert!(run.execution.jobs[1].steps.is_empty());
    let child_pid = std::str::from_utf8(&run.execution.jobs[0].steps[0].observation.stderr)
        .unwrap()
        .parse::<u32>()
        .unwrap();
    assert!(
        !Path::new("/proc").join(child_pid.to_string()).exists(),
        "cancelled shell must be reaped before log finalization returns"
    );
    assert!(!run.run_directory.join("job-001").exists());
    assert_eq!(run.artifact_logs.len(), 1);
    assert_ne!(run.artifact_logs[0].observed_outcome, JobOutcome::Succeeded);
    verify_logs(&contract, &run);
    retained_non_green_jobs_match_report(&run);
}

#[test]
fn dispatch_shares_log_capture_budget_across_workflows() {
    let f = Fixture::new_dispatch(
        GitHashAlgorithm::Sha256,
        "on: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf data\n",
    );
    let contract = logs_config(&f, vec![], 4, 6);
    let dispatch = f
        .node()
        .runtime()
        .block_on(f.node().dispatch_trusted_workflows_with_artifacts_in(
            &f.node().command_request_context(None),
            &reference(),
            b"ci",
            "push",
            [0x76; 16],
            &f.parent(),
            &[b"ci".to_vec()],
            (pinned_head(&f), f.tip),
            WorkflowLimits::default(),
            Some(&contract),
        ))
        .unwrap();
    assert!(!dispatch.succeeded());
    assert_eq!(dispatch.runs().len(), 2);
    assert!(dispatch.runs()[0].succeeded());
    verify_logs(&contract, &dispatch.runs()[0]);
    let second = &dispatch.runs()[1];
    assert!(!second.succeeded());
    assert!(second.workspaces_closed);
    assert_eq!(second.execution.jobs[0].outcome, JobOutcome::Refused);
    assert!(second.artifact_logs.is_empty());
    retained_non_green_jobs_match_report(second);
}
