//! Real source-selected shell execution and persisted native check recovery.
//! These trusted-owner jobs are not evidence of hostile-code isolation.
use super::*;
use fgit_authority::IdempotencyKey;
use fgit_forge::event::workflow_check::WorkflowCheckConclusion;
use fgit_node::{LoopbackReceiveSession, TrustedWorkflowFailure, TrustedWorkflowRun};
use fgit_runner::coordinator::delivery::journal::history::MAX_OBSERVATION_BYTES;
use fgit_runner::coordinator::{CheckRunConclusion, CheckRunStatus};
use fgit_runner::workflow::{StepOutcome, WorkflowPlan};

const MIXED: &str = r#"name: mixed-shells
on: push
jobs:
  inspect:
    runs-on: fgit-trusted-local
    steps:
      - shell: bash
        run: values=(alpha beta); test "${values[1]}" = beta; printf '%s' "${values[1]}" > generated; printf bash-array
      - shell: sh
        run: test -z "$FGIT_SHELL_TEST_UNSET"; test "$(cat generated)" = beta; printf explicit-sh
      - run: case "$-" in *u*) printf legacy-nounset;; *) exit 93;; esac
"#;

fn execute(fixture: &Fixture, nonce: u8) -> TrustedWorkflowRun {
    fixture
        .node()
        .runtime()
        .block_on(fixture.node().run_trusted_workflow_in(
            &fixture.node().request_context(),
            &reference(),
            b"workflow.yml",
            [nonce; 16],
            &fixture.parent(),
            &inputs(),
            (None, Some(fixture.tip)),
            WorkflowLimits::default(),
        ))
        .unwrap()
}

#[test]
fn native_shell_selection_survives_journal_recovery_and_canonical_check_publication() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut fixture = Fixture::new(format, MIXED);
        let before = generation(fixture.node());
        let plan = WorkflowPlan::compile(MIXED).unwrap();
        let sh_plan = WorkflowPlan::compile(&MIXED.replace("shell: bash", "shell: sh")).unwrap();
        assert_ne!(plan.graph_commitment(), sh_plan.graph_commitment());
        let run = execute(&fixture, 0x81);
        assert!(run.succeeded(), "{}", run.to_json());
        assert!(run.workspaces_closed);
        assert!(!run.request_interrupted);
        assert_eq!(run.source_commit, fixture.tip);
        assert_eq!(run.workflow_blob, fixture.workflow);
        assert_eq!(run.execution.source, plan.source_commitment());
        assert_eq!(run.execution.graph, plan.graph_commitment());
        assert_eq!(run.execution.jobs.len(), 1);
        let job = &run.execution.jobs[0];
        assert_eq!(job.outcome, JobOutcome::Succeeded);
        assert_eq!(job.steps.len(), 3);
        for (step, expected) in job.steps.iter().zip([
            b"bash-array".as_slice(),
            b"explicit-sh".as_slice(),
            b"legacy-nounset".as_slice(),
        ]) {
            assert_eq!(step.observation.outcome, StepOutcome::Succeeded);
            assert_eq!(step.observation.exit_code, Some(0));
            assert_eq!(step.observation.stdout, expected);
            assert!(step.observation.stderr.is_empty());
            assert!(step.observation.output_complete);
            assert!(!step.observation.retain_workspace);
        }
        assert_eq!(generation(fixture.node()), before);
        assert!(!run.run_directory.join("job-000").exists());
        let saved = fs::read(run.run_directory.join("report.json")).unwrap();
        let marker = fs::read(run.run_directory.join("attempt.json")).unwrap();
        let owner = fs::read(run.run_directory.join("execution.owner")).unwrap();
        let custody = fs::read(run.run_directory.join("check-proposals.journal")).unwrap();
        assert_eq!(saved, run.to_json().as_bytes());
        let json = run.to_json();
        assert!(json.contains("\"authoritative_check\":false"));
        assert!(json.contains("\"hostile_code_isolated\":false"));
        assert!(json.contains("\"published\":false"));

        // A new native node instance may inspect the old custody but cannot
        // reexecute the occupied run identity, even with identical source.
        fixture.reopen();
        let retry = fixture
            .node()
            .runtime()
            .block_on(fixture.node().run_trusted_workflow_in(
                &fixture.node().request_context(),
                &reference(),
                b"workflow.yml",
                [0x81; 16],
                &fixture.parent(),
                &inputs(),
                (None, Some(fixture.tip)),
                WorkflowLimits::default(),
            ));
        assert!(matches!(
            retry,
            Err(TrustedWorkflowFailure::AttemptExists(_))
        ));
        assert_eq!(generation(fixture.node()), before);
        let mut journal = OneNode::open_trusted_workflow_journal(
            &run.run_directory,
            run.check_journal_scope(),
            None,
            &|| true,
        )
        .unwrap();
        let pin = journal.pin();
        let page = journal
            .read_history(Some(pin), None, 128, 1024 * 1024, &|| true)
            .unwrap();
        assert!(page.next_after().is_none());
        let mut completed = None;
        for entry in page.entries() {
            let batch = entry.batch();
            assert_eq!(batch.source_commit(), fixture.tip);
            assert_eq!(batch.graph_commitment(), plan.graph_commitment());
            assert!(entry.delivery_receipt().is_none());
            for (index, fact) in batch.facts().iter().enumerate() {
                if fact.status != CheckRunStatus::Completed {
                    continue;
                }
                assert!(completed.is_none(), "exactly one completed job is retained");
                assert_eq!(fact.job_id, "inspect");
                assert_eq!(fact.conclusion, Some(CheckRunConclusion::ActionRequired));
                let observation = journal
                    .read_trusted_job(pin, batch.id(), index, MAX_OBSERVATION_BYTES, &|| true)
                    .unwrap();
                assert_eq!(observation.source_commit(), fixture.tip);
                assert_eq!(observation.report().source, plan.source_commitment());
                assert_eq!(observation.report().graph, plan.graph_commitment());
                assert_eq!(observation.report().jobs, run.execution.jobs);
                assert!(!observation.requires_containment());
                let evidence = journal
                    .read_evidence(fact.receipt_commitment.unwrap())
                    .unwrap();
                let record = OneNode::workflow_check_record_from_batch(
                    reference(),
                    batch,
                    index,
                    &evidence,
                    &|| true,
                )
                .unwrap();
                assert_eq!(record.conclusion, WorkflowCheckConclusion::Success);
                assert_eq!(record.source_commit, fixture.tip);
                assert_eq!(record.evidence, evidence);
                assert_eq!(
                    record.graph_root.as_slice(),
                    plan.graph_commitment().digest().bytes().as_bytes()
                );
                completed = Some(record);
            }
        }
        assert_eq!(journal.pin(), pin);
        assert_eq!(journal.retained_batches(), journal.pending_batches());
        drop(journal);
        let record = completed.expect("native job retained its complete evidence");
        let session = LoopbackReceiveSession::authenticated(
            PrincipalId::from_bytes([0x43; 16]),
            IdempotencyKey::new(b"publish-mixed-shell-check".to_vec()).unwrap(),
        );
        let published = fixture
            .node()
            .runtime()
            .block_on(fixture.node().admit_trusted_workflow_check_in(
                &fixture.node().request_context(),
                &session,
                &record,
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            published.1.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let after = generation(fixture.node());
        assert_eq!(after, before + 1);
        let selected = fixture
            .node()
            .runtime()
            .block_on(
                fixture
                    .node()
                    .materialize_admission_in(&fixture.node().request_context()),
            )
            .unwrap();
        assert_eq!(
            selected.snapshot().refs.get(&reference()),
            Some(&fixture.tip)
        );
        fixture.reopen();
        let recovered = fixture
            .node()
            .runtime()
            .block_on(fixture.node().admit_trusted_workflow_check_in(
                &fixture.node().request_context(),
                &session,
                &record,
                Default::default(),
            ))
            .unwrap();
        assert_eq!(recovered, published);
        assert_eq!(generation(fixture.node()), after);
        for (name, expected) in [
            ("attempt.json", marker),
            ("execution.owner", owner),
            ("check-proposals.journal", custody),
            ("report.json", saved),
        ] {
            assert_eq!(
                fs::read(run.run_directory.join(name)).unwrap(),
                expected,
                "{name}"
            );
        }
        assert!(!run.run_directory.join("job-000").exists());
    }
}

#[test]
fn native_bash_pipeline_failure_skips_dependents_while_explicit_sh_twin_succeeds() {
    const SOURCE: &str = r#"name: pipeline-shells
on: push
jobs:
  bash:
    runs-on: fgit-trusted-local
    steps:
      - shell: bash
        run: printf entered; false | true; printf forbidden
      - run: printf forbidden-later-step
  dependent:
    runs-on: fgit-trusted-local
    needs: bash
    steps:
      - run: printf forbidden-dependent
  sh:
    runs-on: fgit-trusted-local
    steps:
      - shell: sh
        run: printf entered; false | true; printf permitted
"#;
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format, SOURCE);
        let before = generation(fixture.node());
        let run = execute(&fixture, 0x82);
        assert!(!run.succeeded());
        assert!(run.workspaces_closed);
        assert!(!run.request_interrupted);
        assert_eq!(run.execution.jobs.len(), 3);
        let job = |name: &str| {
            run.execution
                .jobs
                .iter()
                .find(|job| job.id == name)
                .unwrap()
        };
        let failed = job("bash");
        assert_eq!(failed.outcome, JobOutcome::Failed, "{}", run.to_json());
        assert_eq!(failed.steps.len(), 1);
        assert_eq!(failed.steps[0].observation.outcome, StepOutcome::Failed);
        assert_eq!(failed.steps[0].observation.exit_code, Some(1));
        assert_eq!(failed.steps[0].observation.stdout, b"entered");
        assert_eq!(job("dependent").outcome, JobOutcome::Skipped);
        assert!(job("dependent").steps.is_empty());
        let permitted = job("sh");
        assert_eq!(permitted.outcome, JobOutcome::Succeeded);
        assert_eq!(permitted.steps.len(), 1);
        assert_eq!(permitted.steps[0].observation.exit_code, Some(0));
        assert_eq!(permitted.steps[0].observation.stdout, b"enteredpermitted");
        assert!(
            run.execution
                .jobs
                .iter()
                .all(|job| !job.requires_containment())
        );
        assert_eq!(generation(fixture.node()), before);

        let mut journal = run.open_check_journal(None, &|| true).unwrap();
        let page = journal
            .read_history(None, None, 128, 1024 * 1024, &|| true)
            .unwrap();
        let mut completed = 0;
        for entry in page.entries() {
            let batch = entry.batch();
            for (index, fact) in batch.facts().iter().enumerate() {
                if fact.status != CheckRunStatus::Completed {
                    continue;
                }
                completed += 1;
                let evidence = journal
                    .read_evidence(fact.receipt_commitment.unwrap())
                    .unwrap();
                let record = OneNode::workflow_check_record_from_batch(
                    reference(),
                    batch,
                    index,
                    &evidence,
                    &|| true,
                )
                .unwrap();
                assert_eq!(
                    record.conclusion,
                    match fact.job_id.as_str() {
                        "bash" => WorkflowCheckConclusion::Failure,
                        "dependent" => WorkflowCheckConclusion::ActionRequired,
                        "sh" => WorkflowCheckConclusion::Success,
                        other => panic!("unexpected job {other}"),
                    }
                );
            }
        }
        assert_eq!(completed, 3);
    }
}
