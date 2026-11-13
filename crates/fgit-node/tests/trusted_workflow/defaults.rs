//! Source-imported default shell/directory inheritance through native execution.
//! Recovery reads retained observations and never recreates a job workspace.
use super::*;
use fgit_node::{TrustedWorkflowFailure, TrustedWorkflowRun};
use fgit_runner::coordinator::delivery::journal::history::MAX_OBSERVATION_BYTES;
use fgit_runner::coordinator::{CheckRunConclusion, CheckRunStatus};
use fgit_runner::workflow::{StepOutcome, StepShell, WorkflowPlan};
use std::collections::BTreeSet;

fn tree(source: &Path, format: GitHashAlgorithm, entries: &[(&str, &str, GitOid)]) -> GitOid {
    let mut bytes = Vec::new();
    for (mode, name, oid) in entries {
        bytes.extend_from_slice(mode.as_bytes());
        bytes.push(b' ');
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(oid.as_bytes());
    }
    loose(source, format, GitObjectKind::Tree, "tree", &bytes)
}

fn fixture(format: GitHashAlgorithm, workflow: &str) -> Fixture {
    let mut fixture = Fixture::new(format, workflow);
    let source = fixture.root.join("source");
    let identity = |value: &[u8]| loose(&source, format, GitObjectKind::Blob, "blob", value);
    let base = tree(
        &source,
        format,
        &[("100644", "identity.txt", identity(b"base\n"))],
    );
    let job = tree(
        &source,
        format,
        &[("100644", "identity.txt", identity(b"job\n"))],
    );
    let step = tree(
        &source,
        format,
        &[("100644", "identity.txt", identity(b"step\n"))],
    );
    let packages = tree(
        &source,
        format,
        &[
            ("40000", "base", base),
            ("40000", "job", job),
            ("40000", "step", step),
        ],
    );
    let root = tree(
        &source,
        format,
        &[
            ("100644", "identity.txt", identity(b"root\n")),
            ("40000", "packages", packages),
            ("100644", "workflow.yml", fixture.workflow),
        ],
    );
    let body = format!(
        "tree {root}\nparent {}\nauthor Fixture <fixture@example.invalid> 2 +0000\ncommitter Fixture <fixture@example.invalid> 2 +0000\n\nsource directories for run defaults\n",
        fixture.tip
    );
    fixture.tip = loose(
        &source,
        format,
        GitObjectKind::Commit,
        "commit",
        body.as_bytes(),
    );
    // Native import establishes absent refs; keep the original imported main
    // branch untouched and select the expanded source through a new branch.
    fs::rename(
        source.join("refs/heads/main"),
        fixture.root.join("initial-main-ref"),
    )
    .unwrap();
    fs::write(source.join("HEAD"), "ref: refs/heads/defaults\n").unwrap();
    fs::write(
        source.join("refs/heads/defaults"),
        format!("{}\n", fixture.tip),
    )
    .unwrap();
    let imported = fixture
        .node()
        .runtime()
        .block_on(fixture.node().import_loose_git_directory_durable_in(
            &fixture.node().request_context(),
            &source,
            PrincipalId::from_bytes([0x43; 16]),
            b"workflow-defaults-layout",
        ))
        .unwrap();
    assert!(!imported.commands.is_empty());
    assert!(
        imported
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    fixture
}

fn paths() -> Vec<Vec<u8>> {
    [
        "identity.txt",
        "packages/base/identity.txt",
        "packages/job/identity.txt",
        "packages/step/identity.txt",
        "workflow.yml",
    ]
    .into_iter()
    .map(|path| path.as_bytes().to_vec())
    .collect()
}

fn selected_ref() -> RefName {
    RefName::try_new(b"refs/heads/defaults").unwrap()
}

fn execute(fixture: &Fixture, nonce: u8) -> TrustedWorkflowRun {
    fixture
        .node()
        .runtime()
        .block_on(fixture.node().run_trusted_workflow_in(
            &fixture.node().request_context(),
            &selected_ref(),
            b"workflow.yml",
            [nonce; 16],
            &fixture.parent(),
            &paths(),
            (None, Some(fixture.tip)),
            WorkflowLimits::default(),
        ))
        .unwrap()
}

fn assert_steps(run: &TrustedWorkflowRun, job: &str, expected: &[(&str, StepShell)]) {
    let job = run
        .execution
        .jobs
        .iter()
        .find(|item| item.id == job)
        .unwrap();
    assert_eq!(job.outcome, JobOutcome::Succeeded);
    assert_eq!(job.steps.len(), expected.len());
    for (step, (stdout, shell)) in job.steps.iter().zip(expected) {
        assert_eq!(step.shell, Some(*shell));
        assert_eq!(step.observation.outcome, StepOutcome::Succeeded);
        assert_eq!(step.observation.exit_code, Some(0));
        assert_eq!(step.observation.stdout, stdout.as_bytes());
        assert!(step.observation.stderr.is_empty());
        assert!(step.observation.output_complete);
        assert!(!step.observation.retain_workspace);
    }
}

fn assert_recovery(
    fixture: &mut Fixture,
    run: &TrustedWorkflowRun,
    plan: &WorkflowPlan,
    nonce: u8,
) {
    assert!(run.succeeded(), "{}", run.to_json());
    assert!(run.workspaces_closed);
    assert!(!run.request_interrupted);
    assert_eq!(run.source_commit, fixture.tip);
    assert_eq!(run.workflow_blob, fixture.workflow);
    assert_eq!(run.execution.source, plan.source_commitment());
    assert_eq!(run.execution.graph, plan.graph_commitment());
    assert_eq!(run.read_prefixes, paths());
    assert_eq!(
        fs::read_to_string(run.run_directory.join("report.json")).unwrap(),
        run.to_json()
    );
    let saved = [
        "attempt.json",
        "execution.owner",
        "check-proposals.journal",
        "report.json",
    ]
    .map(|name| (name, fs::read(run.run_directory.join(name)).unwrap()));
    let before = generation(fixture.node());
    fixture.reopen();
    let retry = fixture
        .node()
        .runtime()
        .block_on(fixture.node().run_trusted_workflow_in(
            &fixture.node().request_context(),
            &selected_ref(),
            b"workflow.yml",
            [nonce; 16],
            &fixture.parent(),
            &paths(),
            (None, Some(fixture.tip)),
            WorkflowLimits::default(),
        ));
    assert!(matches!(
        retry,
        Err(TrustedWorkflowFailure::AttemptExists(_))
    ));
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
    let mut recovered = BTreeSet::new();
    for entry in page.entries() {
        let batch = entry.batch();
        assert_eq!(batch.source_commit(), fixture.tip);
        assert_eq!(batch.graph_commitment(), plan.graph_commitment());
        assert!(entry.delivery_receipt().is_none());
        for (index, fact) in batch.facts().iter().enumerate() {
            if fact.status != CheckRunStatus::Completed {
                continue;
            }
            assert_eq!(fact.conclusion, Some(CheckRunConclusion::ActionRequired));
            assert!(recovered.insert(fact.job_id.clone()));
            let observed = journal
                .read_trusted_job(pin, batch.id(), index, MAX_OBSERVATION_BYTES, &|| true)
                .unwrap();
            let expected = run
                .execution
                .jobs
                .iter()
                .find(|job| job.id == fact.job_id)
                .unwrap();
            assert_eq!(observed.source_commit(), fixture.tip);
            assert_eq!(observed.report().source, plan.source_commitment());
            assert_eq!(observed.report().graph, plan.graph_commitment());
            assert_eq!(
                observed.report().jobs.as_slice(),
                std::slice::from_ref(expected)
            );
            assert!(observed.report_json().starts_with("{\"schema_version\":2,"));
            assert!(!observed.requires_containment());
        }
    }
    assert_eq!(recovered.len(), run.execution.jobs.len());
    assert_eq!(journal.pin(), pin);
    assert_eq!(journal.retained_batches(), journal.pending_batches());
    drop(journal);
    for (name, bytes) in saved {
        assert_eq!(
            fs::read(run.run_directory.join(name)).unwrap(),
            bytes,
            "{name}"
        );
    }
    for index in 0..run.execution.jobs.len() {
        assert!(!run.run_directory.join(format!("job-{index:03}")).exists());
    }
    assert_eq!(generation(fixture.node()), before);
}

#[test]
fn native_defaults_resolve_each_field_and_step_and_job_root_resets_independently() {
    const SOURCE: &str = r#"name: native run defaults
on: push
defaults:
  run:
    shell: bash
    working-directory: packages/base
jobs:
  a_workflow:
    runs-on: fgit-trusted-local
    steps:
      - run: values=(base inherited); test "$(cat identity.txt)" = "${values[0]}"; printf saved > generated; printf workflow-base
      - working-directory: packages/step
        run: values=(step inherited); test "$(cat identity.txt)" = "${values[0]}"; test ! -e generated; printf step-directory
      - working-directory: '.'
        run: values=(root inherited); test "$(cat identity.txt)" = "${values[0]}"; test -f packages/base/generated; printf step-root
      - shell: sh
        run: false | true; test -z "$FGIT_DEFAULTS_UNSET"; test "$(cat identity.txt)" = base; printf step-shell
      - run: values=(base inherited); test "$(cat identity.txt)" = "${values[0]}"; test "$(cat generated)" = saved; printf workflow-restored
  b_job_shell:
    runs-on: fgit-trusted-local
    defaults:
      run:
        shell: sh
    steps:
      - run: false | true; test -z "$FGIT_DEFAULTS_UNSET"; test "$(cat identity.txt)" = base; test ! -e generated; printf job-shell
      - shell: bash
        run: values=(base override); test "$(cat identity.txt)" = "${values[0]}"; printf job-step-shell
      - run: false | true; test "$(cat identity.txt)" = base; printf job-shell-restored
  c_job_directory:
    runs-on: fgit-trusted-local
    defaults:
      run:
        working-directory: packages/job
    steps:
      - run: values=(job inherited); test "$(cat identity.txt)" = "${values[0]}"; printf job-directory
      - working-directory: '.'
        run: values=(root inherited); test "$(cat identity.txt)" = "${values[0]}"; printf job-step-root
      - run: values=(job inherited); test "$(cat identity.txt)" = "${values[0]}"; printf job-directory-restored
  d_job_root:
    runs-on: fgit-trusted-local
    defaults:
      run:
        working-directory: '.'
    steps:
      - run: values=(root inherited); test "$(cat identity.txt)" = "${values[0]}"; printf job-root
"#;
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut fixture = fixture(format, SOURCE);
        let before = generation(fixture.node());
        let plan = WorkflowPlan::compile(SOURCE).unwrap();
        let changed =
            WorkflowPlan::compile(&SOURCE.replacen("shell: bash", "shell: sh", 1)).unwrap();
        assert_ne!(plan.graph_commitment(), changed.graph_commitment());
        let run = execute(&fixture, 0x91);
        assert!(run.succeeded(), "{}", run.to_json());
        assert_eq!(run.execution.jobs.len(), 4);
        assert_steps(
            &run,
            "a_workflow",
            &[
                ("workflow-base", StepShell::Bash),
                ("step-directory", StepShell::Bash),
                ("step-root", StepShell::Bash),
                ("step-shell", StepShell::Sh),
                ("workflow-restored", StepShell::Bash),
            ],
        );
        assert_steps(
            &run,
            "b_job_shell",
            &[
                ("job-shell", StepShell::Sh),
                ("job-step-shell", StepShell::Bash),
                ("job-shell-restored", StepShell::Sh),
            ],
        );
        assert_steps(
            &run,
            "c_job_directory",
            &[
                ("job-directory", StepShell::Bash),
                ("job-step-root", StepShell::Bash),
                ("job-directory-restored", StepShell::Bash),
            ],
        );
        assert_steps(&run, "d_job_root", &[("job-root", StepShell::Bash)]);
        assert_eq!(generation(fixture.node()), before);
        assert_recovery(&mut fixture, &run, &plan, 0x91);
    }
}

#[test]
fn native_matrix_job_default_directories_inherit_shell_and_keep_private_source_copies() {
    const SOURCE: &str = r#"name: native matrix defaults
on: push
defaults:
  run:
    shell: bash
    working-directory: packages/base
jobs:
  build:
    runs-on: fgit-trusted-local
    strategy:
      fail-fast: false
      matrix:
        include:
          - directory: packages/base
            expected: base
          - directory: packages/job
            expected: job
    defaults:
      run:
        working-directory: '${{ matrix.directory }}'
    env:
      EXPECTED: '${{ matrix.expected }}'
    steps:
      - run: values=("$EXPECTED" inherited); test "$(cat identity.txt)" = "${values[0]}"; test ! -e generated; printf '%s' "$EXPECTED" > generated; printf '%s' "$EXPECTED"
      - working-directory: '.'
        run: values=(root inherited); test "$(cat identity.txt)" = "${values[0]}"; printf root
      - run: values=("$EXPECTED" inherited); test "$(cat identity.txt)" = "${values[0]}"; test "$(cat generated)" = "$EXPECTED"; printf '%s' "$EXPECTED"
  collect:
    runs-on: fgit-trusted-local
    needs: build
    steps:
      - run: values=(base inherited); test "$(cat identity.txt)" = "${values[0]}"; test ! -e generated; test ! -e ../job/generated; printf joined
"#;
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut fixture = fixture(format, SOURCE);
        let before = generation(fixture.node());
        let plan = WorkflowPlan::compile(SOURCE).unwrap();
        let run = execute(&fixture, 0x92);
        assert!(run.succeeded(), "{}", run.to_json());
        assert_eq!(run.execution.jobs.len(), 3);
        for (index, expected) in ["base", "job"].into_iter().enumerate() {
            assert_steps(
                &run,
                &format!("build__matrix_{index:03}"),
                &[
                    (expected, StepShell::Bash),
                    ("root", StepShell::Bash),
                    (expected, StepShell::Bash),
                ],
            );
        }
        assert_steps(&run, "collect", &[("joined", StepShell::Bash)]);
        assert_eq!(generation(fixture.node()), before);
        assert_recovery(&mut fixture, &run, &plan, 0x92);
    }
}
