#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]

//! Execute the native compiler's block-scalar output with the real trusted
//! process adapter. These are local Linux process tests, not forge publication.

use fgit_runner::workflow::{
    StepLimits, StepOutcome, WorkflowError, WorkflowPlan, run_trusted_step_with_context,
};
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-workflow-script-block-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn workflow(run: &str) -> String {
    format!(
        "name: script blocks\non: workflow_dispatch\njobs:\n  test:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: {run}\n"
    )
}

fn execute(run: &str, expected: &[u8]) {
    let plan = WorkflowPlan::compile(&workflow(run)).unwrap();
    assert_eq!(plan.graph().jobs.len(), 1);
    assert_eq!(plan.graph().jobs[0].steps.len(), 1);
    let step = &plan.graph().jobs[0].steps[0];
    let directory = Directory::new();
    let capture = |name| {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.0.join(name))
            .unwrap()
    };
    let observation = run_trusted_step_with_context(
        &directory.0,
        &step.run,
        &step.context,
        StepLimits {
            timeout: Duration::from_secs(5),
            stream_bytes: 64 * 1024,
        },
        &capture("stdout"),
        &capture("stderr"),
        &|| true,
    )
    .unwrap();
    assert_eq!(observation.outcome, StepOutcome::Succeeded);
    assert_eq!(observation.exit_code, Some(0));
    assert!(observation.output_complete);
    assert!(!observation.retain_workspace);
    assert_eq!(observation.stdout, expected);
    assert!(observation.stderr.is_empty());
}

#[test]
fn literal_blocks_preserve_a_real_heredoc_and_its_blank_lines() {
    for header in ["|-", "|+", "|2-", "|-2", "|2+"] {
        execute(
            &format!(
                "{header}\n          cat <<'END'\n          first: literal # bytes\n\n          ---\n          END\n"
            ),
            b"first: literal # bytes\n\n---\n",
        );
    }
}

#[test]
fn folded_blocks_join_arguments_but_preserve_command_separators() {
    for header in [">", ">-", ">+", ">2-", ">-2"] {
        execute(
            &format!(
                "{header}\n          printf '%s'\n          'folded value'\n\n          printf '%s' ':next'\n"
            ),
            b"folded value:next",
        );
    }
}

#[test]
fn more_indented_folded_lines_preserve_shell_continuations() {
    execute(
        ">-\n          printf '%s\\n' \\\n            'indented argument'\n",
        b"indented argument\n",
    );
}

#[test]
fn equivalent_folded_and_plain_scripts_keep_the_same_graph_identity() {
    let plain = WorkflowPlan::compile(&workflow("printf '%s' 'same bytes'")).unwrap();
    let folded = WorkflowPlan::compile(&workflow(
        ">-\n          printf '%s'\n          'same bytes'",
    ))
    .unwrap();
    assert_eq!(plain.graph_commitment(), folded.graph_commitment());
    assert_ne!(plain.source_commitment(), folded.source_commitment());
}

#[test]
fn block_styles_do_not_admit_unevaluated_workflow_expressions() {
    for header in ["|-", "|+", ">-", ">2"] {
        let source = workflow(&format!(
            "{header}\n          echo ${{{{ secrets.TOKEN }}}}"
        ));
        assert!(matches!(
            WorkflowPlan::compile(&source),
            Err(WorkflowError::InvalidScript)
        ));
    }
    let permitted = WorkflowPlan::compile(&workflow(
        ">-\n          printf '%s'\n          'ordinary literal'",
    ));
    assert!(permitted.is_ok());
}
