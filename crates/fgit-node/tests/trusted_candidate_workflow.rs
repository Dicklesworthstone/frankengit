#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Proposed changes execute before publication, not by importing a temporary ref.
#[path = "trusted_candidate_workflow/support.rs"]
mod support;
use support::*;
use std::fs;
use std::time::Duration;
use fgit_crypto::{GitObjectKind, git_object_id, sha256_digest};
use fgit_runner::workflow::{JobOutcome, WorkflowLimits};
use fgit_types::{DecisionOutcome, GitHashAlgorithm};

const WORKFLOW: &str = "name: candidate-check\non: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: test \"$(cat input.txt)\" = candidate || exit 7; printf candidate > generated; printf first\n      - run: test \"$(cat generated)\" = candidate || exit 8; printf second\n  b:\n    runs-on: fgit-trusted-local\n    needs: a\n    steps:\n      - run: test ! -e generated || exit 9; test \"$(cat input.txt)\" = candidate || exit 10; printf fresh\n";
const SIMPLE: &str = "name: explicit-script\non: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf base-script\n";

#[test]
fn unpublished_input_runs_in_fresh_jobs_and_cannot_publish_or_replay_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, WORKFLOW);
        let before = generation(f.node());
        let base_run = f.node().runtime().block_on(f.node().run_trusted_workflow_in(&f.node().request_context(),
            &reference(), b"workflow.yml", [1; 16], &f.parent(), &inputs(), (None, Some(f.tip)), Default::default())).unwrap();
        assert!(!base_run.succeeded(), "base must fail or the candidate test is vacuous");
        assert_eq!(base_run.execution.jobs[0].outcome, JobOutcome::Failed);
        assert!(base_run.candidate.is_none());
        let candidate = f.replace_file("input.txt", "original\n", "candidate\n");
        assert!(f.node().read_git_object(candidate.candidate_commit).is_err());
        let head = f.node().runtime().block_on(f.node().materialize_admission()).unwrap().basis().id();
        let run = f.node().runtime().block_on(f.node().run_trusted_candidate_workflow_in(&f.node().request_context(),
            &reference(), (f.tip, candidate.candidate_commit), candidate.bundle_bytes(), b"workflow.yml", [2; 16],
            &f.parent(), &inputs(), Some(head), Default::default())).unwrap();
        assert!(run.succeeded()); assert!(run.workspaces_closed);
        assert_eq!(run.source_head, head); assert_eq!(run.source_commit, f.tip);
        assert_eq!(run.source_rcr, candidate.source_rcr);
        assert_eq!(run.executed_commit(), candidate.candidate_commit); assert_eq!(run.executed_tree(), candidate.root_tree);
        assert_eq!(run.workflow_blob, f.workflow);
        let binding = run.candidate.unwrap();
        assert_eq!(binding.bundle_sha256, sha256_digest(candidate.bundle_bytes()));
        assert_eq!(run.execution.jobs[0].steps[0].observation.stdout, b"first");
        assert_eq!(run.execution.jobs[0].steps[1].observation.stdout, b"second");
        assert_eq!(run.execution.jobs[1].steps[0].observation.stdout, b"fresh");
        let json = run.to_json();
        for flag in ["\"input_kind\":\"unpublished_candidate\"", "\"admitted\":false", "\"published\":false", "\"authoritative_check\":false"] {
            assert!(json.contains(flag));
        }
        assert_eq!(fs::read_to_string(run.run_directory.join("report.json")).unwrap(), json);
        assert_eq!(fs::read_dir(&run.run_directory).unwrap().count(), 2);
        let marker = fs::read_to_string(run.run_directory.join("attempt.json")).unwrap();
        assert!(marker.contains(&candidate.candidate_commit.to_string()) && marker.contains("unpublished_candidate"));
        assert_eq!(generation(f.node()), before);
        assert!(f.node().read_git_object(candidate.candidate_commit).is_err());
        assert!(f.node().read_git_object(candidate.root_tree).is_err());
        f.reopen(); assert_eq!(generation(f.node()), before);
        assert!(f.node().runtime().block_on(f.node().run_trusted_candidate_workflow_in(&f.node().request_context(),
            &reference(), (f.tip, candidate.candidate_commit), candidate.bundle_bytes(), b"workflow.yml", [2; 16],
            &f.parent(), &inputs(), Some(head), Default::default())).is_err());
        assert_eq!(fs::read_to_string(run.run_directory.join("report.json")).unwrap(), json);
        assert_eq!(f.node().runtime().block_on(f.node().materialize_admission()).unwrap().snapshot().refs[&reference()], f.tip);
    }
}

#[test]
fn workflow_itself_comes_from_candidate_and_unsupported_candidate_graph_starts_nothing() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format, SIMPLE); let before = generation(f.node());
        let new_workflow = SIMPLE.replace("printf base-script", "printf candidate-script");
        let candidate = f.replace_file("workflow.yml", SIMPLE, &new_workflow);
        let run = f.node().runtime().block_on(f.node().run_trusted_candidate_workflow_in(&f.node().request_context(),
            &reference(), (f.tip, candidate.candidate_commit), candidate.bundle_bytes(), b"workflow.yml", [3; 16],
            &f.parent(), &inputs(), None, Default::default())).unwrap();
        assert!(run.succeeded()); assert_eq!(run.execution.jobs[0].steps[0].observation.stdout, b"candidate-script");
        assert_ne!(run.workflow_blob, f.workflow);
        assert_eq!(run.workflow_blob, git_object_id(format, GitObjectKind::Blob, new_workflow.as_bytes()));
        let unsupported = SIMPLE.replace("fgit-trusted-local", "ubuntu-latest");
        let candidate = f.replace_file("workflow.yml", SIMPLE, &unsupported);
        assert!(f.node().runtime().block_on(f.node().run_trusted_candidate_workflow_in(&f.node().request_context(),
            &reference(), (f.tip, candidate.candidate_commit), candidate.bundle_bytes(), b"workflow.yml", [4; 16],
            &f.parent(), &inputs(), None, Default::default())).is_err());
        assert!(!f.parent().join(format!("workflow-{}", "04".repeat(16))).exists());
        assert_eq!(generation(f.node()), before); assert!(f.node().read_git_object(candidate.candidate_commit).is_err());
    }
}

#[test]
fn actual_bundle_coordinates_scope_and_current_snapshot_precede_any_execution() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format, SIMPLE);
        let candidate = f.replace_file("input.txt", "original\n", "candidate\n");
        let mut corrupt = candidate.bundle_bytes().to_vec(); let end = corrupt.len() - 1; corrupt[end] ^= 1;
        for (base, tip, bundle, prefixes) in [
            (f.tip, candidate.candidate_commit, corrupt.as_slice(), inputs()),
            (f.workflow, candidate.candidate_commit, candidate.bundle_bytes(), inputs()),
            (f.tip, f.workflow, candidate.bundle_bytes(), inputs()),
            (f.tip, candidate.candidate_commit, candidate.bundle_bytes(), vec![b"input.txt".to_vec()]),
        ] {
            assert!(f.node().runtime().block_on(f.node().run_trusted_candidate_workflow_in(&f.node().request_context(),
                &reference(), (base, tip), bundle, b"workflow.yml", [5; 16], &f.parent(), &prefixes,
                None, Default::default())).is_err());
            assert_eq!(fs::read_dir(f.parent()).unwrap().count(), 0);
        }
        // Make the former snapshot stale through the ordinary sealed publisher.
        let old_head = f.node().runtime().block_on(f.node().materialize_admission()).unwrap().basis().id();
        let applied = f.node().runtime().block_on(f.node().apply_workspace_bundle_durable_in(&f.node().request_context(),
            PRINCIPAL, b"independent-publication", &reference(), f.tip, candidate.candidate_commit, candidate.bundle_bytes())).unwrap();
        assert!(matches!(applied.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        assert!(f.node().runtime().block_on(f.node().run_trusted_candidate_workflow_in(&f.node().request_context(),
            &reference(), (f.tip, candidate.candidate_commit), candidate.bundle_bytes(), b"workflow.yml", [5; 16],
            &f.parent(), &inputs(), Some(old_head), Default::default())).is_err());
        assert_eq!(fs::read_dir(f.parent()).unwrap().count(), 0);
    }
}

#[test]
fn candidate_timeout_retains_uncertain_workspace_without_publishing_or_starting_dependents() {
    let f = Fixture::new(GitHashAlgorithm::Sha1, SIMPLE); let before = generation(f.node());
    let timed = SIMPLE.replace("printf base-script", "while true; do true; done")
        + "  b:\n    runs-on: fgit-trusted-local\n    needs: a\n    steps:\n      - run: printf must-not-run\n";
    let candidate = f.replace_file("workflow.yml", SIMPLE, &timed);
    let limits = WorkflowLimits { step_timeout: Duration::from_millis(50), run_timeout: Duration::from_secs(30), ..Default::default() };
    let run = f.node().runtime().block_on(f.node().run_trusted_candidate_workflow_in(&f.node().request_context(),
        &reference(), (f.tip, candidate.candidate_commit), candidate.bundle_bytes(), b"workflow.yml", [6; 16],
        &f.parent(), &inputs(), None, limits)).unwrap();
    assert!(!run.succeeded()); assert!(!run.workspaces_closed);
    assert!(run.run_directory.join("job-000").is_dir()); assert!(!run.run_directory.join("job-001").exists());
    assert!(run.execution.jobs[1].steps.is_empty());
    assert_eq!(fs::read_to_string(run.run_directory.join("report.json")).unwrap(), run.to_json());
    assert_eq!(generation(f.node()), before); assert!(f.node().read_git_object(candidate.candidate_commit).is_err());
}
