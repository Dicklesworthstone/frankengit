#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Actual merge validation -> candidate TreeFS -> processes -> persisted report.
#[path = "trusted_merge_workflow/custom.rs"]
mod custom;
#[path = "trusted_merge_workflow/support.rs"]
mod support;
use fgit_crypto::{GitObjectKind, git_object_id, sha256_digest};
use fgit_runner::workflow::WorkflowLimits;
use fgit_types::{GitHashAlgorithm, RefName};
use std::fs;
use std::time::Duration;
use support::*;

#[test]
fn both_parent_checks_fail_but_actual_merge_passes_without_publishing_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, WORKFLOW);
        let before = generation(f.node());
        for (index, reference, tip) in [(1, target_ref(), f.target), (2, source_ref(), f.source)] {
            let run = f
                .node()
                .runtime()
                .block_on(f.node().run_trusted_workflow_in(
                    &f.node().request_context(),
                    &reference,
                    b"workflow.yml",
                    [index; 16],
                    &f.parent(),
                    &inputs(),
                    (None, Some(tip)),
                    Default::default(),
                ))
                .unwrap();
            assert!(
                !run.succeeded(),
                "testing either parent cannot masquerade as testing the merged result"
            );
            assert!(run.workspaces_closed);
            assert!(run.merge.is_none());
        }
        let (merge, bundle) = f.prepared();
        let run = f
            .node()
            .runtime()
            .block_on(f.node().run_trusted_merge_workflow_in(
                &f.node().request_context(),
                &merge,
                &bundle,
                b"workflow.yml",
                [3; 16],
                &f.parent(),
                &inputs(),
                None,
                Default::default(),
            ))
            .unwrap();
        assert!(run.succeeded());
        assert!(run.workspaces_closed);
        assert_eq!(run.executed_commit(), merge.merge_commit);
        assert_eq!(run.source_commit, f.target);
        assert_eq!(run.workflow_blob, f.workflow);
        assert_eq!(run.merge.as_ref(), Some(&merge));
        assert_eq!(run.candidate.unwrap().bundle_sha256, sha256_digest(&bundle));
        assert_eq!(run.execution.jobs[0].steps[0].observation.stdout, b"merged");
        assert_eq!(run.execution.jobs[1].steps[0].observation.stdout, b"fresh");
        let saved = run.to_json();
        assert_eq!(
            fs::read_to_string(run.run_directory.join("report.json")).unwrap(),
            saved
        );
        let marker = fs::read_to_string(run.run_directory.join("attempt.json")).unwrap();
        for text in [&saved, &marker] {
            assert!(text.contains(&format!("\"source_tip\":\"{}\"", f.source)));
            assert!(text.contains(&format!("\"merge_base\":\"{}\"", f.base)));
            assert!(text.contains(&format!("\"parents\":[\"{}\",\"{}\"]", f.target, f.source)));
            assert!(text.contains("\"authoritative_check\":false"));
        }
        assert_eq!(generation(f.node()), before);
        assert!(f.node().read_git_object(merge.merge_commit).is_err());
        f.reopen();
        assert_eq!(generation(f.node()), before);
        assert!(
            f.node()
                .runtime()
                .block_on(f.node().run_trusted_merge_workflow_in(
                    &f.node().request_context(),
                    &merge,
                    &bundle,
                    b"workflow.yml",
                    [3; 16],
                    &f.parent(),
                    &inputs(),
                    None,
                    Default::default()
                ))
                .is_err()
        );
        assert_eq!(
            fs::read_to_string(run.run_directory.join("report.json")).unwrap(),
            saved
        );
        let state = f
            .node()
            .runtime()
            .block_on(f.node().materialize_admission())
            .unwrap();
        assert_eq!(state.snapshot().refs[&target_ref()], f.target);
        assert_eq!(state.snapshot().refs[&source_ref()], f.source);
        assert!(f.node().read_git_object(merge.merge_commit).is_err());
    }
}

#[test]
fn reviewed_custom_merge_executes_its_own_workflow_not_parent_or_recomputed_scripts() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(
            format,
            "name: wrong\non: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf wrong-parent; exit 7\n",
        );
        let before = generation(f.node());
        let (merge, bundle) = f.custom(WORKFLOW, &[f.target, f.source]);
        let run = f
            .node()
            .runtime()
            .block_on(f.node().run_trusted_merge_workflow_in(
                &f.node().request_context(),
                &merge,
                &bundle,
                b"workflow.yml",
                [4; 16],
                &f.parent(),
                &inputs(),
                None,
                Default::default(),
            ))
            .unwrap();
        assert!(run.succeeded());
        assert_eq!(
            run.workflow_blob,
            git_object_id(format, GitObjectKind::Blob, WORKFLOW.as_bytes())
        );
        assert_ne!(run.workflow_blob, f.workflow);
        assert_eq!(run.execution.jobs[0].steps[0].observation.stdout, b"merged");
        assert!(f.node().read_git_object(run.workflow_blob).is_err());
        assert!(f.node().read_git_object(merge.merge_commit).is_err());
        assert_eq!(generation(f.node()), before);
    }
}

#[test]
fn stale_pins_invalid_ancestry_corruption_and_wrong_parent_shapes_never_start_a_job() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format, WORKFLOW);
        let before = generation(f.node());
        let (merge, bundle) = f.prepared();
        let refused = |m: &fgit_forge::event::NativeMerge, bytes: &[u8], head| {
            assert!(
                f.node()
                    .runtime()
                    .block_on(f.node().run_trusted_merge_workflow_in(
                        &f.node().request_context(),
                        m,
                        bytes,
                        b"workflow.yml",
                        [5; 16],
                        &f.parent(),
                        &inputs(),
                        head,
                        Default::default()
                    ))
                    .is_err()
            );
            assert_eq!(fs::read_dir(f.parent()).unwrap().count(), 0);
            assert_eq!(generation(f.node()), before);
            assert!(f.node().read_git_object(m.merge_commit).is_err());
        };
        let mut changed = merge.clone();
        changed.source_tip = f.target;
        refused(&changed, &bundle, None);
        let mut changed = merge.clone();
        changed.target_tip_before = f.base;
        refused(&changed, &bundle, None);
        let mut changed = merge.clone();
        changed.base_tip = f.source;
        refused(&changed, &bundle, None);
        let mut changed = merge.clone();
        changed.source_ref = RefName::try_new(b"refs/heads/absent").unwrap();
        refused(&changed, &bundle, None);
        refused(&merge, &bundle, Some(f.genesis));
        let mut corrupt = bundle.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        refused(&merge, &corrupt, None);
        let source_line = format!("-{} source\n", f.source);
        let start = bundle
            .windows(source_line.len())
            .position(|s| s == source_line.as_bytes())
            .unwrap();
        let mut missing = bundle.clone();
        missing.drain(start..start + source_line.len());
        refused(&merge, &missing, None);
        for parents in [
            vec![f.source, f.target],
            vec![f.target],
            vec![f.target, f.source, f.base],
        ] {
            let (wrong, bytes) = f.custom(WORKFLOW, &parents);
            refused(&wrong, &bytes, None);
        }
        assert!(
            f.node()
                .runtime()
                .block_on(f.node().run_trusted_candidate_workflow_in(
                    &f.node().request_context(),
                    &target_ref(),
                    (f.target, merge.merge_commit),
                    &bundle,
                    b"workflow.yml",
                    [5; 16],
                    &f.parent(),
                    &inputs(),
                    None,
                    Default::default()
                ))
                .is_err()
        );
        assert_eq!(fs::read_dir(f.parent()).unwrap().count(), 0);
        // All refused attempts leave the original run ID unused; the good twin executes.
        let run = f
            .node()
            .runtime()
            .block_on(f.node().run_trusted_merge_workflow_in(
                &f.node().request_context(),
                &merge,
                &bundle,
                b"workflow.yml",
                [5; 16],
                &f.parent(),
                &inputs(),
                None,
                Default::default(),
            ))
            .unwrap();
        assert!(run.succeeded());
        assert_eq!(generation(f.node()), before);
    }
}

#[test]
fn merge_timeout_retains_provenance_and_workspace_and_stops_later_jobs() {
    let f = Fixture::new(GitHashAlgorithm::Sha1, WORKFLOW);
    let before = generation(f.node());
    let timeout = "name: stop\non: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: while true; do true; done\n  b:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf must-not-run\n";
    let (merge, bundle) = f.custom(timeout, &[f.target, f.source]);
    let limits = WorkflowLimits {
        step_timeout: Duration::from_millis(50),
        run_timeout: Duration::from_secs(30),
        ..Default::default()
    };
    let run = f
        .node()
        .runtime()
        .block_on(f.node().run_trusted_merge_workflow_in(
            &f.node().request_context(),
            &merge,
            &bundle,
            b"workflow.yml",
            [6; 16],
            &f.parent(),
            &inputs(),
            None,
            limits,
        ))
        .unwrap();
    assert!(!run.succeeded());
    assert!(!run.workspaces_closed);
    assert_eq!(run.merge.as_ref(), Some(&merge));
    assert!(run.run_directory.join("job-000").is_dir());
    assert!(!run.run_directory.join("job-001").exists());
    assert!(run.execution.jobs[1].steps.is_empty());
    assert_eq!(
        fs::read_to_string(run.run_directory.join("report.json")).unwrap(),
        run.to_json()
    );
    assert_eq!(generation(f.node()), before);
    assert!(f.node().read_git_object(merge.merge_commit).is_err());
}
