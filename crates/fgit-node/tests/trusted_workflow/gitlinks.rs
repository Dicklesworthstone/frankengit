//! Real native execution preserves opaque submodules without foreign reads.

use super::*;
use fgit_node::{WorkspaceInputSharing, WorkspaceToolFailure};
use fgit_runner::sparse_workspace::HostRefusal;
use std::process::Command;

const FORMATS: [GitHashAlgorithm; 2] = [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256];

fn opaque_pointer(format: GitHashAlgorithm) -> GitOid {
    git_object_id(format, GitObjectKind::Commit, b"foreign module")
}

fn selected_inputs() -> Vec<Vec<u8>> {
    vec![
        b"input.txt".to_vec(),
        b"module".to_vec(),
        b"workflow.yml".to_vec(),
    ]
}

fn workflow(script: &str) -> String {
    format!(
        "name: opaque-submodule\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: {script}\n"
    )
}

#[test]
fn uninitialized_submodules_allow_real_workflow_execution_and_reopen() {
    let source = "name: submodule-jobs\non: push\njobs:\n  first:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: test -d module && test ! -L module && test -z \"$(ls -A module)\" && test \"$(cat input.txt)\" = original && printf changed > input.txt && printf first\n  second:\n    runs-on: fgit-trusted-local\n    needs: first\n    steps:\n      - run: test -d module && test -z \"$(ls -A module)\" && test \"$(cat input.txt)\" = original && printf second\n";
    for format in FORMATS {
        let mut fixture = Fixture::new_gitlink(format, source);
        let before = generation(fixture.node());
        assert!(
            fixture
                .node()
                .read_git_object(opaque_pointer(format))
                .is_err()
        );
        let report = fixture
            .node()
            .runtime()
            .block_on(fixture.node().run_trusted_workflow_in(
                &fixture.node().request_context(),
                &reference(),
                b"workflow.yml",
                [0x61; 16],
                &fixture.parent(),
                &selected_inputs(),
                (None, Some(fixture.tip)),
                WorkflowLimits::default(),
            ))
            .unwrap();
        assert!(report.succeeded(), "{}", report.to_json());
        assert!(report.workspaces_closed);
        assert_eq!(report.source_commit, fixture.tip);
        assert_eq!(report.execution.jobs.len(), 2);
        assert_eq!(
            report.execution.jobs[0].steps[0].observation.stdout,
            b"first"
        );
        assert_eq!(
            report.execution.jobs[1].steps[0].observation.stdout,
            b"second"
        );
        let saved = fs::read_to_string(report.run_directory.join("report.json")).unwrap();
        assert_eq!(saved, report.to_json());
        assert_eq!(generation(fixture.node()), before);
        fixture.reopen();
        assert_eq!(generation(fixture.node()), before);
        assert!(
            fixture
                .node()
                .read_git_object(opaque_pointer(format))
                .is_err()
        );
        assert_eq!(
            fs::read_to_string(report.run_directory.join("report.json")).unwrap(),
            saved,
        );
        let repeated = fixture
            .node()
            .runtime()
            .block_on(fixture.node().run_trusted_workflow_in(
                &fixture.node().request_context(),
                &reference(),
                b"workflow.yml",
                [0x62; 16],
                &fixture.parent(),
                &selected_inputs(),
                (None, Some(fixture.tip)),
                WorkflowLimits::default(),
            ))
            .unwrap();
        assert!(repeated.succeeded(), "{}", repeated.to_json());
        assert!(repeated.workspaces_closed);
    }
}

#[test]
fn successful_commands_cannot_mutate_gitlinks_without_artifact_collection() {
    for format in FORMATS {
        for script in [
            "printf unexpected > module/file",
            "rmdir module && ln -s input.txt module",
            "mv module replaced && mkdir -m 700 module",
        ] {
            let fixture = Fixture::new_gitlink(format, &workflow(script));
            let before = generation(fixture.node());
            let report = fixture
                .node()
                .runtime()
                .block_on(fixture.node().run_trusted_workflow_in(
                    &fixture.node().request_context(),
                    &reference(),
                    b"workflow.yml",
                    [0x63; 16],
                    &fixture.parent(),
                    &selected_inputs(),
                    (None, Some(fixture.tip)),
                    WorkflowLimits::default(),
                ))
                .unwrap();
            assert!(!report.succeeded(), "accepted {script}");
            let job = &report.execution.jobs[0];
            assert_eq!(job.steps[0].observation.exit_code, Some(0));
            assert_eq!(job.outcome, JobOutcome::Refused);
            let failure = job.failure.as_ref().unwrap();
            assert!(failure.detail.contains("opaque inputs:"), "{failure:?}");
            assert!(!failure.retain_workspace, "{failure:?}");
            assert!(report.workspaces_closed, "{}", report.to_json());
            assert_eq!(generation(fixture.node()), before);
            assert!(
                fixture
                    .node()
                    .read_git_object(opaque_pointer(format))
                    .is_err()
            );
        }
    }
}

#[test]
fn trusted_tool_exports_regular_changes_with_identical_opaque_gitlink() {
    for format in FORMATS {
        let fixture = Fixture::new_gitlink(format, &workflow("true"));
        let before = generation(fixture.node());
        let input = git_object_id(format, GitObjectKind::Blob, b"updated\n");
        let expected_tree = git_object_id(
            format,
            GitObjectKind::Tree,
            &[
                b"100644 input.txt\0".as_slice(),
                input.as_bytes(),
                b"160000 module\0".as_slice(),
                opaque_pointer(format).as_bytes(),
                b"100644 workflow.yml\0".as_slice(),
                fixture.workflow.as_bytes(),
            ]
            .concat(),
        );
        let mut previous_pack = None;
        for (index, sharing) in [
            WorkspaceInputSharing::Copy,
            WorkspaceInputSharing::PreferReflink,
        ]
        .into_iter()
        .enumerate()
        {
            let mut command = Command::new("/bin/sh");
            command.args([
                "-c",
                "test -d module && test -z \"$(ls -A module)\" && printf 'updated\n' > input.txt",
            ]);
            let result = fixture
                .node()
                .runtime()
                .block_on(fixture.node().run_trusted_workspace_tool_shared_at_in(
                    &fixture.node().request_context(),
                    &reference(),
                    (None, Some(fixture.tip)),
                    [0x64 + u8::try_from(index).unwrap(); 16],
                    &fixture.parent(),
                    &selected_inputs(),
                    &[b"input.txt".to_vec()],
                    sharing,
                    &mut command,
                    Duration::from_secs(30),
                    ("Fixture <fixture@example.invalid>", 2, b"regular change\n"),
                ))
                .unwrap();
            assert_eq!(result.root_tree, expected_tree);
            assert_eq!(result.source_commit, fixture.tip);
            assert_eq!(result.changed_paths, vec![b"input.txt".to_vec()]);
            assert_eq!(result.object_count, 3, "blob, tree and candidate commit");
            if let Some(previous) = &previous_pack {
                assert_eq!(result.pack_bytes(), previous);
            }
            previous_pack = Some(result.pack_bytes().to_vec());
            assert_eq!(fs::read_dir(fixture.parent()).unwrap().count(), 0);
        }
        assert_eq!(generation(fixture.node()), before);
        assert!(
            fixture
                .node()
                .read_git_object(opaque_pointer(format))
                .is_err()
        );
    }
}

#[test]
fn native_tool_refuses_submodule_outputs_before_spawning() {
    for format in FORMATS {
        let fixture = Fixture::new_gitlink(format, &workflow("true"));
        for output in [b"module".as_slice(), b"module/generated.txt".as_slice()] {
            let mut command = Command::new("/bin/sh");
            command.args(["-c", "exit 97"]);
            let error = fixture
                .node()
                .runtime()
                .block_on(fixture.node().run_trusted_workspace_tool_in(
                    &fixture.node().request_context(),
                    &reference(),
                    [0x66; 16],
                    &fixture.parent(),
                    &selected_inputs(),
                    &[output.to_vec()],
                    &mut command,
                    Duration::from_secs(30),
                    ("Fixture <fixture@example.invalid>", 2, b"forbidden\n"),
                ))
                .unwrap_err();
            assert!(
                matches!(
                    error,
                    WorkspaceToolFailure::Host(HostRefusal::UnsupportedEntry(_))
                ),
                "{error:?}",
            );
            assert_eq!(fs::read_dir(fixture.parent()).unwrap().count(), 0);
        }
    }
}
