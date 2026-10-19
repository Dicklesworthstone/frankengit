//! Real producer settlement, private dependent inputs and immutable lineage.
use super::*;
use fgit_node::TrustedWorkflowArtifactInput as Input;

fn input(consumer: &str, producer: &str, output: &[u8], destination: &[u8]) -> Input {
    Input::new(b"workflow.yml", consumer, producer, output, destination).unwrap()
}

fn no_input_stages(run: &TrustedWorkflowRun) {
    assert!(!fs::read_dir(&run.run_directory).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".job-")
    }));
}

#[test]
fn real_dependent_inputs_survive_producer_cleanup_and_bind_output_lineage() {
    let workflow = r#"name: artifact pipeline
on: push
jobs:
  a:
    runs-on: fgit-trusted-local
    steps:
      - run: printf 'payload\000bytes\377' > out.bin; chmod +x out.bin
  b:
    runs-on: fgit-trusted-local
    needs: a
    steps:
      - run: test ! -d ../job-000; test ! -e out.bin; test -x .fgit-artifacts/data; printf 'payload\000bytes\377' > expected; cmp expected .fgit-artifacts/data; printf changed > .fgit-artifacts/data; cp .fgit-artifacts/data derived.bin
  c:
    runs-on: fgit-trusted-local
    needs: a
    steps:
      - run: test ! -d ../job-000; test ! -d ../job-001; test ! -e derived.bin; printf 'payload\000bytes\377' > expected; cmp expected .fgit-artifacts/data
  d:
    runs-on: fgit-trusted-local
    needs: b
    steps:
      - run: test ! -d ../job-001; test "$(cat .fgit-artifacts/result)" = changed
"#;
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, workflow);
        let contract = Config::new(
            private(&f, "artifacts"),
            vec![
                Selection::new(b"workflow.yml", "a", b"out.bin").unwrap(),
                Selection::new(b"workflow.yml", "b", b"derived.bin").unwrap(),
            ],
            1024,
            4096,
        )
        .unwrap()
        .with_inputs(
            vec![
                input("b", "a", b"out.bin", b"data"),
                input("c", "a", b"out.bin", b"data"),
                input("d", "b", b"derived.bin", b"result"),
            ],
            4096,
        )
        .unwrap();
        let before = generation(f.node());
        let run = execute(&f, &contract, 0x61);
        assert!(run.succeeded(), "{}", run.to_json());
        assert!(run.workspaces_closed);
        assert_eq!(run.artifacts.len(), 2);
        assert_eq!(run.artifact_inputs.len(), 3);
        for (index, consumer) in ["b", "c"].into_iter().enumerate() {
            let received = &run.artifact_inputs[index];
            assert_eq!(received.job_id, consumer);
            assert_eq!(received.inputs.len(), 1);
            let transfer = &received.inputs[0];
            assert_eq!(transfer.producer_job_id, "a");
            assert_eq!(transfer.producer_manifest_id, run.artifacts[0].manifest_id);
            assert_eq!(
                transfer.output.artifact_id,
                run.artifacts[0].outputs[0].artifact_id
            );
            assert!(transfer.output.executable);
            assert_eq!(transfer.destination, b".fgit-artifacts/data");
            let receipt = fs::read_to_string(
                run.run_directory
                    .join(format!("job-{:03}-artifact-inputs.json", index + 1)),
            )
            .unwrap();
            assert!(receipt.contains("\"state\":\"verified_inputs_prepared\""));
            assert!(receipt.contains(&hex(&received.workspace_plan_sha256)));
        }
        let downstream = &run.artifact_inputs[2];
        assert_eq!(downstream.job_id, "d");
        assert_eq!(downstream.inputs.len(), 1);
        assert_eq!(downstream.inputs[0].producer_job_id, "b");
        assert_eq!(
            downstream.inputs[0].producer_manifest_id,
            run.artifacts[1].manifest_id
        );
        assert_eq!(
            downstream.inputs[0].output.artifact_id,
            run.artifacts[1].outputs[0].artifact_id
        );
        assert_eq!(downstream.inputs[0].destination, b".fgit-artifacts/result");
        for index in 0..4 {
            assert!(!run.run_directory.join(format!("job-{index:03}")).exists());
        }
        no_input_stages(&run);
        assert_eq!(
            fs::read_to_string(run.run_directory.join("report.json")).unwrap(),
            run.to_json()
        );
        f.reopen();
        let live = || true;
        let op = ArtifactOperation::new(1024 * 1024, Duration::from_secs(30), &live).unwrap();
        let retained = store(&contract, &run);
        assert_eq!(
            retained
                .read_payload(&run.artifacts[0].outputs[0].artifact_id, &op)
                .unwrap()
                .1,
            b"payload\0bytes\xff"
        );
        assert_eq!(
            retained
                .read_payload(&run.artifacts[1].outputs[0].artifact_id, &op)
                .unwrap()
                .1,
            b"changed"
        );
        let manifest = String::from_utf8(
            retained
                .read_payload(&run.artifacts[1].manifest_id, &op)
                .unwrap()
                .1,
        )
        .unwrap();
        assert!(manifest.contains("\"artifact_inputs\":"));
        assert!(manifest.contains(&hex(run.artifacts[0].manifest_id.bytes().as_bytes())));
        assert!(manifest.contains(&hex(&run.artifact_inputs[0].workspace_plan_sha256)));
        assert!(manifest.contains("\"cache_reuse_authorized\":false"));
        assert_eq!(generation(f.node()), before);
    }
}

#[test]
fn changed_stored_payload_or_provenance_refuses_before_consumers_first_script() {
    for field in ["artifact_id_sha256", "manifest_id_sha256"] {
        for poison in [false, true] {
            // A trusted-owner diagnostic job deliberately damages the retained
            // producer object after a's cleanup, before c is eligible to open.
            let inspect = r#"record=$(cat ../job-000-artifacts.json); id=${record#*\"FIELD\":\"}; id=${id%%\"*}; test ${#id} -eq 64; found=no; for scope in ../../../artifacts/scope-*; do file="$scope/$id"; test -f "$file" || continue; TAMPER; found=yes; done; test "$found" = yes"#
                .replace("FIELD", field)
                .replace("TAMPER", if poison { "printf poisoned >\"$file\"" } else { "test -s \"$file\"" });
            let workflow = format!(
                "name: verify inputs\non: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf immutable > out.bin\n  b:\n    runs-on: fgit-trusted-local\n    needs: a\n    steps:\n      - run: {inspect}\n  c:\n    runs-on: fgit-trusted-local\n    needs:\n      - a\n      - b\n    steps:\n      - run: test \"$(cat .fgit-artifacts/input)\" = immutable; printf consumed\n"
            );
            let f = Fixture::new(GitHashAlgorithm::Sha256, &workflow);
            let contract = config(&f, b"out.bin", 1024, 4096)
                .with_inputs(vec![input("c", "a", b"out.bin", b"input")], 4096)
                .unwrap();
            let before = generation(f.node());
            let run = execute(&f, &contract, 0x62);
            assert_eq!(run.execution.jobs[0].outcome, JobOutcome::Succeeded);
            assert_eq!(
                run.execution.jobs[1].outcome,
                JobOutcome::Succeeded,
                "{}",
                run.to_json()
            );
            assert!(run.workspaces_closed);
            no_input_stages(&run);
            assert!(!run.run_directory.join("job-000").exists());
            assert!(!run.run_directory.join("job-002").exists());
            if poison {
                assert!(!run.succeeded());
                assert_eq!(run.execution.jobs[2].outcome, JobOutcome::Refused);
                assert!(run.execution.jobs[2].steps.is_empty());
                assert!(run.artifact_inputs.is_empty());
                assert!(
                    !run.run_directory
                        .join("job-002-artifact-inputs.json")
                        .exists()
                );
            } else {
                assert!(run.succeeded(), "{}", run.to_json());
                assert_eq!(run.artifact_inputs.len(), 1);
                assert_eq!(
                    run.execution.jobs[2].steps[0].observation.stdout,
                    b"consumed"
                );
            }
            assert_eq!(generation(f.node()), before);
        }
    }
}

#[test]
fn fanout_charges_each_private_copy_against_the_delivery_budget() {
    let workflow = r#"name: fanout
on: push
jobs:
  a:
    runs-on: fgit-trusted-local
    steps:
      - run: printf data > out.bin
  b:
    runs-on: fgit-trusted-local
    needs: a
    steps:
      - run: test "$(cat .fgit-artifacts/input)" = data
  c:
    runs-on: fgit-trusted-local
    needs: a
    steps:
      - run: test "$(cat .fgit-artifacts/input)" = data
"#;
    for total in [6, 8] {
        let f = Fixture::new(GitHashAlgorithm::Sha1, workflow);
        let contract = config(&f, b"out.bin", 4, 4)
            .with_inputs(
                vec![
                    input("b", "a", b"out.bin", b"input"),
                    input("c", "a", b"out.bin", b"input"),
                ],
                total,
            )
            .unwrap();
        let run = execute(&f, &contract, 0x63);
        assert_eq!(run.execution.jobs[0].outcome, JobOutcome::Succeeded);
        assert_eq!(run.execution.jobs[1].outcome, JobOutcome::Succeeded);
        assert_eq!(run.artifacts.len(), 1);
        assert_eq!(run.artifacts[0].outputs[0].payload_bytes, 4);
        assert!(run.workspaces_closed);
        no_input_stages(&run);
        if total == 6 {
            assert_eq!(run.execution.jobs[2].outcome, JobOutcome::Refused);
            assert!(run.execution.jobs[2].steps.is_empty());
            assert!(
                run.execution.jobs[2]
                    .failure
                    .as_ref()
                    .unwrap()
                    .detail
                    .contains("delivery limit")
            );
            assert_eq!(run.artifact_inputs.len(), 1);
        } else {
            assert!(run.succeeded());
            assert_eq!(run.artifact_inputs.len(), 2);
        }
    }
}

#[test]
fn dispatch_delivery_allowance_does_not_reset_between_child_workflows() {
    let workflow = workflow("printf data > out.bin").replace(
        "test ! -e out.bin; printf dependent",
        "test \"$(cat .fgit-artifacts/input)\" = data",
    );
    let f = Fixture::new_dispatch(GitHashAlgorithm::Sha256, &workflow);
    let paths = [b"ci/a.yml".as_slice(), b"ci/b.yml".as_slice()];
    let contract = Config::new(
        private(&f, "artifacts"),
        paths
            .iter()
            .map(|path| Selection::new(path, "a", b"out.bin").unwrap())
            .collect(),
        4,
        8,
    )
    .unwrap()
    .with_inputs(
        paths
            .iter()
            .map(|path| Input::new(path, "b", "a", b"out.bin", b"input").unwrap())
            .collect(),
        6,
    )
    .unwrap();
    let report = f
        .node()
        .runtime()
        .block_on(f.node().dispatch_trusted_workflows_with_artifacts_in(
            &f.node().request_context(),
            &reference(),
            b"ci",
            "push",
            [0x64; 16],
            &f.parent(),
            &[b"ci".to_vec()],
            (pinned_head(&f), f.tip),
            WorkflowLimits::default(),
            Some(&contract),
        ))
        .unwrap();
    assert_eq!(report.runs().len(), 2);
    assert!(report.runs()[0].succeeded());
    assert_eq!(report.runs()[0].artifact_inputs.len(), 1);
    let second = &report.runs()[1];
    assert_eq!(second.execution.jobs[0].outcome, JobOutcome::Succeeded);
    assert_eq!(second.execution.jobs[1].outcome, JobOutcome::Refused);
    assert!(second.execution.jobs[1].steps.is_empty());
    assert!(second.artifact_inputs.is_empty());
    assert!(second.workspaces_closed);
    no_input_stages(second);
}

#[test]
fn all_consumers_and_direct_dependencies_are_validated_before_attempt_reservation() {
    for (consumer, direct) in [("absent", true), ("b", false), ("b", true)] {
        let mut workflow = workflow("printf data > out.bin");
        if !direct {
            workflow = workflow.replace("    needs: a\n", "");
        }
        let f = Fixture::new(GitHashAlgorithm::Sha1, &workflow);
        let contract = config(&f, b"out.bin", 4, 4)
            .with_inputs(vec![input(consumer, "a", b"out.bin", b"input")], 4)
            .unwrap();
        let run = f
            .node()
            .runtime()
            .block_on(f.node().run_trusted_workflow_with_artifacts_in(
                &f.node().request_context(),
                &reference(),
                b"workflow.yml",
                [0x65; 16],
                &f.parent(),
                &inputs(),
                (None, Some(f.tip)),
                WorkflowLimits::default(),
                Some(&contract),
            ));
        if consumer == "b" && direct {
            assert!(run.unwrap().succeeded());
        } else {
            assert!(run.is_err());
            assert_eq!(fs::read_dir(f.parent()).unwrap().count(), 0);
            assert_eq!(fs::read_dir(contract.root()).unwrap().count(), 0);
        }
    }
}

#[test]
fn changed_input_destination_cannot_adopt_an_occupied_attempt() {
    let f = Fixture::new(GitHashAlgorithm::Sha1, &workflow("printf data > out.bin"));
    let capture = config(&f, b"out.bin", 4, 4);
    let first_contract = capture
        .clone()
        .with_inputs(vec![input("b", "a", b"out.bin", b"first")], 4)
        .unwrap();
    let first = execute(&f, &first_contract, 0x66);
    assert!(first.succeeded());
    let marker = fs::read(first.run_directory.join("attempt.json")).unwrap();
    let changed = capture
        .with_inputs(vec![input("b", "a", b"out.bin", b"changed")], 4)
        .unwrap();
    assert!(
        f.node()
            .runtime()
            .block_on(f.node().run_trusted_workflow_with_artifacts_in(
                &f.node().request_context(),
                &reference(),
                b"workflow.yml",
                [0x66; 16],
                &f.parent(),
                &inputs(),
                (None, Some(f.tip)),
                WorkflowLimits::default(),
                Some(&changed),
            ),)
            .is_err()
    );
    assert_eq!(
        fs::read(first.run_directory.join("attempt.json")).unwrap(),
        marker
    );
    assert_eq!(
        fs::read_to_string(first.run_directory.join("report.json")).unwrap(),
        first.to_json()
    );
}

#[test]
fn failed_producer_custody_cannot_authorize_an_always_consumer() {
    let workflow = workflow("printf data > out.bin; exit 9")
        .replace("    needs: a\n", "    needs: a\n    if: always()\n");
    let f = Fixture::new(GitHashAlgorithm::Sha256, &workflow);
    let contract = config(&f, b"out.bin", 4, 4)
        .with_inputs(vec![input("b", "a", b"out.bin", b"input")], 4)
        .unwrap();
    let run = execute(&f, &contract, 0x67);
    assert_eq!(run.execution.jobs[0].outcome, JobOutcome::Failed);
    assert_eq!(run.artifacts.len(), 1);
    assert_eq!(run.execution.jobs[1].outcome, JobOutcome::Refused);
    assert!(run.execution.jobs[1].steps.is_empty());
    assert!(run.artifact_inputs.is_empty());
    assert!(run.workspaces_closed);
    no_input_stages(&run);
}

#[test]
fn cancelled_input_request_starts_no_attempt_and_does_not_spend_future_runs_budget() {
    let f = Fixture::new(GitHashAlgorithm::Sha1, &workflow("printf data > out.bin"));
    let contract = config(&f, b"out.bin", 4, 4)
        .with_inputs(vec![input("b", "a", b"out.bin", b"input")], 4)
        .unwrap();
    let request = f.node().request_context();
    request.cancel();
    assert!(
        f.node()
            .runtime()
            .block_on(f.node().run_trusted_workflow_with_artifacts_in(
                &request,
                &reference(),
                b"workflow.yml",
                [0x68; 16],
                &f.parent(),
                &inputs(),
                (None, Some(f.tip)),
                WorkflowLimits::default(),
                Some(&contract),
            ),)
            .is_err()
    );
    assert_eq!(fs::read_dir(f.parent()).unwrap().count(), 0);
    assert_eq!(fs::read_dir(contract.root()).unwrap().count(), 0);
    assert!(execute(&f, &contract, 0x68).succeeded());
}
