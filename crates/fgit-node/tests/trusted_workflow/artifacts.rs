//! Actual authenticated source selection, process execution, immutable artifact
//! custody and offline journal reopening. These remain trusted-owner tests.
use super::*;
#[path = "artifact_inputs.rs"]
mod input_delivery;
#[path = "logs.rs"]
mod logs;
use fgit_node::{
    TRUSTED_WORKFLOW_ARTIFACT_TRUST, TrustedWorkflowArtifactConfig as Config,
    TrustedWorkflowArtifactSelection as Selection, TrustedWorkflowRun,
};
use fgit_object_fabric::artifact::storage::{ArtifactOperation, ArtifactScope, LocalArtifactStore};
use fgit_runner::coordinator::CheckRunConclusion;
use fgit_runner::coordinator::delivery::journal::history::{
    MAX_HISTORY_BATCHES, MAX_HISTORY_BYTES,
};
use std::os::unix::fs::DirBuilderExt;

fn private(f: &Fixture, name: &str) -> PathBuf {
    let path = f.root.join(name);
    fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
    path
}
fn config(f: &Fixture, path: &[u8], per_file: usize, total: usize) -> Config {
    Config::new(
        private(f, "artifacts"),
        vec![Selection::new(b"workflow.yml", "a", path).unwrap()],
        per_file,
        total,
    )
    .unwrap()
}
fn execute(f: &Fixture, contract: &Config, id: u8) -> TrustedWorkflowRun {
    f.node()
        .runtime()
        .block_on(f.node().run_trusted_workflow_with_artifacts_in(
            &f.node().request_context(),
            &reference(),
            b"workflow.yml",
            [id; 16],
            &f.parent(),
            &inputs(),
            (None, Some(f.tip)),
            WorkflowLimits::default(),
            Some(contract),
        ))
        .unwrap()
}
fn store(contract: &Config, run: &TrustedWorkflowRun) -> LocalArtifactStore {
    LocalArtifactStore::open(
        contract.root(),
        ArtifactScope::new(
            run.tenant,
            run.repository,
            run.incarnation,
            TRUSTED_WORKFLOW_ARTIFACT_TRUST,
        )
        .unwrap(),
    )
    .unwrap()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn workflow(script: &str) -> String {
    format!(
        "name: artifacts\non: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: {script}\n  b:\n    runs-on: fgit-trusted-local\n    needs: a\n    steps:\n      - run: test ! -e out.bin; printf dependent\n"
    )
}

#[test]
fn real_outputs_survive_workspace_cleanup_and_provenance_binds_exact_producing_run() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(
            format,
            &workflow("printf 'payload\\000bytes\\377' > out.bin; chmod +x out.bin"),
        );
        let contract = config(&f, b"out.bin", 1024, 2048);
        assert!(!contract.capture_logs());
        let before = generation(f.node());
        let run = execute(&f, &contract, 0x51);
        assert!(run.succeeded());
        assert!(run.workspaces_closed);
        assert_eq!(run.source_commit, f.tip);
        assert_eq!(run.artifacts.len(), 1);
        assert!(run.artifact_logs.is_empty());
        assert!(!run.to_json().contains("\"artifact_logs\""));
        assert!(!run.run_directory.join("job-000-logs.json").exists());
        let produced = &run.artifacts[0];
        assert_eq!(produced.job_id, "a");
        assert_eq!(produced.outputs.len(), 1);
        assert!(produced.outputs[0].executable);
        assert_eq!(produced.outputs[0].path, b"out.bin");
        assert!(!run.run_directory.join("job-000").exists());
        assert!(!run.run_directory.join("job-001").exists());
        assert!(run.run_directory.join("job-000-artifacts.json").is_file());
        assert!(!fs::read_dir(&run.run_directory).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".pending")
        }));
        let saved = fs::read_to_string(run.run_directory.join("report.json")).unwrap();
        assert_eq!(saved, run.to_json());
        let live = || true;
        let op = ArtifactOperation::new(1024 * 1024, Duration::from_secs(30), &live).unwrap();
        let payload = f.parent().join("exported-payload");
        let identity = store(&contract, &run)
            .export(&produced.outputs[0].artifact_id, &payload, &op)
            .unwrap();
        assert_eq!(fs::read(&payload).unwrap(), b"payload\0bytes\xff");
        assert_eq!(
            identity.payload_len() as usize,
            produced.outputs[0].payload_bytes
        );
        assert!(identity.build_capsule_id().is_none());
        assert!(identity.check_receipt_id().is_none());
        if let Some(source) = identity.source_rcr() {
            assert_eq!(
                source.algorithm(),
                run.source_rcr.as_internal_object_id().algorithm()
            );
            assert_eq!(
                source.bytes(),
                run.source_rcr.as_internal_object_id().digest()
            );
        }
        let provenance = f.parent().join("exported-provenance");
        store(&contract, &run)
            .export(&produced.manifest_id, &provenance, &op)
            .unwrap();
        let manifest = fs::read_to_string(&provenance).unwrap();
        for field in [
            format!("\"run_id\":\"{}\"", "51".repeat(16)),
            format!("\"source_commit\":\"{}\"", run.source_commit),
            format!("\"source_head\":\"{}\"", run.source_head),
            format!("\"source_rcr\":\"{}\"", run.source_rcr),
            format!("\"workflow_blob\":\"{}\"", f.workflow),
            "\"job_id_hex\":\"61\"".into(),
            "\"cache_reuse_authorized\":false".into(),
            "\"job_success_asserted\":false".into(),
            "\"build_input_capsule_id\":null".into(),
        ] {
            assert!(manifest.contains(&field), "{field}");
        }
        assert!(manifest.contains(&hex(produced.outputs[0].artifact_id.bytes().as_bytes())));
        // The configured marker is still accepted by the existing offline reader.
        let journal = run.open_check_journal(None, &live).unwrap();
        drop(journal);
        f.reopen();
        assert_eq!(generation(f.node()), before);
        assert_eq!(
            store(&contract, &run)
                .inspect(&produced.outputs[0].artifact_id, &op)
                .unwrap(),
            identity
        );
    }
}

#[test]
fn missing_oversized_and_aliased_outputs_refuse_before_success_and_still_close() {
    for (script, output, maximum) in [
        ("printf ordinary", b"out.bin".as_slice(), 32),
        ("printf toolarge > out.bin", b"out.bin".as_slice(), 1),
        ("ln -s input.txt out.bin", b"out.bin".as_slice(), 32),
        (
            "mkdir real; printf value > real/out; ln -s real alias",
            b"alias/out".as_slice(),
            32,
        ),
        ("ln input.txt out.bin", b"out.bin".as_slice(), 32),
        ("mkdir out.bin", b"out.bin".as_slice(), 32),
    ] {
        let f = Fixture::new(GitHashAlgorithm::Sha1, &workflow(script));
        let contract = config(&f, output, maximum, 64);
        let before = generation(f.node());
        let run = execute(&f, &contract, 0x52);
        assert!(!run.succeeded(), "{script}");
        assert!(run.workspaces_closed, "{script}");
        assert_eq!(
            run.execution.jobs[0].outcome,
            JobOutcome::Refused,
            "{script}"
        );
        assert!(!run.execution.jobs[0].requires_containment());
        assert_eq!(run.execution.jobs[1].outcome, JobOutcome::Skipped);
        assert!(run.artifacts.is_empty());
        assert!(!run.run_directory.join("job-000").exists());
        assert!(!run.run_directory.join("job-000-artifacts.json").exists());
        assert_eq!(fs::read_dir(contract.root()).unwrap().count(), 0);
        // A green terminal proposal must not escape through offline publication.
        let mut journal = run.open_check_journal(None, &|| true).unwrap();
        let page = journal
            .read_history(None, None, MAX_HISTORY_BATCHES, MAX_HISTORY_BYTES, &|| true)
            .unwrap();
        assert!(
            page.entries()
                .iter()
                .flat_map(|entry| entry.batch().facts())
                .all(|fact| fact.conclusion != Some(CheckRunConclusion::Success))
        );
        assert_eq!(generation(f.node()), before);
    }
}

#[test]
fn poisoned_existing_payload_cannot_be_adopted_or_repaired_by_a_successful_script() {
    let f = Fixture::new(
        GitHashAlgorithm::Sha256,
        &workflow("printf immutable > out.bin"),
    );
    let contract = config(&f, b"out.bin", 32, 64);
    let first = execute(&f, &contract, 0x53);
    assert!(first.succeeded());
    let selected = &first.artifacts[0].outputs[0];
    let artifact_store = store(&contract, &first);
    let container = contract
        .root()
        .join(format!(
            "scope-{}",
            hex(artifact_store.scope().commitment().bytes().as_bytes())
        ))
        .join(hex(selected.artifact_id.bytes().as_bytes()));
    let mut poisoned = fs::read(&container).unwrap();
    *poisoned.last_mut().unwrap() ^= 1;
    fs::write(&container, &poisoned).unwrap();
    let second = execute(&f, &contract, 0x54);
    assert_eq!(second.execution.jobs[0].outcome, JobOutcome::Refused);
    assert_eq!(second.execution.jobs[1].outcome, JobOutcome::Skipped);
    assert!(!second.succeeded());
    assert!(second.workspaces_closed);
    assert!(second.artifacts.is_empty());
    assert_eq!(fs::read(&container).unwrap(), poisoned);
    assert!(!second.run_directory.join("job-000-artifacts.json").exists());
}

#[test]
fn changing_output_root_or_contract_cannot_adopt_an_occupied_attempt() {
    let f = Fixture::new(
        GitHashAlgorithm::Sha1,
        &workflow("printf original > out.bin"),
    );
    let contract = config(&f, b"out.bin", 32, 64);
    let first = execute(&f, &contract, 0x55);
    let marker = fs::read(first.run_directory.join("attempt.json")).unwrap();
    let other_root = private(&f, "other-artifacts");
    let changed = Config::new(
        other_root.clone(),
        vec![Selection::new(b"workflow.yml", "a", b"different-output").unwrap()],
        16,
        32,
    )
    .unwrap();
    assert!(
        f.node()
            .runtime()
            .block_on(f.node().run_trusted_workflow_with_artifacts_in(
                &f.node().request_context(),
                &reference(),
                b"workflow.yml",
                [0x55; 16],
                &f.parent(),
                &inputs(),
                (None, Some(f.tip)),
                WorkflowLimits::default(),
                Some(&changed),
            ))
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
    assert_eq!(fs::read_dir(other_root).unwrap().count(), 0);
}

#[test]
fn all_output_selectors_and_the_private_root_are_validated_before_any_job() {
    let f = Fixture::new(GitHashAlgorithm::Sha1, &workflow("printf must-not-run"));
    let root = private(&f, "artifacts");
    for (workflow, job) in [
        (b"workflow.yml".as_slice(), "absent"),
        (b"absent.yml".as_slice(), "a"),
    ] {
        let contract = Config::new(
            root.clone(),
            vec![Selection::new(workflow, job, b"out").unwrap()],
            32,
            64,
        )
        .unwrap();
        assert!(
            f.node()
                .runtime()
                .block_on(f.node().run_trusted_workflow_with_artifacts_in(
                    &f.node().request_context(),
                    &reference(),
                    b"workflow.yml",
                    [0x56; 16],
                    &f.parent(),
                    &inputs(),
                    (None, Some(f.tip)),
                    WorkflowLimits::default(),
                    Some(&contract),
                ))
                .is_err()
        );
        assert_eq!(fs::read_dir(f.parent()).unwrap().count(), 0);
    }
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    let contract = Config::new(
        root,
        vec![Selection::new(b"workflow.yml", "a", b"out").unwrap()],
        32,
        64,
    )
    .unwrap();
    assert!(
        f.node()
            .runtime()
            .block_on(f.node().run_trusted_workflow_with_artifacts_in(
                &f.node().request_context(),
                &reference(),
                b"workflow.yml",
                [0x56; 16],
                &f.parent(),
                &inputs(),
                (None, Some(f.tip)),
                WorkflowLimits::default(),
                Some(&contract),
            ))
            .is_err()
    );
    assert_eq!(fs::read_dir(f.parent()).unwrap().count(), 0);
}

fn pinned_head(f: &Fixture) -> fgit_types::RepositoryAuthorityHeadId {
    use fgit_codec::{
        CryptoBodyIdentity, DecodeLimits, RepositoryAuthorityHeadBody, body_id, decode_body,
    };
    let head = f
        .node()
        .runtime()
        .block_on(f.node().authenticate_authority_head())
        .unwrap();
    let body =
        decode_body::<RepositoryAuthorityHeadBody>(head.receipt().body(), DecodeLimits::DEFAULT)
            .unwrap();
    fgit_types::RepositoryAuthorityHeadId::from_internal_object_id(
        body_id(&CryptoBodyIdentity, &body).unwrap(),
    )
    .unwrap()
}

#[test]
fn dispatch_shares_one_artifact_allowance_across_real_child_workflows() {
    let f = Fixture::new_dispatch(GitHashAlgorithm::Sha256, &workflow("printf data > out.bin"));
    let root = private(&f, "artifacts");
    let contract = Config::new(
        root,
        [b"ci/a.yml".as_slice(), b"ci/b.yml".as_slice()]
            .into_iter()
            .map(|path| Selection::new(path, "a", b"out.bin").unwrap())
            .collect(),
        4,
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
            [0x57; 16],
            &f.parent(),
            &[b"ci".to_vec()],
            (pinned_head(&f), f.tip),
            WorkflowLimits::default(),
            Some(&contract),
        ))
        .unwrap();
    assert!(!report.succeeded());
    assert_eq!(report.runs().len(), 2);
    assert_eq!(report.runs()[0].workflow_path, b"ci/a.yml");
    assert!(report.runs()[0].succeeded());
    assert_eq!(report.runs()[0].artifacts[0].outputs[0].payload_bytes, 4);
    let second = &report.runs()[1];
    assert_eq!(second.workflow_path, b"ci/b.yml");
    assert_eq!(second.execution.jobs[0].outcome, JobOutcome::Refused);
    assert_eq!(second.execution.jobs[1].outcome, JobOutcome::Skipped);
    assert!(second.workspaces_closed);
    assert!(second.artifacts.is_empty());
    assert!(
        report
            .to_json()
            .contains("\"stop_reason\":\"workflow_refused\"")
    );
    assert_eq!(
        fs::read_to_string(report.run_directory.join("report.json")).unwrap(),
        report.to_json()
    );
}

#[test]
fn dispatch_validates_every_selected_output_before_reserving_the_batch() {
    for (source_event, selected_path) in [
        ("push", b"ci/missing.yml".as_slice()),
        ("workflow_dispatch", b"ci/a.yml".as_slice()),
    ] {
        let source = workflow("printf must-not-run > out.bin")
            .replace("on: push", &format!("on: {source_event}"));
        let f = Fixture::new_dispatch(GitHashAlgorithm::Sha1, &source);
        let contract = Config::new(
            private(&f, "artifacts"),
            vec![Selection::new(selected_path, "a", b"out.bin").unwrap()],
            32,
            64,
        )
        .unwrap();
        assert!(
            f.node()
                .runtime()
                .block_on(f.node().dispatch_trusted_workflows_with_artifacts_in(
                    &f.node().request_context(),
                    &reference(),
                    b"ci",
                    "push",
                    [0x58; 16],
                    &f.parent(),
                    &[b"ci".to_vec()],
                    (pinned_head(&f), f.tip),
                    WorkflowLimits::default(),
                    Some(&contract),
                ))
                .is_err()
        );
        assert_eq!(fs::read_dir(f.parent()).unwrap().count(), 0);
        assert_eq!(fs::read_dir(contract.root()).unwrap().count(), 0);
    }
}
