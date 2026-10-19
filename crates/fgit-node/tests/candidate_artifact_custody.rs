#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Real pre-merge execution and durable output export, without candidate admission.
#[path = "trusted_candidate_workflow/support.rs"]
mod candidate;
#[path = "trusted_merge_workflow/support.rs"]
mod merge;
use fgit_crypto::sha256_digest;
use fgit_node::{
    TRUSTED_WORKFLOW_ARTIFACT_TRUST, TrustedWorkflowArtifactConfig as Config,
    TrustedWorkflowArtifactSelection as Selection, TrustedWorkflowFailure, TrustedWorkflowRun,
    WorkspacePatchCandidate,
};
use fgit_object_fabric::artifact::storage::{ArtifactOperation, ArtifactScope, LocalArtifactStore};
use fgit_runner::workflow::JobOutcome;
use fgit_types::GitHashAlgorithm;
use std::os::unix::fs::DirBuilderExt;
use std::{fs, path::Path, time::Duration};

fn configuration(
    root: &Path,
    name: &str,
    selections: &[(&str, &[u8])],
    maximum: usize,
    total: usize,
) -> Config {
    let directory = root.join(name);
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    Config::new(
        directory,
        selections
            .iter()
            .map(|(job, path)| Selection::new(b"workflow.yml", job, path).unwrap())
            .collect(),
        maximum,
        total,
    )
    .unwrap()
}
fn execute(
    f: &candidate::Fixture,
    prepared: &WorkspacePatchCandidate,
    config: &Config,
    id: u8,
) -> Result<TrustedWorkflowRun, TrustedWorkflowFailure> {
    f.node()
        .runtime()
        .block_on(f.node().run_trusted_candidate_workflow_with_artifacts_in(
            &f.node().request_context(),
            &candidate::reference(),
            (f.tip, prepared.candidate_commit),
            prepared.bundle_bytes(),
            b"workflow.yml",
            [id; 16],
            &f.parent(),
            &candidate::inputs(),
            None,
            Default::default(),
            Some(config),
        ))
}
fn store(config: &Config, report: &TrustedWorkflowRun) -> LocalArtifactStore {
    LocalArtifactStore::open(
        config.root(),
        ArtifactScope::new(
            report.tenant,
            report.repository,
            report.incarnation,
            TRUSTED_WORKFLOW_ARTIFACT_TRUST,
        )
        .unwrap(),
    )
    .unwrap()
}
fn export(config: &Config, report: &TrustedWorkflowRun, root: &Path) -> (Vec<u8>, String) {
    let live = || true;
    let op = ArtifactOperation::new(1024 * 1024, Duration::from_secs(30), &live).unwrap();
    let selected = &report.artifacts[0];
    let payload = root.join("exported-output");
    let provenance = root.join("exported-provenance");
    let identity = store(config, report)
        .export(&selected.outputs[0].artifact_id, &payload, &op)
        .unwrap();
    assert!(identity.build_capsule_id().is_none());
    assert!(identity.check_receipt_id().is_none());
    store(config, report)
        .export(&selected.manifest_id, &provenance, &op)
        .unwrap();
    (
        fs::read(payload).unwrap(),
        fs::read_to_string(provenance).unwrap(),
    )
}
fn assert_provenance(report: &TrustedWorkflowRun, manifest: &str) {
    for field in [
        format!("\"source_commit\":\"{}\"", report.source_commit),
        format!("\"source_rcr\":\"{}\"", report.source_rcr),
        format!("\"executed_commit\":\"{}\"", report.executed_commit()),
        "\"input_kind\":\"unpublished_candidate\"".into(),
        "\"cache_reuse_authorized\":false".into(),
        "\"job_success_asserted\":false".into(),
        "\"check_receipt_id\":null".into(),
    ] {
        assert!(manifest.contains(&field), "missing provenance: {field}");
    }
    assert_ne!(report.source_commit, report.executed_commit());
    assert_eq!(
        fs::read_to_string(report.run_directory.join("report.json")).unwrap(),
        report.to_json()
    );
    assert!(report.to_json().contains("\"authoritative_check\":false"));
    assert!(report.workspaces_closed);
    assert!(!report.run_directory.join("job-000").exists());
    drop(report.open_check_journal(None, &|| true).unwrap());
}
const SCRIPT: &str = "name: candidate-artifacts\non: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: cat input.txt > output.txt\n";

#[test]
fn candidate_outputs_survive_reopen_with_exact_provenance_without_importing_the_candidate() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = candidate::Fixture::new(format, SCRIPT);
        let prepared = f.replace_file("input.txt", "original\n", "candidate output\n");
        let config = configuration(&f.root, "artifacts", &[("a", b"output.txt")], 128, 256);
        let head = f
            .node()
            .runtime()
            .block_on(f.node().materialize_admission())
            .unwrap()
            .basis()
            .clone();
        let report = execute(&f, &prepared, &config, 21).unwrap();
        assert!(report.succeeded());
        assert_eq!(report.artifacts.len(), 1);
        assert_eq!(report.artifacts[0].outputs.len(), 1);
        assert_eq!(report.artifacts[0].outputs[0].path, b"output.txt");
        assert_eq!(
            report.candidate.as_ref().unwrap().bundle_sha256,
            sha256_digest(prepared.bundle_bytes())
        );
        assert_eq!(report.executed_commit(), prepared.candidate_commit);
        assert_eq!(report.executed_tree(), prepared.root_tree);
        f.reopen();
        let (bytes, manifest) = export(&config, &report, &f.parent());
        assert_eq!(bytes, b"candidate output\n");
        assert_provenance(&report, &manifest);
        assert!(f.node().read_git_object(prepared.candidate_commit).is_err());
        assert_eq!(
            f.node()
                .runtime()
                .block_on(f.node().materialize_admission())
                .unwrap()
                .basis(),
            &head
        );
        assert!(matches!(
            execute(&f, &prepared, &config, 21),
            Err(TrustedWorkflowFailure::AttemptExists(_))
        ));
    }
}

#[test]
fn candidate_workflow_itself_is_the_recorded_producer_not_the_base_script() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = candidate::Fixture::new(format, SCRIPT);
        let changed = SCRIPT.replace("cat input.txt", "printf changed-candidate");
        let prepared = f.replace_file("workflow.yml", SCRIPT, &changed);
        let config = configuration(&f.root, "artifacts", &[("a", b"output.txt")], 128, 128);
        let report = execute(&f, &prepared, &config, 22).unwrap();
        assert!(report.succeeded());
        assert_ne!(report.workflow_blob, f.workflow);
        let (bytes, manifest) = export(&config, &report, &f.parent());
        assert_eq!(bytes, b"changed-candidate");
        assert_provenance(&report, &manifest);
        assert!(manifest.contains(&report.workflow_blob.to_string()));
    }
}

#[test]
fn merge_candidate_outputs_preserve_both_parent_coordinates_and_no_publication() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let workflow =
            merge::WORKFLOW.replace("printf temporary > job-only", "cat left right > job-only");
        let mut f = merge::Fixture::new(format, &workflow);
        let (coordinates, bundle) = f.prepared();
        let config = configuration(&f.root, "artifacts", &[("a", b"job-only")], 128, 128);
        let before = merge::generation(f.node());
        let report = f
            .node()
            .runtime()
            .block_on(f.node().run_trusted_merge_workflow_with_artifacts_in(
                &f.node().request_context(),
                &coordinates,
                &bundle,
                b"workflow.yml",
                [23; 16],
                &f.parent(),
                &merge::inputs(),
                None,
                Default::default(),
                Some(&config),
            ))
            .unwrap();
        assert!(report.succeeded());
        assert_eq!(report.merge.as_ref(), Some(&coordinates));
        assert_eq!(report.execution.jobs.len(), 2);
        f.reopen();
        let (bytes, manifest) = export(&config, &report, &f.parent());
        assert_eq!(bytes, b"target\nsource\n");
        assert_provenance(&report, &manifest);
        for id in [f.base, f.target, f.source, coordinates.merge_commit] {
            assert!(manifest.contains(&id.to_string()));
        }
        assert!(f.node().read_git_object(coordinates.merge_commit).is_err());
        assert_eq!(merge::generation(f.node()), before);
    }
}

#[test]
fn missing_or_over_budget_candidate_outputs_cannot_become_successful_jobs() {
    for (path, maximum, total) in [
        (b"missing".as_slice(), 128, 128),
        (b"output.txt".as_slice(), 4, 128),
        (b"output.txt".as_slice(), 128, 4),
    ] {
        let f = candidate::Fixture::new(GitHashAlgorithm::Sha256, SCRIPT);
        let prepared = f.replace_file("input.txt", "original\n", "candidate output\n");
        let config = configuration(&f.root, "artifacts", &[("a", path)], maximum, total);
        let before = candidate::generation(f.node());
        let report = execute(&f, &prepared, &config, 24).unwrap();
        assert!(!report.succeeded());
        assert_ne!(report.execution.jobs[0].outcome, JobOutcome::Succeeded);
        assert!(report.artifacts.is_empty());
        assert!(!report.run_directory.join("job-000-artifacts.json").exists());
        assert!(report.workspaces_closed);
        assert_eq!(candidate::generation(f.node()), before);
        let allowed = configuration(&f.root, "allowed", &[("a", b"output.txt")], 128, 128);
        assert!(execute(&f, &prepared, &allowed, 25).unwrap().succeeded());
    }
}

#[test]
fn invalid_candidate_or_mismatched_selection_and_cancelled_requests_start_no_attempt() {
    let f = candidate::Fixture::new(GitHashAlgorithm::Sha1, SCRIPT);
    let prepared = f.replace_file("input.txt", "original\n", "candidate output\n");
    let config = configuration(&f.root, "artifacts", &[("a", b"output.txt")], 128, 128);
    let other = Config::new(
        config.root().to_path_buf(),
        vec![Selection::new(b"other.yml", "a", b"output.txt").unwrap()],
        128,
        128,
    )
    .unwrap();
    assert!(execute(&f, &prepared, &other, 26).is_err());
    let absent_job = Config::new(
        config.root().to_path_buf(),
        vec![Selection::new(b"workflow.yml", "absent", b"output.txt").unwrap()],
        128,
        128,
    )
    .unwrap();
    assert!(execute(&f, &prepared, &absent_job, 26).is_err());
    let request = f.node().request_context();
    request.cancel();
    assert!(
        f.node()
            .runtime()
            .block_on(f.node().run_trusted_candidate_workflow_with_artifacts_in(
                &request,
                &candidate::reference(),
                (f.tip, prepared.candidate_commit),
                prepared.bundle_bytes(),
                b"workflow.yml",
                [26; 16],
                &f.parent(),
                &candidate::inputs(),
                None,
                Default::default(),
                Some(&config),
            ))
            .is_err()
    );
    let mut damaged = prepared.bundle_bytes().to_vec();
    *damaged.last_mut().unwrap() ^= 1;
    assert!(
        f.node()
            .runtime()
            .block_on(f.node().run_trusted_candidate_workflow_with_artifacts_in(
                &f.node().request_context(),
                &candidate::reference(),
                (f.tip, prepared.candidate_commit),
                &damaged,
                b"workflow.yml",
                [26; 16],
                &f.parent(),
                &candidate::inputs(),
                None,
                Default::default(),
                Some(&config),
            ))
            .is_err()
    );
    assert_eq!(fs::read_dir(f.parent()).unwrap().count(), 0);
    assert!(execute(&f, &prepared, &config, 26).unwrap().succeeded());
}
