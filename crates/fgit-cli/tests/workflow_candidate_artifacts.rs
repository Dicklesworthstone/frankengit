#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Actual fg candidate execution, artifact export and saved-result recovery.
#[path = "../../fgit-node/tests/trusted_candidate_workflow/support.rs"]
mod candidate;
#[path = "../../fgit-node/tests/trusted_merge_workflow/support.rs"]
mod merge;
use fgit_crypto::sha256_digest;
use fgit_node::TRUSTED_WORKFLOW_ARTIFACT_TRUST;
use fgit_types::GitHashAlgorithm;
use std::os::unix::fs::DirBuilderExt;
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

const WORKFLOW: &str = "name: candidate-output\non: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: cat input.txt > output.txt\n";
fn fg() -> Command {
    Command::new(env!("CARGO_BIN_EXE_fg"))
}
fn completed(output: Output, code: i32) -> String {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn field<'a>(json: &'a str, name: &str) -> &'a str {
    json.split_once(&format!("\"{name}\":\""))
        .unwrap()
        .1
        .split_once('"')
        .unwrap()
        .0
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn capture_root(root: &Path) {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(root.join("artifacts"))
        .unwrap();
}
fn candidate_command(f: &candidate::Fixture, commit: &str, run: &str, output: &str) -> Command {
    let mut command = fg();
    command
        .args(["workflow", "run-candidate"])
        .arg(f.root.join("node"))
        .args([
            candidate::TENANT.to_string(),
            candidate::REPOSITORY.to_string(),
        ])
        .arg("refs/heads/main")
        .args(["--trusted-local", "--workflow", "workflow.yml", "--run-id"])
        .arg(run.repeat(16))
        .arg("--run-parent")
        .arg(f.parent())
        .args([
            "--object-format",
            f.tip.algorithm().as_str(),
            "--expected-commit",
        ])
        .arg(f.tip.to_string())
        .args(["--candidate-commit", commit, "--bundle"])
        .arg(f.root.join("candidate.bundle"))
        .args([
            "--input",
            "workflow.yml",
            "--input",
            "input.txt",
            "--artifact-root",
        ])
        .arg(f.root.join("artifacts"))
        .arg("--artifact")
        .arg(format!("workflow.yml:a:{output}"));
    command
}
fn retrieve(
    root: &Path,
    tenant: &str,
    repository: &str,
    incarnation: &str,
    report: &str,
) -> String {
    let artifact = field(report, "artifact_id_sha256");
    let manifest = field(report, "manifest_id_sha256");
    assert_eq!(artifact.len(), 64);
    for (id, filename) in [(artifact, "payload"), (manifest, "provenance")] {
        let output = fg()
            .args(["artifact", "export"])
            .arg(root.join("artifacts"))
            .args([
                tenant,
                repository,
                incarnation,
                "--trusted-local",
                "--trust-domain",
                TRUSTED_WORKFLOW_ARTIFACT_TRUST,
                "--id",
                id,
                "--output",
            ])
            .arg(root.join("runs").join(filename))
            .output()
            .unwrap();
        let exported = completed(output, 0);
        assert!(exported.contains(id));
    }
    let provenance = fs::read_to_string(root.join("runs/provenance")).unwrap();
    assert!(provenance.contains("\"input_kind\":\"unpublished_candidate\""));
    assert!(provenance.contains("\"cache_reuse_authorized\":false"));
    assert!(provenance.contains("\"check_receipt_id\":null"));
    provenance
}

#[test]
fn cli_candidate_capture_exports_and_recovers_offline_without_replaying_or_publishing() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = candidate::Fixture::new(format, WORKFLOW);
        let prepared = f.replace_file("input.txt", "original\n", "retained candidate\n");
        fs::write(f.root.join("candidate.bundle"), prepared.bundle_bytes()).unwrap();
        capture_root(&f.root);
        let incarnation = f.node().repository_incarnation_id().to_string();
        let generation = candidate::generation(f.node());
        f.node.take().unwrap().shutdown().unwrap();
        let report = completed(
            candidate_command(
                &f,
                &prepared.candidate_commit.to_string(),
                "61",
                "output.txt",
            )
            .output()
            .unwrap(),
            0,
        );
        assert!(report.contains("\"node_closed\":true"));
        assert!(report.contains("\"authoritative_check\":false"));
        assert_eq!(
            field(&report, "executed_commit"),
            prepared.candidate_commit.to_string()
        );
        assert_eq!(field(&report, "source_commit"), f.tip.to_string());
        let directory = f.parent().join(format!("workflow-{}", "61".repeat(16)));
        let saved = fs::read_to_string(directory.join("report.json")).unwrap();
        assert!(report.contains(&saved));
        assert!(!directory.join("job-000").exists());
        let marker = hex(&sha256_digest(
            &fs::read(directory.join("attempt.json")).unwrap(),
        ));
        fs::rename(f.root.join("source"), f.root.join("source-offline")).unwrap();
        fs::rename(
            f.root.join("candidate.bundle"),
            f.root.join("bundle-offline"),
        )
        .unwrap();
        let provenance = retrieve(
            &f.root,
            &candidate::TENANT.to_string(),
            &candidate::REPOSITORY.to_string(),
            &incarnation,
            &report,
        );
        assert_eq!(
            fs::read(f.parent().join("payload")).unwrap(),
            b"retained candidate\n"
        );
        assert!(provenance.contains(&prepared.candidate_commit.to_string()));
        assert!(provenance.contains(&marker));
        let journal_before = fs::read(directory.join("check-proposals.journal")).unwrap();
        let recovered = completed(
            fg().args(["workflow", "recover"])
                .arg(&directory)
                .args([
                    candidate::TENANT.to_string(),
                    candidate::REPOSITORY.to_string(),
                ])
                .args(["--journal-id", &marker])
                .output()
                .unwrap(),
            0,
        );
        assert!(recovered.contains("\"execution_completion\":\"not_asserted\""));
        assert_eq!(
            fs::read(directory.join("check-proposals.journal")).unwrap(),
            journal_before
        );
        assert_eq!(
            fs::read_to_string(directory.join("report.json")).unwrap(),
            saved
        );
        fs::rename(
            f.root.join("bundle-offline"),
            f.root.join("candidate.bundle"),
        )
        .unwrap();
        let replay = candidate_command(
            &f,
            &prepared.candidate_commit.to_string(),
            "61",
            "output.txt",
        )
        .output()
        .unwrap();
        assert!(completed(replay, 2).is_empty());
        f.reopen();
        assert_eq!(candidate::generation(f.node()), generation);
        assert!(f.node().read_git_object(prepared.candidate_commit).is_err());
        assert_eq!(
            f.node()
                .runtime()
                .block_on(f.node().materialize_admission())
                .unwrap()
                .snapshot()
                .refs[&candidate::reference()],
            f.tip
        );
    }
}

#[test]
fn cli_merge_candidate_capture_exports_the_actual_two_parent_output() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let workflow =
            merge::WORKFLOW.replace("printf temporary > job-only", "cat left right > job-only");
        let mut f = merge::Fixture::new(format, &workflow);
        let (coordinates, bundle) = f.prepared();
        fs::write(f.root.join("merge.bundle"), &bundle).unwrap();
        capture_root(&f.root);
        let incarnation = f.node().repository_incarnation_id().to_string();
        let generation = merge::generation(f.node());
        f.node.take().unwrap().shutdown().unwrap();
        let report = completed(
            fg().args(["workflow", "run-merge-candidate"])
                .arg(f.root.join("node"))
                .args([merge::TENANT.to_string(), merge::REPOSITORY.to_string()])
                .arg("refs/heads/main")
                .args([
                    "--trusted-local",
                    "--source-ref",
                    "refs/heads/topic",
                    "--expected-source",
                ])
                .arg(f.source.to_string())
                .arg("--expected-commit")
                .arg(f.target.to_string())
                .arg("--merge-base")
                .arg(f.base.to_string())
                .arg("--candidate-commit")
                .arg(coordinates.merge_commit.to_string())
                .arg("--bundle")
                .arg(f.root.join("merge.bundle"))
                .args([
                    "--workflow",
                    "workflow.yml",
                    "--input",
                    "workflow.yml",
                    "--input",
                    "left",
                    "--input",
                    "right",
                    "--object-format",
                    format.as_str(),
                    "--run-id",
                    &"62".repeat(16),
                    "--run-parent",
                ])
                .arg(f.parent())
                .arg("--artifact-root")
                .arg(f.root.join("artifacts"))
                .args([
                    "--artifact-hex",
                    &format!("{}:a:{}", hex(b"workflow.yml"), hex(b"job-only")),
                ])
                .output()
                .unwrap(),
            0,
        );
        assert!(report.contains("\"node_closed\":true"));
        assert_eq!(
            field(&report, "executed_commit"),
            coordinates.merge_commit.to_string()
        );
        let provenance = retrieve(
            &f.root,
            &merge::TENANT.to_string(),
            &merge::REPOSITORY.to_string(),
            &incarnation,
            &report,
        );
        assert_eq!(
            fs::read(f.parent().join("payload")).unwrap(),
            b"target\nsource\n"
        );
        assert!(provenance.contains(&format!("\"parents\":[\"{}\",\"{}\"]", f.target, f.source)));
        f.reopen();
        assert_eq!(merge::generation(f.node()), generation);
        assert!(f.node().read_git_object(coordinates.merge_commit).is_err());
    }
}

#[test]
fn cli_missing_artifact_is_a_non_green_completed_run_with_a_permitted_output_twin() {
    let mut f = candidate::Fixture::new(GitHashAlgorithm::Sha256, WORKFLOW);
    let prepared = f.replace_file("input.txt", "original\n", "candidate\n");
    fs::write(f.root.join("candidate.bundle"), prepared.bundle_bytes()).unwrap();
    capture_root(&f.root);
    let generation = candidate::generation(f.node());
    f.node.take().unwrap().shutdown().unwrap();
    let failed = completed(
        candidate_command(
            &f,
            &prepared.candidate_commit.to_string(),
            "63",
            "missing.txt",
        )
        .output()
        .unwrap(),
        1,
    );
    assert!(failed.contains("\"node_closed\":true"));
    assert!(failed.contains("\"succeeded\":false"));
    assert!(failed.contains("\"artifacts\":[]"));
    let permitted = completed(
        candidate_command(
            &f,
            &prepared.candidate_commit.to_string(),
            "64",
            "output.txt",
        )
        .output()
        .unwrap(),
        0,
    );
    assert!(permitted.contains("\"succeeded\":true"));
    assert!(permitted.contains("artifact_id_sha256"));
    f.reopen();
    assert_eq!(candidate::generation(f.node()), generation);
    assert!(f.node().read_git_object(prepared.candidate_commit).is_err());
}
