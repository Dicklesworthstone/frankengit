//! Pure identity/contract tests use fabricated coordinates; actual repository,
//! storage and child-process execution is covered by tests/trusted_workflow.
use super::*;
use fgit_types::{CANONICAL_CODEC_VERSION, GitOidSha1};

fn selection(job: &str, output: &[u8]) -> TrustedWorkflowArtifactSelection {
    TrustedWorkflowArtifactSelection::new(b"workflow.yml", job, output).unwrap()
}
fn config(
    root: &str,
    selections: Vec<TrustedWorkflowArtifactSelection>,
) -> TrustedWorkflowArtifactConfig {
    TrustedWorkflowArtifactConfig::new(
        root.into(),
        selections,
        DEFAULT_ARTIFACT_BYTES,
        DEFAULT_ARTIFACT_TOTAL_BYTES,
    )
    .unwrap()
}
fn report() -> TrustedWorkflowRun {
    let plan = WorkflowPlan::compile(
        "name: output\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf result > out\n",
    ).unwrap();
    let bytes = DigestBytes::try_new(&[9; 32]).unwrap();
    TrustedWorkflowRun {
        tenant: TenantId::from_bytes([1; 16]),
        repository: RepositoryId::from_bytes([2; 16]),
        incarnation: RepositoryIncarnationId::from_bytes([3; 16]),
        source_head: RepositoryAuthorityHeadId::from_digest(
            DigestAlgorithm::Sha256.id(),
            CANONICAL_CODEC_VERSION,
            bytes,
        ),
        source_rcr: RepositoryCommitId::from_digest(
            DigestAlgorithm::Sha256.id(),
            CANONICAL_CODEC_VERSION,
            bytes,
        ),
        source_commit: GitOid::Sha1(GitOidSha1::from_bytes([4; 20])),
        source_tree: GitOid::Sha1(GitOidSha1::from_bytes([5; 20])),
        source_reference: b"refs/heads/main".to_vec(),
        candidate: None,
        merge: None,
        merge_style: Default::default(),
        workflow_blob: GitOid::Sha1(GitOidSha1::from_bytes([6; 20])),
        workflow_path: b"workflow.yml".to_vec(),
        read_prefixes: vec![b"workflow.yml".to_vec()],
        run_id: [7; 16],
        run_directory: "/operator/workflow-run".into(),
        workspaces_closed: false,
        request_interrupted: false,
        artifact_contract: None,
        artifacts: Vec::new(),
        artifact_inputs: Vec::new(),
        execution: WorkflowReport {
            source: plan.source_commitment(),
            graph: plan.graph_commitment(),
            limits: WorkflowLimits::default(),
            jobs: Vec::new(),
        },
    }
}

#[test]
fn artifact_selection_is_exact_bounded_and_cannot_name_the_ownership_marker() {
    let raw =
        TrustedWorkflowArtifactSelection::new(b"ci/\xff.yml", "build__matrix_007", b"out/\xfe")
            .unwrap();
    assert_eq!(raw.workflow_path(), b"ci/\xff.yml");
    assert_eq!(raw.output_path(), b"out/\xfe");
    for path in [
        b"../out".as_slice(),
        b"/out",
        b"out/../secret",
        b".fgit-host-receipt",
        b"out\0",
    ] {
        assert!(TrustedWorkflowArtifactSelection::new(b"workflow.yml", "build", path).is_err());
    }
    for job in ["", "bad job", "job:other"] {
        assert!(TrustedWorkflowArtifactSelection::new(b"workflow.yml", job, b"out").is_err());
    }
    let selected = selection("build", b"out");
    for (root, count, per_file, total) in [
        ("relative", 1, 16, 32),
        ("/operator/store", 0, 16, 32),
        ("/operator/store", 65, 16, 32),
        ("/operator/store", 1, 0, 32),
        ("/operator/store", 1, MAX_ARTIFACT_BYTES + 1, 32),
        ("/operator/store", 1, 16, MAX_ARTIFACT_TOTAL_BYTES + 1),
    ] {
        assert!(
            TrustedWorkflowArtifactConfig::new(
                root.into(),
                vec![selected.clone(); count],
                per_file,
                total
            )
            .is_err()
        );
    }
    assert!(
        TrustedWorkflowArtifactConfig::new(
            "/operator/store".into(),
            vec![selected.clone(), selected],
            16,
            32
        )
        .is_err()
    );
}

#[test]
fn absent_capture_retains_marker_bytes_and_contract_root_limits_and_paths_bind_recovery_identity() {
    let mut run = report();
    let original = run.attempt_marker();
    assert!(!original.contains("\"artifact_contract\""));
    assert!(!run.to_json().contains("\"artifacts\""));
    run.artifact_contract = Some(config("/operator/store", vec![selection("build", b"out")]));
    let enabled = run.attempt_marker();
    assert_ne!(original, enabled);
    assert!(run.to_json().contains("\"artifacts\":[]"));
    assert_eq!(enabled, run.attempt_marker());
    for changed in [
        config("/operator/other-store", vec![selection("build", b"out")]),
        config("/operator/store", vec![selection("build", b"other")]),
        TrustedWorkflowArtifactConfig::new(
            "/operator/store".into(),
            vec![selection("build", b"out")],
            DEFAULT_ARTIFACT_BYTES / 2,
            DEFAULT_ARTIFACT_TOTAL_BYTES,
        )
        .unwrap(),
        TrustedWorkflowArtifactConfig::new(
            "/operator/store".into(),
            vec![selection("build", b"out")],
            DEFAULT_ARTIFACT_BYTES,
            DEFAULT_ARTIFACT_TOTAL_BYTES / 2,
        )
        .unwrap(),
    ] {
        run.artifact_contract = Some(changed);
        assert_ne!(enabled, run.attempt_marker());
    }
    run.artifact_contract = None;
    assert_eq!(original, run.attempt_marker());
}

#[test]
fn selector_order_is_canonical_and_unknown_jobs_refuse_the_entire_preflight() {
    let first = selection("build", b"a");
    let second = selection("build", b"b");
    assert_eq!(
        config("/operator/store", vec![first.clone(), second.clone()]),
        config("/operator/store", vec![second, first]),
    );
    let plan = WorkflowPlan::compile(
        "name: jobs\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf done\n",
    ).unwrap();
    assert!(
        config("/operator/store", vec![selection("build", b"out")])
            .validate_workflow(b"workflow.yml", &plan)
            .is_ok()
    );
    assert!(
        config("/operator/store", vec![selection("missing", b"out")])
            .validate_workflow(b"workflow.yml", &plan)
            .is_err()
    );
}

#[test]
fn staging_cancellation_keeps_exact_cleanup_responsibility_and_never_finishes_a_receipt() {
    let name = format!(
        "fgit-artifact-stage-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let directory = std::env::temp_dir().join(name);
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let mut stages = Vec::new();
    assert!(stage_bytes(&directory, "never-created", b"x", &mut stages, &|| false).is_err());
    assert!(stages.is_empty());
    assert!(!directory.join("never-created").exists());
    let calls = Cell::new(0usize);
    let live = || {
        calls.set(calls.get() + 1);
        calls.get() < 3
    };
    let payload = vec![0xa5; 128 * 1024];
    assert!(stage_bytes(&directory, "partial.pending", &payload, &mut stages, &live).is_err());
    assert_eq!(calls.get(), 3);
    assert_eq!(stages, [directory.join("partial.pending")]);
    assert_eq!(fs::metadata(&stages[0]).unwrap().len(), 64 * 1024);
    // The caller's non-cancellable close owns the acquired stage even after stop.
    remove_stage(&mut stages).unwrap();
    assert!(stages.is_empty());
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
    fs::remove_dir(directory).unwrap();
}

fn input(
    consumer: &str,
    producer: &str,
    output: &[u8],
    destination: &[u8],
) -> TrustedWorkflowArtifactInput {
    TrustedWorkflowArtifactInput::new(b"workflow.yml", consumer, producer, output, destination)
        .unwrap()
}

#[test]
fn input_contract_requires_exact_capture_safe_destinations_and_bounded_delivery() {
    let capture = config("/operator/store", vec![selection("build", b"out")]);
    let selected = input("test", "build", b"out", b"bin/tool");
    assert!(
        capture
            .clone()
            .with_inputs(vec![selected.clone()], 4)
            .is_ok()
    );
    for total in [0, MAX_ARTIFACT_TOTAL_BYTES + 1] {
        assert!(
            capture
                .clone()
                .with_inputs(vec![selected.clone()], total)
                .is_err()
        );
    }
    assert!(capture.clone().with_inputs(Vec::new(), 4).is_err());
    assert!(
        capture
            .clone()
            .with_inputs(vec![selected.clone(); 65], 4)
            .is_err()
    );
    assert!(
        capture
            .clone()
            .with_inputs(vec![input("test", "build", b"other", b"bin/tool")], 4)
            .is_err()
    );
    assert!(
        capture
            .clone()
            .with_inputs(vec![input("test", "other", b"out", b"bin/tool")], 4)
            .is_err()
    );
    for path in [
        b"/outside".as_slice(),
        b"../outside",
        b"bin/../../outside",
        b".fgit-host-receipt",
        b"out\0",
    ] {
        assert!(
            TrustedWorkflowArtifactInput::new(b"workflow.yml", "test", "build", b"out", path)
                .is_err()
        );
    }
    assert!(
        TrustedWorkflowArtifactInput::new(b"workflow.yml", "build", "build", b"out", b"bin/tool")
            .is_err()
    );
    assert!(
        TrustedWorkflowArtifactInput::new(
            b"workflow.yml",
            "test",
            "build",
            b"out",
            &vec![b'x'; 4001]
        )
        .is_err()
    );
    for destination in [b"bin".as_slice(), b"bin/tool", b"bin/tool/child"] {
        assert!(
            capture
                .clone()
                .with_inputs(
                    vec![
                        selected.clone(),
                        input("test", "build", b"out", destination)
                    ],
                    4,
                )
                .is_err()
        );
    }
    let enabled = capture
        .with_inputs(
            vec![
                selected.clone(),
                input("package", "build", b"out", b"bin/tool"),
            ],
            8,
        )
        .unwrap();
    assert!(enabled.with_inputs(vec![selected], 4).is_err());
}

#[test]
fn input_contract_is_canonical_and_binds_attempt_destinations_and_delivery_limit() {
    let capture = config("/operator/store", vec![selection("build", b"out")]);
    let mut run = report();
    run.artifact_contract = Some(capture.clone());
    let original = run.attempt_marker();
    assert!(!original.contains("\"input_delivery\""));
    assert!(!run.to_json().contains("\"artifact_inputs\""));
    let first = input("test", "build", b"out", b"bin/tool");
    let second = input("package", "build", b"out", b"bin/tool");
    let forward = capture
        .clone()
        .with_inputs(vec![first.clone(), second.clone()], 8)
        .unwrap();
    let reverse = capture
        .clone()
        .with_inputs(vec![second, first.clone()], 8)
        .unwrap();
    assert_eq!(forward, reverse);
    run.artifact_contract = Some(forward);
    let enabled = run.attempt_marker();
    assert_ne!(original, enabled);
    assert!(run.to_json().contains("\"artifact_inputs\":[]"));
    for changed in [
        capture.clone().with_inputs(vec![first], 4).unwrap(),
        capture
            .clone()
            .with_inputs(vec![input("test", "build", b"out", b"different")], 8)
            .unwrap(),
    ] {
        run.artifact_contract = Some(changed);
        assert_ne!(enabled, run.attempt_marker());
    }
    run.artifact_contract = Some(capture);
    assert_eq!(run.attempt_marker(), original);
}

#[test]
fn artifact_inputs_require_present_consumers_and_direct_not_transitive_dependencies() {
    let plan = WorkflowPlan::compile(
        "name: dependencies\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf build\n  test:\n    runs-on: fgit-trusted-local\n    needs: build\n    steps:\n      - run: printf test\n  package:\n    runs-on: fgit-trusted-local\n    needs: test\n    steps:\n      - run: printf package\n",
    ).unwrap();
    let capture = config("/operator/store", vec![selection("build", b"out")]);
    for (consumer, allowed) in [("test", true), ("package", false), ("absent", false)] {
        let contract = capture
            .clone()
            .with_inputs(vec![input(consumer, "build", b"out", b"tool")], 4)
            .unwrap();
        assert_eq!(
            contract.validate_workflow(b"workflow.yml", &plan).is_ok(),
            allowed
        );
    }
}

#[test]
fn combined_source_and_input_headroom_cannot_be_replenished_by_child_preflight() {
    // Budget semantics use fabricated scope coordinates and a real empty store;
    // this test creates neither payload custody nor an execution observation.
    let directory = std::env::temp_dir().join(format!(
        "fgit-input-budget-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();

    let coordinates = report();
    let contract = config(
        directory.to_str().unwrap(),
        vec![selection("build", b"out")],
    )
    .with_inputs(
        vec![input("test", "build", b"out", b"input")],
        MAX_ARTIFACT_TOTAL_BYTES,
    )
    .unwrap();

    let session = || Session {
        config: &contract,
        store: LocalArtifactStore::open(
            &directory,
            ArtifactScope::new(
                coordinates.tenant,
                coordinates.repository,
                coordinates.incarnation,
                TRUSTED_WORKFLOW_ARTIFACT_TRUST,
            )
            .unwrap(),
        )
        .unwrap(),
        remaining: Cell::new(contract.total_bytes),
        input_remaining: Cell::new(contract.input_total_bytes),
        input_materialization_remaining: Cell::new(MAX_REPLICATED_BYTES),
        input_entry_remaining: Cell::new(MAX_REPLICATED_ENTRIES),
    };

    let first = session();
    first.restrict_input_materialization(MAX_REPLICATED_BYTES - 4, MAX_REPLICATED_ENTRIES - 2);
    first.charge_input(3).unwrap();

    // A child's smaller source selection cannot reset the batch's remaining
    // capacity. Rejected delivery also cannot partially charge another counter.
    first.restrict_input_materialization(1, 1);
    let before = (
        first.input_remaining.get(),
        first.input_materialization_remaining.get(),
        first.input_entry_remaining.get(),
    );
    assert!(
        first
            .charge_input(2)
            .unwrap_err()
            .contains("materialization limit")
    );
    assert_eq!(
        before,
        (
            first.input_remaining.get(),
            first.input_materialization_remaining.get(),
            first.input_entry_remaining.get(),
        )
    );
    first.charge_input(1).unwrap();
    assert_eq!(first.input_materialization_remaining.get(), 0);
    assert!(
        first
            .charge_input(1)
            .unwrap_err()
            .contains("materialization limit")
    );

    // Empty payloads still consume manifest-entry capacity.
    let second = session();
    second.restrict_input_materialization(1, MAX_REPLICATED_ENTRIES - 1);
    second.charge_input(0).unwrap();
    second.restrict_input_materialization(1, 1);
    assert!(second.charge_input(0).unwrap_err().contains("entry limit"));
    assert_eq!(second.input_remaining.get(), MAX_ARTIFACT_TOTAL_BYTES);

    drop((first, second));
    fs::remove_dir(&directory).unwrap();
}
