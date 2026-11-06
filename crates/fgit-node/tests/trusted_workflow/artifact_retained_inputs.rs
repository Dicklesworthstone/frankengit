//! Persisted custody crosses real executions without treating an old result as
//! a fresh check. All selected consumers execute against new private copies.
use super::*;
use fgit_crypto::{DigestAlgorithm, sha256_digest};
use fgit_node::{
    TrustedWorkflowArtifactInput as Input, TrustedWorkflowRetainedArtifactInput as Retained,
};
use fgit_object_fabric::artifact::{
    ArtifactIdentity, ArtifactPayloadKind, MediaType, RetentionProfile,
};
use fgit_types::{Digest, DigestBytes};

const PIPELINE: &str = r#"name: retained pipeline
on: push
jobs:
  a:
    runs-on: fgit-trusted-local
    steps:
      - run: if test -f .fgit-artifacts/data; then test -x .fgit-artifacts/data; printf 'payload\000bytes\377' > expected; cmp expected .fgit-artifacts/data; cp .fgit-artifacts/data derived.bin; printf changed > .fgit-artifacts/data; printf consumed-a; else printf 'payload\000bytes\377' > out.bin; chmod +x out.bin; printf produced; fi
  b:
    runs-on: fgit-trusted-local
    needs: a
    steps:
      - run: if test -f .fgit-artifacts/data; then printf 'payload\000bytes\377' > expected; cmp expected .fgit-artifacts/data; printf consumed-b; fi
  c:
    runs-on: fgit-trusted-local
    needs: a
    steps:
      - run: if test -f .fgit-artifacts/fresh; then printf 'payload\000bytes\377' > expected; cmp expected .fgit-artifacts/fresh; printf consumed-c; fi
"#;

fn retained(
    producer: &TrustedWorkflowRun,
    workflow: &[u8],
    consumer: &str,
    destination: &[u8],
) -> Retained {
    let original = &producer.artifacts[0];
    Retained::new(
        workflow,
        consumer,
        original.manifest_id,
        original.outputs[0].artifact_id,
        &original.outputs[0].path,
        destination,
    )
    .unwrap()
}
fn consume(config: &Config, inputs: Vec<Retained>, total: usize) -> Config {
    Config::new_with_retained_inputs(
        config.root().to_owned(),
        Vec::new(),
        1024,
        4096,
        false,
        inputs,
        total,
    )
    .unwrap()
}
fn no_stages(run: &TrustedWorkflowRun) {
    assert!(run.workspaces_closed);
    assert!(!fs::read_dir(&run.run_directory).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".job-")
    }));
}
fn assert_refused_before_execution(run: &TrustedWorkflowRun) {
    assert!(!run.succeeded(), "{}", run.to_json());
    assert_eq!(
        run.execution.jobs[0].outcome,
        JobOutcome::Refused,
        "{}",
        run.to_json()
    );
    assert!(run.execution.jobs[0].steps.is_empty());
    assert!(run.artifact_inputs.is_empty());
    no_stages(run);
}
fn container(store: &LocalArtifactStore, root: &Path, id: Digest) -> PathBuf {
    root.join(format!(
        "scope-{}",
        hex(store.scope().commitment().bytes().as_bytes())
    ))
    .join(hex(id.bytes().as_bytes()))
}

#[test]
fn retained_outputs_reopen_and_feed_real_jobs_with_original_lineage_and_private_copies() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, PIPELINE);
        let capture = config(&f, b"out.bin", 1024, 4096);
        let original = execute(&f, &capture, 0x71);
        assert!(original.succeeded(), "{}", original.to_json());
        assert_eq!(
            original.execution.jobs[0].steps[0].observation.stdout,
            b"produced"
        );
        let before = generation(f.node());
        no_stages(&original);
        f.reopen();
        fs::remove_dir_all(&original.run_directory).unwrap();
        let retained = vec![
            retained(&original, b"workflow.yml", "a", b"data"),
            retained(&original, b"workflow.yml", "b", b"data"),
        ];
        let contract = Config::new_with_retained_inputs(
            capture.root().to_owned(),
            vec![Selection::new(b"workflow.yml", "a", b"derived.bin").unwrap()],
            1024,
            4096,
            false,
            retained.clone(),
            4096,
        )
        .unwrap()
        .with_inputs(
            vec![Input::new(b"workflow.yml", "c", "a", b"derived.bin", b"fresh").unwrap()],
            4096,
        )
        .unwrap();
        let received = execute(&f, &contract, 0x72);
        assert!(received.succeeded(), "{}", received.to_json());
        for (job, expected) in received.execution.jobs.iter().zip([
            b"consumed-a".as_slice(),
            b"consumed-b",
            b"consumed-c",
        ]) {
            assert_eq!(job.steps.len(), 1);
            assert_eq!(job.steps[0].observation.stdout, expected);
        }
        assert_eq!(received.artifact_inputs.len(), 3);
        for inputs in &received.artifact_inputs[..2] {
            let input = &inputs.inputs[0];
            assert_eq!(
                input.producer_manifest_id,
                original.artifacts[0].manifest_id
            );
            assert_eq!(
                input.output.artifact_id,
                original.artifacts[0].outputs[0].artifact_id
            );
            let provenance = input.retained_producer.as_ref().unwrap();
            assert_eq!(provenance.run_id, original.run_id);
            assert_eq!(provenance.executed_commit, original.executed_commit());
            assert_eq!(provenance.source_rcr, original.source_rcr.to_string());
            assert_eq!(provenance.workflow_path, b"workflow.yml");
            assert!(input.output.executable);
        }
        assert!(
            received.artifact_inputs[2].inputs[0]
                .retained_producer
                .is_none()
        );
        let live = || true;
        let op = ArtifactOperation::new(1024 * 1024, Duration::from_secs(30), &live).unwrap();
        let store = store(&contract, &received);
        let (_, bytes) = store
            .read_payload(&received.artifacts[0].manifest_id, &op)
            .unwrap();
        let manifest = String::from_utf8(bytes).unwrap();
        assert!(manifest.contains("\"retained_producer\":"));
        assert!(manifest.contains("\"producer_success_asserted\":false"));
        assert!(manifest.contains("\"cache_reuse_authorized\":false"));
        assert!(manifest.contains(&hex(original.artifacts[0].manifest_id.bytes().as_bytes())));
        no_stages(&received);
        assert_eq!(generation(f.node()), before);
        // Input-only consumers need no artificial new output/log capture.
        let input_only = consume(&capture, retained, 4096);
        let third = execute(&f, &input_only, 0x73);
        assert!(third.succeeded(), "{}", third.to_json());
        assert!(third.artifacts.is_empty());
        assert_eq!(third.artifact_inputs.len(), 2);
        assert!(third.to_json().contains("\"artifact_inputs\":[{"));
    }
}

#[test]
fn retained_selection_scope_and_payload_tampering_refuse_before_consumer_execution() {
    let mut f = Fixture::new(GitHashAlgorithm::Sha256, PIPELINE);
    let capture = config(&f, b"out.bin", 1024, 4096);
    let original = execute(&f, &capture, 0x74);
    assert!(original.succeeded());
    f.reopen();
    let exact = retained(&original, b"workflow.yml", "a", b"data");
    let store = store(&capture, &original);
    let live = || true;
    let op = ArtifactOperation::new(1024 * 1024, Duration::from_secs(30), &live).unwrap();
    let (manifest_identity, manifest_bytes) = store
        .read_payload(&exact.producer_manifest_id(), &op)
        .unwrap();
    for (index, bad) in [
        Retained::new(
            b"workflow.yml",
            "a",
            exact.producer_manifest_id(),
            exact.artifact_id(),
            b"absent",
            b"data",
        )
        .unwrap(),
        Retained::new(
            b"workflow.yml",
            "a",
            exact.producer_manifest_id(),
            exact.producer_manifest_id(),
            b"out.bin",
            b"data",
        )
        .unwrap(),
        Retained::new(
            b"workflow.yml",
            "a",
            exact.artifact_id(),
            exact.artifact_id(),
            b"out.bin",
            b"data",
        )
        .unwrap(),
    ]
    .into_iter()
    .enumerate()
    {
        let run = execute(&f, &consume(&capture, vec![bad], 4096), 0x80 + index as u8);
        assert_refused_before_execution(&run);
    }
    for (index, id) in [exact.producer_manifest_id(), exact.artifact_id()]
        .into_iter()
        .enumerate()
    {
        let path = container(&store, capture.root(), id);
        let saved = fs::read(&path).unwrap();
        fs::write(&path, b"poisoned payload container").unwrap();
        let run = execute(
            &f,
            &consume(&capture, vec![exact.clone()], 4096),
            0x83 + index as u8,
        );
        assert_refused_before_execution(&run);
        fs::write(path, saved).unwrap();
    }
    // Even copying a fully valid foreign-scope container under the selected
    // namespace cannot turn its immutable metadata into this repository's data.
    let foreign = LocalArtifactStore::open(
        capture.root(),
        ArtifactScope::new(
            original.tenant,
            original.repository,
            original.incarnation,
            "different-trust-domain",
        )
        .unwrap(),
    )
    .unwrap();
    foreign
        .put_reader(&manifest_identity, &mut manifest_bytes.as_slice(), &op)
        .unwrap();
    let path = container(&store, capture.root(), exact.producer_manifest_id());
    let saved = fs::read(&path).unwrap();
    fs::copy(
        container(&foreign, capture.root(), exact.producer_manifest_id()),
        &path,
    )
    .unwrap();
    let refused = execute(&f, &consume(&capture, vec![exact.clone()], 4096), 0x85);
    assert_refused_before_execution(&refused);
    fs::write(path, saved).unwrap();
    // Independently named malformed manifests still refuse after their bytes
    // pass the storage digest check; storage integrity is not semantic validity.
    let text = String::from_utf8(manifest_bytes).unwrap();
    for (index, bad) in [
        "{}".to_owned(),
        text.replace("\"object_format\":\"sha256\"", "\"object_format\":\"sha1\""),
        text.replace(
            &format!("\"repository_incarnation\":\"{}\"", original.incarnation),
            &format!("\"repository_incarnation\":\"{}\"", "00".repeat(16)),
        ),
        text.replace(
            "\"job_success_asserted\":false",
            "\"job_success_asserted\":true",
        ),
        text.replace(
            "\"output_path_hex\":\"6f75742e62696e\"",
            "\"output_path_hex\":\"6f74686572\"",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let payload = Digest::new(
            DigestAlgorithm::Sha256.id(),
            DigestBytes::try_new(&sha256_digest(bad.as_bytes())).unwrap(),
        );
        let identity = ArtifactIdentity::new(
            payload,
            bad.len() as u64,
            MediaType::parse("application/json").unwrap(),
            ArtifactPayloadKind::Provenance,
            None,
            None,
            manifest_identity.source_rcr().copied(),
            RetentionProfile::HotEphemeral { ttl_seconds: 86400 },
        );
        store
            .put_reader(&identity, &mut bad.as_bytes(), &op)
            .unwrap();
        let selected = Retained::new(
            b"workflow.yml",
            "a",
            *identity.artifact_id(),
            exact.artifact_id(),
            b"out.bin",
            b"data",
        )
        .unwrap();
        let run = execute(
            &f,
            &consume(&capture, vec![selected], 4096),
            0x86 + index as u8,
        );
        assert_refused_before_execution(&run);
    }
    let permitted = execute(&f, &consume(&capture, vec![exact], 4096), 0x8c);
    assert!(permitted.succeeded(), "{}", permitted.to_json());
    assert_eq!(
        permitted.execution.jobs[0].steps[0].observation.stdout,
        b"consumed-a"
    );
}

#[test]
fn retained_and_fresh_inputs_charge_each_copy_and_cannot_reuse_an_occupied_attempt() {
    let f = Fixture::new(GitHashAlgorithm::Sha1, PIPELINE);
    let capture = config(&f, b"out.bin", 1024, 4096);
    let original = execute(&f, &capture, 0x75);
    assert!(original.succeeded());
    let length = original.artifacts[0].outputs[0].payload_bytes;
    for (index, total) in [length * 3 - 1, length * 3].into_iter().enumerate() {
        let contract = Config::new_with_retained_inputs(
            capture.root().to_owned(),
            vec![Selection::new(b"workflow.yml", "a", b"derived.bin").unwrap()],
            1024,
            4096,
            false,
            vec![
                retained(&original, b"workflow.yml", "a", b"data"),
                retained(&original, b"workflow.yml", "b", b"data"),
            ],
            total,
        )
        .unwrap()
        .with_inputs(
            vec![Input::new(b"workflow.yml", "c", "a", b"derived.bin", b"fresh").unwrap()],
            total,
        )
        .unwrap();
        let run = execute(&f, &contract, 0x90 + index as u8);
        assert_eq!(run.execution.jobs[0].outcome, JobOutcome::Succeeded);
        assert_eq!(run.execution.jobs[1].outcome, JobOutcome::Succeeded);
        if index == 0 {
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
        } else {
            assert!(run.succeeded(), "{}", run.to_json());
        }
        no_stages(&run);
    }
    let contract = consume(
        &capture,
        vec![retained(&original, b"workflow.yml", "a", b"data")],
        length,
    );
    let request = f.node().request_context();
    request.cancel();
    let invoke = |request: &fgit_node::NodeRequestContext, contract: &Config| {
        f.node()
            .runtime()
            .block_on(f.node().run_trusted_workflow_with_artifacts_in(
                request,
                &reference(),
                b"workflow.yml",
                [0x92; 16],
                &f.parent(),
                &inputs(),
                (None, Some(f.tip)),
                WorkflowLimits::default(),
                Some(contract),
            ))
    };
    let before = fs::read_dir(f.parent()).unwrap().count();
    assert!(invoke(&request, &contract).is_err());
    assert_eq!(fs::read_dir(f.parent()).unwrap().count(), before);
    let completed = invoke(&f.node().request_context(), &contract).unwrap();
    assert!(completed.succeeded());
    let marker = fs::read(completed.run_directory.join("attempt.json")).unwrap();
    assert!(invoke(&f.node().request_context(), &contract).is_err());
    let changed = consume(
        &capture,
        vec![retained(&original, b"workflow.yml", "a", b"changed")],
        length,
    );
    assert!(invoke(&f.node().request_context(), &changed).is_err());
    assert_eq!(
        fs::read(completed.run_directory.join("attempt.json")).unwrap(),
        marker
    );
    assert_eq!(
        fs::read_to_string(completed.run_directory.join("report.json")).unwrap(),
        completed.to_json()
    );
}

#[test]
fn retained_dispatch_budget_and_selection_are_shared_across_selected_workflows() {
    let workflow = "name: retained dispatch\non: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: if test -f .fgit-artifacts/input; then test \"$(cat .fgit-artifacts/input)\" = data; printf consumed; else printf data > out.bin; fi\n";
    let mut f = Fixture::new_dispatch(GitHashAlgorithm::Sha256, workflow);
    let paths = [b"ci/a.yml".as_slice(), b"ci/b.yml".as_slice()];
    let capture = Config::new(
        private(&f, "artifacts"),
        paths
            .iter()
            .map(|path| Selection::new(path, "a", b"out.bin").unwrap())
            .collect(),
        4,
        8,
    )
    .unwrap();
    let dispatch = |f: &Fixture, contract: &Config, id| {
        f.node()
            .runtime()
            .block_on(f.node().dispatch_trusted_workflows_with_artifacts_in(
                &f.node().request_context(),
                &reference(),
                b"ci",
                "push",
                [id; 16],
                &f.parent(),
                &[b"ci".to_vec()],
                (pinned_head(f), f.tip),
                WorkflowLimits::default(),
                Some(contract),
            ))
    };
    let original = dispatch(&f, &capture, 0x76).unwrap();
    assert!(original.succeeded());
    f.reopen();
    let contract = consume(
        &capture,
        paths
            .iter()
            .map(|path| retained(&original.runs()[0], path, "a", b"input"))
            .collect(),
        6,
    );
    let run = dispatch(&f, &contract, 0x77).unwrap();
    assert_eq!(run.runs().len(), 2);
    assert!(run.runs()[0].succeeded());
    assert_refused_before_execution(&run.runs()[1]);
    let absent = consume(
        &capture,
        vec![retained(
            &original.runs()[0],
            b"ci/absent.yml",
            "a",
            b"input",
        )],
        4,
    );
    let before = fs::read_dir(f.parent()).unwrap().count();
    assert!(dispatch(&f, &absent, 0x78).is_err());
    assert_eq!(fs::read_dir(f.parent()).unwrap().count(), before);
}
