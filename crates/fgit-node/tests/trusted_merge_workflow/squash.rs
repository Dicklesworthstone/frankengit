use super::*;
use fgit_forge::event::NativeMerge;
use fgit_forge::preparation::{
    MergeCommitStyle as Style, MergeMetadata, MergePreparation, MergeProfile,
};
use fgit_node::{
    TRUSTED_WORKFLOW_ARTIFACT_TRUST, TrustedWorkflowArtifactConfig as Config,
    TrustedWorkflowArtifactInput as Input, TrustedWorkflowArtifactSelection as Selection,
    TrustedWorkflowRun,
};
use fgit_object_fabric::artifact::storage::{ArtifactOperation, ArtifactScope, LocalArtifactStore};
use std::os::unix::fs::DirBuilderExt;

fn execute(
    f: &Fixture,
    merge: &NativeMerge,
    bundle: &[u8],
    id: u8,
    style: Style,
    artifacts: Option<&Config>,
) -> Result<TrustedWorkflowRun, fgit_node::TrustedWorkflowFailure> {
    let n = f.node();
    n.runtime()
        .block_on(n.run_trusted_merge_workflow_with_options_in(
            &n.command_request_context(None),
            merge,
            bundle,
            b"workflow.yml",
            [id; 16],
            &f.parent(),
            &inputs(),
            None,
            Default::default(),
            artifacts,
            style,
        ))
}
fn prepared(f: &Fixture) -> (NativeMerge, Vec<u8>) {
    let n = f.node();
    let p = n
        .runtime()
        .block_on(n.prepare_merge_bundle_with_options_in(
            &n.command_request_context(None),
            &target_ref(),
            &source_ref(),
            &Default::default(),
            &MergeMetadata {
                author: "Test <t@example.invalid>".into(),
                committer: "Test <t@example.invalid>".into(),
                timestamp: 9,
                message: b"checked squash\n".to_vec(),
            },
            Default::default(),
            MergeProfile::PathMergeV1,
            Style::Squash,
        ))
        .unwrap();
    let MergePreparation::Clean(plan) = p.outcome else {
        panic!("clean squash")
    };
    assert_eq!(plan.style, Style::Squash);
    (f.coordinates(plan.commit), p.bundle.unwrap())
}

#[test]
fn squash_candidate_executes_actual_merged_tree() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, WORKFLOW);
        let before = generation(f.node());
        let (merge, bundle) = prepared(&f);
        let mut run = execute(&f, &merge, &bundle, 31, Style::Squash, None).unwrap();
        assert!(run.succeeded(), "{}", run.to_json());
        assert_eq!(run.merge_style, Style::Squash);
        assert_eq!(run.merge.as_ref(), Some(&merge));
        assert_eq!(run.executed_commit(), merge.merge_commit);
        assert_eq!(run.source_commit, f.target);
        assert_eq!(run.candidate.unwrap().bundle_sha256, sha256_digest(&bundle));
        assert_eq!(run.execution.jobs[0].steps[0].observation.stdout, b"merged");
        assert_eq!(run.execution.jobs[1].steps[0].observation.stdout, b"fresh");
        let saved = run.to_json();
        for text in [
            &saved,
            &fs::read_to_string(run.run_directory.join("attempt.json")).unwrap(),
        ] {
            assert!(text.contains("\"method\":\"squash\""));
            assert!(text.contains(&format!("\"parents\":[\"{}\"]", f.target)));
            assert!(text.contains(&format!("\"source_tip\":\"{}\"", f.source)));
            assert!(text.contains(&format!("\"merge_base\":\"{}\"", f.base)));
            assert!(text.contains("\"authoritative_check\":false"));
        }
        assert_eq!(
            fs::read_to_string(run.run_directory.join("report.json")).unwrap(),
            saved
        );
        assert_eq!(generation(f.node()), before);
        assert!(f.node().read_git_object(merge.merge_commit).is_err());
        f.reopen();
        run.merge_style = Style::TwoParent;
        assert!(run.open_check_journal(None, &|| true).is_err());
        run.merge_style = Style::Squash;
        drop(run.open_check_journal(None, &|| true).unwrap());
        assert!(execute(&f, &merge, &bundle, 31, Style::Squash, None).is_err());
        assert_eq!(generation(f.node()), before);
        assert_eq!(
            fs::read_to_string(run.run_directory.join("report.json")).unwrap(),
            saved
        );
    }
}

#[test]
fn squash_runs_reviewed_candidate_scripts_not_parent_scripts() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(
            format,
            "name: wrong\non: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: exit 7\n",
        );
        let before = generation(f.node());
        let (merge, bundle) = f.custom(WORKFLOW, &[f.target]);
        let run = execute(&f, &merge, &bundle, 32, Style::Squash, None).unwrap();
        assert!(run.succeeded());
        assert_ne!(run.workflow_blob, f.workflow);
        assert_eq!(
            run.workflow_blob,
            git_object_id(format, GitObjectKind::Blob, WORKFLOW.as_bytes())
        );
        assert!(f.node().read_git_object(run.workflow_blob).is_err());
        assert_eq!(generation(f.node()), before);
    }
}

#[test]
fn explicit_squash_keeps_ancestry_prerequisites_and_source_freshness_gates() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format, WORKFLOW);
        let before = generation(f.node());
        let (merge, bundle) = prepared(&f);
        let refused = |m: &NativeMerge, b: &[u8], style: Style| {
            assert!(execute(&f, m, b, 33, style, None).is_err());
            assert_eq!(fs::read_dir(f.parent()).unwrap().count(), 0);
            assert_eq!(generation(f.node()), before);
            assert!(f.node().read_git_object(m.merge_commit).is_err());
        };
        refused(&merge, &bundle, Style::TwoParent);
        let mut wrong = merge.clone();
        wrong.source_tip = f.target;
        refused(&wrong, &bundle, Style::Squash);
        let mut wrong = merge.clone();
        wrong.target_tip_before = f.base;
        refused(&wrong, &bundle, Style::Squash);
        let mut wrong = merge.clone();
        wrong.base_tip = f.source;
        refused(&wrong, &bundle, Style::Squash);
        let mut wrong = merge.clone();
        wrong.source_ref = RefName::try_new(b"refs/heads/missing").unwrap();
        refused(&wrong, &bundle, Style::Squash);
        let mut corrupt = bundle.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        refused(&merge, &corrupt, Style::Squash);
        let mut missing = bundle.clone();
        let prefix = format!("-{} ", f.source).into_bytes();
        let at = missing
            .windows(prefix.len())
            .position(|s| s == prefix)
            .unwrap();
        let len = missing[at..].iter().position(|b| *b == b'\n').unwrap() + 1;
        missing.drain(at..at + len);
        refused(&merge, &missing, Style::Squash);
        for parents in [
            vec![f.source],
            vec![f.target, f.source],
            vec![f.target, f.source, f.base],
        ] {
            let (m, b) = f.custom(WORKFLOW, &parents);
            refused(&m, &b, Style::Squash);
        }
        let n = f.node();
        assert!(
            n.runtime()
                .block_on(n.run_trusted_merge_workflow_with_options_in(
                    &n.command_request_context(None),
                    &merge,
                    &bundle,
                    b"workflow.yml",
                    [33; 16],
                    &f.parent(),
                    &inputs(),
                    Some(f.genesis),
                    Default::default(),
                    None,
                    Style::Squash
                ))
                .is_err()
        );
        assert_eq!(fs::read_dir(f.parent()).unwrap().count(), 0);
        assert!(
            execute(&f, &merge, &bundle, 33, Style::Squash, None)
                .unwrap()
                .succeeded()
        );
        let (ordinary, bytes) = f.prepared();
        let twin = execute(&f, &ordinary, &bytes, 34, Style::TwoParent, None).unwrap();
        assert!(twin.succeeded());
        assert!(!twin.to_json().contains("\"method\":"));
        assert_eq!(generation(n), before);
    }
}

#[test]
fn squash_artifacts_keep_single_parent_provenance_and_same_run_delivery_after_reopen() {
    let workflow = "name: squash-artifacts\non: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: cat left right > result.bin; chmod +x result.bin\n  b:\n    runs-on: fgit-trusted-local\n    needs: a\n    steps:\n      - run: test ! -e result.bin; test -x .fgit-artifacts/input; cat left right > expected; cmp expected .fgit-artifacts/input; printf delivered\n";
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, workflow);
        let before = generation(f.node());
        let root = f.root.join("artifacts");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let config = Config::new(
            root,
            vec![Selection::new(b"workflow.yml", "a", b"result.bin").unwrap()],
            1024,
            4096,
        )
        .unwrap()
        .with_inputs(
            vec![Input::new(b"workflow.yml", "b", "a", b"result.bin", b"input").unwrap()],
            4096,
        )
        .unwrap();
        let (merge, bundle) = prepared(&f);
        let run = execute(&f, &merge, &bundle, 35, Style::Squash, Some(&config)).unwrap();
        assert!(run.succeeded(), "{}", run.to_json());
        assert!(run.workspaces_closed);
        assert_eq!(run.artifacts.len(), 1);
        assert_eq!(run.artifact_inputs.len(), 1);
        assert_eq!(
            run.artifact_inputs[0].inputs[0].output.artifact_id,
            run.artifacts[0].outputs[0].artifact_id
        );
        assert_eq!(
            run.execution.jobs[1].steps[0].observation.stdout,
            b"delivered"
        );
        for i in 0..2 {
            assert!(!run.run_directory.join(format!("job-{i:03}")).exists());
        }
        f.reopen();
        let store = LocalArtifactStore::open(
            config.root(),
            ArtifactScope::new(
                run.tenant,
                run.repository,
                run.incarnation,
                TRUSTED_WORKFLOW_ARTIFACT_TRUST,
            )
            .unwrap(),
        )
        .unwrap();
        let live = || true;
        let op = ArtifactOperation::new(1024 * 1024, Duration::from_secs(30), &live).unwrap();
        let payload = f.parent().join("exported");
        store
            .export(&run.artifacts[0].outputs[0].artifact_id, &payload, &op)
            .unwrap();
        assert_eq!(fs::read(payload).unwrap(), b"target\nsource\n");
        let manifest = f.parent().join("provenance");
        store
            .export(&run.artifacts[0].manifest_id, &manifest, &op)
            .unwrap();
        let text = fs::read_to_string(manifest).unwrap();
        assert!(text.contains("\"method\":\"squash\""));
        assert!(text.contains(&format!("\"parents\":[\"{}\"]", f.target)));
        assert!(text.contains(&format!("\"executed_commit\":\"{}\"", merge.merge_commit)));
        assert!(text.contains("\"cache_reuse_authorized\":false"));
        drop(run.open_check_journal(None, &|| true).unwrap());
        assert_eq!(generation(f.node()), before);
    }
}

#[test]
fn cancelled_squash_preflight_never_claims_an_attempt_or_starts_code() {
    let f = Fixture::new(GitHashAlgorithm::Sha256, WORKFLOW);
    let (merge, bundle) = prepared(&f);
    let n = f.node();
    let request = n.command_request_context(None);
    request.cancel();
    assert!(
        n.runtime()
            .block_on(n.run_trusted_merge_workflow_with_options_in(
                &request,
                &merge,
                &bundle,
                b"workflow.yml",
                [36; 16],
                &f.parent(),
                &inputs(),
                None,
                Default::default(),
                None,
                Style::Squash
            ))
            .is_err()
    );
    assert_eq!(fs::read_dir(f.parent()).unwrap().count(), 0);
    assert!(
        execute(&f, &merge, &bundle, 36, Style::Squash, None)
            .unwrap()
            .succeeded()
    );
}

#[test]
fn squash_timeout_keeps_an_occupied_nonpassing_attempt_after_restart() {
    let f = Fixture::new(GitHashAlgorithm::Sha1, WORKFLOW);
    let script = "name: stopped\non: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: exec sleep 30\n";
    let (merge, bundle) = f.custom(script, &[f.target]);
    let n = f.node();
    let run = n
        .runtime()
        .block_on(n.run_trusted_merge_workflow_with_options_in(
            &n.command_request_context(None),
            &merge,
            &bundle,
            b"workflow.yml",
            [37; 16],
            &f.parent(),
            &inputs(),
            None,
            WorkflowLimits {
                step_timeout: Duration::from_millis(100),
                run_timeout: Duration::from_secs(5),
                ..Default::default()
            },
            None,
            Style::Squash,
        ))
        .unwrap();
    assert!(!run.succeeded());
    assert!(run.to_json().contains("\"method\":\"squash\""));
    let mut f = f;
    f.reopen();
    assert!(execute(&f, &merge, &bundle, 37, Style::Squash, None).is_err());
}
