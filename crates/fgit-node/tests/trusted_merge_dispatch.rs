#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Actual candidate validation, shared dispatch, fresh processes and custody.
#[path = "trusted_merge_workflow/support.rs"]
mod support;
use fgit_crypto::{GitObjectKind, git_object_id, sha256_digest};
use fgit_forge::{event::NativeMerge, preparation::MergeCommitStyle};
use fgit_node::{TrustedWorkflowArtifactConfig, TrustedWorkflowArtifactSelection};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, PackLimits, PackPlanner, PackWriteError,
    PackWriteProfile, PackWriter,
};
use fgit_runner::workflow::WorkflowLimits;
use fgit_types::{GitHashAlgorithm, GitOid};
use std::{collections::BTreeMap, fs};
use support::*;

struct Objects(BTreeMap<GitOid, (GitObjectKind, Vec<u8>)>);
impl Objects {
    fn put(&mut self, format: GitHashAlgorithm, kind: GitObjectKind, bytes: Vec<u8>) -> GitOid {
        let id = git_object_id(format, kind, &bytes);
        self.0.insert(id, (kind, bytes));
        id
    }
}
impl CanonicalObjectSource for Objects {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        let (kind, bytes) = self
            .0
            .get(id)
            .ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        Ok(CanonicalPackObject::new(
            *id,
            *kind,
            bytes.clone(),
            Vec::new(),
            0,
            0,
        ))
    }
}
fn candidate(
    f: &Fixture,
    style: MergeCommitStyle,
    definitions: &[(&str, String)],
) -> (NativeMerge, Vec<u8>) {
    let format = f.target.algorithm();
    let mut objects = Objects(BTreeMap::new());
    let left = objects.put(format, GitObjectKind::Blob, b"target\n".to_vec());
    let right = objects.put(format, GitObjectKind::Blob, b"source\n".to_vec());
    let mut names = definitions.iter().collect::<Vec<_>>();
    names.sort_by_key(|(name, _)| *name);
    let mut ci = Vec::new();
    for (name, workflow) in names {
        let blob = objects.put(format, GitObjectKind::Blob, workflow.as_bytes().to_vec());
        ci.extend_from_slice(format!("100644 {name}\0").as_bytes());
        ci.extend_from_slice(blob.as_bytes());
    }
    let ci = objects.put(format, GitObjectKind::Tree, ci);
    let tree = objects.put(
        format,
        GitObjectKind::Tree,
        [
            b"40000 ci\0".as_slice(),
            ci.as_bytes(),
            b"100644 left\0",
            left.as_bytes(),
            b"100644 right\0",
            right.as_bytes(),
            b"100644 workflow.yml\0",
            f.workflow.as_bytes(),
        ]
        .concat(),
    );
    let parents = if style == MergeCommitStyle::Squash {
        vec![f.target]
    } else {
        vec![f.target, f.source]
    };
    let commit = objects.put(
        format,
        GitObjectKind::Commit,
        commit_bytes(tree, &parents, "reviewed candidate workflows"),
    );
    let limits = PackLimits::default();
    let ids = objects.0.keys().copied().collect::<Vec<_>>();
    let plan = PackPlanner::new(
        format,
        PackWriteProfile::COMPRESSED_NO_DELTA_V1,
        limits.clone(),
    )
    .plan_selected(&objects, &ids, &mut || true)
    .unwrap();
    let (pack, _) = PackWriter::new(limits).write(&plan, &mut || true).unwrap();
    let mut bundle = if format == GitHashAlgorithm::Sha1 {
        b"# v2 git bundle\n".to_vec()
    } else {
        b"# v3 git bundle\n@object-format=sha256\n".to_vec()
    };
    bundle.extend_from_slice(
        format!(
            "-{} target\n-{} source\n{commit} refs/heads/main\n\n",
            f.target, f.source
        )
        .as_bytes(),
    );
    bundle.extend_from_slice(&pack);
    (f.coordinates(commit), bundle)
}
fn workflow(trigger: &str, command: &str) -> String {
    format!(
        "name: batch\non:\n{trigger}\njobs:\n  check:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: {command}\n"
    )
}
fn inputs() -> Vec<Vec<u8>> {
    vec![b"ci".to_vec(), b"left".to_vec(), b"right".to_vec()]
}
const PR: &str = "  pull_request: ''";
const CHECK: &str = "test \"$(cat left)\" = target && test \"$(cat right)\" = source && test ! -e dirty; printf checked; printf x > dirty";

#[test]
fn every_workflow_reads_the_same_actual_merge_and_filters_use_canonical_incoming_changes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for style in [MergeCommitStyle::TwoParent, MergeCommitStyle::Squash] {
            let mut f = Fixture::new(format, WORKFLOW);
            let before = generation(f.node());
            let definitions = [
                (
                    "a.yml",
                    workflow(
                        "  pull_request:\n    branches:\n      - main\n    paths:\n      - right",
                        CHECK,
                    ),
                ),
                (
                    "b.yml",
                    workflow("  pull_request:\n    paths-ignore:\n      - left", CHECK),
                ),
                (
                    "excluded.yml",
                    workflow("  pull_request:\n    branches:\n      - topic", "exit 92"),
                ),
                (
                    "target-only.yml",
                    workflow("  pull_request:\n    paths:\n      - left", "exit 93"),
                ),
            ];
            let (merge, bundle) = candidate(&f, style, &definitions);
            let report = f
                .node()
                .runtime()
                .block_on(f.node().dispatch_trusted_merge_workflows_in(
                    &f.node().request_context(),
                    &merge,
                    &bundle,
                    style,
                    b"ci",
                    "pull_request",
                    [41; 16],
                    &f.parent(),
                    &inputs(),
                    None,
                    Default::default(),
                    None,
                ))
                .unwrap();
            assert!(report.succeeded(), "{}", report.to_json());
            assert_eq!(report.runs().len(), 2);
            for run in report.runs() {
                assert_eq!(run.executed_commit(), merge.merge_commit);
                assert_eq!(run.source_commit, f.target);
                assert_eq!(run.merge.as_ref(), Some(&merge));
                assert_eq!(run.merge_style, style);
                assert_eq!(run.candidate.unwrap().bundle_sha256, sha256_digest(&bundle));
                assert_eq!(
                    run.execution.jobs[0].steps[0].observation.stdout,
                    b"checked"
                );
                assert_eq!(
                    fs::read_to_string(run.run_directory.join("report.json")).unwrap(),
                    run.to_json()
                );
            }
            let saved = report.to_json();
            assert_eq!(
                fs::read_to_string(report.run_directory.join("report.json")).unwrap(),
                saved
            );
            assert!(saved.contains(&format!("\"executed_commit\":\"{}\"", merge.merge_commit)));
            assert!(saved.contains(&format!("\"after\":\"{}\"", f.source)));
            assert!(saved.contains("\"matched_count\":2"));
            assert_eq!(generation(f.node()), before);
            assert!(f.node().read_git_object(merge.merge_commit).is_err());
            f.reopen();
            assert!(
                f.node()
                    .runtime()
                    .block_on(f.node().dispatch_trusted_merge_workflows_in(
                        &f.node().request_context(),
                        &merge,
                        &bundle,
                        style,
                        b"ci",
                        "pull_request",
                        [41; 16],
                        &f.parent(),
                        &inputs(),
                        None,
                        Default::default(),
                        None
                    ))
                    .is_err()
            );
            assert_eq!(
                fs::read_to_string(report.run_directory.join("report.json")).unwrap(),
                saved
            );
            assert_eq!(generation(f.node()), before);
        }
    }
}

#[test]
fn stale_branches_corruption_wrong_style_and_late_invalid_definition_never_reserve() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format, WORKFLOW);
        let before = generation(f.node());
        let (merge, bundle) = candidate(
            &f,
            MergeCommitStyle::TwoParent,
            &[("a.yml", workflow(PR, CHECK))],
        );
        let refuse = |merge: &NativeMerge, bundle: &[u8], style, event, head| {
            assert!(
                f.node()
                    .runtime()
                    .block_on(f.node().dispatch_trusted_merge_workflows_in(
                        &f.node().request_context(),
                        merge,
                        bundle,
                        style,
                        b"ci",
                        event,
                        [42; 16],
                        &f.parent(),
                        &inputs(),
                        head,
                        Default::default(),
                        None
                    ))
                    .is_err()
            );
            assert_eq!(fs::read_dir(f.parent()).unwrap().count(), 0);
            assert_eq!(generation(f.node()), before);
        };
        let mut bad = merge.clone();
        bad.source_tip = f.target;
        refuse(
            &bad,
            &bundle,
            MergeCommitStyle::TwoParent,
            "pull_request",
            None,
        );
        refuse(
            &merge,
            &bundle,
            MergeCommitStyle::Squash,
            "pull_request",
            None,
        );
        refuse(&merge, &bundle, MergeCommitStyle::TwoParent, "push", None);
        refuse(
            &merge,
            &bundle,
            MergeCommitStyle::TwoParent,
            "pull_request",
            Some(f.genesis),
        );
        let mut corrupt = bundle.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        refuse(
            &merge,
            &corrupt,
            MergeCommitStyle::TwoParent,
            "pull_request",
            None,
        );
        let (bad, bytes) = candidate(
            &f,
            MergeCommitStyle::TwoParent,
            &[
                ("a.yml", workflow(PR, CHECK)),
                ("z.yml", "unsupported: yes\n".into()),
            ],
        );
        refuse(
            &bad,
            &bytes,
            MergeCommitStyle::TwoParent,
            "pull_request",
            None,
        );
        let report = f
            .node()
            .runtime()
            .block_on(f.node().dispatch_trusted_merge_workflows_in(
                &f.node().request_context(),
                &merge,
                &bundle,
                MergeCommitStyle::TwoParent,
                b"ci",
                "pull_request",
                [42; 16],
                &f.parent(),
                &inputs(),
                None,
                Default::default(),
                None,
            ))
            .unwrap();
        assert!(report.succeeded());
    }
}

#[test]
fn failure_does_not_hide_independent_results_but_output_budget_stops_later_work() {
    let f = Fixture::new(GitHashAlgorithm::Sha1, WORKFLOW);
    let (merge, bundle) = candidate(
        &f,
        MergeCommitStyle::TwoParent,
        &[
            ("a.yml", workflow(PR, "printf no; exit 7")),
            ("b.yml", workflow(PR, "printf yes")),
        ],
    );
    let report = f
        .node()
        .runtime()
        .block_on(f.node().dispatch_trusted_merge_workflows_in(
            &f.node().request_context(),
            &merge,
            &bundle,
            MergeCommitStyle::TwoParent,
            b"ci",
            "pull_request",
            [43; 16],
            &f.parent(),
            &inputs(),
            None,
            Default::default(),
            None,
        ))
        .unwrap();
    assert!(!report.succeeded());
    assert_eq!(report.runs().len(), 2);
    assert!(report.runs()[1].succeeded());
    let limits = WorkflowLimits {
        total_output_bytes: 2,
        ..Default::default()
    };
    let report = f
        .node()
        .runtime()
        .block_on(f.node().dispatch_trusted_merge_workflows_in(
            &f.node().request_context(),
            &merge,
            &bundle,
            MergeCommitStyle::TwoParent,
            b"ci",
            "pull_request",
            [44; 16],
            &f.parent(),
            &inputs(),
            None,
            limits,
            None,
        ))
        .unwrap();
    assert!(!report.succeeded());
    assert_eq!(report.runs().len(), 1);
}

#[test]
fn excluded_artifact_contract_refuses_and_manual_dispatch_never_borrows_pr_filters() {
    let f = Fixture::new(GitHashAlgorithm::Sha256, WORKFLOW);
    let (merge, bundle) = candidate(
        &f,
        MergeCommitStyle::Squash,
        &[(
            "a.yml",
            workflow(
                "  pull_request:\n    branches:\n      - not-main",
                "printf nope",
            ),
        )],
    );
    let root = f.parent();
    let config = TrustedWorkflowArtifactConfig::new(
        root.clone(),
        vec![TrustedWorkflowArtifactSelection::new(b"ci/a.yml", "check", b"output").unwrap()],
        1024,
        1024,
    )
    .unwrap();
    assert!(
        f.node()
            .runtime()
            .block_on(f.node().dispatch_trusted_merge_workflows_in(
                &f.node().request_context(),
                &merge,
                &bundle,
                MergeCommitStyle::Squash,
                b"ci",
                "pull_request",
                [45; 16],
                &f.parent(),
                &inputs(),
                None,
                Default::default(),
                Some(&config)
            ))
            .is_err()
    );
    assert_eq!(fs::read_dir(f.parent()).unwrap().count(), 0);
    let report = f
        .node()
        .runtime()
        .block_on(f.node().dispatch_trusted_merge_workflows_in(
            &f.node().request_context(),
            &merge,
            &bundle,
            MergeCommitStyle::Squash,
            b"ci",
            "workflow_dispatch",
            [45; 16],
            &f.parent(),
            &inputs(),
            None,
            Default::default(),
            None,
        ))
        .unwrap();
    assert!(report.runs().is_empty());
    assert!(report.to_json().contains("\"matched_count\":0"));
}

#[test]
fn artifact_capture_allowance_is_shared_by_candidate_workflows_with_exact_provenance() {
    let f = Fixture::new(GitHashAlgorithm::Sha256, WORKFLOW);
    let definitions = [
        ("a.yml", workflow(PR, "printf 12345678 > output")),
        ("b.yml", workflow(PR, "printf 12345678 > output")),
    ];
    let (merge, bundle) = candidate(&f, MergeCommitStyle::TwoParent, &definitions);
    let artifact_root = f.root.join("artifacts");
    fs::create_dir(&artifact_root).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&artifact_root, fs::Permissions::from_mode(0o700)).unwrap();
    let selections = || {
        vec![
            TrustedWorkflowArtifactSelection::new(b"ci/a.yml", "check", b"output").unwrap(),
            TrustedWorkflowArtifactSelection::new(b"ci/b.yml", "check", b"output").unwrap(),
        ]
    };
    for (id, total, success) in [(46, 8, false), (47, 16, true)] {
        let config =
            TrustedWorkflowArtifactConfig::new(artifact_root.clone(), selections(), 8, total)
                .unwrap();
        let report = f
            .node()
            .runtime()
            .block_on(f.node().dispatch_trusted_merge_workflows_in(
                &f.node().request_context(),
                &merge,
                &bundle,
                MergeCommitStyle::TwoParent,
                b"ci",
                "pull_request",
                [id; 16],
                &f.parent(),
                &inputs(),
                None,
                Default::default(),
                Some(&config),
            ))
            .unwrap();
        assert_eq!(report.succeeded(), success, "{}", report.to_json());
        assert_eq!(report.runs().len(), 2);
        assert!(report.runs()[0].succeeded());
        assert_eq!(report.runs()[1].succeeded(), success);
        for run in report.runs() {
            assert_eq!(run.executed_commit(), merge.merge_commit);
        }
    }
}
