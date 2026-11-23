#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Actual two-commit rebase execution, retained evidence and protected PR merge.
#[path = "trusted_rebase_workflow/support.rs"]
mod support;
use support::*;

use fgit_crypto::{
    GitHashAlgorithm as Hash, GitObjectKind, Sha1, Sha256, git_object_id, sha256_digest,
};
use fgit_forge::event::NativeMerge;
use fgit_forge::event::workflow_check::WorkflowCheckConclusion;
use fgit_node::{
    TRUSTED_WORKFLOW_ARTIFACT_TRUST, TrustedWorkflowArtifactConfig,
    TrustedWorkflowArtifactSelection, TrustedWorkflowRun,
};
use fgit_object_fabric::artifact::storage::{ArtifactOperation, ArtifactScope, LocalArtifactStore};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, PackLimits, PackPlanner, PackWriteError,
    PackWriteProfile, PackWriter,
};
use fgit_treefs::{SparseLimits, TreeCapability, TreePath, WorkspaceId};
use fgit_types::{ByteCount, DecisionOutcome, GitHashAlgorithm, GitOid, RefusalCode};
use fgit_wire::visibility::RefVisibility;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

fn refs(case: &Case) -> BTreeMap<fgit_types::RefName, GitOid> {
    case.node()
        .runtime()
        .block_on(case.node().materialize_admission())
        .unwrap()
        .snapshot()
        .refs
        .clone()
}
fn unplaced(case: &Case) {
    for step in &case.plan.steps {
        assert!(case.node().read_git_object(step.rewritten).is_err());
    }
    assert_eq!(
        fs::read_dir(case.node().storage_root().join("staging"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn complete_rebase_executes_final_tree_and_retains_actual_parent_artifacts_and_journal() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut case = Case::new(format);
        let before = generation(case.node());
        let original_refs = refs(&case);
        for (nonce, reference, tip) in [
            (1, source_ref(), case.f.source),
            (2, target_ref(), case.f.target),
        ] {
            let run = case
                .node()
                .runtime()
                .block_on(case.node().run_trusted_workflow_in(
                    &case.node().request_context(),
                    &reference,
                    b"workflow.yml",
                    [nonce; 16],
                    &case.f.parent(),
                    &inputs(),
                    (None, Some(tip)),
                    Default::default(),
                ))
                .unwrap();
            assert!(
                !run.succeeded(),
                "neither original branch contains the combined result"
            );
        }
        let root = case.f.root.join("artifacts");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let artifacts = TrustedWorkflowArtifactConfig::new(
            root.clone(),
            vec![TrustedWorkflowArtifactSelection::new(b"workflow.yml", "a", b"job-only").unwrap()],
            4096,
            16384,
        )
        .unwrap();
        let mut run = case
            .execute(3, Default::default(), Some(&artifacts))
            .unwrap();
        assert!(run.succeeded(), "{}", run.to_json());
        assert!(run.workspaces_closed);
        assert!(run.merge.is_none());
        let rebase = run.rebase.as_ref().unwrap();
        assert_eq!(rebase.merge, case.merge);
        assert_eq!(rebase.parent, case.plan.steps[0].rewritten);
        assert_ne!(rebase.parent, case.f.target);
        assert_eq!(run.source_commit, case.f.target);
        assert_eq!(run.executed_commit(), case.binding.commit);
        assert_eq!(
            run.candidate.unwrap().bundle_sha256,
            sha256_digest(&case.bundle)
        );
        assert_eq!(run.execution.jobs[0].steps[0].observation.stdout, b"merged");
        assert_eq!(run.execution.jobs[1].steps[0].observation.stdout, b"fresh");
        let report = run.to_json();
        let marker = fs::read_to_string(run.run_directory.join("attempt.json")).unwrap();
        for text in [&report, &marker] {
            assert!(text.contains("\"rebase\":{\"method\":\"rebase\""));
            assert!(text.contains(&format!(
                "\"parents\":[\"{}\"]",
                case.plan.steps[0].rewritten
            )));
            assert!(text.contains(&format!("\"source_tip\":\"{}\"", case.f.source)));
            assert!(text.contains("\"authoritative_check\":false"));
        }
        assert_eq!(generation(case.node()), before);
        assert_eq!(refs(&case), original_refs);
        unplaced(&case);
        let record = case.record(&run);
        assert_eq!(record.check.conclusion, WorkflowCheckConclusion::Success);
        case.f.reopen();
        let parent = run.rebase.as_ref().unwrap().parent;
        run.rebase.as_mut().unwrap().parent = case.f.target;
        assert!(run.open_check_journal(None, &|| true).is_err());
        run.rebase.as_mut().unwrap().parent = parent;
        drop(run.open_check_journal(None, &|| true).unwrap());
        assert!(
            case.execute(3, Default::default(), Some(&artifacts))
                .is_err()
        );
        assert_eq!(
            fs::read_to_string(run.run_directory.join("report.json")).unwrap(),
            report
        );
        fs::remove_file(run.run_directory.join("report.json")).unwrap();
        assert_eq!(
            case.record(&run),
            record,
            "retained jobs do not depend on the final report"
        );
        let store = LocalArtifactStore::open(
            &root,
            ArtifactScope::new(
                TENANT,
                REPOSITORY,
                case.node().repository_incarnation_id(),
                TRUSTED_WORKFLOW_ARTIFACT_TRUST,
            )
            .unwrap(),
        )
        .unwrap();
        let live = || true;
        let op = ArtifactOperation::new(64 * 1024, Duration::from_secs(30), &live).unwrap();
        let payload = case.f.parent().join("exported-output");
        store
            .export(&run.artifacts[0].outputs[0].artifact_id, &payload, &op)
            .unwrap();
        assert_eq!(fs::read(payload).unwrap(), b"temporary");
        let provenance = case.f.parent().join("exported-provenance");
        store
            .export(&run.artifacts[0].manifest_id, &provenance, &op)
            .unwrap();
        let text = fs::read_to_string(provenance).unwrap();
        assert!(text.contains("\"rebase\":{\"method\":\"rebase\""));
        assert!(text.contains("\"cache_reuse_authorized\":false"));
        assert_eq!(generation(case.node()), before);
        unplaced(&case);
    }
}

#[test]
fn actual_rebase_checks_unlock_protected_merge_and_recover_without_reexecuting_or_bundle_access() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut case = Case::new(format);
        let original_refs = refs(&case);
        let run = case.execute(4, Default::default(), None).unwrap();
        assert!(run.succeeded(), "{}", run.to_json());
        let original = case.record(&run);
        case.protect(&original);
        let check = case.record(&run);
        case.approve();
        let missing = case.merge(b"rebase-missing-check", &case.bundle).unwrap();
        assert!(matches!(
            missing.1.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::ProtectedRefTransitionDenied,
                ..
            }
        ));
        let generic = case
            .node()
            .runtime()
            .block_on(case.node().admit_trusted_candidate_workflow_check_in(
                &case.node().request_context(),
                &session(OWNER, b"wrong-single-commit-profile"),
                &check,
                &case.bundle,
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(generic.1.outcome, DecisionOutcome::Refused { .. }));
        assert_eq!(
            case.publish(&check, b"wrong-single-commit-profile", b"")
                .unwrap(),
            generic,
            "changing validation cannot replace an original canonical refusal"
        );
        let stale = case
            .publish(&original, b"old-policy-rebase-check", &case.bundle)
            .unwrap();
        assert!(matches!(
            stale.1.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::EvidenceStale,
                ..
            }
        ));
        let green = committed(case.publish(&check, b"rebase-green", &case.bundle).unwrap());
        assert_eq!(refs(&case), original_refs);
        unplaced(&case);

        let failed_run = case
            .execute(
                5,
                fgit_runner::workflow::WorkflowLimits {
                    stream_bytes: 2,
                    total_output_bytes: 2,
                    ..Default::default()
                },
                None,
            )
            .unwrap();
        assert!(!failed_run.succeeded());
        let failed = case.record(&failed_run);
        assert_eq!(failed.check.conclusion, WorkflowCheckConclusion::Failure);
        committed(
            case.publish(&failed, b"newer-failed-rebase-check", &case.bundle)
                .unwrap(),
        );
        let blocked = case
            .merge(b"latest-rebase-check-failed", &case.bundle)
            .unwrap();
        assert!(matches!(
            blocked.1.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::ProtectedRefTransitionDenied,
                ..
            }
        ));
        assert_eq!(case.publish(&check, b"rebase-green", b"").unwrap(), green);
        let rerun = case.execute(6, Default::default(), None).unwrap();
        assert!(rerun.succeeded(), "{}", rerun.to_json());
        let latest = case.record(&rerun);
        committed(
            case.publish(&latest, b"latest-green-rebase-check", &case.bundle)
                .unwrap(),
        );
        let before = generation(case.node());
        let landed = committed(
            case.merge(b"land-exact-checked-rebase", &case.bundle)
                .unwrap(),
        );
        assert_eq!(generation(case.node()), before + 1);
        let final_refs = refs(&case);
        assert_eq!(final_refs.len(), 2);
        assert_eq!(final_refs[&target_ref()], case.binding.commit);
        assert_eq!(final_refs[&source_ref()], case.f.source);
        let attempts = fs::read_dir(case.f.parent()).unwrap().count();
        case.f.reopen();
        let before_retry = generation(case.node());
        assert_eq!(case.publish(&check, b"rebase-green", b"").unwrap(), green);
        assert_eq!(
            case.merge(b"land-exact-checked-rebase", b"").unwrap(),
            landed
        );
        assert_eq!(case.merge(b"rebase-missing-check", b"").unwrap(), missing);
        assert_eq!(generation(case.node()), before_retry);
        assert_eq!(fs::read_dir(case.f.parent()).unwrap().count(), attempts);
        let mut altered = check.clone();
        altered.bundle_sha256[0] ^= 1;
        assert!(case.publish(&altered, b"rebase-green", b"").is_err());
    }
}

struct Objects(BTreeMap<GitOid, (GitObjectKind, Vec<u8>)>);
impl CanonicalObjectSource for Objects {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        let (kind, body) = self
            .0
            .get(id)
            .ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        Ok(CanonicalPackObject::new(
            *id,
            *kind,
            body.clone(),
            Vec::new(),
            0,
            0,
        ))
    }
}
fn series_bundle(
    case: &Case,
    omit_intermediate_blob: bool,
    nonlinear: bool,
) -> (NativeMerge, Vec<u8>) {
    let format = case.f.target.algorithm();
    let mut objects = Objects(
        case.plan
            .objects
            .iter()
            .map(|object| (object.id, (object.kind, object.body.clone())))
            .collect(),
    );
    for body in [b"intermediate\n".as_slice(), b"source\n"] {
        let id = git_object_id(format, GitObjectKind::Blob, body);
        objects.0.insert(id, (GitObjectKind::Blob, body.to_vec()));
    }
    if omit_intermediate_blob {
        objects.0.remove(&git_object_id(
            format,
            GitObjectKind::Blob,
            b"intermediate\n",
        ));
    }
    let mut merge = case.merge.clone();
    if nonlinear {
        let (_, old) = objects.0.remove(&merge.merge_commit).unwrap();
        let at = old
            .windows(8)
            .position(|part| part == b"\nauthor ")
            .unwrap();
        let mut body = old[..at].to_vec();
        body.extend(format!("\nparent {}", case.f.target).as_bytes());
        body.extend(&old[at..]);
        merge.merge_commit = git_object_id(format, GitObjectKind::Commit, &body);
        objects
            .0
            .insert(merge.merge_commit, (GitObjectKind::Commit, body));
    }
    let limits = PackLimits::default();
    let plan = PackPlanner::new(
        format,
        PackWriteProfile::COMPRESSED_NO_DELTA_V1,
        limits.clone(),
    )
    .plan_selected(
        &objects,
        &objects.0.keys().copied().collect::<Vec<_>>(),
        &mut || true,
    )
    .unwrap();
    let (pack, _) = PackWriter::new(limits).write(&plan, &mut || true).unwrap();
    let mut bytes = match format {
        GitHashAlgorithm::Sha1 => b"# v2 git bundle\n".to_vec(),
        GitHashAlgorithm::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".to_vec(),
    };
    bytes.extend(
        format!(
            "-{} target\n{} refs/heads/main\n\n",
            case.f.target, merge.merge_commit
        )
        .as_bytes(),
    );
    bytes.extend(pack);
    (merge, bytes)
}
fn select<A: Hash>(
    case: &Case,
    merge: &NativeMerge,
    bundle: &[u8],
    visibility: &RefVisibility,
) -> bool {
    let mut capability = TreeCapability::new(
        WorkspaceId::from_bytes([9; 16]),
        REPOSITORY,
        inputs()
            .iter()
            .map(|path| TreePath::parse_default(path).unwrap())
            .collect(),
        Vec::new(),
    )
    .with_fetch_budget(ByteCount::try_new("test", 64 * 1024 * 1024, 64 * 1024 * 1024).unwrap())
    .with_file_budget(1000);
    case.node()
        .runtime()
        .block_on(case.node().sparse_rebase_candidate_manifest_in::<A>(
            &case.node().request_context(),
            merge,
            bundle,
            visibility,
            None,
            &mut capability,
            0,
            SparseLimits {
                max_entries: 10_000,
                max_entry_bytes: 16 * 1024 * 1024,
                max_payload_bytes: 64 * 1024 * 1024,
            },
        ))
        .is_ok()
}
fn preflight<A: Hash>(format: GitHashAlgorithm) {
    let case = Case::new(format);
    let before = generation(case.node());
    let (valid, bundle) = series_bundle(&case, false, false);
    assert!(select::<A>(&case, &valid, &bundle, &RefVisibility::new()));
    for (omit, nonlinear) in [(true, false), (false, true)] {
        let (merge, bad) = series_bundle(&case, omit, nonlinear);
        assert!(!select::<A>(&case, &merge, &bad, &RefVisibility::new()));
    }
    for reference in [source_ref(), target_ref()] {
        let mut visibility = RefVisibility::new();
        visibility
            .push_rule(reference.as_bytes(), &Default::default())
            .unwrap();
        assert!(!select::<A>(&case, &valid, &bundle, &visibility));
    }
    for field in 0..3 {
        let mut stale = case.merge.clone();
        match field {
            0 => stale.source_tip = case.f.base,
            1 => stale.target_tip_before = case.f.base,
            _ => stale.base_tip = case.f.source,
        }
        assert!(!select::<A>(
            &case,
            &stale,
            &case.bundle,
            &RefVisibility::new()
        ));
    }
    let mut corrupt = case.bundle.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(!select::<A>(
        &case,
        &case.merge,
        &corrupt,
        &RefVisibility::new()
    ));
    let node = case.node();
    let request = node.request_context();
    request.cancel();
    assert!(
        node.runtime()
            .block_on(node.run_trusted_rebase_workflow_in(
                &request,
                &case.merge,
                &case.bundle,
                b"workflow.yml",
                [9; 16],
                &case.f.parent(),
                &inputs(),
                None,
                Default::default(),
                None,
            ))
            .is_err()
    );
    assert!(
        node.runtime()
            .block_on(node.run_trusted_merge_workflow_in(
                &node.request_context(),
                &case.merge,
                &case.bundle,
                b"workflow.yml",
                [9; 16],
                &case.f.parent(),
                &inputs(),
                None,
                Default::default(),
            ))
            .is_err()
    );
    assert_eq!(fs::read_dir(case.f.parent()).unwrap().count(), 0);
    assert_eq!(generation(node), before);
    unplaced(&case);
    let run: TrustedWorkflowRun = case.execute(9, Default::default(), None).unwrap();
    assert!(run.succeeded(), "{}", run.to_json());
}
#[test]
fn sha1_rebase_preflight_preserves_whole_series_original_scope_and_no_execution_on_refusal() {
    preflight::<Sha1>(GitHashAlgorithm::Sha1);
}
#[test]
fn sha256_rebase_preflight_preserves_whole_series_original_scope_and_no_execution_on_refusal() {
    preflight::<Sha256>(GitHashAlgorithm::Sha256);
}
