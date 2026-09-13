//! Real selected authority -> conflict decisions -> complete pack -> publication.
use super::*;
use fgit_forge::preparation::rebase::resolutions::RebaseCommitResolution;
use fgit_forge::preparation::resolution::{ConflictResolution, ResolutionChoice};

fn choices(original: GitOid) -> Vec<RebaseCommitResolution> {
    vec![RebaseCommitResolution {
        original,
        paths: vec![ConflictResolution {
            path: b"selected".to_vec(),
            choice: ResolutionChoice::File {
                mode: 0o100644,
                bytes: b"\0resolved exact bytes\xff\n".to_vec(),
            },
        }],
    }]
}

#[test]
fn resolved_rebase_is_read_only_until_the_reviewed_complete_series_is_admitted() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, f) = fixture(&scratch, format, true);
        let request = node.request_context();
        let before = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        let stopped = node
            .runtime()
            .block_on(node.prepare_rebase_bundle_in(
                &request,
                &topic_ref(),
                &main_ref(),
                rebase_inputs(&f),
                &Default::default(),
                Some(before.basis().id()),
                &committer(),
                PreparationLimits::default(),
            ))
            .unwrap();
        assert!(matches!(stopped.outcome, RebasePreparation::Stopped { .. }));
        assert!(stopped.bundle.is_none());
        let recipe = choices(f.picked);
        let (artifact, decisions) = node
            .runtime()
            .block_on(node.prepare_resolved_rebase_bundle_in(
                &request,
                &topic_ref(),
                &main_ref(),
                rebase_inputs(&f),
                &Default::default(),
                Some(before.basis().id()),
                &committer(),
                PreparationLimits::default(),
                &recipe,
            ))
            .unwrap();
        let RebasePreparation::Clean(plan) = &artifact.outcome else {
            panic!("{artifact:?}");
        };
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].original, f.picked);
        let resolved = decisions[0].paths[0].result.as_ref().unwrap().oid;
        assert_eq!(
            resolved,
            git_object_id(format, GitObjectKind::Blob, b"\0resolved exact bytes\xff\n")
        );
        assert!(
            node.read_git_object(resolved).is_err(),
            "preparation staged a resolution blob"
        );
        assert!(
            node.read_git_object(plan.commit).is_err(),
            "preparation staged a commit"
        );
        assert_eq!(
            node.runtime()
                .block_on(node.materialize_admission_in(&request))
                .unwrap()
                .basis(),
            before.basis()
        );
        let (again, repeated) = node
            .runtime()
            .block_on(node.prepare_resolved_rebase_bundle_in(
                &request,
                &topic_ref(),
                &main_ref(),
                rebase_inputs(&f),
                &Default::default(),
                Some(before.basis().id()),
                &committer(),
                PreparationLimits::default(),
                &recipe,
            ))
            .unwrap();
        assert_eq!(again.bundle, artifact.bundle);
        assert_eq!(repeated, decisions);
        let candidate = plan.commit;
        let bundle = artifact.bundle.unwrap();
        let applied = node
            .runtime()
            .block_on(node.apply_rebase_bundle_durable_in(
                &request,
                principal(),
                b"resolved-rebase",
                &topic_ref(),
                f.source,
                f.target,
                candidate,
                &bundle,
            ))
            .unwrap();
        assert!(matches!(
            applied.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let after = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        assert_eq!(after.snapshot().refs[&topic_ref()], candidate);
        assert_eq!(after.snapshot().refs[&main_ref()], f.target);
        assert_eq!(after.snapshot().outbox, before.snapshot().outbox);
        assert_eq!(
            after.basis().body().forge_position_root,
            before.basis().body().forge_position_root
        );
        assert_eq!(
            node.read_git_object(resolved).unwrap().payload(),
            b"\0resolved exact bytes\xff\n"
        );
        node.shutdown().unwrap();
        let reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        let retry = reopened
            .runtime()
            .block_on(reopened.apply_rebase_bundle_durable_in(
                &reopened.request_context(),
                principal(),
                b"resolved-rebase",
                &topic_ref(),
                f.source,
                f.target,
                candidate,
                &bundle,
            ))
            .unwrap();
        assert_eq!(retry, applied);
        assert_eq!(
            reopened
                .runtime()
                .block_on(reopened.materialize_admission_in(&reopened.request_context()))
                .unwrap()
                .basis(),
            after.basis()
        );
        reopened.shutdown().unwrap();
    }
}

#[test]
fn resolution_intake_cannot_bypass_current_visibility_exact_tips_or_cancellation() {
    let scratch = Scratch::new();
    let (node, f) = fixture(&scratch, GitHashAlgorithm::Sha256, true);
    let request = node.request_context();
    let before = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    let mut hidden = RefVisibility::default();
    hidden
        .push_rule(topic_ref().as_bytes(), &Default::default())
        .unwrap();
    let recipe = choices(f.picked);
    assert!(matches!(
        node.runtime()
            .block_on(node.prepare_resolved_rebase_bundle_in(
                &request,
                &topic_ref(),
                &main_ref(),
                rebase_inputs(&f),
                &hidden,
                None,
                &committer(),
                PreparationLimits::default(),
                &recipe
            )),
        Err(RebasePreparationRefusal::RefUnavailable)
    ));
    let mut stale = rebase_inputs(&f);
    stale.source_tip = f.picked;
    assert!(matches!(
        node.runtime()
            .block_on(node.prepare_resolved_rebase_bundle_in(
                &request,
                &topic_ref(),
                &main_ref(),
                stale,
                &Default::default(),
                None,
                &committer(),
                PreparationLimits::default(),
                &recipe
            )),
        Err(RebasePreparationRefusal::TipMoved)
    ));
    assert!(matches!(
        node.runtime()
            .block_on(node.prepare_resolved_rebase_bundle_in(
                &request,
                &topic_ref(),
                &main_ref(),
                rebase_inputs(&f),
                &Default::default(),
                None,
                &committer(),
                PreparationLimits::default(),
                &choices(f.base)
            )),
        Err(RebasePreparationRefusal::Preparation(_))
    ));
    let cancelled = node.request_context();
    cancelled.authority().cancel();
    assert!(
        node.runtime()
            .block_on(node.prepare_resolved_rebase_bundle_in(
                &cancelled,
                &topic_ref(),
                &main_ref(),
                rebase_inputs(&f),
                &Default::default(),
                None,
                &committer(),
                PreparationLimits::default(),
                &recipe
            ))
            .is_err()
    );
    assert_eq!(
        node.runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap()
            .basis(),
        before.basis()
    );
    node.shutdown().unwrap();
}
