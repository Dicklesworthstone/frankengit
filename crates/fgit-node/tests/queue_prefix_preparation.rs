#![forbid(unsafe_code)]
#![cfg(unix)]
//! Actual canonical queue selection and unpublished native prefix artifacts.
#[path = "queue_prefix_preparation/support.rs"]
mod support;
use support::*;

use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::QueueNumber;
use fgit_forge::event::pull_request::PullRequestAction;
use fgit_forge::merge_queue::QueueCommandAction;
use fgit_forge::preparation::queue_prefix::{PrefixPreparation, PrefixStop};
use fgit_forge::preparation::{MergeProfile, PreparationError, PreparationLimits};
use fgit_node::NodeWorkspaceRefusal;
use fgit_pack::full_bundle::{FullBundleInput, FullBundleLimits};
use fgit_pack::{EntryKind, NativeChecksumVerifier, PackLimits, read_verified_pack};
use fgit_types::{GitHashAlgorithm, PolicyEpoch};
use fgit_wire::visibility::RefVisibility;
use std::collections::BTreeMap;

const FORMATS: [GitHashAlgorithm; 2] = [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256];

#[test]
fn real_two_pr_prefix_preserves_original_subjects_and_exports_one_deterministic_native_chain() {
    for format in FORMATS {
        let (mut f, entries) = fixture(format, false);
        let before = state(f.node());
        let prepared = prepare(
            &f,
            2,
            &entries,
            &RefVisibility::new(),
            MergeProfile::PathMergeV1,
        )
        .unwrap();
        assert_eq!(prepared.source_head, before.head);
        assert_eq!(prepared.number, QueueNumber::FIRST);
        assert_eq!(prepared.expected_version, version(2));
        assert_eq!(prepared.entries, entries);
        let id = prepared.preparation_id.expect("complete prefix identity");
        let PrefixPreparation::Clean(plan) = &prepared.outcome else {
            panic!("both distinct PR changes must construct");
        };
        assert_eq!(plan.initial_target, f.target);
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.steps[0].source, f.source);
        assert_eq!(plan.steps[0].projected_target, f.target);
        assert_eq!(plan.steps[1].source, entries[1].subject.source_tip);
        assert_eq!(plan.steps[1].projected_target, plan.steps[0].commit);
        assert_eq!(plan.final_commit, plan.steps[1].commit);
        assert!(
            entries
                .iter()
                .all(|entry| entry.subject.target_tip == f.target)
        );
        assert_ne!(
            entries[1].subject.target_tip,
            plan.steps[1].projected_target
        );

        let extra = git_object_id(format, GitObjectKind::Blob, b"second\n");
        let left = git_object_id(format, GitObjectKind::Blob, b"target\n");
        let right = git_object_id(format, GitObjectKind::Blob, b"source\n");
        let expected_tree = git_object_id(
            format,
            GitObjectKind::Tree,
            &[
                b"100644 extra\0".as_slice(),
                extra.as_bytes(),
                b"100644 left\0",
                left.as_bytes(),
                b"100644 right\0",
                right.as_bytes(),
                b"100644 workflow.yml\0",
                f.workflow.as_bytes(),
            ]
            .concat(),
        );
        assert_eq!(plan.steps[1].tree, expected_tree);
        for (entry, step) in entries.iter().zip(&plan.steps) {
            assert_eq!(step.base, f.base);
            let mut body = format!(
                "tree {}\nparent {}\nparent {}\nauthor {} {} +0000\ncommitter {} {} +0000\n\n",
                step.tree,
                step.projected_target,
                step.source,
                entry.metadata.author,
                entry.metadata.timestamp,
                entry.metadata.committer,
                entry.metadata.timestamp,
            )
            .into_bytes();
            body.extend_from_slice(&entry.metadata.message);
            assert_eq!(
                step.commit,
                git_object_id(format, GitObjectKind::Commit, &body)
            );
            assert!(
                plan.objects
                    .iter()
                    .any(|object| object.id == step.commit && object.body == body)
            );
            assert!(f.node().read_git_object(step.commit).is_err());
        }
        for object in &plan.objects {
            assert_eq!(object.id, git_object_id(format, object.kind, &object.body));
        }
        let bundle = prepared.bundle.as_ref().unwrap();
        let parsed =
            FullBundleInput::parse_incremental(bundle, FullBundleLimits::default(), &mut || true)
                .unwrap();
        parsed
            .verify_pack_framing(&PackLimits::default(), &mut || true)
            .unwrap();
        assert_eq!(parsed.format(), format);
        assert_eq!(parsed.references().len(), 1);
        assert_eq!(parsed.references()[0].name(), &target_ref());
        assert_eq!(parsed.references()[0].target(), &plan.final_commit);
        let mut prerequisites = vec![f.target, f.source, entries[1].subject.source_tip];
        prerequisites.sort();
        prerequisites.dedup();
        assert_eq!(parsed.prerequisites(), prerequisites);
        assert!(!parsed.prerequisites().contains(&plan.steps[0].commit));
        let packed = read_verified_pack(
            parsed.pack_bytes(),
            format,
            &PackLimits::default(),
            &mut || true,
            &NativeChecksumVerifier,
        )
        .unwrap();
        let mut actual_objects = BTreeMap::new();
        for object in packed.entries() {
            assert!(object.delta_base.is_none());
            let kind = match object.header.kind {
                EntryKind::Commit => GitObjectKind::Commit,
                EntryKind::Tree => GitObjectKind::Tree,
                EntryKind::Blob => GitObjectKind::Blob,
                other => panic!("unexpected prefix pack entry: {other:?}"),
            };
            let id = git_object_id(format, kind, &object.inflated);
            assert!(
                actual_objects
                    .insert(id, (kind, object.inflated.clone()))
                    .is_none()
            );
        }
        assert_eq!(
            actual_objects,
            plan.objects
                .iter()
                .map(|object| (object.id, (object.kind, object.body.clone())))
                .collect::<BTreeMap<_, _>>()
        );
        assert_eq!(state(f.node()), before);

        let renamed = prepare(
            &f,
            2,
            &entries,
            &RefVisibility::new(),
            MergeProfile::ExactRenamesV1,
        )
        .unwrap();
        assert_eq!(renamed.outcome, prepared.outcome);
        assert_eq!(renamed.bundle, prepared.bundle);
        assert_ne!(
            renamed.preparation_id,
            Some(id),
            "the selected profile is committed"
        );
        let attributes = prepare(
            &f,
            2,
            &entries,
            &RefVisibility::new(),
            MergeProfile::BuiltinAttributesV1,
        )
        .unwrap();
        assert_eq!(attributes.outcome, prepared.outcome);
        assert_eq!(attributes.bundle, prepared.bundle);
        assert_ne!(attributes.preparation_id, Some(id));
        assert_ne!(
            attributes.preparation_id, renamed.preparation_id,
            "identical candidate bytes still bind the selected attribute policy"
        );
        let mut changed = entries.clone();
        changed[1].metadata.message = b"different explicit second commit message\n".to_vec();
        let changed = prepare(
            &f,
            2,
            &changed,
            &RefVisibility::new(),
            MergeProfile::PathMergeV1,
        )
        .unwrap();
        assert_ne!(changed.preparation_id, Some(id));
        let PrefixPreparation::Clean(changed_plan) = changed.outcome else {
            panic!()
        };
        assert_eq!(changed_plan.steps[0], plan.steps[0]);
        assert_eq!(changed_plan.steps[1].tree, plan.steps[1].tree);
        assert_ne!(changed_plan.final_commit, plan.final_commit);
        let shorter = prepare(
            &f,
            2,
            &entries[..1],
            &RefVisibility::new(),
            MergeProfile::PathMergeV1,
        )
        .unwrap();
        assert_ne!(shorter.preparation_id, Some(id));
        assert_eq!(state(f.node()), before);

        f.reopen();
        let restarted = prepare(
            &f,
            2,
            &entries,
            &RefVisibility::new(),
            MergeProfile::PathMergeV1,
        )
        .unwrap();
        assert_eq!(restarted.source_head, prepared.source_head);
        assert_eq!(restarted.preparation_id, Some(id));
        assert_eq!(restarted.outcome, prepared.outcome);
        assert_eq!(restarted.bundle, prepared.bundle);
        assert_eq!(state(f.node()), before);
    }
}

#[test]
fn the_request_must_name_an_exact_ordered_canonical_prefix_not_projected_pr_subjects() {
    for format in FORMATS {
        let (f, entries) = fixture(format, false);
        let before = state(f.node());
        let good = prepare(
            &f,
            2,
            &entries,
            &RefVisibility::new(),
            MergeProfile::PathMergeV1,
        )
        .unwrap();
        let PrefixPreparation::Clean(plan) = good.outcome else {
            panic!()
        };
        assert!(matches!(
            prepare(
                &f,
                1,
                &entries,
                &RefVisibility::new(),
                MergeProfile::PathMergeV1
            ),
            Err(NodeWorkspaceRefusal::StaleWorkspaceBase)
        ));
        assert!(matches!(
            prepare(
                &f,
                2,
                &entries[1..],
                &RefVisibility::new(),
                MergeProfile::PathMergeV1
            ),
            Err(NodeWorkspaceRefusal::StaleWorkspaceBase)
        ));
        let mut wrong = entries.clone();
        wrong.swap(0, 1);
        assert!(matches!(
            prepare(
                &f,
                2,
                &wrong,
                &RefVisibility::new(),
                MergeProfile::PathMergeV1
            ),
            Err(NodeWorkspaceRefusal::StaleWorkspaceBase)
        ));
        for field in ["pr-version", "source-tip", "target-tip", "policy"] {
            let mut wrong = entries.clone();
            match field {
                "pr-version" => wrong[1].subject.pull_request_version = version(2),
                "source-tip" => wrong[1].subject.source_tip = f.source,
                "target-tip" => {
                    for entry in &mut wrong {
                        entry.subject.target_tip = f.base;
                    }
                }
                "policy" => {
                    for entry in &mut wrong {
                        entry.subject.policy_epoch = PolicyEpoch::FIRST.next().unwrap();
                    }
                }
                _ => unreachable!(),
            }
            assert!(
                matches!(
                    prepare(
                        &f,
                        2,
                        &wrong,
                        &RefVisibility::new(),
                        MergeProfile::PathMergeV1
                    ),
                    Err(NodeWorkspaceRefusal::StaleWorkspaceBase)
                ),
                "{field}"
            );
        }
        let mut duplicated = entries.clone();
        duplicated[1] = duplicated[0].clone();
        assert!(matches!(
            prepare(
                &f,
                2,
                &duplicated,
                &RefVisibility::new(),
                MergeProfile::PathMergeV1
            ),
            Err(NodeWorkspaceRefusal::InvalidWorkspaceCandidate(_))
        ));
        let mut projected = entries.clone();
        projected[1].subject.target_tip = plan.steps[0].commit;
        assert!(matches!(
            prepare(
                &f,
                2,
                &projected,
                &RefVisibility::new(),
                MergeProfile::PathMergeV1
            ),
            Err(NodeWorkspaceRefusal::InvalidWorkspaceCandidate(_))
        ));
        assert_eq!(state(f.node()), before);
    }
}

#[test]
fn hidden_later_members_cancelled_requests_and_shared_budgets_refuse_without_mutation() {
    for format in FORMATS {
        let (f, entries) = fixture(format, false);
        let before = state(f.node());
        let first = prepare(
            &f,
            2,
            &entries[..1],
            &RefVisibility::new(),
            MergeProfile::PathMergeV1,
        )
        .unwrap();
        let PrefixPreparation::Clean(first) = first.outcome else {
            panic!()
        };
        let mut hidden = RefVisibility::new();
        hidden
            .push_rule(second_ref().as_bytes(), &Default::default())
            .unwrap();
        assert!(
            matches!(
                prepare(&f, 1, &entries, &hidden, MergeProfile::PathMergeV1),
                Err(NodeWorkspaceRefusal::RefUnavailable)
            ),
            "hidden membership is refused before the deliberately stale queue version"
        );

        let request = f.node().request_context();
        request.cancel();
        assert!(matches!(
            f.node()
                .runtime()
                .block_on(f.node().prepare_queue_prefix_bundle_in(
                    &request,
                    QueueNumber::FIRST,
                    version(2),
                    &entries,
                    &RefVisibility::new(),
                    PreparationLimits::default(),
                    MergeProfile::PathMergeV1,
                )),
            Err(NodeWorkspaceRefusal::Cancelled { .. })
        ));
        let limits = PreparationLimits {
            max_objects: first.objects.len(),
            ..PreparationLimits::default()
        };
        let allowed = f
            .node()
            .runtime()
            .block_on(f.node().prepare_queue_prefix_bundle_in(
                &f.node().request_context(),
                QueueNumber::FIRST,
                version(2),
                &entries[..1],
                &RefVisibility::new(),
                limits,
                MergeProfile::PathMergeV1,
            ))
            .unwrap();
        assert!(matches!(allowed.outcome, PrefixPreparation::Clean(_)));
        assert!(matches!(
            f.node()
                .runtime()
                .block_on(f.node().prepare_queue_prefix_bundle_in(
                    &f.node().request_context(),
                    QueueNumber::FIRST,
                    version(2),
                    &entries,
                    &RefVisibility::new(),
                    limits,
                    MergeProfile::PathMergeV1,
                )),
            Err(NodeWorkspaceRefusal::MergePreparation(
                PreparationError::Budget("objects")
            ))
        ));
        assert_eq!(state(f.node()), before);
    }
}

#[test]
fn a_real_later_pr_conflict_returns_only_diagnostics_without_identity_or_bundle() {
    for format in FORMATS {
        let (f, entries) = fixture(format, true);
        let before = state(f.node());
        let first = prepare(
            &f,
            2,
            &entries[..1],
            &RefVisibility::new(),
            MergeProfile::PathMergeV1,
        )
        .unwrap();
        let PrefixPreparation::Clean(first) = first.outcome else {
            panic!()
        };
        let stopped = prepare(
            &f,
            2,
            &entries,
            &RefVisibility::new(),
            MergeProfile::PathMergeV1,
        )
        .unwrap();
        assert!(stopped.bundle.is_none());
        assert!(stopped.preparation_id.is_none());
        assert_eq!(stopped.entries, entries);
        let PrefixPreparation::Stopped {
            index,
            source,
            projected_target,
            completed,
            reason: PrefixStop::Conflicted { base, conflicts },
        } = stopped.outcome
        else {
            panic!("the conflict cannot turn into a shorter successful prefix");
        };
        assert_eq!(index, 1);
        assert_eq!(source, entries[1].subject.source_tip);
        assert_eq!(projected_target, first.final_commit);
        assert_eq!(completed, first.steps);
        assert_eq!(base, f.base);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].path, b"right");
        assert!(f.node().read_git_object(projected_target).is_err());
        assert_eq!(state(f.node()), before);
    }
}

#[test]
fn canonical_queue_pr_source_target_and_policy_changes_invalidate_the_old_selection() {
    #[derive(Clone, Copy, Debug)]
    enum Moved {
        Queue,
        PullRequest,
        Source,
        Target,
        Policy,
    }
    for format in FORMATS {
        for moved in [
            Moved::Queue,
            Moved::PullRequest,
            Moved::Source,
            Moved::Target,
            Moved::Policy,
        ] {
            let (f, entries) = fixture(format, false);
            let original = prepare(
                &f,
                2,
                &entries,
                &RefVisibility::new(),
                MergeProfile::PathMergeV1,
            )
            .unwrap();
            match moved {
                Moved::Queue => change_queue(
                    f.node(),
                    2,
                    QueueCommandAction::Reorder {
                        order: vec![pr(2), pr(1)],
                    },
                    "prefix-reorder",
                ),
                Moved::PullRequest => change_pull(
                    f.node(),
                    &entries[1],
                    PullRequestAction::Update,
                    false,
                    "prefix-update-pr",
                ),
                Moved::Source => advance(
                    f.node(),
                    second_ref(),
                    entries[1].subject.source_tip,
                    "prefix-advance-source",
                ),
                Moved::Target => advance(f.node(), target_ref(), f.target, "prefix-advance-target"),
                Moved::Policy => change_policy(f.node()),
            }
            let before = state(f.node());
            assert!(
                matches!(
                    prepare(
                        &f,
                        2,
                        &entries,
                        &RefVisibility::new(),
                        MergeProfile::PathMergeV1
                    ),
                    Err(NodeWorkspaceRefusal::StaleWorkspaceBase)
                ),
                "{moved:?}"
            );
            assert_eq!(state(f.node()), before, "{moved:?}");

            // Positive twins use newly read canonical coordinates. A title-only
            // PR update and a policy change keep the same native artifact while
            // changing the selection identity; neither grants publication.
            let refreshed = match moved {
                Moved::Queue => {
                    let mut reordered = entries.clone();
                    reordered.swap(0, 1);
                    Some(
                        prepare(
                            &f,
                            3,
                            &reordered,
                            &RefVisibility::new(),
                            MergeProfile::PathMergeV1,
                        )
                        .unwrap(),
                    )
                }
                Moved::PullRequest => {
                    let mut updated = entries.clone();
                    updated[1].subject.pull_request_version = version(2);
                    Some(
                        prepare(
                            &f,
                            2,
                            &updated,
                            &RefVisibility::new(),
                            MergeProfile::PathMergeV1,
                        )
                        .unwrap(),
                    )
                }
                Moved::Policy => {
                    let mut updated = entries.clone();
                    for entry in &mut updated {
                        entry.subject.policy_epoch = PolicyEpoch::FIRST.next().unwrap();
                    }
                    Some(
                        prepare(
                            &f,
                            2,
                            &updated,
                            &RefVisibility::new(),
                            MergeProfile::PathMergeV1,
                        )
                        .unwrap(),
                    )
                }
                _ => None,
            };
            if let Some(refreshed) = refreshed {
                assert_ne!(refreshed.preparation_id, original.preparation_id);
                assert_eq!(refreshed.source_head, before.head);
                if !matches!(moved, Moved::Queue) {
                    assert_eq!(refreshed.outcome, original.outcome);
                    assert_eq!(refreshed.bundle, original.bundle);
                }
            }
            assert_eq!(state(f.node()), before, "{moved:?}");
        }
    }
}
