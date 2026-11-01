//! Real native merge graphs and refusal twins for whole-prefix construction.
mod support;

use crate::preparation::queue_prefix::{
    MAX_PREFIX_ENTRIES, PrefixInput, PrefixPreparation, PrefixStop, PreparedPrefix,
    prepare_queue_prefix,
};
use crate::preparation::{
    ConflictKind, MergeMetadata, MergePreparation, MergeProfile, MergeSourceError,
    PreparationError, PreparationLimits, prepare_merge_with_profile,
};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_diff::MergeBaseError;
use fgit_types::{GitHashAlgorithm, GitOid};
use support::*;

const FORMATS: [GitHashAlgorithm; 2] = [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256];

fn inputs<'a>(tips: &[GitOid], metadata: &'a MergeMetadata) -> Vec<PrefixInput<'a>> {
    tips.iter()
        .map(|source| PrefixInput {
            source: *source,
            metadata,
        })
        .collect()
}

fn run(
    source: &Source,
    target: GitOid,
    inputs: &[PrefixInput<'_>],
    limits: PreparationLimits,
    profile: MergeProfile,
) -> Result<PrefixPreparation, PreparationError> {
    prepare_queue_prefix(source, source.format, target, inputs, limits, profile)
}

fn clean(result: Result<PrefixPreparation, PreparationError>) -> PreparedPrefix {
    let PrefixPreparation::Clean(plan) = result.unwrap() else {
        panic!("expected the complete prefix to construct");
    };
    plan
}

fn is_cancelled(error: &PreparationError) -> bool {
    matches!(
        error,
        PreparationError::Source(MergeSourceError::Cancelled)
            | PreparationError::Graph(MergeBaseError::Source(MergeSourceError::Cancelled))
    )
}

#[test]
fn divergent_and_stacked_changes_build_real_two_parent_commits_in_both_formats() {
    for format in FORMATS {
        let (source, base, target, tips) = fixture(format);
        let original = source.objects.clone();
        let metadata = metadata();
        let inputs = inputs(&tips, &metadata);
        let plan = clean(run(
            &source,
            target,
            &inputs,
            PreparationLimits::default(),
            MergeProfile::PathMergeV1,
        ));
        assert_eq!(plan.initial_target, target);
        assert_eq!(plan.steps.len(), 3);
        let mut expected = Source::new(format);
        let mut projected = target;
        for (index, text) in [MERGED_FIRST, MERGED_SECOND, MERGED_THIRD]
            .into_iter()
            .enumerate()
        {
            let step = &plan.steps[index];
            let tree = expected.write_tree(&files(text));
            let body = commit_body(tree, projected, tips[index], &metadata);
            let commit = git_object_id(format, GitObjectKind::Commit, &body);
            assert_eq!(step.source, tips[index]);
            assert_eq!(step.base, if index == 2 { tips[0] } else { base });
            assert_eq!(step.projected_target, projected);
            assert_eq!(step.tree, tree);
            assert_eq!(step.commit, commit);
            assert!(plan.objects.iter().any(|object| {
                object.id == commit && object.kind == GitObjectKind::Commit && object.body == body
            }));
            let blob = git_object_id(format, GitObjectKind::Blob, text);
            assert!(!source.objects.contains_key(&blob));
            assert!(plan.objects.iter().any(|object| {
                object.id == blob && object.kind == GitObjectKind::Blob && object.body == text
            }));
            projected = commit;
        }
        assert_eq!(plan.final_commit, projected);
        assert_eq!(
            source.objects, original,
            "construction cannot extend the source"
        );
        assert!(plan.objects.windows(2).all(|pair| pair[0].id < pair[1].id));
        for object in &plan.objects {
            assert_eq!(object.id, git_object_id(format, object.kind, &object.body));
        }
        let stable = expected.write_tree(&[(b"unchanged", b"borrow this subtree\n", 0o100644)]);
        assert!(!plan.objects.iter().any(|object| object.id == stable));
        assert_eq!(
            plan,
            clean(run(
                &source,
                target,
                &inputs,
                PreparationLimits::default(),
                MergeProfile::PathMergeV1,
            )),
            "the same source, order and metadata produce the same artifact"
        );
    }
}

#[test]
fn source_order_and_each_steps_metadata_bind_the_native_chain() {
    for format in FORMATS {
        let (source, _, target, tips) = fixture(format);
        let original = metadata();
        let first = clean(run(
            &source,
            target,
            &inputs(&tips, &original),
            PreparationLimits::default(),
            MergeProfile::PathMergeV1,
        ));
        let reordered = clean(run(
            &source,
            target,
            &inputs(&[tips[1], tips[0], tips[2]], &original),
            PreparationLimits::default(),
            MergeProfile::PathMergeV1,
        ));
        assert_eq!(first.steps[2].tree, reordered.steps[2].tree);
        assert_ne!(first.final_commit, reordered.final_commit);
        assert_eq!(reordered.steps[0].source, tips[1]);
        assert_eq!(
            reordered.steps[1].projected_target,
            reordered.steps[0].commit
        );

        let mut changed = original.clone();
        changed.timestamp += 1;
        changed.message = b"independently reviewed second step\n".to_vec();
        let mut request = inputs(&tips, &original);
        request[1].metadata = &changed;
        let updated = clean(run(
            &source,
            target,
            &request,
            PreparationLimits::default(),
            MergeProfile::PathMergeV1,
        ));
        assert_eq!(first.steps[0], updated.steps[0]);
        assert_ne!(first.steps[1].commit, updated.steps[1].commit);
        assert_ne!(first.final_commit, updated.final_commit);
        assert_eq!(first.steps[2].tree, updated.steps[2].tree);
        let body = commit_body(
            updated.steps[1].tree,
            updated.steps[0].commit,
            tips[1],
            &changed,
        );
        assert!(
            updated
                .objects
                .iter()
                .any(|object| { object.id == updated.steps[1].commit && object.body == body })
        );
    }
}

#[test]
fn one_entry_preserves_the_existing_native_merge_profile_and_object_contract() {
    for format in FORMATS {
        let (source, _, target, tips) = fixture(format);
        let metadata = metadata();
        for profile in [MergeProfile::PathMergeV1, MergeProfile::ExactRenamesV1] {
            let prefix = clean(run(
                &source,
                target,
                &inputs(&tips[..1], &metadata),
                PreparationLimits::default(),
                profile,
            ));
            let MergePreparation::Clean(single) = prepare_merge_with_profile(
                &source,
                format,
                target,
                tips[0],
                &metadata,
                PreparationLimits::default(),
                profile,
            )
            .unwrap() else {
                panic!("the independently supported single merge must construct");
            };
            assert_eq!(prefix.final_commit, single.commit);
            assert_eq!(prefix.steps[0].tree, single.tree);
            assert_eq!(prefix.steps[0].base, single.base);
            assert_eq!(prefix.objects, single.objects);
        }
    }
}

#[test]
fn a_later_conflict_stops_the_exact_entry_without_exposing_partial_objects() {
    for format in FORMATS {
        for (base_text, first_text, second_text, kind) in [
            (
                b"base\n".as_slice(),
                b"first\n".as_slice(),
                b"second\n".as_slice(),
                ConflictKind::Content,
            ),
            (
                b"\0base".as_slice(),
                b"\0first".as_slice(),
                b"\0second".as_slice(),
                ConflictKind::Binary,
            ),
        ] {
            let mut source = Source::new(format);
            let base = source.write_commit(&[(b"file", base_text, 0o100644)], &[], "base");
            let target = source.write_commit(
                &[
                    (b"file", base_text, 0o100644),
                    (b"target", b"retained target change", 0o100644),
                ],
                &[base],
                "target",
            );
            let first = source.write_commit(&[(b"file", first_text, 0o100644)], &[base], "first");
            let second = source.write_commit(
                &[(b"file", second_text, 0o100644)],
                &[base],
                "conflicting second",
            );
            let later =
                source.write_commit(&[(b"unread", b"later", 0o100644)], &[base], "unread third");
            let metadata = metadata();
            let original = source.objects.clone();
            let one = clean(run(
                &source,
                target,
                &inputs(&[first], &metadata),
                PreparationLimits::default(),
                MergeProfile::PathMergeV1,
            ));
            source.seen.borrow_mut().clear();
            let PrefixPreparation::Stopped {
                index,
                source: stopped_source,
                projected_target,
                completed,
                reason:
                    PrefixStop::Conflicted {
                        base: actual_base,
                        conflicts,
                    },
            } = run(
                &source,
                target,
                &inputs(&[first, second, later], &metadata),
                PreparationLimits::default(),
                MergeProfile::PathMergeV1,
            )
            .unwrap()
            else {
                panic!("a conflicted second entry must not return a clean shorter prefix");
            };
            assert_eq!(index, 1);
            assert_eq!(stopped_source, second);
            assert_eq!(projected_target, one.final_commit);
            assert_eq!(completed, one.steps);
            assert_eq!(actual_base, base);
            assert_eq!(conflicts.len(), 1);
            assert_eq!(conflicts[0].path, b"file");
            assert_eq!(conflicts[0].kind, kind);
            assert!(!source.seen.borrow().contains(&later));
            assert_eq!(source.objects, original);
            assert!(matches!(
                run(
                    &source,
                    first,
                    &inputs(&[second], &metadata),
                    PreparationLimits::default(),
                    MergeProfile::PathMergeV1,
                )
                .unwrap(),
                PrefixPreparation::Stopped { index: 0, completed, .. } if completed.is_empty()
            ));
        }
    }
}

#[test]
fn repeated_or_already_integrated_sources_are_explicit_stops_not_skipped_entries() {
    for format in FORMATS {
        let (source, _, target, tips) = fixture(format);
        let metadata = metadata();
        let one = clean(run(
            &source,
            target,
            &inputs(&tips[..1], &metadata),
            PreparationLimits::default(),
            MergeProfile::PathMergeV1,
        ));
        let PrefixPreparation::Stopped {
            index,
            source: stopped_source,
            projected_target,
            completed,
            reason: PrefixStop::AlreadyIntegrated,
        } = run(
            &source,
            target,
            &inputs(&[tips[0], tips[0], tips[1]], &metadata),
            PreparationLimits::default(),
            MergeProfile::PathMergeV1,
        )
        .unwrap()
        else {
            panic!("the repeated source is an explicit terminal stop");
        };
        assert_eq!(index, 1);
        assert_eq!(stopped_source, tips[0]);
        assert_eq!(projected_target, one.final_commit);
        assert_eq!(completed, one.steps);
        assert!(matches!(
            run(
                &source,
                target,
                &inputs(&[target], &metadata),
                PreparationLimits::default(),
                MergeProfile::PathMergeV1,
            )
            .unwrap(),
            PrefixPreparation::Stopped {
                index: 0,
                reason: PrefixStop::AlreadyIntegrated,
                completed,
                ..
            } if completed.is_empty()
        ));
    }
}

#[test]
fn later_exact_rename_preserves_prior_commits_and_reuses_the_generated_blob() {
    for format in FORMATS {
        let mut source = Source::new(format);
        let base = source.write_commit(&[(b"old/file", BASE, 0o100644)], &[], "base");
        let target = source.write_commit(&[(b"old/file", TARGET, 0o100644)], &[base], "target");
        let first = source.write_commit(&[(b"old/file", FIRST, 0o100644)], &[base], "edit");
        let rename =
            source.write_commit(&[(b"new/nested/name", BASE, 0o100755)], &[base], "rename");
        let metadata = metadata();
        let request = inputs(&[first, rename], &metadata);
        let plan = clean(run(
            &source,
            target,
            &request,
            PreparationLimits::default(),
            MergeProfile::ExactRenamesV1,
        ));
        let mut expected = Source::new(format);
        let first_tree = expected.write_tree(&[(b"old/file", MERGED_FIRST, 0o100644)]);
        let second_tree = expected.write_tree(&[(b"new/nested/name", MERGED_FIRST, 0o100755)]);
        assert_eq!(plan.steps[0].tree, first_tree);
        assert_eq!(plan.steps[1].tree, second_tree);
        let blob = git_object_id(format, GitObjectKind::Blob, MERGED_FIRST);
        assert!(!source.objects.contains_key(&blob));
        assert_eq!(
            plan.objects
                .iter()
                .filter(|object| object.id == blob)
                .count(),
            1
        );
        for step in &plan.steps {
            let body = commit_body(step.tree, step.projected_target, step.source, &metadata);
            assert!(plan.objects.iter().any(|object| {
                object.id == step.commit
                    && object.kind == GitObjectKind::Commit
                    && object.body == body
            }));
            assert!(plan.objects.iter().any(|object| object.id == step.tree));
        }
        // Both commits remain independently readable from the aggregate
        // artifact, including the first commit's old-path tree closure.
        let mut consumed = source.clone();
        consumed.install(&plan.objects);
        for step in &plan.steps {
            assert_eq!(consumed.commits[&step.commit].tree, step.tree);
        }
        assert!(matches!(
            run(
                &source,
                target,
                &request,
                PreparationLimits::default(),
                MergeProfile::PathMergeV1,
            )
            .unwrap(),
            PrefixPreparation::Stopped {
                index: 1,
                reason: PrefixStop::Conflicted { .. },
                ..
            }
        ));
    }
}

#[test]
fn content_tree_object_and_output_limits_cover_the_entire_prefix() {
    for format in FORMATS {
        let (source, _, target, tips) = fixture(format);
        let metadata = metadata();
        let request = inputs(&tips, &metadata);
        let first = clean(run(
            &source,
            target,
            &request[..1],
            PreparationLimits::default(),
            MergeProfile::PathMergeV1,
        ));
        let first_bytes: usize = first.objects.iter().map(|object| object.body.len()).sum();
        let cases = [
            (
                PreparationLimits {
                    max_content_merges: 1,
                    ..PreparationLimits::default()
                },
                "content merges",
            ),
            (
                PreparationLimits {
                    // Three two-entry roots plus three one-entry src trees.
                    max_tree_entries: 9,
                    ..PreparationLimits::default()
                },
                "tree entries",
            ),
            (
                PreparationLimits {
                    max_objects: first.objects.len(),
                    ..PreparationLimits::default()
                },
                "objects",
            ),
            (
                PreparationLimits {
                    max_output_bytes: first_bytes,
                    ..PreparationLimits::default()
                },
                "output bytes",
            ),
        ];
        for (limits, label) in cases {
            assert_eq!(
                clean(run(
                    &source,
                    target,
                    &request[..1],
                    limits,
                    MergeProfile::PathMergeV1
                )),
                first,
                "the first entry fits the {label} allowance"
            );
            let error =
                run(&source, target, &request, limits, MergeProfile::PathMergeV1).unwrap_err();
            assert!(
                matches!(&error, PreparationError::Budget(actual) if *actual == label),
                "a later entry must exhaust the shared {label} allowance: {error:?}"
            );
        }
        let full = clean(run(
            &source,
            target,
            &request,
            PreparationLimits::default(),
            MergeProfile::PathMergeV1,
        ));
        let bytes: usize = full.objects.iter().map(|object| object.body.len()).sum();
        let exact = PreparationLimits {
            max_content_merges: 3,
            max_tree_entries: 27,
            max_objects: full.objects.len(),
            max_output_bytes: bytes,
            ..PreparationLimits::default()
        };
        assert_eq!(
            clean(run(
                &source,
                target,
                &request,
                exact,
                MergeProfile::PathMergeV1
            )),
            full
        );
        for limits in [
            PreparationLimits {
                max_objects: full.objects.len() - 1,
                ..exact
            },
            PreparationLimits {
                max_output_bytes: bytes - 1,
                ..exact
            },
            PreparationLimits {
                max_tree_entries: 26,
                ..exact
            },
            PreparationLimits {
                max_content_merges: 2,
                ..exact
            },
        ] {
            assert!(matches!(
                run(&source, target, &request, limits, MergeProfile::PathMergeV1),
                Err(PreparationError::Budget(_))
            ));
        }
    }
}

#[test]
fn commit_and_edge_allowances_cannot_reset_for_the_second_projected_query() {
    for format in FORMATS {
        let (source, _, target, tips) = fixture(format);
        let metadata = metadata();
        let request = inputs(&tips[..2], &metadata);
        let first = clean(run(
            &source,
            target,
            &request[..1],
            PreparationLimits::default(),
            MergeProfile::PathMergeV1,
        ));
        let mut next_source = source.clone();
        next_source.install(&first.objects);
        for (limits, commits) in [
            (
                PreparationLimits {
                    max_commits: 5,
                    ..PreparationLimits::default()
                },
                true,
            ),
            (
                PreparationLimits {
                    max_edges: 5,
                    ..PreparationLimits::default()
                },
                false,
            ),
        ] {
            clean(run(
                &source,
                target,
                &request[..1],
                limits,
                MergeProfile::PathMergeV1,
            ));
            clean(run(
                &next_source,
                first.final_commit,
                &request[1..],
                limits,
                MergeProfile::PathMergeV1,
            ));
            let error =
                run(&source, target, &request, limits, MergeProfile::PathMergeV1).unwrap_err();
            assert!(
                if commits {
                    matches!(
                        error,
                        PreparationError::Graph(MergeBaseError::CommitLimitExceeded { .. })
                    )
                } else {
                    matches!(
                        error,
                        PreparationError::Graph(MergeBaseError::EdgeLimitExceeded { .. })
                    )
                },
                "each query fits separately, but the prefix must charge both"
            );
        }
    }
}

#[test]
fn cancellation_when_a_later_source_is_first_read_returns_no_prefix() {
    for format in FORMATS {
        let (source, _, target, tips) = fixture(format);
        let metadata = metadata();
        source.cancel_on_commit.set(Some(tips[1]));
        clean(run(
            &source,
            target,
            &inputs(&tips[..1], &metadata),
            PreparationLimits::default(),
            MergeProfile::PathMergeV1,
        ));
        let error = run(
            &source,
            target,
            &inputs(&tips, &metadata),
            PreparationLimits::default(),
            MergeProfile::PathMergeV1,
        )
        .unwrap_err();
        assert!(is_cancelled(&error), "{error:?}");
        assert!(source.seen.borrow().contains(&tips[0]));
        assert!(source.seen.borrow().contains(&tips[1]));
        assert!(!source.seen.borrow().contains(&tips[2]));
    }
}

#[test]
fn every_checkpoint_cancellation_refuses_including_after_the_final_commit_is_built() {
    let (source, _, target, tips) = fixture(GitHashAlgorithm::Sha256);
    let metadata = metadata();
    let request = inputs(&tips, &metadata);
    clean(run(
        &source,
        target,
        &request,
        PreparationLimits::default(),
        MergeProfile::PathMergeV1,
    ));
    let polls = source.polls.get();
    for stop in 1..=polls {
        source.polls.set(0);
        source.seen.borrow_mut().clear();
        source.stop.set(stop);
        let error = run(
            &source,
            target,
            &request,
            PreparationLimits::default(),
            MergeProfile::PathMergeV1,
        )
        .unwrap_err();
        assert!(is_cancelled(&error), "checkpoint {stop}/{polls}: {error:?}");
    }
}

#[test]
fn shape_format_and_all_metadata_are_checked_before_any_object_read() {
    for format in FORMATS {
        let (source, _, target, tips) = fixture(format);
        let metadata = metadata();
        assert!(matches!(
            run(
                &source,
                target,
                &[],
                PreparationLimits::default(),
                MergeProfile::PathMergeV1
            ),
            Err(PreparationError::InvalidPrefix)
        ));
        assert!(matches!(
            run(
                &source,
                target,
                &inputs(&vec![tips[0]; MAX_PREFIX_ENTRIES + 1], &metadata),
                PreparationLimits::default(),
                MergeProfile::PathMergeV1,
            ),
            Err(PreparationError::InvalidPrefix)
        ));
        let foreign = match format {
            GitHashAlgorithm::Sha1 => GitHashAlgorithm::Sha256,
            GitHashAlgorithm::Sha256 => GitHashAlgorithm::Sha1,
        };
        let foreign_tip = git_object_id(foreign, GitObjectKind::Commit, b"foreign");
        assert!(matches!(
            run(
                &source,
                target,
                &inputs(&[tips[0], foreign_tip], &metadata),
                PreparationLimits::default(),
                MergeProfile::PathMergeV1,
            ),
            Err(PreparationError::ObjectFormat)
        ));
        let zero = GitOid::from_hex(format, &"0".repeat(format.digest_len() * 2)).unwrap();
        assert!(matches!(
            run(
                &source,
                zero,
                &inputs(&tips[..1], &metadata),
                PreparationLimits::default(),
                MergeProfile::PathMergeV1,
            ),
            Err(PreparationError::ObjectFormat)
        ));
        let mut invalid = metadata.clone();
        invalid.message.push(0);
        let mut request = inputs(&tips, &metadata);
        request[2].metadata = &invalid;
        assert!(matches!(
            run(
                &source,
                target,
                &request,
                PreparationLimits::default(),
                MergeProfile::PathMergeV1,
            ),
            Err(PreparationError::InvalidMetadata)
        ));
        assert!(source.seen.borrow().is_empty());
    }
}

#[test]
fn the_maximum_supported_prefix_constructs_every_distinct_source() {
    for format in FORMATS {
        let mut source = Source::new(format);
        let base = source.write_commit(&[], &[], "base");
        let target = source.write_commit(&[(b"target", b"target", 0o100644)], &[base], "target");
        let mut tips = Vec::new();
        let names: Vec<_> = (0..MAX_PREFIX_ENTRIES)
            .map(|index| format!("pr-{index:02}"))
            .collect();
        for name in &names {
            tips.push(source.write_commit(
                &[(name.as_bytes(), name.as_bytes(), 0o100644)],
                &[base],
                name,
            ));
        }
        let metadata = metadata();
        let plan = clean(run(
            &source,
            target,
            &inputs(&tips, &metadata),
            PreparationLimits::default(),
            MergeProfile::PathMergeV1,
        ));
        assert_eq!(plan.steps.len(), MAX_PREFIX_ENTRIES);
        let mut expected_files = vec![(b"target".as_slice(), b"target".as_slice(), 0o100644)];
        expected_files.extend(
            names
                .iter()
                .map(|name| (name.as_bytes(), name.as_bytes(), 0o100644)),
        );
        let mut expected = Source::new(format);
        let tree = expected.write_tree(&expected_files);
        assert_eq!(plan.steps.last().unwrap().tree, tree);
        assert_eq!(
            plan.objects
                .iter()
                .filter(|object| object.kind == GitObjectKind::Commit)
                .count(),
            MAX_PREFIX_ENTRIES
        );
        assert_eq!(plan.final_commit, plan.steps.last().unwrap().commit);
    }
}

#[test]
fn unrelated_later_history_refuses_without_accepting_the_constructed_first_step() {
    for format in FORMATS {
        let (mut source, _, target, tips) = fixture(format);
        let unrelated =
            source.write_commit(&[(b"unrelated", b"root", 0o100644)], &[], "other root");
        let metadata = metadata();
        clean(run(
            &source,
            target,
            &inputs(&tips[..1], &metadata),
            PreparationLimits::default(),
            MergeProfile::PathMergeV1,
        ));
        assert!(matches!(
            run(
                &source,
                target,
                &inputs(&[tips[0], unrelated], &metadata),
                PreparationLimits::default(),
                MergeProfile::PathMergeV1,
            ),
            Err(PreparationError::NoCommonAncestor)
        ));
    }
}

#[test]
fn pruning_virtual_rename_trees_does_not_refill_the_prefix_object_allowance() {
    for format in FORMATS {
        let mut source = Source::new(format);
        let base = source.write_commit(&[(b"old/file", BASE, 0o100644)], &[], "base");
        let target = source.write_commit(&[(b"old/file", TARGET, 0o100644)], &[base], "target");
        let first = source.write_commit(
            &[(b"renamed/one/first", BASE, 0o100755)],
            &[base],
            "first rename and mode",
        );
        let second = source.write_commit(
            &[(b"another/two/second", BASE, 0o100644)],
            &[first],
            "second rename and mode",
        );
        let metadata = metadata();
        let request = inputs(&[first, second], &metadata);
        let one = clean(run(
            &source,
            target,
            &request[..1],
            PreparationLimits::default(),
            MergeProfile::ExactRenamesV1,
        ));
        let full = clean(run(
            &source,
            target,
            &request,
            PreparationLimits::default(),
            MergeProfile::ExactRenamesV1,
        ));
        // Each rename emits three trees for the aligned base, three for the
        // aligned target, three final trees, and one commit. The six temporary
        // trees are omitted from the artifact, but their work stays charged.
        assert_eq!(one.objects.len(), 4);
        assert_eq!(full.objects.len(), 8);
        let limits = PreparationLimits {
            max_objects: 14,
            ..PreparationLimits::default()
        };
        clean(run(
            &source,
            target,
            &request[..1],
            limits,
            MergeProfile::ExactRenamesV1,
        ));
        let mut next_source = source.clone();
        next_source.install(&one.objects);
        clean(run(
            &next_source,
            one.final_commit,
            &request[1..],
            limits,
            MergeProfile::ExactRenamesV1,
        ));
        assert!(matches!(
            run(
                &source,
                target,
                &request,
                limits,
                MergeProfile::ExactRenamesV1
            ),
            Err(PreparationError::Budget("objects"))
        ));
        assert_eq!(
            clean(run(
                &source,
                target,
                &request,
                PreparationLimits {
                    max_objects: 20,
                    ..PreparationLimits::default()
                },
                MergeProfile::ExactRenamesV1,
            )),
            full
        );
        assert!(matches!(
            run(
                &source,
                target,
                &request,
                PreparationLimits {
                    max_objects: 19,
                    ..PreparationLimits::default()
                },
                MergeProfile::ExactRenamesV1,
            ),
            Err(PreparationError::Budget("objects"))
        ));
    }
}
