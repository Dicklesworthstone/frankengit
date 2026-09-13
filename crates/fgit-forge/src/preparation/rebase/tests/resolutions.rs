use super::*;
use crate::preparation::rebase::resolutions::{
    RebaseCommitResolution, ResolvedRebasePreparation, prepare_resolved_rebase,
    validate_rebase_resolutions,
};
use crate::preparation::resolution::{ConflictResolution, ResolutionChoice, ResolutionError};

fn conflicted(format: GitHashAlgorithm, twice: bool) -> (Source, RebaseRequest, [GitOid; 2]) {
    let mut source = Source::new(format);
    let upstream = source.store_commit(BASE, &[], b"base");
    let onto = source.store_commit(ONTO, &[upstream], b"onto");
    let first = source.store_commit(b"X\nb\nc\nd\ne\nf\n", &[upstream], b"original first\n\xff");
    let second = source.store_commit(
        if twice {
            b"Y\nb\nc\nd\ne\nf\n"
        } else {
            b"X\nb\nc\nd\ne\nF\n"
        },
        &[first],
        b"original second",
    );
    (
        source,
        RebaseRequest {
            source_tip: second,
            upstream,
            onto,
            empty: EmptyCommitPolicy::Keep,
        },
        [first, second],
    )
}
fn recipe(original: GitOid, choice: ResolutionChoice) -> RebaseCommitResolution {
    RebaseCommitResolution {
        original,
        paths: vec![ConflictResolution {
            path: b"file".to_vec(),
            choice,
        }],
    }
}
fn resolved(
    source: &Source,
    inputs: RebaseRequest,
    choices: &[RebaseCommitResolution],
) -> ResolvedRebasePreparation {
    prepare_resolved_rebase(
        source,
        source.format,
        inputs,
        &committer(),
        PreparationLimits::default(),
        choices,
    )
    .unwrap()
}
fn final_file(source: &Source, plan: &PreparedRebase) -> Option<(u32, Vec<u8>)> {
    let (mode, id) = if let Some(object) = plan.objects.iter().find(|o| o.id == plan.tree) {
        assert_eq!(object.kind, GitObjectKind::Tree);
        if object.body.is_empty() {
            return None;
        }
        let end = object.body.iter().position(|b| *b == 0).unwrap();
        let header = std::str::from_utf8(&object.body[..end]).unwrap();
        let (mode, path) = header.split_once(' ').unwrap();
        assert_eq!(path, "file");
        assert_eq!(object.body.len() - end - 1, source.format.digest_len());
        let hex: String = object.body[end + 1..]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        (
            u32::from_str_radix(mode, 8).unwrap(),
            GitOid::from_hex(source.format, &hex).unwrap(),
        )
    } else {
        let tree = &source.trees[&plan.tree];
        if tree.is_empty() {
            return None;
        }
        assert_eq!(tree.len(), 1);
        (tree[0].mode, tree[0].oid)
    };
    let bytes = plan
        .objects
        .iter()
        .find(|o| o.id == id)
        .map(|o| {
            assert_eq!(o.kind, GitObjectKind::Blob);
            o.body.clone()
        })
        .unwrap_or_else(|| source.blobs[&id].clone());
    Some((mode, bytes))
}

#[test]
fn resolved_tree_is_the_real_base_for_later_replays_and_preserves_original_metadata() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (source, inputs, originals) = conflicted(format, false);
        let choices = [recipe(
            originals[0],
            ResolutionChoice::File {
                mode: 0o100755,
                bytes: b"R\nb\nc\nd\ne\nf\n".to_vec(),
            },
        )];
        let result = resolved(&source, inputs, &choices);
        let RebasePreparation::Clean(plan) = &result.preparation else {
            panic!("{result:?}");
        };
        assert_eq!(
            final_file(&source, plan),
            Some((0o100755, b"R\nb\nc\nd\ne\nF\n".to_vec()))
        );
        assert_eq!(
            plan.steps.iter().map(|s| s.original).collect::<Vec<_>>(),
            originals
        );
        assert_eq!(result.resolutions.len(), 1);
        assert_eq!(result.resolutions[0].original, originals[0]);
        assert_eq!(
            result.resolutions[0].paths[0].result.as_ref().unwrap().mode,
            0o100755
        );
        let mut parent = inputs.onto;
        for step in &plan.steps {
            let object = plan
                .objects
                .iter()
                .find(|o| o.id == step.rewritten)
                .unwrap();
            assert!(
                object.body.starts_with(
                    format!("tree {}\nparent {parent}\nauthor ", step.tree).as_bytes()
                )
            );
            assert!(
                object
                    .body
                    .ends_with(&source.metadata[&step.original].message)
            );
            assert_eq!(git_object_id(format, object.kind, &object.body), object.id);
            parent = step.rewritten;
        }
        assert_eq!(result, resolved(&source, inputs, &choices));
    }
}

#[test]
fn each_conflicted_original_needs_its_own_recipe_and_recipe_order_is_irrelevant() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (source, inputs, originals) = conflicted(format, true);
        let first = recipe(
            originals[0],
            ResolutionChoice::File {
                mode: 0o100644,
                bytes: b"R\nb\nc\nd\ne\nf\n".to_vec(),
            },
        );
        let second = recipe(originals[1], ResolutionChoice::Theirs);
        let stopped = resolved(&source, inputs, std::slice::from_ref(&first));
        let RebasePreparation::Stopped {
            original,
            completed,
            reason: RebaseStop::Conflicted(conflicts),
            ..
        } = &stopped.preparation
        else {
            panic!("{stopped:?}");
        };
        assert_eq!(*original, originals[1]);
        assert_eq!(completed.len(), 1);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(stopped.resolutions.len(), 1);
        let choices = [first, second];
        let result = resolved(&source, inputs, &choices);
        assert_eq!(
            result,
            resolved(&source, inputs, &[choices[1].clone(), choices[0].clone()])
        );
        assert_eq!(
            result
                .resolutions
                .iter()
                .map(|r| r.original)
                .collect::<Vec<_>>(),
            originals
        );
        let RebasePreparation::Clean(plan) = result.preparation else {
            panic!();
        };
        assert_eq!(
            final_file(&source, &plan),
            Some((0o100644, b"Y\nb\nc\nd\ne\nf\n".to_vec()))
        );
    }
}

#[test]
fn side_selection_delete_and_binary_files_are_explicit_not_conflict_marker_heuristics() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (source, mut inputs, originals) = conflicted(format, true);
        inputs.source_tip = originals[0];
        for (choice, expected) in [
            (ResolutionChoice::Base, Some((0o100644, BASE.to_vec()))),
            (ResolutionChoice::Ours, Some((0o100644, ONTO.to_vec()))),
            (
                ResolutionChoice::Theirs,
                Some((0o100644, b"X\nb\nc\nd\ne\nf\n".to_vec())),
            ),
            (ResolutionChoice::Delete, None),
            (
                ResolutionChoice::File {
                    mode: 0o100755,
                    bytes: b"\0\xff<<<<<<< literal user content\n".to_vec(),
                },
                Some((0o100755, b"\0\xff<<<<<<< literal user content\n".to_vec())),
            ),
        ] {
            let result = resolved(&source, inputs, &[recipe(originals[0], choice)]);
            let RebasePreparation::Clean(plan) = result.preparation else {
                panic!();
            };
            assert_eq!(final_file(&source, &plan), expected);
        }
        inputs.empty = EmptyCommitPolicy::Stop;
        let result = resolved(
            &source,
            inputs,
            &[recipe(originals[0], ResolutionChoice::Ours)],
        );
        assert!(matches!(
            result.preparation,
            RebasePreparation::Stopped {
                reason: RebaseStop::BecameEmpty,
                ..
            }
        ));
        assert_eq!(result.resolutions.len(), 1);
        inputs.empty = EmptyCommitPolicy::Drop;
        let result = resolved(
            &source,
            inputs,
            &[recipe(originals[0], ResolutionChoice::Ours)],
        );
        let RebasePreparation::Clean(plan) = result.preparation else {
            panic!();
        };
        assert_eq!(plan.commit, inputs.onto);
        assert_eq!(plan.steps[0].kind, RebaseStepKind::DroppedEmpty);
    }
}

#[test]
fn wrong_original_clean_step_duplicate_or_nonconflict_path_cannot_silently_accept_a_recipe() {
    let (source, inputs, originals) = conflicted(GitHashAlgorithm::Sha1, true);
    let run = |choices: &[RebaseCommitResolution]| {
        prepare_resolved_rebase(
            &source,
            source.format,
            inputs,
            &committer(),
            PreparationLimits::default(),
            choices,
        )
    };
    let first = recipe(originals[0], ResolutionChoice::Theirs);
    assert!(matches!(
        run(&[recipe(inputs.onto, ResolutionChoice::Ours)]),
        Err(RebaseError::ResolutionOutsideSuffix(_))
    ));
    assert!(matches!(
        run(&[first.clone(), first.clone()]),
        Err(RebaseError::DuplicateResolutionCommit(_))
    ));
    let mut extra = first.clone();
    extra.paths.push(ConflictResolution {
        path: b"not-a-conflict".to_vec(),
        choice: ResolutionChoice::Delete,
    });
    assert!(matches!(
        run(&[extra]),
        Err(RebaseError::Resolution {
            error: ResolutionError::NonConflictPath(_),
            ..
        })
    ));
    let mut duplicate = first.clone();
    duplicate.paths.push(duplicate.paths[0].clone());
    assert!(matches!(
        run(&[duplicate]),
        Err(RebaseError::Resolution {
            error: ResolutionError::DuplicatePath(_),
            ..
        })
    ));
    let (clean_source, clean_inputs, clean_originals) = fixture(GitHashAlgorithm::Sha256);
    assert!(matches!(
        prepare_resolved_rebase(
            &clean_source,
            clean_source.format,
            clean_inputs,
            &committer(),
            PreparationLimits::default(),
            &[recipe(clean_originals[0], ResolutionChoice::Ours)]
        ),
        Err(RebaseError::Resolution {
            error: ResolutionError::NoConflicts,
            ..
        })
    ));
    assert_eq!(
        resolved(&clean_source, clean_inputs, &[]).preparation,
        run_without_choices(&clean_source, clean_inputs)
    );
}
fn run_without_choices(source: &Source, inputs: RebaseRequest) -> RebasePreparation {
    prepare_rebase(
        source,
        source.format,
        inputs,
        &committer(),
        PreparationLimits::default(),
    )
    .unwrap()
}

#[test]
fn whole_series_resolution_intake_and_output_budgets_are_not_reset_per_step() {
    let (source, inputs, originals) = conflicted(GitHashAlgorithm::Sha1, true);
    // Keep a distinct resolved first-line value, so the second original
    // really conflicts too. Choosing Theirs here reproduces the second
    // commit's exact base and correctly makes its later recipe invalid.
    let choices = [
        recipe(
            originals[0],
            ResolutionChoice::File {
                mode: 0o100644,
                bytes: b"R\nb\nc\nd\ne\nf\n".to_vec(),
            },
        ),
        recipe(originals[1], ResolutionChoice::Theirs),
    ];
    source.polls.set(0);
    assert!(matches!(
        prepare_resolved_rebase(
            &source,
            source.format,
            inputs,
            &committer(),
            PreparationLimits {
                max_conflicts: 1,
                ..PreparationLimits::default()
            },
            &choices
        ),
        Err(RebaseError::Preparation(PreparationError::Budget(
            "rebase resolution paths"
        )))
    ));
    assert_eq!(
        source.polls.get(),
        0,
        "intake refusal precedes source reads"
    );
    let large = originals.map(|id| {
        recipe(
            id,
            ResolutionChoice::File {
                mode: 0o100644,
                bytes: vec![b'x'; 8],
            },
        )
    });
    assert!(matches!(
        validate_rebase_resolutions(
            source.format,
            PreparationLimits {
                max_output_bytes: 12,
                ..PreparationLimits::default()
            },
            &large
        ),
        Err(RebaseError::Preparation(PreparationError::Budget(
            "rebase resolution bytes"
        )))
    ));
    let baseline = resolved(&source, inputs, &choices);
    assert_eq!(
        baseline
            .resolutions
            .iter()
            .map(|step| step.original)
            .collect::<Vec<_>>(),
        originals
    );
    let RebasePreparation::Clean(plan) = baseline.preparation else {
        panic!();
    };
    assert_eq!(plan.steps.len(), 2);
    assert_eq!(
        final_file(&source, &plan),
        Some((0o100644, b"Y\nb\nc\nd\ne\nf\n".to_vec()))
    );
    let limits = PreparationLimits {
        max_objects: plan.objects.len() - 1,
        ..PreparationLimits::default()
    };
    assert!(
        prepare_resolved_rebase(
            &source,
            source.format,
            inputs,
            &committer(),
            limits,
            &choices
        )
        .is_err()
    );
}

#[test]
fn cancellation_during_discovery_resolution_or_later_replay_never_returns_a_candidate() {
    let (source, inputs, originals) = conflicted(GitHashAlgorithm::Sha256, true);
    // Keep a distinct resolved first-line value, so the second original
    // really conflicts too. Choosing Theirs here reproduces the second
    // commit's exact base and correctly makes its later recipe invalid.
    let choices = [
        recipe(
            originals[0],
            ResolutionChoice::File {
                mode: 0o100644,
                bytes: b"R\nb\nc\nd\ne\nf\n".to_vec(),
            },
        ),
        recipe(originals[1], ResolutionChoice::Theirs),
    ];
    let baseline = resolved(&source, inputs, &choices);
    assert_eq!(
        baseline
            .resolutions
            .iter()
            .map(|step| step.original)
            .collect::<Vec<_>>(),
        originals
    );
    assert!(matches!(baseline.preparation, RebasePreparation::Clean(_)));
    let polls = source.polls.get();
    for cutoff in [1, polls / 3, polls * 2 / 3, polls] {
        source.polls.set(0);
        source.stop.set(cutoff);
        let result = prepare_resolved_rebase(
            &source,
            source.format,
            inputs,
            &committer(),
            PreparationLimits::default(),
            &choices,
        );
        assert!(
            matches!(
                result,
                Err(RebaseError::Preparation(PreparationError::Source(
                    MergeSourceError::Cancelled
                ))) | Err(RebaseError::Resolution {
                    error: ResolutionError::Preparation(PreparationError::Source(
                        MergeSourceError::Cancelled
                    )),
                    ..
                })
            ),
            "{result:?}"
        );
    }
}

#[test]
fn selecting_original_first_tree_requires_no_resolution_of_clean_second_replay() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (source, inputs, originals) = conflicted(format, true);
        let first = recipe(originals[0], ResolutionChoice::Theirs);
        let result = resolved(&source, inputs, std::slice::from_ref(&first));
        assert_eq!(result.resolutions.len(), 1);
        let RebasePreparation::Clean(plan) = result.preparation else {
            panic!();
        };
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(
            final_file(&source, &plan),
            Some((0o100644, b"Y\nb\nc\nd\ne\nf\n".to_vec()))
        );
        assert!(
            matches!(prepare_resolved_rebase(&source, format, inputs, &committer(),
            PreparationLimits::default(), &[first, recipe(originals[1], ResolutionChoice::Theirs)]),
            Err(RebaseError::Resolution { original, error: ResolutionError::NoConflicts }) if original == originals[1])
        );
    }
}
