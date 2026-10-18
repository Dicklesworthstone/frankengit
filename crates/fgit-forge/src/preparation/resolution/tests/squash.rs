//! Exact resolved trees reuse the conflict oracle under both commit styles.
use super::*;

fn run_squash(
    source: &Source,
    inputs: ResolutionInputs,
    choices: &[ConflictResolution],
    limits: PreparationLimits,
) -> Result<ResolvedMerge, ResolutionError> {
    prepare_resolved_merge_with_style(
        source,
        source.format,
        inputs,
        choices,
        &metadata(),
        limits,
        MergeCommitStyle::Squash,
    )
}

#[test]
fn every_resolution_choice_preserves_legacy_bytes_and_has_one_exact_squash_parent() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut source, inputs, entries) = simple(format);
        let manual = source.file(b"file", b"\xff\0resolved\r\nwithout newline", 0o100755);
        for (choice, expected) in [
            (ResolutionChoice::Base, Some(entries[0].clone())),
            (ResolutionChoice::Ours, Some(entries[1].clone())),
            (ResolutionChoice::Theirs, Some(entries[2].clone())),
            (ResolutionChoice::Delete, None),
            (
                ResolutionChoice::File {
                    mode: 0o100755,
                    bytes: b"\xff\0resolved\r\nwithout newline".to_vec(),
                },
                Some(manual.clone()),
            ),
        ] {
            let expected_tree = source.store_tree(expected.clone().into_iter().collect());
            let choices = [resolution(b"file", choice)];
            let legacy = run(&source, inputs, &choices).unwrap();
            assert_eq!(
                legacy,
                prepare_resolved_merge_with_style(
                    &source,
                    format,
                    inputs,
                    &choices,
                    &metadata(),
                    PreparationLimits::default(),
                    MergeCommitStyle::TwoParent,
                )
                .unwrap()
            );
            let squash =
                run_squash(&source, inputs, &choices, PreparationLimits::default()).unwrap();
            assert_eq!(
                squash,
                run_squash(&source, inputs, &choices, PreparationLimits::default()).unwrap()
            );
            assert_eq!(squash.plan.style, MergeCommitStyle::Squash);
            assert_eq!(legacy.plan.style, MergeCommitStyle::TwoParent);
            assert_eq!(squash.plan.tree, expected_tree);
            assert_eq!(legacy.plan.tree, expected_tree);
            assert_eq!(squash.resolutions, legacy.resolutions);
            assert_eq!(squash.resolutions[0].result, expected);
            assert_eq!(
                (squash.plan.base, squash.plan.target, squash.plan.source),
                (inputs.base, inputs.target, inputs.source)
            );
            let expected_body = format!(
                "tree {expected_tree}\nparent {}\nauthor T <t@x> 1 +0000\ncommitter T <t@x> 1 +0000\n\nexplicitly resolved\n",
                inputs.target
            ).into_bytes();
            let commit = squash
                .plan
                .objects
                .iter()
                .find(|object| object.id == squash.plan.commit)
                .unwrap();
            assert_eq!(commit.body, expected_body);
            assert_eq!(commit.kind, GitObjectKind::Commit);
            assert_eq!(
                squash.plan.commit,
                git_object_id(format, GitObjectKind::Commit, &expected_body)
            );
            assert_ne!(squash.plan.commit, legacy.plan.commit);
            let data_objects = |plan: &PreparedMerge| {
                plan.objects
                    .iter()
                    .filter(|object| object.kind != GitObjectKind::Commit)
                    .cloned()
                    .collect::<Vec<_>>()
            };
            assert_eq!(data_objects(&squash.plan), data_objects(&legacy.plan));
            for object in &squash.plan.objects {
                assert_eq!(object.id, git_object_id(format, object.kind, &object.body));
            }
            assert!(
                matches!(
                    prepare_merge(
                        &source,
                        format,
                        inputs.target,
                        inputs.source,
                        &metadata(),
                        PreparationLimits::default()
                    )
                    .unwrap(),
                    MergePreparation::Conflicted { .. }
                ),
                "resolving a candidate cannot rewrite its inputs or erase their conflict"
            );
        }
    }
}

#[test]
fn squash_resolution_keeps_clean_automatic_content_and_untouched_objects() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let base = source.file(b"conflict", b"base\n", 0o100644);
        let ours = source.file(b"conflict", b"ours\n", 0o100644);
        let theirs = source.file(b"conflict", b"theirs\n", 0o100644);
        let auto_base = source.file(b"auto", b"a\nb\nc\nd\ne\n", 0o100644);
        let auto_ours = source.file(b"auto", b"A\nb\nc\nd\ne\n", 0o100644);
        let auto_theirs = source.file(b"auto", b"a\nb\nc\nd\nE\n", 0o100644);
        let keep = source.file(b"keep", b"unchanged", 0o100644);
        let inputs = source.fork(
            vec![auto_base, base, keep.clone()],
            vec![auto_ours, ours, keep.clone()],
            vec![auto_theirs, theirs.clone(), keep.clone()],
        );
        let auto = source.file(b"auto", b"A\nb\nc\nd\nE\n", 0o100644);
        let expected = source.store_tree(vec![auto, theirs, keep.clone()]);
        let choices = [resolution(b"conflict", ResolutionChoice::Theirs)];
        let result = run_squash(&source, inputs, &choices, PreparationLimits::default()).unwrap();
        assert_eq!(result.plan.tree, expected);
        assert_eq!(result.resolutions.len(), 1);
        assert_eq!(result.resolutions[0].conflict.path, b"conflict");
        assert!(
            !result
                .plan
                .objects
                .iter()
                .any(|object| object.id == keep.oid)
        );
        assert!(matches!(
            run_squash(
                &source,
                inputs,
                &[
                    choices[0].clone(),
                    resolution(b"auto", ResolutionChoice::Delete)
                ],
                PreparationLimits::default()
            ),
            Err(ResolutionError::NonConflictPath(_))
        ));
    }
}

#[test]
fn squash_choices_reject_missing_duplicate_extra_stale_base_and_absent_sides() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (source, inputs, _) = simple(format);
        let choices = [resolution(b"file", ResolutionChoice::Theirs)];
        assert!(matches!(
            run_squash(&source, inputs, &[], PreparationLimits::default()),
            Err(ResolutionError::Unresolved(_))
        ));
        assert!(matches!(
            run_squash(
                &source,
                inputs,
                &[choices[0].clone(), choices[0].clone()],
                PreparationLimits::default()
            ),
            Err(ResolutionError::DuplicatePath(_))
        ));
        assert!(matches!(
            run_squash(
                &source,
                inputs,
                &[resolution(b"missing", ResolutionChoice::Delete)],
                PreparationLimits::default()
            ),
            Err(ResolutionError::NonConflictPath(_))
        ));
        assert!(matches!(
            run_squash(
                &source,
                ResolutionInputs {
                    base: inputs.target,
                    ..inputs
                },
                &choices,
                PreparationLimits::default()
            ),
            Err(ResolutionError::BaseMismatch { .. })
        ));
        assert!(run_squash(&source, inputs, &choices, PreparationLimits::default()).is_ok());

        let mut source = Source::new(format);
        let base = source.file(b"file", b"base", 0o100644);
        let theirs = source.file(b"file", b"changed", 0o100644);
        let inputs = source.fork(vec![base], vec![], vec![theirs]);
        assert!(matches!(
            run_squash(
                &source,
                inputs,
                &[resolution(b"file", ResolutionChoice::Ours)],
                PreparationLimits::default()
            ),
            Err(ResolutionError::MissingSide { .. })
        ));
        assert!(
            run_squash(
                &source,
                inputs,
                &[resolution(b"file", ResolutionChoice::Delete)],
                PreparationLimits::default()
            )
            .is_ok()
        );
    }
}

#[test]
fn squash_discovery_reconstruction_and_commit_share_inclusive_budgets() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (source, inputs, _) = simple(format);
        let choices = [resolution(
            b"file",
            ResolutionChoice::File {
                mode: 0o100755,
                bytes: b"explicit\n".to_vec(),
            },
        )];
        let baseline = run_squash(&source, inputs, &choices, PreparationLimits::default()).unwrap();
        for limits in [
            PreparationLimits {
                max_content_merges: 1,
                ..PreparationLimits::default()
            },
            PreparationLimits {
                max_tree_entries: 3,
                ..PreparationLimits::default()
            },
        ] {
            assert!(matches!(
                run_squash(&source, inputs, &choices, limits),
                Err(ResolutionError::Preparation(PreparationError::Budget(_)))
            ));
        }
        let bytes = baseline
            .plan
            .objects
            .iter()
            .map(|object| object.body.len())
            .sum::<usize>();
        let limits = PreparationLimits {
            max_output_bytes: bytes,
            ..PreparationLimits::default()
        };
        assert_eq!(
            run_squash(&source, inputs, &choices, limits).unwrap(),
            baseline
        );
        let limits = PreparationLimits {
            max_output_bytes: bytes - 1,
            ..limits
        };
        assert!(matches!(
            run_squash(&source, inputs, &choices, limits),
            Err(ResolutionError::Preparation(PreparationError::Budget(_)))
        ));
    }
}

#[test]
fn cancellation_at_every_resolution_checkpoint_returns_no_candidate_and_does_not_poison_retry() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (source, inputs, _) = simple(format);
        let choices = [resolution(b"file", ResolutionChoice::Theirs)];
        let baseline = run_squash(&source, inputs, &choices, PreparationLimits::default()).unwrap();
        let checkpoints = usize::MAX - source.remaining.get();
        assert!(checkpoints > 10);
        for remaining in 0..checkpoints {
            source.remaining.set(remaining);
            assert!(
                run_squash(&source, inputs, &choices, PreparationLimits::default()).is_err(),
                "checkpoint {remaining}"
            );
            assert_eq!(
                source.remaining.get(),
                0,
                "refusal must reach the injected cancellation"
            );
        }
        source.remaining.set(usize::MAX);
        assert_eq!(
            run_squash(&source, inputs, &choices, PreparationLimits::default()).unwrap(),
            baseline
        );
    }
}

#[test]
fn a_squash_resolution_cannot_create_conflicts_or_accept_invalid_native_inputs() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let entry = source.file(b"file", b"unchanged", 0o100644);
        let tree = source.store_tree(vec![entry]);
        let target = source.store_commit(tree, &[], "target");
        let incoming = source.store_commit(tree, &[target], "source");
        let inputs = ResolutionInputs {
            base: target,
            target,
            source: incoming,
        };
        assert!(matches!(
            run_squash(&source, inputs, &[], PreparationLimits::default()),
            Err(ResolutionError::NoConflicts)
        ));
        assert!(matches!(
            run_squash(
                &source,
                ResolutionInputs {
                    source: target,
                    ..inputs
                },
                &[],
                PreparationLimits::default()
            ),
            Err(ResolutionError::InvalidInputs)
        ));
        let (source, inputs, _) = simple(format);
        let mut invalid = metadata();
        invalid.author.push('\n');
        assert!(matches!(
            prepare_resolved_merge_with_style(
                &source,
                format,
                inputs,
                &[resolution(b"file", ResolutionChoice::Theirs)],
                &invalid,
                PreparationLimits::default(),
                MergeCommitStyle::Squash
            ),
            Err(ResolutionError::Preparation(
                PreparationError::InvalidMetadata
            ))
        ));
    }
}
