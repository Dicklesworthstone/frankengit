use super::*;

fn clean(result: Result<MergePreparation, PreparationError>) -> PreparedMerge {
    match result.unwrap() {
        MergePreparation::Clean(plan) => plan,
        other => panic!("expected a clean candidate, got {other:?}"),
    }
}

fn candidate_body(plan: &PreparedMerge) -> &[u8] {
    &plan
        .objects
        .iter()
        .find(|object| object.id == plan.commit)
        .expect("the generated commit is included")
        .body
}

#[test]
fn squash_preserves_merged_tree_and_exact_metadata_with_one_target_parent() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for profile in [MergeProfile::PathMergeV1, MergeProfile::ExactRenamesV1] {
            let mut source = Source::new(format);
            let b = source.file(b"file", b"one\ntwo\nthree\nfour\nfive\n", 0o100644);
            let o = source.file(b"file", b"ONE\ntwo\nthree\nfour\nfive\n", 0o100755);
            let t = source.file(b"file", b"one\ntwo\nthree\nfour\nFIVE\n", 0o100644);
            let (target, incoming) = branch_pair(&mut source, vec![b], vec![o], vec![t]);
            let metadata = MergeMetadata {
                author: "Author <author@example.test>".into(),
                committer: "Committer <committer@example.test>".into(),
                timestamp: 1_700_000_000,
                message: b"squash message\nraw byte: \xff\n".to_vec(),
            };
            let prepare = |style| {
                prepare_merge_with_options(
                    &source,
                    format,
                    target,
                    incoming,
                    &metadata,
                    PreparationLimits::default(),
                    profile,
                    style,
                )
            };
            let plan = clean(prepare(MergeCommitStyle::Squash));
            assert_eq!(plan, clean(prepare(MergeCommitStyle::Squash)));
            assert_eq!(plan.style, MergeCommitStyle::Squash);
            assert_eq!(plan.target, target);
            assert_eq!(plan.source, incoming);
            let blob_body = b"ONE\ntwo\nthree\nfour\nFIVE\n";
            let blob = git_object_id(format, GitObjectKind::Blob, blob_body);
            let mut tree_body = b"100755 file\0".to_vec();
            tree_body.extend_from_slice(blob.as_bytes());
            let tree = git_object_id(format, GitObjectKind::Tree, &tree_body);
            let mut body = format!(
                "tree {tree}\nparent {target}\nauthor Author <author@example.test> 1700000000 +0000\ncommitter Committer <committer@example.test> 1700000000 +0000\n\n"
            )
            .into_bytes();
            body.extend_from_slice(&metadata.message);
            assert_eq!(plan.tree, tree);
            assert_eq!(candidate_body(&plan), body);
            assert_eq!(plan.commit, git_object_id(format, GitObjectKind::Commit, &body));
            assert_ne!(plan.commit, target);
            assert_ne!(plan.commit, incoming);
            assert!(plan.objects.iter().any(|object| {
                object.id == blob && object.kind == GitObjectKind::Blob && object.body == blob_body
            }));
            assert!(plan.objects.iter().any(|object| {
                object.id == tree && object.kind == GitObjectKind::Tree && object.body == tree_body
            }));
            let ordinary = clean(prepare(MergeCommitStyle::TwoParent));
            assert_eq!(ordinary.tree, plan.tree);
            assert_ne!(ordinary.commit, plan.commit);
            assert_eq!(
                ordinary
                    .objects
                    .iter()
                    .filter(|object| object.kind != GitObjectKind::Commit)
                    .collect::<Vec<_>>(),
                plan.objects
                    .iter()
                    .filter(|object| object.kind != GitObjectKind::Commit)
                    .collect::<Vec<_>>()
            );
            for object in &plan.objects {
                assert_eq!(object.id, git_object_id(format, object.kind, &object.body));
            }
        }
    }
}

#[test]
fn legacy_entry_points_keep_the_same_two_parent_commit_and_default() {
    assert_eq!(MergeCommitStyle::default(), MergeCommitStyle::TwoParent);
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let old_tree = source.store_tree(vec![]);
        let target = source.store_commit(old_tree, &[], "target");
        let added = source.file(b"added", b"new\n", 0o100644);
        let tree = source.store_tree(vec![added]);
        let incoming = source.store_commit(tree, &[target], "incoming");
        let metadata = metadata();
        let legacy = clean(prepare_merge(
            &source,
            format,
            target,
            incoming,
            &metadata,
            PreparationLimits::default(),
        ));
        let body = format!(
            "tree {tree}\nparent {target}\nparent {incoming}\nauthor T <t@x> 1 +0000\ncommitter T <t@x> 1 +0000\n\nmerge\n"
        );
        assert_eq!(candidate_body(&legacy), body.as_bytes());
        assert_eq!(
            legacy.commit,
            git_object_id(format, GitObjectKind::Commit, body.as_bytes())
        );
        for profile in [MergeProfile::PathMergeV1, MergeProfile::ExactRenamesV1] {
            assert_eq!(
                legacy,
                clean(prepare_merge_with_profile(
                    &source,
                    format,
                    target,
                    incoming,
                    &metadata,
                    PreparationLimits::default(),
                    profile,
                ))
            );
            assert_eq!(
                legacy,
                clean(prepare_merge_with_options(
                    &source,
                    format,
                    target,
                    incoming,
                    &metadata,
                    PreparationLimits::default(),
                    profile,
                    MergeCommitStyle::TwoParent,
                ))
            );
        }
    }
}

#[test]
fn fast_forward_capable_squash_constructs_a_commit_and_integrated_source_is_a_noop() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let old_tree = source.store_tree(vec![]);
        let target = source.store_commit(old_tree, &[], "target");
        let middle = source.store_commit(old_tree, &[target], "middle");
        let file = source.file(b"added", b"topic changes\n", 0o100644);
        let tree = source.store_tree(vec![file]);
        let incoming = source.store_commit(tree, &[middle], "incoming");
        for profile in [MergeProfile::PathMergeV1, MergeProfile::ExactRenamesV1] {
            let prepare = |target, incoming| {
                prepare_merge_with_options(
                    &source,
                    format,
                    target,
                    incoming,
                    &metadata(),
                    PreparationLimits::default(),
                    profile,
                    MergeCommitStyle::Squash,
                )
            };
            let plan = clean(prepare(target, incoming));
            assert_eq!(plan.tree, tree);
            assert_eq!(plan.objects.len(), 1);
            assert_ne!(plan.commit, incoming);
            assert_eq!(
                candidate_body(&plan),
                format!(
                    "tree {tree}\nparent {target}\nauthor T <t@x> 1 +0000\ncommitter T <t@x> 1 +0000\n\nmerge\n"
                )
                .as_bytes()
            );
            assert_eq!(
                prepare(incoming, target).unwrap(),
                MergePreparation::AlreadyUpToDate { target: incoming }
            );
            assert_eq!(
                prepare(incoming, incoming).unwrap(),
                MergePreparation::AlreadyUpToDate { target: incoming }
            );
        }
    }
}

#[test]
fn explicit_rename_profile_preserves_rename_and_edit_only_when_selected() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let b = source.file(b"old", b"original\n", 0o100644);
        let o = source.file(b"new", b"original\n", 0o100644);
        let t = source.file(b"old", b"edited\n", 0o100755);
        let expected = source.file(b"new", b"edited\n", 0o100755);
        let tree = source.store_tree(vec![expected]);
        let (target, incoming) = branch_pair(&mut source, vec![b], vec![o], vec![t]);
        let prepare = |profile| {
            prepare_merge_with_options(
                &source,
                format,
                target,
                incoming,
                &metadata(),
                PreparationLimits::default(),
                profile,
                MergeCommitStyle::Squash,
            )
        };
        assert!(matches!(
            prepare(MergeProfile::PathMergeV1).unwrap(),
            MergePreparation::Conflicted { .. }
        ));
        let plan = clean(prepare(MergeProfile::ExactRenamesV1));
        assert_eq!(plan.tree, tree);
        assert_eq!(plan.style, MergeCommitStyle::Squash);
        assert!(candidate_body(&plan).starts_with(
            format!("tree {tree}\nparent {target}\nauthor ").as_bytes()
        ));
    }
}

#[test]
fn squash_cannot_convert_content_or_binary_conflicts_into_a_candidate() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for (base, ours, theirs, kind) in [
            (
                b"base\n".as_slice(),
                b"ours\n".as_slice(),
                b"theirs\n".as_slice(),
                ConflictKind::Content,
            ),
            (
                b"\0base".as_slice(),
                b"\0ours".as_slice(),
                b"\0theirs".as_slice(),
                ConflictKind::Binary,
            ),
        ] {
            let mut source = Source::new(format);
            let b = source.file(b"file", base, 0o100644);
            let o = source.file(b"file", ours, 0o100644);
            let t = source.file(b"file", theirs, 0o100644);
            let (target, incoming) = branch_pair(&mut source, vec![b], vec![o], vec![t]);
            for profile in [MergeProfile::PathMergeV1, MergeProfile::ExactRenamesV1] {
                let result = prepare_merge_with_options(
                    &source,
                    format,
                    target,
                    incoming,
                    &metadata(),
                    PreparationLimits::default(),
                    profile,
                    MergeCommitStyle::Squash,
                )
                .unwrap();
                assert!(matches!(
                    &result,
                    MergePreparation::Conflicted { conflicts, .. }
                        if conflicts.len() == 1 && conflicts[0].kind == kind
                ));
                assert_eq!(
                    result,
                    prepare_merge_with_profile(
                        &source,
                        format,
                        target,
                        incoming,
                        &metadata(),
                        PreparationLimits::default(),
                        profile,
                    )
                    .unwrap()
                );
            }
        }
    }
}

#[test]
fn squash_refuses_multiple_unrelated_or_mixed_format_ancestors() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let tree = source.store_tree(vec![]);
        let root = source.store_commit(tree, &[], "root");
        let a = source.store_commit(tree, &[root], "a");
        let b = source.store_commit(tree, &[root], "b");
        let left = source.store_commit(tree, &[a, b], "left");
        let right = source.store_commit(tree, &[b, a], "right");
        let other = source.store_commit(tree, &[], "unrelated");
        let opposite = match format {
            GitHashAlgorithm::Sha1 => GitHashAlgorithm::Sha256,
            GitHashAlgorithm::Sha256 => GitHashAlgorithm::Sha1,
        };
        let mixed = git_object_id(opposite, GitObjectKind::Commit, b"mixed");
        for profile in [MergeProfile::PathMergeV1, MergeProfile::ExactRenamesV1] {
            let prepare = |target, incoming| {
                prepare_merge_with_options(
                    &source,
                    format,
                    target,
                    incoming,
                    &metadata(),
                    PreparationLimits::default(),
                    profile,
                    MergeCommitStyle::Squash,
                )
            };
            assert!(matches!(
                prepare(left, right),
                Err(PreparationError::MultipleMergeBases(bases)) if bases.len() == 2
            ));
            assert!(matches!(
                prepare(left, other),
                Err(PreparationError::NoCommonAncestor)
            ));
            assert!(matches!(
                prepare(left, mixed),
                Err(PreparationError::ObjectFormat)
            ));
            assert_eq!(clean(prepare(a, b)).tree, tree);
        }
    }
}

#[test]
fn squash_commit_bytes_keep_the_existing_output_budget_and_metadata_guards() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let tree = source.store_tree(vec![]);
        let target = source.store_commit(tree, &[], "target");
        let incoming = source.store_commit(tree, &[target], "incoming");
        let metadata = metadata();
        let prepare = |metadata: &MergeMetadata, limits| {
            prepare_merge_with_options(
                &source,
                format,
                target,
                incoming,
                metadata,
                limits,
                MergeProfile::PathMergeV1,
                MergeCommitStyle::Squash,
            )
        };
        let plan = clean(prepare(&metadata, PreparationLimits::default()));
        assert_eq!(plan.objects.len(), 1);
        let required = candidate_body(&plan).len();
        assert!(matches!(
            prepare(
                &metadata,
                PreparationLimits {
                    max_output_bytes: required - 1,
                    ..PreparationLimits::default()
                }
            ),
            Err(PreparationError::Budget("commit bytes"))
        ));
        assert_eq!(
            plan,
            clean(prepare(
                &metadata,
                PreparationLimits {
                    max_output_bytes: required,
                    ..PreparationLimits::default()
                }
            ))
        );
        let mut invalid = metadata;
        invalid.author = "T <t@x>\nparent forged".into();
        assert!(matches!(
            prepare(&invalid, PreparationLimits::default()),
            Err(PreparationError::InvalidMetadata)
        ));
    }
}

struct InterruptedSource<'a> {
    source: &'a Source,
    checkpoints: Cell<usize>,
    stop_at: usize,
}

impl MergeObjectSource for InterruptedSource<'_> {
    fn checkpoint(&self) -> Result<(), MergeSourceError> {
        let observed = self.checkpoints.get() + 1;
        self.checkpoints.set(observed);
        if observed >= self.stop_at {
            return Err(MergeSourceError::Cancelled);
        }
        self.source.checkpoint()
    }

    fn commit(&self, id: GitOid) -> Result<CommitInput, MergeSourceError> {
        self.source.commit(id)
    }

    fn tree(&self, id: GitOid) -> Result<Vec<MergeEntry>, MergeSourceError> {
        self.source.tree(id)
    }

    fn blob(&self, id: GitOid) -> Result<Vec<u8>, MergeSourceError> {
        self.source.blob(id)
    }
}

#[test]
fn cancellation_at_every_observed_checkpoint_returns_no_squash_candidate() {
    let mut source = Source::new(GitHashAlgorithm::Sha256);
    let b = source.file(b"file", b"one\ntwo\nthree\nfour\nfive\n", 0o100644);
    let o = source.file(b"file", b"ONE\ntwo\nthree\nfour\nfive\n", 0o100644);
    let t = source.file(b"file", b"one\ntwo\nthree\nfour\nFIVE\n", 0o100644);
    let (target, incoming) = branch_pair(&mut source, vec![b], vec![o], vec![t]);
    for profile in [MergeProfile::PathMergeV1, MergeProfile::ExactRenamesV1] {
        let run = |interrupted: &InterruptedSource<'_>| {
            prepare_merge_with_options(
                interrupted,
                source.format,
                target,
                incoming,
                &metadata(),
                PreparationLimits::default(),
                profile,
                MergeCommitStyle::Squash,
            )
        };
        let uninterrupted = InterruptedSource {
            source: &source,
            checkpoints: Cell::new(0),
            stop_at: usize::MAX,
        };
        let baseline = clean(run(&uninterrupted));
        let checkpoints = uninterrupted.checkpoints.get();
        assert!(checkpoints > 10);
        for stop_at in 1..=checkpoints {
            let interrupted = InterruptedSource {
                source: &source,
                checkpoints: Cell::new(0),
                stop_at,
            };
            assert!(run(&interrupted).is_err(), "checkpoint {stop_at}");
        }
        assert_eq!(clean(run(&uninterrupted)), baseline);
    }
}

#[test]
fn squash_may_reuse_a_single_topic_commit_when_metadata_and_parent_bytes_are_identical() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let old_tree = source.store_tree(vec![]);
        let target = source.store_commit(old_tree, &[], "target");
        let file = source.file(b"file", b"single topic change\n", 0o100644);
        let tree = source.store_tree(vec![file]);
        let incoming = source.store_commit(tree, &[target], "single topic\n");
        let mut metadata = metadata();
        metadata.message = b"single topic\n".to_vec();
        for profile in [MergeProfile::PathMergeV1, MergeProfile::ExactRenamesV1] {
            let plan = clean(prepare_merge_with_options(
                &source,
                format,
                target,
                incoming,
                &metadata,
                PreparationLimits::default(),
                profile,
                MergeCommitStyle::Squash,
            ));
            assert_eq!(plan.style, MergeCommitStyle::Squash);
            assert_eq!(plan.commit, incoming);
            assert_eq!(plan.tree, tree);
            assert_eq!(plan.objects.len(), 1);
            assert_eq!(
                candidate_body(&plan),
                format!(
                    "tree {tree}\nparent {target}\nauthor T <t@x> 1 +0000\ncommitter T <t@x> 1 +0000\n\nsingle topic\n"
                )
                .as_bytes()
            );
            let ordinary = clean(prepare_merge_with_profile(
                &source,
                format,
                target,
                incoming,
                &metadata,
                PreparationLimits::default(),
                profile,
            ));
            assert_ne!(ordinary.commit, incoming);
        }
    }
}
