use super::*;

fn recursive(
    source: &Source,
    target: GitOid,
    incoming: GitOid,
    limits: PreparationLimits,
) -> Result<MergePreparation, PreparationError> {
    prepare_merge_with_profile(
        source,
        source.format,
        target,
        incoming,
        &metadata(),
        limits,
        MergeProfile::RecursivePathMergeV1,
    )
}

fn clean(result: Result<MergePreparation, PreparationError>) -> PreparedMerge {
    match result.unwrap() {
        MergePreparation::Clean(plan) => plan,
        other => panic!("expected clean recursive merge: {other:?}"),
    }
}

fn files(source: &mut Source, values: &[(&[u8], &[u8])]) -> GitOid {
    let entries = values
        .iter()
        .map(|(name, bytes)| source.file(name, bytes, 0o100644))
        .collect();
    source.store_tree(entries)
}

// Compute the oracle without making its tree or blob available to the source.
// A missing generated-object overlay must fail instead of reading the answer
// from fixture storage.
fn expected_files(format: GitHashAlgorithm, values: &[(&[u8], &[u8])]) -> GitOid {
    let mut values = values.to_vec();
    values.sort_by(|left, right| left.0.cmp(right.0));
    let mut body = Vec::new();
    for (name, bytes) in values {
        body.extend_from_slice(b"100644 ");
        body.extend_from_slice(name);
        body.push(0);
        body.extend_from_slice(git_object_id(format, GitObjectKind::Blob, bytes).as_bytes());
    }
    git_object_id(format, GitObjectKind::Tree, &body)
}

struct Cross {
    bases: Vec<GitOid>,
    target: GitOid,
    incoming: GitOid,
    comparison: GitOid,
    result: GitOid,
}

// Each tip has integrated both bases, then independently reverts one change.
// Choosing either original base instead of synthesizing their joint tree loses
// one of those reversions. The expected result is the original root tree.
fn reverted_cross(source: &mut Source) -> Cross {
    let root_tree = files(source, &[(b"a", b"0\n"), (b"b", b"0\n")]);
    let root = source.store_commit(root_tree, &[], "root");
    let a_tree = files(source, &[(b"a", b"1\n"), (b"b", b"0\n")]);
    let b_tree = files(source, &[(b"a", b"0\n"), (b"b", b"1\n")]);
    let a = source.store_commit(a_tree, &[root], "a");
    let b = source.store_commit(b_tree, &[root], "b");
    let target = source.store_commit(b_tree, &[a, b], "revert a");
    let incoming = source.store_commit(a_tree, &[b, a], "revert b");
    let comparison = expected_files(source.format, &[(b"a", b"1\n"), (b"b", b"1\n")]);
    let mut bases = vec![a, b];
    bases.sort();
    Cross {
        bases,
        target,
        incoming,
        comparison,
        result: root_tree,
    }
}

#[test]
fn criss_cross_reverts_use_the_joint_base_not_either_individual_ancestor() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let fixture = reverted_cross(&mut source);
        let plan = clean(recursive(
            &source,
            fixture.target,
            fixture.incoming,
            PreparationLimits::default(),
        ));
        assert_eq!(plan.tree, fixture.result);
        assert_eq!(plan.base, fixture.bases[0]);
        assert_eq!(
            plan.recursive_base,
            Some(RecursiveMergeBase {
                bases: fixture.bases.clone(),
                tree: fixture.comparison,
            })
        );
        assert_eq!(
            plan,
            clean(recursive(
                &source,
                fixture.target,
                fixture.incoming,
                PreparationLimits::default(),
            ))
        );
        // This comparison tree is transient; only the final candidate closure
        // belongs in the bundle, and the sole constructed commit is the result.
        assert!(plan.objects.iter().all(|object| object.id != fixture.comparison));
        let commits: Vec<_> = plan.objects.iter()
            .filter(|object| object.kind == GitObjectKind::Commit)
            .collect();
        assert_eq!(commits.len(), 1);
        assert_eq!(commits[0].id, plan.commit);
        let expected_commit = format!(
            "tree {}\nparent {}\nparent {}\nauthor T <t@x> 1 +0000\ncommitter T <t@x> 1 +0000\n\nmerge\n",
            fixture.result, fixture.target, fixture.incoming,
        );
        assert_eq!(commits[0].body, expected_commit.as_bytes());
        assert_eq!(
            plan.commit,
            git_object_id(format, GitObjectKind::Commit, expected_commit.as_bytes())
        );
        for base in &fixture.bases {
            let mut planner = Planner::new(&source, format, PreparationLimits::default());
            let arbitrary = planner.directory(
                Some(source.commit(*base).unwrap().tree),
                source.commit(fixture.target).unwrap().tree,
                source.commit(fixture.incoming).unwrap().tree,
                &[],
                0,
                false,
            ).unwrap().unwrap();
            assert_ne!(arbitrary, fixture.result);
        }
        let swapped = clean(recursive(
            &source,
            fixture.incoming,
            fixture.target,
            PreparationLimits::default(),
        ));
        assert_eq!(swapped.tree, plan.tree);
        assert_eq!(swapped.recursive_base, plan.recursive_base);
        assert_eq!(swapped.base, plan.base);
        assert_ne!(swapped.commit, plan.commit);
        assert!(matches!(
            prepare_merge(
                &source,
                format,
                fixture.target,
                fixture.incoming,
                &metadata(),
                PreparationLimits::default(),
            ),
            Err(PreparationError::MultipleMergeBases(_))
        ));
    }
}

fn nested_cross(source: &mut Source) -> Cross {
    let tree = |source: &mut Source, values: &[u8; 6]| {
        let entries = (b'a'..=b'f').zip(values)
            .map(|(name, value)| source.file(&[name], &[*value, b'\n'], 0o100644))
            .collect();
        source.store_tree(entries)
    };
    let r_tree = tree(source, b"000000");
    let r = source.store_commit(r_tree, &[], "root");
    let a_tree = tree(source, b"100000");
    let b_tree = tree(source, b"010000");
    let a = source.store_commit(a_tree, &[r], "a");
    let b = source.store_commit(b_tree, &[r], "b");
    let c_tree = tree(source, b"111000");
    let d_tree = tree(source, b"110100");
    let c = source.store_commit(c_tree, &[a, b], "c");
    let d = source.store_commit(d_tree, &[b, a], "d");
    let left_tree = tree(source, b"110110");
    let right_tree = tree(source, b"111001");
    let target = source.store_commit(left_tree, &[c, d], "revert c add e");
    let incoming = source.store_commit(right_tree, &[d, c], "revert d add f");
    let mut bases = vec![c, d];
    bases.sort();
    let comparison = tree(source, b"111100");
    let result = tree(source, b"110011");
    source.trees.remove(&comparison);
    source.trees.remove(&result);
    Cross { bases, target, incoming, comparison, result }
}

#[test]
fn nested_criss_cross_uses_the_ancestors_own_recursive_base() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let fixture = nested_cross(&mut source);
        let plan = clean(recursive(&source, fixture.target, fixture.incoming, PreparationLimits::default()));
        assert_eq!(plan.tree, fixture.result);
        assert_eq!(plan.recursive_base, Some(RecursiveMergeBase {
            bases: fixture.bases,
            tree: fixture.comparison,
        }));
        assert!(matches!(
            recursive(&source, fixture.target, fixture.incoming, PreparationLimits {
                max_depth: 1,
                ..PreparationLimits::default()
            }),
            Err(PreparationError::Budget("merge-base recursion depth"))
        ));
    }
}

#[test]
fn three_bases_use_all_virtual_parents_and_are_independent_of_parent_order() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let tree = |source: &mut Source, values: &[u8; 3]| {
            let entries = (b'a'..=b'c').zip(values)
                .map(|(name, value)| source.file(&[name], &[*value, b'\n'], 0o100644))
                .collect();
            source.store_tree(entries)
        };
        let root_tree = tree(&mut source, b"000");
        let root = source.store_commit(root_tree, &[], "root");
        let u_tree = tree(&mut source, b"100");
        let v_tree = tree(&mut source, b"010");
        let w_tree = tree(&mut source, b"001");
        let u = source.store_commit(u_tree, &[root], "u");
        let v = source.store_commit(v_tree, &[root], "v");
        let w = source.store_commit(w_tree, &[root], "w");
        let a_tree = tree(&mut source, b"110");
        let b_tree = tree(&mut source, b"011");
        let c_tree = tree(&mut source, b"101");
        let a = source.store_commit(a_tree, &[u, v], "a");
        let b = source.store_commit(b_tree, &[v, w], "b");
        let c = source.store_commit(c_tree, &[w, u], "c");
        let comparison = tree(&mut source, b"111");
        source.trees.remove(&comparison);
        let left_tree = tree(&mut source, b"011");
        let right_tree = tree(&mut source, b"100");
        let target = source.store_commit(left_tree, &[a, b, c], "revert a");
        let incoming = source.store_commit(right_tree, &[c, b, a], "revert b c");
        let plan = clean(recursive(&source, target, incoming, PreparationLimits::default()));
        let mut bases = vec![a, b, c];
        bases.sort();
        assert_eq!(plan.tree, root_tree);
        assert_eq!(plan.recursive_base, Some(RecursiveMergeBase { bases, tree: comparison }));
        let permuted = source.store_commit(right_tree, &[b, a, c], "same tree different parents");
        let repeated = clean(recursive(&source, target, permuted, PreparationLimits::default()));
        assert_eq!(repeated.tree, plan.tree);
        assert_eq!(repeated.recursive_base, plan.recursive_base);
    }
}

fn content_cross(source: &mut Source, conflicting: bool) -> Cross {
    let base_tree = files(source, &[(b"text", b"one\ntwo\nthree\nfour\nfive\n")]);
    let root = source.store_commit(base_tree, &[], "root");
    let a_tree = files(source, &[(b"text", b"ONE\ntwo\nthree\nfour\nfive\n")]);
    let b_tree = files(source, &[(b"text", if conflicting {
        b"OTHER\ntwo\nthree\nfour\nfive\n"
    } else {
        b"one\ntwo\nthree\nfour\nFIVE\n"
    })]);
    let a = source.store_commit(a_tree, &[root], "a");
    let b = source.store_commit(b_tree, &[root], "b");
    let target = source.store_commit(b_tree, &[a, b], "revert a");
    let incoming = source.store_commit(a_tree, &[b, a], "revert b");
    let comparison = expected_files(source.format, &[(b"text", b"ONE\ntwo\nthree\nfour\nFIVE\n")]);
    let mut bases = vec![a, b];
    bases.sort();
    Cross { bases, target, incoming, comparison, result: base_tree }
}

#[test]
fn virtual_blob_merges_share_the_final_merges_content_budget() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let fixture = content_cross(&mut source, false);
        // The effective base's blob is available only through the planner's
        // generated-object overlay during the final two-sided content merge.
        let plan = clean(recursive(
            &source, fixture.target, fixture.incoming,
            PreparationLimits { max_content_merges: 2, ..PreparationLimits::default() },
        ));
        assert_eq!(plan.tree, fixture.result);
        assert_eq!(plan.recursive_base.unwrap().tree, fixture.comparison);
        assert!(matches!(
            recursive(&source, fixture.target, fixture.incoming,
                PreparationLimits { max_content_merges: 1, ..PreparationLimits::default() }),
            Err(PreparationError::Budget("content merges"))
        ));
    }
}

#[test]
fn conflicts_between_best_bases_refuse_instead_of_manufacturing_a_clean_base() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let fixture = content_cross(&mut source, true);
        match recursive(&source, fixture.target, fixture.incoming, PreparationLimits::default()) {
            Err(PreparationError::RecursiveBaseConflict { bases, conflicts }) => {
                assert_eq!(bases, fixture.bases);
                assert_eq!(conflicts.len(), 1);
                assert_eq!(conflicts[0].path, b"text");
                assert_eq!(conflicts[0].kind, ConflictKind::Content);
            }
            other => panic!("expected internal-base conflict refusal: {other:?}"),
        }
        let mut permitted = Source::new(format);
        let clean_fixture = content_cross(&mut permitted, false);
        assert_eq!(
            clean(recursive(&permitted, clean_fixture.target, clean_fixture.incoming, PreparationLimits::default())).tree,
            clean_fixture.result,
        );
    }
}

#[test]
fn unrelated_or_missing_inner_ancestors_never_use_an_empty_comparison_base() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let a_tree = files(&mut source, &[(b"a", b"left\n")]);
        let b_tree = files(&mut source, &[(b"b", b"right\n")]);
        let a = source.store_commit(a_tree, &[], "unrelated a");
        let b = source.store_commit(b_tree, &[], "unrelated b");
        let target = source.store_commit(a_tree, &[a, b], "left");
        let incoming = source.store_commit(b_tree, &[b, a], "right");
        assert!(matches!(recursive(&source, target, incoming, PreparationLimits::default()), Err(PreparationError::NoCommonAncestor)));
        let mut permitted = Source::new(format);
        let fixture = reverted_cross(&mut permitted);
        clean(recursive(&permitted, fixture.target, fixture.incoming, PreparationLimits::default()));
        let root = permitted.commits[&fixture.bases[0]].parents[0];
        permitted.commits.remove(&root);
        assert!(matches!(
            recursive(&permitted, fixture.target, fixture.incoming, PreparationLimits::default()),
            Err(PreparationError::Graph(MergeBaseError::Source(MergeSourceError::Unavailable(id)))) if id == root
        ));
    }
}

#[test]
fn final_conflicts_keep_the_real_ancestry_anchor_and_the_comparison_tree() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let fixture = reverted_cross(&mut source);
        let left_tree = files(&mut source, &[(b"a", b"left\n"), (b"b", b"1\n")]);
        let right_tree = files(&mut source, &[(b"a", b"right\n"), (b"b", b"1\n")]);
        let target = source.store_commit(left_tree, &fixture.bases, "left conflict");
        let incoming = source.store_commit(right_tree, &fixture.bases, "right conflict");
        match recursive(&source, target, incoming, PreparationLimits::default()).unwrap() {
            MergePreparation::Conflicted { base, recursive_base, conflicts } => {
                assert_eq!(base, fixture.bases[0]);
                assert_eq!(recursive_base, Some(RecursiveMergeBase { bases: fixture.bases, tree: fixture.comparison }));
                assert_eq!(conflicts.len(), 1);
                assert_eq!(conflicts[0].path, b"a");
                assert_eq!(conflicts[0].kind, ConflictKind::Content);
            }
            other => panic!("expected final conflict: {other:?}"),
        }
    }
}

#[test]
fn recursive_queries_and_discarded_objects_share_one_preparation_budget() {
    let mut source = Source::new(GitHashAlgorithm::Sha1);
    let fixture = reverted_cross(&mut source);
    let limits = PreparationLimits::default();
    let mut initial_work = AncestryQueryWork::default();
    frontier_merge_bases_all(
        &Graph { source: &source, format: source.format },
        fixture.target,
        fixture.incoming,
        MergeBaseLimits { max_commits: limits.max_commits, max_edges: limits.max_edges },
        &mut initial_work,
        || source.checkpoint(),
    ).unwrap();
    assert!(matches!(
        recursive(&source, fixture.target, fixture.incoming, PreparationLimits {
            max_commits: initial_work.visited_commits, ..limits
        }),
        Err(PreparationError::Graph(MergeBaseError::CommitLimitExceeded { .. }))
    ));
    assert!(matches!(
        recursive(&source, fixture.target, fixture.incoming, PreparationLimits {
            max_edges: initial_work.examined_edges, ..limits
        }),
        Err(PreparationError::Graph(MergeBaseError::EdgeLimitExceeded { .. }))
    ));
    let plan = clean(recursive(&source, fixture.target, fixture.incoming, limits));
    // Pruning the temporary tree does not refund the work that created it.
    assert!(matches!(
        recursive(&source, fixture.target, fixture.incoming, PreparationLimits {
            max_objects: plan.objects.len(), ..limits
        }),
        Err(PreparationError::Budget("objects"))
    ));
}

struct CancelBlob<'a>(&'a Source, Cell<bool>);

impl MergeObjectSource for CancelBlob<'_> {
    fn checkpoint(&self) -> Result<(), MergeSourceError> { self.0.checkpoint() }
    fn commit(&self, id: GitOid) -> Result<CommitInput, MergeSourceError> { self.0.commit(id) }
    fn tree(&self, id: GitOid) -> Result<Vec<MergeEntry>, MergeSourceError> { self.0.tree(id) }
    fn blob(&self, _id: GitOid) -> Result<Vec<u8>, MergeSourceError> {
        self.1.set(true);
        Err(MergeSourceError::Cancelled)
    }
}

#[test]
fn cancellation_during_virtual_content_construction_returns_no_candidate() {
    let mut source = Source::new(GitHashAlgorithm::Sha1);
    let fixture = content_cross(&mut source, false);
    let cancelled = CancelBlob(&source, Cell::new(false));
    assert!(matches!(
        prepare_merge_with_profile(
            &cancelled,
            source.format,
            fixture.target,
            fixture.incoming,
            &metadata(),
            PreparationLimits::default(),
            MergeProfile::RecursivePathMergeV1,
        ),
        Err(PreparationError::Source(MergeSourceError::Cancelled))
    ));
    assert!(cancelled.1.get());
    assert!(recursive(&source, fixture.target, fixture.incoming, PreparationLimits::default()).is_ok());
}

#[test]
fn recursive_profile_preserves_single_base_bytes_squash_and_integrated_results() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let a = source.file(b"a", b"0\n", 0o100644);
        let b = source.file(b"a", b"1\n", 0o100644);
        let c = source.file(b"b", b"2\n", 0o100644);
        let (target, incoming) = branch_pair(&mut source, vec![a.clone()], vec![b], vec![a, c]);
        let legacy = clean(prepare_merge(&source, format, target, incoming, &metadata(), PreparationLimits::default()));
        let mut plan = clean(recursive(&source, target, incoming, PreparationLimits::default()));
        assert_eq!(plan.recursive_base.take(), Some(RecursiveMergeBase { bases: vec![legacy.base], tree: source.commit(legacy.base).unwrap().tree }));
        assert_eq!(plan, legacy);
        let squash = clean(prepare_merge_with_options(&source, format, target, incoming, &metadata(), PreparationLimits::default(), MergeProfile::RecursivePathMergeV1, MergeCommitStyle::Squash));
        assert_eq!(squash.tree, legacy.tree);
        let commit = squash.objects.iter().find(|object| object.id == squash.commit).unwrap();
        assert_eq!(String::from_utf8_lossy(&commit.body).lines().filter(|line| line.starts_with("parent ")).collect::<Vec<_>>(), vec![format!("parent {target}")]);
        assert_eq!(recursive(&source, target, legacy.base, PreparationLimits::default()).unwrap(), MergePreparation::AlreadyUpToDate { target });
    }
}

#[test]
fn transport_refusal_predicates_preserve_nested_graph_failure_kinds() {
    for error in [
        PreparationError::Source(MergeSourceError::Cancelled),
        PreparationError::Graph(MergeBaseError::Source(MergeSourceError::Cancelled)),
    ] {
        assert!(error.is_cancelled());
        assert!(!error.is_resource_limit());
    }
    for error in [
        PreparationError::Budget("content merges"),
        PreparationError::Source(MergeSourceError::BudgetExceeded),
        PreparationError::Graph(MergeBaseError::Source(MergeSourceError::BudgetExceeded)),
        PreparationError::Graph(MergeBaseError::CommitLimitExceeded { limit: 7 }),
        PreparationError::Graph(MergeBaseError::EdgeLimitExceeded { limit: 13 }),
    ] {
        assert!(error.is_resource_limit());
        assert!(!error.is_cancelled());
    }
    for error in [
        PreparationError::InvalidLimits,
        PreparationError::InvalidTree,
        PreparationError::NoCommonAncestor,
        PreparationError::Source(MergeSourceError::OutsideSelection),
        PreparationError::Graph(MergeBaseError::Cycle),
    ] {
        assert!(!error.is_cancelled());
        assert!(!error.is_resource_limit());
    }
}
