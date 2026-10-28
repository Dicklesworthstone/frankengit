//! Reference-source tests of the production planner, not durable-node evidence.
use super::*;
use std::sync::Arc;

struct Counted<'a> {
    source: &'a Source,
    reads: Cell<usize>,
}
impl<'a> Counted<'a> {
    fn new(source: &'a Source) -> Self {
        Self {
            source,
            reads: Cell::new(0),
        }
    }
}
impl MergeObjectSource for Counted<'_> {
    fn checkpoint(&self) -> Result<(), MergeSourceError> {
        self.source.checkpoint()
    }
    fn commit(&self, id: GitOid) -> Result<CommitInput, MergeSourceError> {
        self.source.commit(id)
    }
    fn tree(&self, id: GitOid) -> Result<Vec<MergeEntry>, MergeSourceError> {
        self.reads.set(self.reads.get() + 1);
        self.source.tree(id)
    }
    fn blob(&self, id: GitOid) -> Result<Vec<u8>, MergeSourceError> {
        self.source.blob(id)
    }
}

#[test]
fn borrowed_join_matches_the_old_sorted_union_for_every_small_membership_pattern() {
    let names = [b"a".as_slice(), b"a.c", b"a0", b"\xff"];
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for pattern in 0usize..4096 {
            let mut trees = [BTreeMap::new(), BTreeMap::new(), BTreeMap::new()];
            for (index, name) in names.iter().enumerate() {
                for (side, tree) in trees.iter_mut().enumerate() {
                    if (pattern >> (index * 3 + side)) & 1 == 0 {
                        continue;
                    }
                    tree.insert(
                        name.to_vec(),
                        MergeEntry {
                            name: name.to_vec(),
                            mode: if index == 0 { 0o040000 } else { 0o100644 },
                            oid: git_object_id(
                                format,
                                GitObjectKind::Blob,
                                &[index as u8, side as u8],
                            ),
                        },
                    );
                }
            }
            let names: BTreeSet<_> = trees.iter().flat_map(|t| t.keys()).collect();
            let expected: Vec<_> = names
                .into_iter()
                .map(|name| {
                    (
                        name.as_slice(),
                        [trees[0].get(name), trees[1].get(name), trees[2].get(name)],
                    )
                })
                .collect();
            let joined: Vec<_> =
                tree_entries::Join::new(&trees[0], &trees[1], &trees[2]).collect();
            assert_eq!(joined, expected, "pattern {pattern}, format {format:?}");
        }
    }
}

#[test]
fn cached_source_maps_are_shared_but_every_visit_keeps_the_exact_entry_budget() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let file = source.file(b"file", b"content", 0o100644);
        let tree = source.store_tree(vec![file]);
        let counted = Counted::new(&source);
        let mut planner = Planner::new(
            &counted,
            format,
            PreparationLimits {
                max_tree_entries: 2,
                ..PreparationLimits::default()
            },
        );
        let first = planner.entries(Some(tree)).unwrap();
        let second = planner.entries(Some(tree)).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(counted.reads.get(), 1);
        assert_eq!(planner.entries, 2);
        assert!(matches!(
            planner.entries(Some(tree)),
            Err(PreparationError::Budget("tree entries"))
        ));
        assert_eq!(counted.reads.get(), 1);
    }
}

#[test]
fn large_source_trees_remain_readable_without_being_retained_in_the_optional_cache() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let entries = (0..=tree_entries::MAX_CACHED_SOURCE_ENTRIES)
            .map(|n| source.file(format!("f{n:05}").as_bytes(), b"shared", 0o100644))
            .collect();
        let tree = source.store_tree(entries);
        let counted = Counted::new(&source);
        let mut planner = Planner::new(&counted, format, PreparationLimits::default());
        let first = planner.entries(Some(tree)).unwrap();
        let second = planner.entries(Some(tree)).unwrap();
        assert_eq!(first, second);
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(counted.reads.get(), 2);
        assert!(!planner.trees.contains_key(&tree));
    }
}

#[test]
fn source_name_storage_and_slot_ceilings_do_not_evict_generated_trees() {
    let format = GitHashAlgorithm::Sha256;
    let mut source = Source::new(format);
    let mut ids = Vec::new();
    for n in 0..=tree_entries::MAX_CACHED_SOURCE_TREES {
        let entry = source.file(b"file", format!("{n}").as_bytes(), 0o100644);
        ids.push(source.store_tree(vec![entry]));
    }
    let long_entries = (0..9)
        .map(|n| {
            source.file(
                format!("{n}{}", "x".repeat(4095)).as_bytes(),
                b"long",
                0o100644,
            )
        })
        .collect();
    let long_tree = source.store_tree(long_entries);
    let leaf = source.file(b"generated", b"new", 0o100644);
    let counted = Counted::new(&source);
    let mut planner = Planner::new(&counted, format, PreparationLimits::default());
    // The name-byte ceiling is independent of both slot and entry counts.
    planner.entries(Some(long_tree)).unwrap();
    assert!(!planner.trees.contains_key(&long_tree));
    for id in &ids {
        planner.entries(Some(*id)).unwrap();
    }
    assert_eq!(planner.trees.len(), tree_entries::MAX_CACHED_SOURCE_TREES);
    assert!(planner.trees.contains_key(&ids[0]));
    assert!(!planner.trees.contains_key(ids.last().unwrap()));
    let mut bytes = b"100644 generated\0".to_vec();
    bytes.extend_from_slice(leaf.oid.as_bytes());
    let generated = planner.emit(GitObjectKind::Tree, bytes).unwrap();
    planner.remember_tree(generated, vec![leaf]).unwrap();
    let reads = counted.reads.get();
    let first = planner.entries(Some(generated)).unwrap();
    let second = planner.entries(Some(generated)).unwrap();
    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(counted.reads.get(), reads);
    assert_eq!(planner.trees.len(), tree_entries::MAX_CACHED_SOURCE_TREES + 1);
}

#[test]
fn warm_cache_checks_cancellation_and_never_crosses_a_planner_boundary() {
    let format = GitHashAlgorithm::Sha1;
    let mut source = Source::new(format);
    let entry = source.file(b"file", b"data", 0o100644);
    let tree = source.store_tree(vec![entry]);
    let counted = Counted::new(&source);
    let mut first = Planner::new(&counted, format, PreparationLimits::default());
    first.entries(Some(tree)).unwrap();
    source.live.set(false);
    assert!(matches!(
        first.entries(Some(tree)),
        Err(PreparationError::Source(MergeSourceError::Cancelled))
    ));
    assert_eq!(counted.reads.get(), 1);
    source.live.set(true);
    first.entries(Some(tree)).unwrap();
    let mut second = Planner::new(&counted, format, PreparationLimits::default());
    second.entries(Some(tree)).unwrap();
    assert_eq!(counted.reads.get(), 2);
}

#[test]
fn malformed_original_metadata_never_becomes_a_cached_tree() {
    let format = GitHashAlgorithm::Sha1;
    let mut source = Source::new(format);
    let entry = source.file(b"file", b"data", 0o100644);
    let id = source.store_tree(vec![entry.clone()]);
    // Deliberately invalid adapter output tests the planner's independent
    // structural checks; this is not a claim that these are valid Git bytes.
    source.trees.insert(id, vec![entry.clone(), entry]);
    let counted = Counted::new(&source);
    let mut planner = Planner::new(&counted, format, PreparationLimits::default());
    for _ in 0..2 {
        assert!(matches!(
            planner.entries(Some(id)),
            Err(PreparationError::InvalidTree)
        ));
        assert!(!planner.trees.contains_key(&id));
    }
    assert_eq!(counted.reads.get(), 2);
}

#[test]
fn repeated_conflict_discovery_reuses_source_maps_without_changing_conflict_order() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let mut roots = Vec::new();
        for value in [b"\0base".as_slice(), b"\0ours", b"\0theirs"] {
            let entries = [b"z".as_slice(), b"a", b"\xff"]
                .into_iter()
                .map(|name| source.file(name, value, 0o100644))
                .collect();
            roots.push(source.store_tree(entries));
        }
        let counted = Counted::new(&source);
        let mut planner = Planner::new(&counted, format, PreparationLimits::default());
        assert_eq!(
            planner.directory(Some(roots[0]), roots[1], roots[2], &[], 0, false).unwrap(),
            None
        );
        let conflicts = std::mem::take(&mut planner.conflicts);
        assert_eq!(
            conflicts.iter().map(|c| c.path.as_slice()).collect::<Vec<_>>(),
            [b"a".as_slice(), b"z", b"\xff"]
        );
        assert_eq!(
            planner.directory(Some(roots[0]), roots[1], roots[2], &[], 0, false).unwrap(),
            None
        );
        assert_eq!(planner.conflicts, conflicts);
        assert_eq!(counted.reads.get(), 3);
        assert_eq!(planner.entries, 18);
    }
}

#[test]
fn clean_wide_directory_produces_the_exact_expected_native_tree_and_mode() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let base: Vec<_> = (0..4096)
            .map(|n| source.file(format!("f{n:05}").as_bytes(), b"unchanged", 0o100644))
            .collect();
        let mut ours = base.clone();
        ours[0] = source.file(b"f00000", b"our change", 0o100755);
        let mut theirs = base.clone();
        theirs[4095] = source.file(b"f04095", b"their change", 0o100644);
        let mut expected = ours.clone();
        expected[4095] = theirs[4095].clone();
        let expected = source.store_tree(expected);
        let (ours, theirs) = branch_pair(&mut source, base, ours, theirs);
        let result = prepare_merge(
            &source, format, ours, theirs, &metadata(), PreparationLimits::default(),
        ).unwrap();
        let MergePreparation::Clean(plan) = result else {
            panic!("clean merge required");
        };
        assert_eq!(plan.tree, expected);
        assert_eq!(plan.objects.len(), 2);
        for object in &plan.objects {
            assert_eq!(object.id, git_object_id(format, object.kind, &object.body));
        }
    }
}

#[test]
fn trivial_entries_do_not_bypass_full_path_limits() {
    let format = GitHashAlgorithm::Sha1;
    let mut source = Source::new(format);
    let keep = source.file(b"keep", b"same", 0o100644);
    let a = source.file(b"a", b"ours", 0o100644);
    let z = source.file(b"z", b"theirs", 0o100644);
    let base = source.store_tree(vec![keep.clone()]);
    let ours = source.store_tree(vec![keep.clone(), a]);
    let theirs = source.store_tree(vec![keep, z]);
    let mut planner = Planner::new(
        &source,
        format,
        PreparationLimits {
            max_path_bytes: 4,
            ..PreparationLimits::default()
        },
    );
    assert!(matches!(
        planner.directory(Some(base), ours, theirs, b"x", 0, false),
        Err(PreparationError::Budget("path bytes"))
    ));
}

impl rebase::RebaseObjectSource for Counted<'_> {
    fn rebase_metadata(&self, id: GitOid) -> Result<rebase::RebaseCommitMetadata, MergeSourceError> {
        self.source.commit(id)?;
        Ok(rebase::RebaseCommitMetadata {
            author: b"T <t@x> 1 +0000".to_vec(),
            encoding: None,
            message: id.to_string().into_bytes(),
        })
    }
}

#[test]
fn eight_step_rebase_shares_original_and_generated_trees_without_refunding_work() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let mut original: Vec<_> = (0..4096)
            .map(|n| source.file(format!("f{n:05}").as_bytes(), b"unchanged", 0o100644))
            .collect();
        let base_tree = source.store_tree(original.clone());
        let upstream = source.store_commit(base_tree, &[], "upstream");
        let mut onto_entries = original.clone();
        let onto_only = source.file(b"f04095", b"onto only", 0o100755);
        onto_entries[4095] = onto_only.clone();
        let onto_tree = source.store_tree(onto_entries);
        let onto = source.store_commit(onto_tree, &[upstream], "onto");
        let mut tip = upstream;
        for step in 0..8 {
            original[step] = source.file(
                format!("f{step:05}").as_bytes(),
                format!("step {step}").as_bytes(),
                0o100644,
            );
            let tree = source.store_tree(original.clone());
            tip = source.store_commit(tree, &[tip], &format!("original {step}"));
        }
        original[4095] = onto_only;
        let expected = source.store_tree(original);
        let counted = Counted::new(&source);
        let request = rebase::RebaseRequest {
            source_tip: tip,
            upstream,
            onto,
            empty: rebase::EmptyCommitPolicy::Stop,
        };
        let committer = rebase::RebaseCommitter {
            identity: "T <t@x>".into(),
            timestamp: 2,
        };
        let limits = PreparationLimits {
            max_tree_entries: 8 * 3 * 4096,
            ..PreparationLimits::default()
        };
        let result =
            rebase::prepare_rebase(&counted, format, request, &committer, limits).unwrap();
        let rebase::RebasePreparation::Clean(plan) = result else {
            panic!("complete rebase required");
        };
        assert_eq!(plan.tree, expected);
        assert_eq!(plan.steps.len(), 8);
        assert_eq!(counted.reads.get(), 10, "nine original trees plus onto, each read once");
        for object in &plan.objects {
            assert_eq!(object.id, git_object_id(format, object.kind, &object.body));
        }
        let narrowed = PreparationLimits {
            max_tree_entries: limits.max_tree_entries - 1,
            ..limits
        };
        assert!(matches!(
            rebase::prepare_rebase(&counted, format, request, &committer, narrowed),
            Err(rebase::RebaseError::Preparation(PreparationError::Budget("tree entries")))
        ));
    }
}
