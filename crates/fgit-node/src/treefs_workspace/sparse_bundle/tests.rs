//! Native-byte equivalence and bounded-work tests for the artifact selector.
//! The map is a read-only object-source oracle, not a durable node substitute.
use super::*;
use std::cell::{Cell, RefCell};
use std::fmt::Write as _;

use fgit_admission::merge::native::objects::{CanonicalObjectHeader, validate_commit_closure};
use fgit_crypto::git_object_id;
use fgit_pack::{CanonicalPackObject, PackLimits, PackPlanner, PackWriteProfile};
use fgit_types::GitHashAlgorithm;

struct Source {
    format: GitHashAlgorithm,
    objects: BTreeMap<GitOid, (ObjectType, Vec<u8>)>,
    reads: RefCell<Vec<GitOid>>,
    forbidden: BTreeSet<GitOid>,
    bad_header: Cell<Option<GitOid>>,
}
impl Source {
    fn new(format: GitHashAlgorithm) -> Self {
        Self {
            format,
            objects: BTreeMap::new(),
            reads: RefCell::new(Vec::new()),
            forbidden: BTreeSet::new(),
            bad_header: Cell::new(None),
        }
    }
    fn put(&mut self, kind: ObjectType, bytes: Vec<u8>) -> GitOid {
        let id = git_object_id(self.format, kind, &bytes);
        self.objects.insert(id, (kind, bytes));
        id
    }
    fn tree(&mut self, entries: &[(&str, u32, GitOid)]) -> GitOid {
        let mut bytes = Vec::new();
        for (name, mode, id) in entries {
            bytes.extend_from_slice(format!("{mode:o} {name}\0").as_bytes());
            bytes.extend_from_slice(id.as_bytes());
        }
        self.put(ObjectType::Tree, bytes)
    }
    fn commit(&mut self, tree: GitOid, parents: &[GitOid], sequence: usize) -> GitOid {
        let mut body = format!("tree {tree}\n");
        for parent in parents {
            writeln!(body, "parent {parent}").expect("writing to a String cannot fail");
        }
        writeln!(body, "author Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\ncommit {sequence}").expect("writing to a String cannot fail");
        self.put(ObjectType::Commit, body.into_bytes())
    }
    fn full(&self, commit: GitOid) -> BTreeSet<GitOid> {
        validate_commit_closure(self, commit, MergeObjectLimits::default(), &mut || true)
            .unwrap()
            .objects
    }
}
impl CanonicalObjectSource for Source {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        self.reads.borrow_mut().push(*id);
        if self.forbidden.contains(id) {
            return Err(PackWriteError::MissingCanonicalObject(*id));
        }
        let (kind, bytes) = self
            .objects
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
impl FrontierObjectHeaders for Source {
    fn load_header(&self, id: &GitOid) -> Result<Option<CanonicalObjectHeader>, PackWriteError> {
        let (kind, bytes) = self
            .objects
            .get(id)
            .ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        Ok(Some(CanonicalObjectHeader {
            id: *id,
            object_type: if self.bad_header.get() == Some(*id) {
                ObjectType::Commit
            } else {
                *kind
            },
            body_bytes: bytes.len(),
        }))
    }
}

fn selected(source: &Source, target: GitOid, candidate: GitOid) -> BTreeSet<GitOid> {
    objects_above_target(
        source,
        target,
        candidate,
        4096,
        MergeObjectLimits::default(),
        &mut || true,
    )
    .unwrap()
}

#[test]
fn nested_changes_and_source_only_subtrees_produce_complete_target_only_packs() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let keep = source.put(ObjectType::Blob, b"inherited\n".to_vec());
        let before = source.put(ObjectType::Blob, b"before\n".to_vec());
        let after = source.put(ObjectType::Blob, b"after\n".to_vec());
        let borrowed = source.put(ObjectType::Blob, b"from source only\n".to_vec());
        let shared = source.tree(&[("keep", 0o100644, keep)]);
        let old_dir = source.tree(&[("changed", 0o100644, before), ("shared", 0o040000, shared)]);
        let target_tree = source.tree(&[("dir", 0o040000, old_dir)]);
        let target = source.commit(target_tree, &[], 0);
        let new_dir = source.tree(&[("changed", 0o100644, after), ("shared", 0o040000, shared)]);
        let new_subtree = source.tree(&[("borrowed", 0o100755, borrowed)]);
        let candidate_tree = source.tree(&[
            ("dir", 0o040000, new_dir),
            ("source", 0o040000, new_subtree),
        ]);
        let candidate = source.commit(candidate_tree, &[target], 1);
        let target_closure = source.full(target);
        let candidate_closure = source.full(candidate);
        let expected: BTreeSet<_> = candidate_closure
            .difference(&target_closure)
            .copied()
            .collect();
        source.forbidden.extend([keep, before, shared]);
        source.reads.borrow_mut().clear();
        let needed = selected(&source, target, candidate);
        assert_eq!(needed, expected);
        assert!(needed.contains(&borrowed));
        assert!(
            source
                .reads
                .borrow()
                .iter()
                .all(|id| !source.forbidden.contains(id))
        );
        let ordered: Vec<_> = needed.iter().copied().collect();
        PackPlanner::new(
            format,
            PackWriteProfile::COMPRESSED_NO_DELTA_V1,
            PackLimits::default(),
        )
        .plan_selected(&source, &ordered, &mut || true)
        .unwrap();
        // A receiver holding only target history plus the chosen pack has every
        // reachable object, including every borrowed source-only subtree leaf.
        assert!(candidate_closure.is_subset(&target_closure.union(&needed).copied().collect()));
        assert_eq!(selected(&source, target, candidate), needed);
    }
}

#[test]
fn long_target_history_does_not_enter_candidate_selection() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let old_tree = source.tree(&[]);
        let mut parent = source.commit(old_tree, &[], 0);
        for number in 1..100_001 {
            parent = source.commit(old_tree, &[parent], number);
        }
        let target = parent;
        let added = source.put(ObjectType::Blob, b"one change\n".to_vec());
        let new_tree = source.tree(&[("added", 0o100644, added)]);
        let candidate = source.commit(new_tree, &[target], 100_001);
        assert!(matches!(
            validate_commit_closure(&source, target, MergeObjectLimits::default(), &mut || true),
            Err(ProjectionFailure::Unavailable(
                RefusalCode::ResourceBudgetExceeded
            ))
        ));
        source.reads.borrow_mut().clear();
        let needed = selected(&source, target, candidate);
        assert_eq!(needed, BTreeSet::from([candidate, new_tree, added]));
        assert!(
            source.reads.borrow().len() < 12,
            "the old history must not be walked"
        );
    }
}

#[test]
fn inherited_blob_bytes_do_not_consume_the_changed_object_budget() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let large = source.put(ObjectType::Blob, vec![b'x'; 1024 * 1024]);
        let target_tree = source.tree(&[("large", 0o100644, large)]);
        let target = source.commit(target_tree, &[], 0);
        let added = source.put(ObjectType::Blob, b"new\n".to_vec());
        let candidate_tree = source.tree(&[("added", 0o100644, added), ("large", 0o100644, large)]);
        let candidate = source.commit(candidate_tree, &[target], 1);
        let limits = MergeObjectLimits {
            max_total_bytes: 4096,
            ..MergeObjectLimits::default()
        };
        assert!(matches!(
            validate_commit_closure(&source, candidate, limits, &mut || true),
            Err(ProjectionFailure::Unavailable(
                RefusalCode::ResourceBudgetExceeded
            ))
        ));
        source.forbidden.insert(large);
        let needed =
            objects_above_target(&source, target, candidate, 1, limits, &mut || true).unwrap();
        assert_eq!(needed, BTreeSet::from([candidate, candidate_tree, added]));
        source.bad_header.set(Some(large));
        assert!(matches!(
            objects_above_target(&source, target, candidate, 1, limits, &mut || true),
            Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))
        ));
        source.bad_header.set(None);
        assert_eq!(
            objects_above_target(&source, target, candidate, 1, limits, &mut || true).unwrap(),
            needed
        );
        source.objects.remove(&large);
        assert!(matches!(
            objects_above_target(&source, target, candidate, 1, limits, &mut || true),
            Err(ProjectionFailure::Unavailable(RefusalCode::EvidenceMissing))
        ));
    }
}

#[test]
fn every_intermediate_rebase_tree_is_complete_and_only_target_is_a_prerequisite() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let inherited = source.put(ObjectType::Blob, b"inherited\n".to_vec());
        let transient = source.put(ObjectType::Blob, b"first rewritten commit only\n".to_vec());
        let old = source.tree(&[("keep", 0o100644, inherited)]);
        let target = source.commit(old, &[], 0);
        let middle_tree = source.tree(&[
            ("keep", 0o100644, inherited),
            ("transient", 0o100644, transient),
        ]);
        let middle = source.commit(middle_tree, &[target], 1);
        let candidate = source.commit(old, &[middle], 2);
        assert_eq!(
            selected(&source, target, candidate),
            BTreeSet::from([middle_tree, transient, middle, candidate])
        );
        assert!(matches!(
            objects_above_target(
                &source,
                target,
                candidate,
                1,
                MergeObjectLimits::default(),
                &mut || true
            ),
            Err(ProjectionFailure::Unavailable(
                RefusalCode::ResourceBudgetExceeded
            ))
        ));
        assert!(selected(&source, target, target).is_empty());
        let unrelated = source.commit(old, &[], 3);
        assert!(matches!(
            objects_above_target(
                &source,
                unrelated,
                candidate,
                4,
                MergeObjectLimits::default(),
                &mut || true
            ),
            Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))
        ));
        let merge = source.commit(old, &[target, unrelated], 4);
        assert!(matches!(
            objects_above_target(
                &source,
                target,
                merge,
                4,
                MergeObjectLimits::default(),
                &mut || true
            ),
            Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))
        ));
    }
}

#[test]
fn cached_flat_directory_entries_are_charged_once_per_native_tree() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let keep = source.put(ObjectType::Blob, b"keep\n".to_vec());
        let old = source.tree(&[
            ("a", 0o100644, keep),
            ("b", 0o100644, keep),
            ("c", 0o100644, keep),
            ("d", 0o100644, keep),
        ]);
        let target = source.commit(old, &[], 0);
        let mut candidate = target;
        for number in 1..=3 {
            let value = source.put(ObjectType::Blob, format!("change {number}\n").into_bytes());
            let tree = source.tree(&[
                ("a", 0o100644, keep),
                ("b", 0o100644, keep),
                ("c", 0o100644, keep),
                ("d", 0o100644, value),
            ]);
            candidate = source.commit(tree, &[candidate], number);
        }
        // Four unique trees of four entries plus seven commit edges. Cached
        // flat trees have no directory comparisons or payload copies to charge.
        let limits = MergeObjectLimits {
            max_edges: 22,
            ..MergeObjectLimits::default()
        };
        assert!(matches!(
            objects_above_target(&source, target, candidate, 3, limits, &mut || true),
            Err(ProjectionFailure::Unavailable(
                RefusalCode::ResourceBudgetExceeded
            ))
        ));
        let limits = MergeObjectLimits {
            max_edges: 23,
            ..limits
        };
        assert_eq!(
            objects_above_target(&source, target, candidate, 3, limits, &mut || true).unwrap(),
            selected(&source, target, candidate)
        );
    }
}

#[test]
fn cancelled_corrupt_or_exhausted_frontiers_never_return_a_partial_pack() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let blob = source.put(ObjectType::Blob, b"payload\n".to_vec());
        let old = source.tree(&[]);
        let target = source.commit(old, &[], 0);
        let new = source.tree(&[("file", 0o100644, blob)]);
        let candidate = source.commit(new, &[target], 1);
        let mut checkpoints = 0;
        objects_above_target(
            &source,
            target,
            candidate,
            1,
            MergeObjectLimits::default(),
            &mut || {
                checkpoints += 1;
                true
            },
        )
        .unwrap();
        for cancel_at in 1..=checkpoints {
            let mut calls = 0;
            assert!(matches!(
                objects_above_target(
                    &source,
                    target,
                    candidate,
                    1,
                    MergeObjectLimits::default(),
                    &mut || {
                        calls += 1;
                        calls < cancel_at
                    }
                ),
                Err(ProjectionFailure::Unavailable(
                    RefusalCode::CancellationInProgress
                ))
            ));
        }
        for limits in [
            MergeObjectLimits {
                max_objects: 1,
                ..MergeObjectLimits::default()
            },
            MergeObjectLimits {
                max_edges: 1,
                ..MergeObjectLimits::default()
            },
            MergeObjectLimits {
                max_total_bytes: 1,
                ..MergeObjectLimits::default()
            },
        ] {
            assert!(matches!(
                objects_above_target(&source, target, candidate, 1, limits, &mut || true),
                Err(ProjectionFailure::Unavailable(
                    RefusalCode::ResourceBudgetExceeded
                ))
            ));
        }
        source.objects.get_mut(&old).unwrap().1.push(b'!');
        assert!(matches!(
            objects_above_target(
                &source,
                target,
                candidate,
                1,
                MergeObjectLimits::default(),
                &mut || true
            ),
            Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))
        ));
    }
}

#[test]
fn cached_tree_payloads_are_shared_but_caching_never_grants_target_membership() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let blob = source.put(ObjectType::Blob, b"shared payload\n".to_vec());
        let names: Vec<_> = (0..1024).map(|i| format!("file-{i:04}")).collect();
        let entries: Vec<_> = names
            .iter()
            .map(|name| (name.as_str(), 0o100644, blob))
            .collect();
        let id = source.tree(&entries);
        let mut live = || true;
        let mut walk = Walk {
            source: &source,
            limits: MergeObjectLimits::default(),
            deadline: &mut live,
            objects: 0,
            bytes: 0,
            edges: 0,
            trees: BTreeMap::new(),
            expanded: BTreeSet::new(),
            frontier: BTreeMap::new(),
        };
        let first = walk.tree(id).unwrap();
        let again = walk.tree(id).unwrap();
        assert!(Arc::ptr_eq(&first, &again));
        assert_eq!(walk.objects, 1);
        assert_eq!(walk.edges, 1024);
        assert!(first.directories.is_empty());
        assert!(matches!(
            walk.prove_tree(id),
            Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))
        ));
        assert!(walk.frontier.is_empty());
        assert!(walk.expanded.is_empty());
        // Simulate the independently read target edge; a cached parsed tree
        // alone did not supply this proof or authorize any inherited omission.
        walk.remember(id, ObjectType::Tree).unwrap();
        assert!(Arc::ptr_eq(&first, &walk.prove_tree(id).unwrap()));
        assert_eq!(walk.frontier.len(), 2);
        assert_eq!(walk.expanded.len(), 1);
        assert!(Arc::ptr_eq(&first, &walk.prove_tree(id).unwrap()));
        assert_eq!(walk.edges, 1024);
        assert_eq!(source.reads.borrow().as_slice(), &[id]);
    }
}

#[test]
fn repeated_directory_pair_lookups_still_have_an_inclusive_work_bound() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let left = source.put(ObjectType::Blob, b"left\n".to_vec());
        let right = source.put(ObjectType::Blob, b"right\n".to_vec());
        let new_blob = source.put(ObjectType::Blob, b"replacement\n".to_vec());
        let old_left = source.tree(&[("file", 0o100644, left)]);
        let old_right = source.tree(&[("file", 0o100644, right)]);
        let old = source.tree(&[("a", 0o040000, old_left), ("b", 0o040000, old_right)]);
        let target = source.commit(old, &[], 0);
        let shared = source.tree(&[("file", 0o100644, new_blob)]);
        let new = source.tree(&[("a", 0o040000, shared), ("b", 0o040000, shared)]);
        let candidate = source.commit(new, &[target], 1);
        let limits = MergeObjectLimits {
            max_edges: 12,
            ..MergeObjectLimits::default()
        };
        // Three commit edges, seven unique tree entries, two directory lookups.
        let needed =
            objects_above_target(&source, target, candidate, 1, limits, &mut || true).unwrap();
        assert_eq!(needed, BTreeSet::from([candidate, new, shared, new_blob]));
        // One parse during frontier discovery and one independent validation,
        // despite pairing the same new subtree with two different old trees.
        assert_eq!(
            source
                .reads
                .borrow()
                .iter()
                .filter(|id| **id == shared)
                .count(),
            2
        );
        assert!(matches!(
            objects_above_target(
                &source,
                target,
                candidate,
                1,
                MergeObjectLimits {
                    max_edges: 11,
                    ..limits
                },
                &mut || true,
            ),
            Err(ProjectionFailure::Unavailable(
                RefusalCode::ResourceBudgetExceeded
            ))
        ));
    }
}

#[test]
fn eight_step_flat_rebase_reuses_target_inventory_without_losing_intermediate_objects() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let keep = source.put(ObjectType::Blob, b"keep\n".to_vec());
        let names: Vec<_> = (0..64).map(|i| format!("file-{i:02}")).collect();
        let mut entries: Vec<_> = names
            .iter()
            .map(|name| (name.as_str(), 0o100644, keep))
            .collect();
        let old = source.tree(&entries);
        let target = source.commit(old, &[], 0);
        let mut candidate = target;
        for number in 1..=8 {
            let value = source.put(ObjectType::Blob, format!("step {number}\n").into_bytes());
            entries.last_mut().unwrap().2 = value;
            let tree = source.tree(&entries);
            candidate = source.commit(tree, &[candidate], number);
        }
        let before = source.full(target);
        let after = source.full(candidate);
        let expected: BTreeSet<_> = after.difference(&before).copied().collect();
        assert_eq!(expected.len(), 24);
        source.reads.borrow_mut().clear();
        source.forbidden.insert(keep);
        // Nine unique 64-entry trees and seventeen commit edges. Repeatedly
        // cloning/scanning the old root would consume 1041 units instead.
        let limits = MergeObjectLimits {
            max_objects: 24,
            max_edges: 593,
            ..MergeObjectLimits::default()
        };
        assert_eq!(
            objects_above_target(&source, target, candidate, 8, limits, &mut || true,).unwrap(),
            expected
        );
        assert_eq!(
            source
                .reads
                .borrow()
                .iter()
                .filter(|id| **id == old)
                .count(),
            1
        );
        assert!(!source.reads.borrow().contains(&keep));
        assert!(matches!(
            objects_above_target(
                &source,
                target,
                candidate,
                8,
                MergeObjectLimits {
                    max_edges: 592,
                    ..limits
                },
                &mut || true,
            ),
            Err(ProjectionFailure::Unavailable(
                RefusalCode::ResourceBudgetExceeded
            ))
        ));
    }
}
