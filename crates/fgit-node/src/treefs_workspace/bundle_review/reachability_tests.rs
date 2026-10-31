//! Native-byte disclosure fixtures. These test the parent reachability proof;
//! durable admission, bundle inflation and publication belong to other suites.

use super::reachability::ParentReachability;
use super::*;
use std::fmt::Write as _;

#[derive(Default)]
struct Objects {
    bodies: BTreeMap<GitOid, (ObjectType, Vec<u8>)>,
    reads: RefCell<Vec<GitOid>>,
}

impl Objects {
    fn put(&mut self, format: GitHashAlgorithm, kind: ObjectType, bytes: Vec<u8>) -> GitOid {
        let id = git_object_id(format, kind, &bytes);
        self.bodies.insert(id, (kind, bytes));
        id
    }

    fn tree(&mut self, format: GitHashAlgorithm, entries: &[(&str, u32, GitOid)]) -> GitOid {
        let mut bytes = Vec::new();
        for (name, mode, id) in entries {
            bytes.extend_from_slice(format!("{mode:o} {name}\0").as_bytes());
            bytes.extend_from_slice(id.as_bytes());
        }
        self.put(format, ObjectType::Tree, bytes)
    }

    fn commit(&mut self, tree: GitOid, parents: &[GitOid], label: &str) -> GitOid {
        let mut bytes = format!("tree {tree}\n");
        for parent in parents {
            writeln!(bytes, "parent {parent}").expect("writing to a String cannot fail");
        }
        bytes.push_str("author Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\n");
        bytes.push_str(label);
        self.put(tree.algorithm(), ObjectType::Commit, bytes.into_bytes())
    }

    fn load_graph(&self, id: GitOid) -> Result<(ObjectType, Vec<u8>), MergeSourceError> {
        self.reads.borrow_mut().push(id);
        let value = self
            .bodies
            .get(&id)
            .ok_or(MergeSourceError::Unavailable(id))?;
        assert_ne!(
            value.0,
            ObjectType::Blob,
            "reachability must not load blob bodies"
        );
        Ok(value.clone())
    }
}

fn prove(
    graph: &mut ParentReachability,
    objects: &Objects,
    wanted: GitOid,
) -> Result<bool, MergeSourceError> {
    graph.ensure(wanted, |id| objects.load_graph(id), || Ok(()))
}

#[test]
fn wide_tree_proves_every_leaf_without_reading_a_blob_or_charging_leaf_object_reads() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut objects = Objects::default();
        let names: Vec<_> = (0..100_001_u32)
            .map(|index| format!("file-{index:06}"))
            .collect();
        let leaves: Vec<_> = (0..100_001_u32)
            .map(|index| git_object_id(format, ObjectType::Blob, &index.to_be_bytes()))
            .collect();
        assert!(leaves.len() > MergeObjectLimits::default().max_objects);
        let entries: Vec<_> = names
            .iter()
            .zip(&leaves)
            .map(|(name, id)| (name.as_str(), 0o100_644, *id))
            .collect();
        let tree = objects.tree(format, &entries);
        let root = objects.commit(tree, &[], "visible root");
        let limits = MergeObjectLimits {
            max_objects: 2,
            max_edges: leaves.len() + 1,
            ..MergeObjectLimits::default()
        };
        let mut graph = ParentReachability::new(format, &[root], limits).unwrap();
        for leaf in leaves {
            assert_eq!(prove(&mut graph, &objects, leaf), Ok(true));
        }
        // No blob body even exists in this source. Native edges are sufficient
        // to prove a leaf's disclosure; its eventual read verifies its bytes.
        assert_eq!(*objects.reads.borrow(), vec![root, tree]);
        let absent = git_object_id(format, ObjectType::Blob, b"unreachable");
        assert_eq!(prove(&mut graph, &objects, absent), Ok(false));
        assert_eq!(*objects.reads.borrow(), vec![root, tree]);
    }
}

#[test]
fn only_visible_parent_histories_grant_disclosure_even_when_other_objects_exist() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut objects = Objects::default();
        let old = objects.put(format, ObjectType::Blob, b"historical content".to_vec());
        let old_tree = objects.tree(format, &[("old", 0o100_644, old)]);
        let ancestor = objects.commit(old_tree, &[], "visible ancestor");
        let current = objects.put(format, ObjectType::Blob, b"current content".to_vec());
        let current_tree = objects.tree(format, &[("current", 0o100_644, current)]);
        let root = objects.commit(current_tree, &[ancestor], "visible root");
        let secret = objects.put(
            format,
            ObjectType::Blob,
            b"hidden deleted or force-pushed content".to_vec(),
        );
        let hidden_tree = objects.tree(format, &[("secret", 0o100_644, secret)]);
        let hidden = objects.commit(hidden_tree, &[], "unrelated admitted branch");
        let mut graph =
            ParentReachability::new(format, &[root], MergeObjectLimits::default()).unwrap();
        assert_eq!(prove(&mut graph, &objects, current), Ok(true));
        assert_eq!(*objects.reads.borrow(), vec![root, current_tree]);
        assert_eq!(prove(&mut graph, &objects, old), Ok(true));
        assert_eq!(prove(&mut graph, &objects, secret), Ok(false));
        assert_eq!(prove(&mut graph, &objects, hidden), Ok(false));
        assert_eq!(prove(&mut graph, &objects, hidden_tree), Ok(false));
        let reads = objects.reads.borrow();
        assert!(!reads.contains(&hidden));
        assert!(!reads.contains(&hidden_tree));
        drop(reads);
        // An independently authorized second parent changes the permitted set.
        let mut both =
            ParentReachability::new(format, &[root, hidden], MergeObjectLimits::default()).unwrap();
        assert_eq!(prove(&mut both, &objects, secret), Ok(true));
    }
}

#[test]
fn observing_uploaded_or_unrelated_bytes_cannot_widen_the_parent_capability() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut objects = Objects::default();
        let tree = objects.tree(format, &[]);
        let root = objects.commit(tree, &[], "visible root");
        let secret = git_object_id(format, ObjectType::Blob, b"withheld original");
        let hidden_tree = objects.tree(format, &[("secret", 0o100_644, secret)]);
        let hidden = objects.commit(hidden_tree, &[], "uploaded hidden commit");
        let mut graph =
            ParentReachability::new(format, &[root], MergeObjectLimits::default()).unwrap();
        for id in [hidden, hidden_tree] {
            let (kind, bytes) = &objects.bodies[&id];
            assert_eq!(
                graph.observe(id, *kind, bytes, &mut || Ok(())),
                Err(MergeSourceError::InvalidObject(id))
            );
        }
        assert_eq!(prove(&mut graph, &objects, secret), Ok(false));
        assert_eq!(*objects.reads.borrow(), vec![root, tree]);
    }
}

#[test]
fn observed_native_edges_are_reused_without_reloading_their_graph_objects() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut objects = Objects::default();
        let leaf = git_object_id(format, ObjectType::Blob, b"leaf");
        let tree = objects.tree(format, &[("file", 0o100_644, leaf)]);
        let root = objects.commit(tree, &[], "visible root");
        let mut graph =
            ParentReachability::new(format, &[root], MergeObjectLimits::default()).unwrap();
        for id in [root, tree] {
            let (kind, bytes) = &objects.bodies[&id];
            graph.observe(id, *kind, bytes, &mut || Ok(())).unwrap();
        }
        assert_eq!(prove(&mut graph, &objects, leaf), Ok(true));
        let absent = git_object_id(format, ObjectType::Blob, b"absent");
        assert_eq!(prove(&mut graph, &objects, absent), Ok(false));
        assert!(objects.reads.borrow().is_empty());
    }
}

#[test]
fn missing_corrupt_and_wrong_kind_native_objects_never_prove_descendants() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut objects = Objects::default();
        let leaf = git_object_id(format, ObjectType::Blob, b"leaf");
        let tree = objects.tree(format, &[("file", 0o100_644, leaf)]);
        let root = objects.commit(tree, &[], "visible root");
        let correct = objects.bodies[&tree].clone();
        for (replacement, expected) in [
            (None, MergeSourceError::Unavailable(tree)),
            (
                Some((ObjectType::Tree, b"corrupt".to_vec())),
                MergeSourceError::InvalidObject(tree),
            ),
            (
                Some((ObjectType::Commit, correct.1.clone())),
                MergeSourceError::InvalidObject(tree),
            ),
        ] {
            match replacement {
                Some(value) => {
                    objects.bodies.insert(tree, value);
                }
                None => {
                    objects.bodies.remove(&tree);
                }
            }
            let mut graph =
                ParentReachability::new(format, &[root], MergeObjectLimits::default()).unwrap();
            assert_eq!(prove(&mut graph, &objects, leaf), Err(expected));
        }
        objects.bodies.insert(tree, correct);
        let mut graph =
            ParentReachability::new(format, &[root], MergeObjectLimits::default()).unwrap();
        assert_eq!(prove(&mut graph, &objects, leaf), Ok(true));
    }
}

#[test]
fn contradictory_native_edge_kinds_refuse_even_when_the_identity_is_reused() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut objects = Objects::default();
        let leaf = git_object_id(format, ObjectType::Blob, b"shared");
        let tree = objects.tree(
            format,
            &[("file", 0o100_644, leaf), ("tree", 0o040_000, leaf)],
        );
        let root = objects.commit(tree, &[], "contradictory kinds");
        let mut graph =
            ParentReachability::new(format, &[root], MergeObjectLimits::default()).unwrap();
        assert_eq!(
            prove(&mut graph, &objects, leaf),
            Err(MergeSourceError::InvalidObject(leaf))
        );
    }
}

#[test]
fn exact_object_edge_and_byte_budgets_have_retryable_refused_twins() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut objects = Objects::default();
        let leaf = git_object_id(format, ObjectType::Blob, b"shared");
        let tree = objects.tree(format, &[("a", 0o100_644, leaf), ("b", 0o100_644, leaf)]);
        let root = objects.commit(tree, &[], "visible root");
        let largest = objects
            .bodies
            .values()
            .map(|(_, body)| body.len())
            .max()
            .unwrap();
        let total = objects.bodies.values().map(|(_, body)| body.len()).sum();
        let exact = MergeObjectLimits {
            max_objects: 2,
            max_edges: 3,
            max_object_bytes: largest,
            max_reused_blob_bytes: largest,
            max_total_bytes: total,
        };
        let run = |limits| {
            let mut graph = ParentReachability::new(format, &[root], limits).unwrap();
            prove(&mut graph, &objects, leaf)
        };
        assert_eq!(run(exact), Ok(true));
        for limits in [
            MergeObjectLimits {
                max_objects: 1,
                ..exact
            },
            MergeObjectLimits {
                max_edges: 2,
                ..exact
            },
            // Exercise the parser's tree-entry ceiling, not only its outer edge counter.
            MergeObjectLimits {
                max_edges: 1,
                ..exact
            },
            MergeObjectLimits {
                max_object_bytes: largest - 1,
                ..exact
            },
            MergeObjectLimits {
                max_total_bytes: total - 1,
                ..exact
            },
        ] {
            assert_eq!(run(limits), Err(MergeSourceError::BudgetExceeded));
        }
        assert_eq!(run(exact), Ok(true));
    }
}

#[test]
fn repeated_actual_reads_consume_bytes_without_recharging_native_edges() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut objects = Objects::default();
        let tree = objects.tree(format, &[]);
        let root = objects.commit(tree, &[], "visible root");
        let (kind, bytes) = &objects.bodies[&root];
        let limits = MergeObjectLimits {
            max_objects: 1,
            max_edges: 1,
            max_total_bytes: bytes.len() * 2,
            ..MergeObjectLimits::default()
        };
        let mut graph = ParentReachability::new(format, &[root], limits).unwrap();
        graph.observe(root, *kind, bytes, &mut || Ok(())).unwrap();
        graph.observe(root, *kind, bytes, &mut || Ok(())).unwrap();
        assert_eq!(
            graph.observe(root, *kind, bytes, &mut || Ok(())),
            Err(MergeSourceError::BudgetExceeded)
        );
    }
}

#[test]
fn gitlinks_consume_edge_work_without_authorizing_external_commits() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut objects = Objects::default();
        let leaf = git_object_id(format, ObjectType::Blob, b"leaf");
        let external_tree = objects.tree(format, &[]);
        let external = objects.commit(external_tree, &[], "other repository");
        let tree = objects.tree(
            format,
            &[("file", 0o100_644, leaf), ("module", 0o160_000, external)],
        );
        let root = objects.commit(tree, &[], "visible root");
        let exact = MergeObjectLimits {
            max_objects: 2,
            max_edges: 3,
            ..MergeObjectLimits::default()
        };
        let mut graph = ParentReachability::new(format, &[root], exact).unwrap();
        assert_eq!(prove(&mut graph, &objects, leaf), Ok(true));
        assert_eq!(prove(&mut graph, &objects, external), Ok(false));
        assert!(!objects.reads.borrow().contains(&external));
        let mut bounded = ParentReachability::new(
            format,
            &[root],
            MergeObjectLimits {
                max_edges: 2,
                ..exact
            },
        )
        .unwrap();
        assert_eq!(
            prove(&mut bounded, &objects, leaf),
            Err(MergeSourceError::BudgetExceeded)
        );
    }
}

#[test]
fn cancellation_at_every_checkpoint_returns_no_successful_disclosure_result() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut objects = Objects::default();
        let leaf = git_object_id(format, ObjectType::Blob, b"leaf");
        let tree = objects.tree(format, &[("file", 0o100_644, leaf)]);
        let root = objects.commit(tree, &[], "visible root");
        let mut complete =
            ParentReachability::new(format, &[root], MergeObjectLimits::default()).unwrap();
        let mut checkpoints = 0;
        assert_eq!(
            complete.ensure(
                leaf,
                |id| objects.load_graph(id),
                || {
                    checkpoints += 1;
                    Ok(())
                }
            ),
            Ok(true)
        );
        for stop in 0..checkpoints {
            let mut graph =
                ParentReachability::new(format, &[root], MergeObjectLimits::default()).unwrap();
            let mut calls = 0;
            assert_eq!(
                graph.ensure(
                    leaf,
                    |id| objects.load_graph(id),
                    || {
                        let live = calls < stop;
                        calls += 1;
                        if live {
                            Ok(())
                        } else {
                            Err(MergeSourceError::Cancelled)
                        }
                    }
                ),
                Err(MergeSourceError::Cancelled)
            );
        }
        let mut retry =
            ParentReachability::new(format, &[root], MergeObjectLimits::default()).unwrap();
        assert_eq!(prove(&mut retry, &objects, leaf), Ok(true));
    }
}
