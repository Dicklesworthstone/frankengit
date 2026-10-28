//! Real native bytes and the production proof; this source records graph reads.
//! It is not a durable-node or pack-inflation substitute.
use super::*;
use std::cell::RefCell;

#[derive(Default)]
struct Objects {
    bodies: BTreeMap<GitOid, (ObjectType, Vec<u8>)>,
    reads: RefCell<Vec<GitOid>>,
}
impl Objects {
    fn put(&mut self, format: GitHashAlgorithm, kind: ObjectType, body: Vec<u8>) -> GitOid {
        let id = git_object_id(format, kind, &body);
        self.bodies.insert(id, (kind, body));
        id
    }
    fn tree(&mut self, format: GitHashAlgorithm, entries: &[(&str, u32, GitOid)]) -> GitOid {
        let mut body = Vec::new();
        for (name, mode, id) in entries {
            body.extend_from_slice(format!("{mode:o} {name}\0").as_bytes());
            body.extend_from_slice(id.as_bytes());
        }
        self.put(format, ObjectType::Tree, body)
    }
    fn commit(&mut self, tree: GitOid, parents: &[GitOid], label: &str) -> GitOid {
        let mut body = format!("tree {tree}\n");
        for parent in parents {
            body.push_str(&format!("parent {parent}\n"));
        }
        body.push_str(&format!("author Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\n{label}\n"));
        self.put(tree.algorithm(), ObjectType::Commit, body.into_bytes())
    }
    fn load(&self, id: GitOid) -> Result<(ObjectType, Vec<u8>), MergeSourceError> {
        self.reads.borrow_mut().push(id);
        let (kind, body) = self.bodies.get(&id).ok_or(MergeSourceError::Unavailable(id))?;
        assert_ne!(*kind, ObjectType::Blob, "proof discovery must not read blobs");
        Ok((*kind, body.clone()))
    }
    fn upload(&self, ids: &[GitOid]) -> BTreeMap<GitOid, PlannedMergeObject> {
        ids.iter().map(|id| {
            let (kind, body) = &self.bodies[id];
            (*id, PlannedMergeObject { id: *id, kind: *kind, body: body.clone() })
        }).collect()
    }
}
struct Fixture {
    objects: Objects,
    uploaded: BTreeMap<GitOid, PlannedMergeObject>,
    root: GitOid,
    old_tree: GitOid,
    old_dir: GitOid,
    old_deep: GitOid,
    inherited: GitOid,
}
fn fixture(format: GitHashAlgorithm) -> Fixture {
    let mut objects = Objects::default();
    let inherited = git_object_id(format, ObjectType::Blob, b"inherited; no body available");
    let added = git_object_id(format, ObjectType::Blob, b"added; pack owns this body");
    let old_deep = objects.tree(format, &[("keep", 0o100644, inherited)]);
    let old_dir = objects.tree(format, &[("deep", 0o040000, old_deep)]);
    // Neither this sibling nor the old history has a body available. A full or
    // breadth-first search before reaching z/deep therefore fails this fixture.
    let sibling = git_object_id(format, ObjectType::Tree, b"unopened sibling");
    let ancestor = git_object_id(format, ObjectType::Commit, b"unopened ancestry");
    let old_tree = objects.tree(format, &[("a", 0o040000, sibling), ("z", 0o040000, old_dir)]);
    let root = objects.commit(old_tree, &[ancestor], "approved");
    let new_deep = objects.tree(format, &[("added", 0o100644, added), ("keep", 0o100644, inherited)]);
    let new_dir = objects.tree(format, &[("deep", 0o040000, new_deep)]);
    let new_tree = objects.tree(format, &[("a", 0o040000, sibling), ("z", 0o040000, new_dir)]);
    let candidate = objects.commit(new_tree, &[root], "candidate");
    let uploaded = objects.upload(&[new_deep, new_dir, new_tree, candidate]);
    Fixture { objects, uploaded, root, old_tree, old_dir, old_deep, inherited }
}
fn run(f: &Fixture, limits: MergeObjectLimits) -> Result<ParentReachability, MergeSourceError> {
    let mut proof = ParentReachability::new(f.root.algorithm(), &[f.root], limits)?;
    proof.guide_uploaded(&f.uploaded, |id| f.objects.load(id), || Ok(()))?;
    Ok(proof)
}

#[test]
fn nested_sparse_candidates_do_not_open_siblings_history_or_blob_payloads() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = fixture(format);
        let mut proof = run(&f, MergeObjectLimits::default()).unwrap();
        assert_eq!(*f.objects.reads.borrow(), [f.root, f.old_tree, f.old_dir, f.old_deep]);
        assert_eq!(proof.require_kind(f.inherited, ObjectType::Blob), Ok(()));
        assert_eq!(proof.ensure(f.inherited, |_| panic!("already proved"), || Ok(())), Ok(true));
        for id in f.uploaded.keys() {
            assert!(!proof.required.contains_key(id), "hints must not authorize uploaded identities");
        }
    }
}

#[test]
fn already_observed_parent_graph_is_not_read_again_for_guidance() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = fixture(format);
        let mut proof = ParentReachability::new(format, &[f.root], MergeObjectLimits::default()).unwrap();
        for id in [f.root, f.old_tree, f.old_dir, f.old_deep] {
            let (kind, body) = &f.objects.bodies[&id];
            proof.observe(id, *kind, body, &mut || Ok(())).unwrap();
        }
        proof.guide_uploaded(&f.uploaded, |_| panic!("cached proof shape"), || Ok(())).unwrap();
        assert_eq!(proof.require_kind(f.inherited, ObjectType::Blob), Ok(()));
    }
}

#[test]
fn hidden_uploaded_graphs_and_claimed_parents_never_grant_original_membership() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut objects = Objects::default();
        let empty = objects.tree(format, &[]);
        let root = objects.commit(empty, &[], "approved");
        let secret = git_object_id(format, ObjectType::Blob, b"withheld");
        let hidden_tree = objects.tree(format, &[("secret", 0o100644, secret)]);
        let hidden = objects.commit(hidden_tree, &[], "hidden original");
        let malicious = objects.commit(hidden_tree, &[hidden], "claimed hidden parent");
        let uploaded = objects.upload(&[hidden_tree, malicious]);
        let mut proof = ParentReachability::new(format, &[root], MergeObjectLimits::default()).unwrap();
        proof.guide_uploaded(&uploaded, |id| objects.load(id), || Ok(())).unwrap();
        assert_eq!(proof.ensure(secret, |id| objects.load(id), || Ok(())), Ok(false));
        assert_eq!(proof.ensure(hidden, |id| objects.load(id), || Ok(())), Ok(false));
        assert_eq!(*objects.reads.borrow(), [root, empty]);
    }
}

#[test]
fn historical_and_moved_objects_keep_the_existing_authorized_fallback() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut objects = Objects::default();
        let leaf = git_object_id(format, ObjectType::Blob, b"historical");
        let old = objects.tree(format, &[("old", 0o100644, leaf)]);
        let ancestor = objects.commit(old, &[], "ancestor");
        let empty = objects.tree(format, &[]);
        let root = objects.commit(empty, &[ancestor], "approved");
        let result = objects.tree(format, &[("moved", 0o100644, leaf)]);
        let candidate = objects.commit(result, &[root], "candidate");
        let uploaded = objects.upload(&[result, candidate]);
        let mut proof = ParentReachability::new(format, &[root], MergeObjectLimits::default()).unwrap();
        proof.guide_uploaded(&uploaded, |id| objects.load(id), || Ok(())).unwrap();
        assert!(!objects.reads.borrow().contains(&ancestor));
        assert!(!proof.required.contains_key(&leaf));
        assert_eq!(proof.ensure(leaf, |id| objects.load(id), || Ok(())), Ok(true));
        assert!(objects.reads.borrow().contains(&ancestor));
        assert!(objects.reads.borrow().contains(&old));
    }
}

#[test]
fn both_selected_parents_and_intermediate_rebase_trees_supply_path_hints() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut objects = Objects::default();
        let a = git_object_id(format, ObjectType::Blob, b"first parent");
        let b = git_object_id(format, ObjectType::Blob, b"second parent");
        let extra = git_object_id(format, ObjectType::Blob, b"new");
        let first_dir = objects.tree(format, &[("keep", 0o100644, a)]);
        let second_dir = objects.tree(format, &[("keep", 0o100644, b)]);
        let first_tree = objects.tree(format, &[("one", 0o040000, first_dir)]);
        let second_tree = objects.tree(format, &[("two", 0o040000, second_dir)]);
        let first = objects.commit(first_tree, &[], "first");
        let second = objects.commit(second_tree, &[], "second");
        let one = objects.tree(format, &[("added", 0o100644, extra), ("keep", 0o100644, a)]);
        let two = objects.tree(format, &[("added", 0o100644, extra), ("keep", 0o100644, b)]);
        let mid_tree = objects.tree(format, &[("one", 0o040000, one)]);
        let mid = objects.commit(mid_tree, &[first], "intermediate");
        let final_tree = objects.tree(format, &[("two", 0o040000, two)]);
        let final_commit = objects.commit(final_tree, &[mid], "final");
        let uploaded = objects.upload(&[one, two, mid_tree, mid, final_tree, final_commit]);
        let mut proof = ParentReachability::new(format, &[first, second], MergeObjectLimits::default()).unwrap();
        proof.guide_uploaded(&uploaded, |id| objects.load(id), || Ok(())).unwrap();
        assert_eq!(proof.require_kind(a, ObjectType::Blob), Ok(()));
        assert_eq!(proof.require_kind(b, ObjectType::Blob), Ok(()));
        let expected = BTreeSet::from([first, second, first_tree, second_tree, first_dir, second_dir]);
        assert_eq!(objects.reads.borrow().iter().copied().collect::<BTreeSet<_>>(), expected);
        assert_eq!(objects.reads.borrow().len(), expected.len());
    }
}

#[test]
fn all_work_limits_are_cumulative_inclusive_and_do_not_reset_before_fallback() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = fixture(format);
        let full = run(&f, MergeObjectLimits::default()).unwrap();
        let exact = MergeObjectLimits {
            max_objects: full.expanded.len() + full.hint_objects,
            max_edges: full.edges,
            max_total_bytes: full.bytes,
            ..MergeObjectLimits::default()
        };
        let mut proof = run(&f, exact).unwrap();
        assert_eq!(proof.ensure(f.inherited, |_| panic!("known identity"), || Ok(())), Ok(true));
        for limits in [
            MergeObjectLimits { max_objects: exact.max_objects - 1, ..exact },
            MergeObjectLimits { max_edges: exact.max_edges - 1, ..exact },
            MergeObjectLimits { max_total_bytes: exact.max_total_bytes - 1, ..exact },
        ] {
            assert!(matches!(run(&f, limits), Err(MergeSourceError::BudgetExceeded)));
        }
        let absent = git_object_id(format, ObjectType::Blob, b"absent");
        assert_eq!(proof.ensure(absent, |_| panic!("no remaining object-read budget"), || Ok(())),
            Err(MergeSourceError::BudgetExceeded));
    }
}

#[test]
fn cancellation_and_corrupt_hint_or_original_bytes_never_complete_the_guide() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = fixture(format);
        let mut calls = 0usize;
        let mut proof = ParentReachability::new(format, &[f.root], MergeObjectLimits::default()).unwrap();
        proof.guide_uploaded(&f.uploaded, |id| f.objects.load(id), || { calls += 1; Ok(()) }).unwrap();
        for stop in 0..calls {
            let mut seen = 0;
            let mut proof = ParentReachability::new(format, &[f.root], MergeObjectLimits::default()).unwrap();
            assert_eq!(proof.guide_uploaded(&f.uploaded, |id| f.objects.load(id), || {
                let cancelled = seen == stop;
                seen += 1;
                if cancelled { Err(MergeSourceError::Cancelled) } else { Ok(()) }
            }), Err(MergeSourceError::Cancelled));
        }
        let id = *f.uploaded.keys().next().unwrap();
        f.uploaded.get_mut(&id).unwrap().body.push(b'!');
        f.objects.reads.borrow_mut().clear();
        assert!(matches!(run(&f, MergeObjectLimits::default()), Err(MergeSourceError::InvalidObject(bad)) if bad == id));
        assert!(f.objects.reads.borrow().is_empty());
        f.uploaded.get_mut(&id).unwrap().body.pop();
        f.objects.bodies.get_mut(&f.old_deep).unwrap().1.push(b'!');
        assert!(matches!(run(&f, MergeObjectLimits::default()), Err(MergeSourceError::InvalidObject(bad)) if bad == f.old_deep));
    }
}
