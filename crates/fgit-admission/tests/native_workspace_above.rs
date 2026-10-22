#![forbid(unsafe_code)]
//! Native-byte fixtures for workspace validation above an authenticated parent
//! frontier. Node tests separately exercise actual parent disclosure authority.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use fgit_admission::merge::native::objects::{
    MergeObjectLimits, validate_workspace_objects, validate_workspace_objects_above,
};
use fgit_admission::{PermittedObjectClosure, ProjectionFailure, permitted_object_closure_root};
use fgit_crypto::git_object_id;
use fgit_git_object::ObjectType;
use fgit_pack::{CanonicalObjectSource, CanonicalPackObject, PackWriteError};
use fgit_types::{GitHashAlgorithm, GitOid, RefusalCode};

#[derive(Default)]
struct Objects {
    bodies: BTreeMap<GitOid, (ObjectType, Vec<u8>)>,
    reads: RefCell<BTreeSet<GitOid>>,
}

impl Objects {
    fn put(&mut self, format: GitHashAlgorithm, kind: ObjectType, body: Vec<u8>) -> GitOid {
        let id = git_object_id(format, kind, &body);
        self.bodies.insert(id, (kind, body));
        id
    }

    fn tree(&mut self, format: GitHashAlgorithm, entries: &[(&str, GitOid)]) -> GitOid {
        let mut body = Vec::new();
        for (name, id) in entries {
            body.extend_from_slice(format!("100644 {name}\0").as_bytes());
            body.extend_from_slice(id.as_bytes());
        }
        self.put(format, ObjectType::Tree, body)
    }

    fn commit(&mut self, tree: GitOid, parents: &[GitOid], message: &str) -> GitOid {
        let mut body = format!("tree {tree}\n");
        for parent in parents {
            writeln!(body, "parent {parent}").unwrap();
        }
        body.push_str("author Fixture <test@example.invalid> 1 +0000\ncommitter Fixture <test@example.invalid> 1 +0000\n\n");
        body.push_str(message);
        self.put(tree.algorithm(), ObjectType::Commit, body.into_bytes())
    }
}

impl CanonicalObjectSource for Objects {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        self.reads.borrow_mut().insert(*id);
        let (kind, body) = self
            .bodies
            .get(id)
            .ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        Ok(CanonicalPackObject::new(
            *id,
            *kind,
            body.clone(),
            Vec::new(),
            0,
            0,
        ))
    }
}

struct Fixture {
    objects: Objects,
    selected: BTreeSet<GitOid>,
    parent: GitOid,
    candidate: GitOid,
    tree: GitOid,
    blob: GitOid,
    inherited: GitOid,
    old_commit: GitOid,
}

fn fixture(format: GitHashAlgorithm) -> Fixture {
    let mut objects = Objects::default();
    let inherited = objects.put(format, ObjectType::Blob, b"unchanged\n".to_vec());
    let original_tree = objects.tree(format, &[("keep", inherited)]);
    let old_commit = objects.commit(original_tree, &[], "old history\n");
    let parent = objects.commit(original_tree, &[old_commit], "parent\n");
    let selected = objects.bodies.keys().copied().collect();
    let blob = objects.put(format, ObjectType::Blob, b"new content\n".to_vec());
    let tree = objects.tree(format, &[("keep", inherited), ("new", blob)]);
    let candidate = objects.commit(tree, &[parent], "workspace change\n");
    Fixture {
        objects,
        selected,
        parent,
        candidate,
        tree,
        blob,
        inherited,
        old_commit,
    }
}

fn run(
    f: &Fixture,
    limits: MergeObjectLimits,
) -> Result<fgit_admission::ValidatedClosure, ProjectionFailure> {
    validate_workspace_objects_above(
        &f.objects,
        f.candidate,
        f.parent,
        &f.selected,
        limits,
        &mut || true,
    )
}

fn refused<T: std::fmt::Debug>(actual: Result<T, ProjectionFailure>, code: RefusalCode) {
    assert!(
        matches!(actual, Err(ProjectionFailure::Refuse(value)) if value == code),
        "{actual:?}"
    );
}

fn unavailable<T: std::fmt::Debug>(actual: Result<T, ProjectionFailure>, code: RefusalCode) {
    assert!(
        matches!(actual, Err(ProjectionFailure::Unavailable(value)) if value == code),
        "{actual:?}"
    );
}

#[test]
fn workspace_delta_preserves_the_full_serving_union_without_reading_old_history() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = fixture(format);
        let result = run(&f, MergeObjectLimits::default()).unwrap();
        let expected = BTreeSet::from([f.candidate, f.tree, f.blob, f.parent]);
        assert_eq!(result.objects, expected);
        assert_eq!(
            result.object_closure_root,
            permitted_object_closure_root(&PermittedObjectClosure::new(expected)).unwrap()
        );
        assert!(!f.objects.reads.borrow().contains(&f.old_commit));
        assert!(f.objects.reads.borrow().contains(&f.inherited));
        let full = validate_workspace_objects(
            &f.objects,
            f.candidate,
            f.parent,
            MergeObjectLimits::default(),
            &mut || true,
        )
        .unwrap();
        assert_eq!(
            full.objects,
            f.selected.union(&result.objects).copied().collect()
        );
        assert_ne!(full.object_closure_root, result.object_closure_root);
    }
}

#[test]
fn an_unselected_parent_is_not_authorized_by_local_object_existence() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = fixture(format);
        f.selected.remove(&f.parent);
        refused(
            run(&f, MergeObjectLimits::default()),
            RefusalCode::ObjectClosureIncomplete,
        );
        assert!(f.objects.reads.borrow().is_empty());
        f.selected.insert(f.parent);
        run(&f, MergeObjectLimits::default()).unwrap();
    }
}

#[test]
fn selected_candidates_still_require_exactly_the_expected_parent_and_strict_creation() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = fixture(format);
        f.selected.extend([f.candidate, f.tree, f.blob]);
        let good = run(&f, MergeObjectLimits::default()).unwrap();
        assert_eq!(good.objects, BTreeSet::from([f.candidate, f.parent]));
        let original = f.candidate;
        for parents in [
            vec![],
            vec![f.old_commit],
            vec![f.parent, f.old_commit],
            vec![f.parent, f.parent],
        ] {
            f.candidate = f
                .objects
                .commit(f.tree, &parents, "bad selected candidate\n");
            f.selected.insert(f.candidate);
            refused(
                run(&f, MergeObjectLimits::default()),
                RefusalCode::EvidenceInvalid,
            );
        }
        let bytes = format!(
            "tree {}\nparent {}\n\nmissing identities\n",
            f.tree, f.parent
        )
        .into_bytes();
        f.candidate = f.objects.put(format, ObjectType::Commit, bytes);
        f.selected.insert(f.candidate);
        refused(
            run(&f, MergeObjectLimits::default()),
            RefusalCode::EvidenceInvalid,
        );
        f.candidate = original;
        assert_eq!(run(&f, MergeObjectLimits::default()).unwrap(), good);
    }
}

#[test]
fn required_native_kinds_missing_dependencies_and_created_hashes_still_fail_closed() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = fixture(format);
        let good = run(&f, MergeObjectLimits::default()).unwrap();
        let held = f.objects.bodies.remove(&f.inherited).unwrap();
        unavailable(
            run(&f, MergeObjectLimits::default()),
            RefusalCode::EvidenceMissing,
        );
        f.objects
            .bodies
            .insert(f.inherited, (ObjectType::Tree, held.1.clone()));
        refused(
            run(&f, MergeObjectLimits::default()),
            RefusalCode::EvidenceInvalid,
        );
        f.objects.bodies.insert(f.inherited, held);
        f.objects.bodies.get_mut(&f.blob).unwrap().1.push(b'!');
        refused(
            run(&f, MergeObjectLimits::default()),
            RefusalCode::EvidenceInvalid,
        );
        f.objects.bodies.get_mut(&f.blob).unwrap().1.pop();
        assert_eq!(run(&f, MergeObjectLimits::default()).unwrap(), good);
    }
}

#[test]
fn narrowed_native_tree_parser_budget_is_unavailable_and_can_be_retried() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = fixture(format);
        let names: Vec<_> = (0..5).map(|n| format!("file{n}")).collect();
        let entries: Vec<_> = names
            .iter()
            .map(|name| (name.as_str(), f.inherited))
            .collect();
        f.tree = f.objects.tree(format, &entries);
        f.candidate = f.objects.commit(f.tree, &[f.parent], "wide native tree\n");
        let good = run(&f, MergeObjectLimits::default()).unwrap();
        // Two candidate edges precede this five-entry tree. The lowered tree
        // parser limit, not a graph-edge charge, must remain retryable.
        let limits = MergeObjectLimits {
            max_edges: 4,
            ..MergeObjectLimits::default()
        };
        unavailable(run(&f, limits), RefusalCode::ResourceBudgetExceeded);
        // The shared full validator must classify the same parser exhaustion
        // identically; a resource choice is not malformed native evidence.
        unavailable(
            validate_workspace_objects(&f.objects, f.candidate, f.parent, limits, &mut || true),
            RefusalCode::ResourceBudgetExceeded,
        );
        assert_eq!(run(&f, MergeObjectLimits::default()).unwrap(), good);
    }
}

#[test]
fn cancellation_and_resource_limits_never_return_partial_workspace_evidence() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = fixture(format);
        let mut count = 0;
        let good = validate_workspace_objects_above(
            &f.objects,
            f.candidate,
            f.parent,
            &f.selected,
            MergeObjectLimits::default(),
            &mut || {
                count += 1;
                true
            },
        )
        .unwrap();
        for stop in 0..count {
            let mut calls = 0;
            unavailable(
                validate_workspace_objects_above(
                    &f.objects,
                    f.candidate,
                    f.parent,
                    &f.selected,
                    MergeObjectLimits::default(),
                    &mut || {
                        let live = calls < stop;
                        calls += 1;
                        live
                    },
                ),
                RefusalCode::CancellationInProgress,
            );
        }
        for limits in [
            MergeObjectLimits {
                max_objects: 1,
                ..MergeObjectLimits::default()
            },
            MergeObjectLimits {
                max_object_bytes: 1,
                ..MergeObjectLimits::default()
            },
            MergeObjectLimits {
                max_total_bytes: 1,
                ..MergeObjectLimits::default()
            },
        ] {
            unavailable(run(&f, limits), RefusalCode::ResourceBudgetExceeded);
        }
        assert_eq!(run(&f, MergeObjectLimits::default()).unwrap(), good);
    }
}
