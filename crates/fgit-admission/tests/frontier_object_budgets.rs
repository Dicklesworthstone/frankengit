#![forbid(unsafe_code)]
//! Real native-byte validation with a read-only source/header test double.
//! Header metadata is not an authority implementation or a durability claim.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

use fgit_admission::merge::native::objects::{
    CanonicalObjectHeader, FrontierObjectHeaders, MergeObjectLimits, ObjectFrontier,
    validate_commit_closure, validate_commit_closure_above, validate_workspace_objects_above,
};
use fgit_admission::{ProjectionFailure, ValidatedClosure};
use fgit_crypto::git_object_id;
use fgit_git_object::ObjectType;
use fgit_pack::{CanonicalObjectSource, CanonicalPackObject, PackWriteError};
use fgit_types::{GitHashAlgorithm, GitOid, RefusalCode};

struct Source {
    format: GitHashAlgorithm,
    objects: BTreeMap<GitOid, (ObjectType, Vec<u8>)>,
    bodies: RefCell<Vec<GitOid>>,
    headers: RefCell<Vec<GitOid>>,
    fallback: BTreeSet<GitOid>,
    wrong_kind: Cell<Option<GitOid>>,
    wrong_identity: Cell<Option<GitOid>>,
    oversized: Cell<Option<GitOid>>,
}
impl Source {
    const fn new(format: GitHashAlgorithm) -> Self {
        Self {
            format,
            objects: BTreeMap::new(),
            bodies: RefCell::new(Vec::new()),
            headers: RefCell::new(Vec::new()),
            fallback: BTreeSet::new(),
            wrong_kind: Cell::new(None),
            wrong_identity: Cell::new(None),
            oversized: Cell::new(None),
        }
    }

    fn put(&mut self, kind: ObjectType, body: Vec<u8>) -> GitOid {
        let id = git_object_id(self.format, kind, &body);
        self.objects.insert(id, (kind, body));
        id
    }

    fn tree(&mut self, entries: &[(String, u32, GitOid)]) -> GitOid {
        let mut body = Vec::new();
        for (name, mode, id) in entries {
            body.extend_from_slice(format!("{mode:o} {name}\0").as_bytes());
            body.extend_from_slice(id.as_bytes());
        }
        self.put(ObjectType::Tree, body)
    }

    fn commit(&mut self, tree: GitOid, parent: Option<GitOid>, label: &str) -> GitOid {
        let parent = parent.map_or_else(String::new, |id| format!("parent {id}\n"));
        self.put(
            ObjectType::Commit,
            format!("tree {tree}\n{parent}author Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\n{label}\n").into_bytes(),
        )
    }

    fn reset_reads(&self) {
        self.bodies.borrow_mut().clear();
        self.headers.borrow_mut().clear();
    }
}
impl CanonicalObjectSource for Source {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        self.bodies.borrow_mut().push(*id);
        let (kind, body) = self
            .objects
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
impl FrontierObjectHeaders for Source {
    fn load_header(&self, id: &GitOid) -> Result<Option<CanonicalObjectHeader>, PackWriteError> {
        self.headers.borrow_mut().push(*id);
        if self.fallback.contains(id) {
            return Ok(None);
        }
        let (kind, body) = self
            .objects
            .get(id)
            .ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        Ok(Some(CanonicalObjectHeader {
            id: if self.wrong_identity.get() == Some(*id) {
                git_object_id(self.format, ObjectType::Blob, b"wrong identity")
            } else {
                *id
            },
            object_type: if self.wrong_kind.get() == Some(*id) {
                ObjectType::Tree
            } else {
                *kind
            },
            body_bytes: if self.oversized.get() == Some(*id) {
                MergeObjectLimits::default().max_object_bytes + 1
            } else {
                body.len()
            },
        }))
    }
}

struct Fixture {
    source: Source,
    frontier: BTreeSet<GitOid>,
    parent: GitOid,
    candidate: GitOid,
    added: BTreeSet<GitOid>,
    inherited: GitOid,
    entries: Vec<(String, u32, GitOid)>,
}
impl Fixture {
    fn new(format: GitHashAlgorithm, width: usize, shared: bool) -> Self {
        let mut source = Source::new(format);
        let mut entries = Vec::new();
        for i in 0..width {
            let body = format!("inherited {}\n", if shared { 0 } else { i });
            let id = source.put(ObjectType::Blob, body.into_bytes());
            entries.push((format!("f{i:06}"), 0o100644, id));
        }
        let inherited = entries[0].2;
        let base_tree = source.tree(&entries);
        let parent = source.commit(base_tree, None, "base");
        let frontier = source.objects.keys().copied().collect();
        let new_blob = source.put(ObjectType::Blob, b"new payload\n".to_vec());
        entries.push(("z-new".into(), 0o100755, new_blob));
        let tree = source.tree(&entries);
        let candidate = source.commit(tree, Some(parent), "candidate");
        Self {
            source,
            frontier,
            parent,
            candidate,
            added: BTreeSet::from([candidate, tree, new_blob]),
            inherited,
            entries,
        }
    }

    fn read(&self, limits: MergeObjectLimits) -> Result<ValidatedClosure, ProjectionFailure> {
        validate_commit_closure_above(
            &self.source,
            self.candidate,
            ObjectFrontier::with_headers(&self.frontier, &self.source),
            limits,
            &mut || true,
        )
    }

    fn body_bytes(&self) -> usize {
        self.added
            .iter()
            .map(|id| self.source.objects[id].1.len())
            .sum()
    }
}
fn three() -> MergeObjectLimits {
    MergeObjectLimits {
        max_objects: 3,
        ..MergeObjectLimits::default()
    }
}
fn resource_refusal(result: Result<ValidatedClosure, ProjectionFailure>) {
    assert!(matches!(
        result,
        Err(ProjectionFailure::Unavailable(
            RefusalCode::ResourceBudgetExceeded
        ))
    ));
}

#[test]
fn inherited_width_does_not_spend_the_new_body_allowance_in_either_native_format() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format, 257, false);
        assert_eq!(f.read(three()).unwrap().objects, f.added);
        assert_eq!(f.source.bodies.borrow().len(), 3);
        assert_eq!(f.source.headers.borrow().len(), 258);
        assert!(
            f.source
                .bodies
                .borrow()
                .iter()
                .all(|id| f.added.contains(id))
        );
        let workspace = validate_workspace_objects_above(
            &f.source,
            f.candidate,
            f.parent,
            ObjectFrontier::with_headers(&f.frontier, &f.source),
            three(),
            &mut || true,
        )
        .unwrap();
        let mut expected = f.added.clone();
        expected.insert(f.parent);
        assert_eq!(workspace.objects, expected);
        resource_refusal(validate_commit_closure(
            &f.source,
            f.candidate,
            three(),
            &mut || true,
        ));
        resource_refusal(validate_commit_closure_above(
            &f.source,
            f.candidate,
            &f.frontier,
            three(),
            &mut || true,
        ));
        resource_refusal(f.read(MergeObjectLimits {
            max_objects: 2,
            ..three()
        }));
    }
}

#[test]
fn default_frontier_supports_more_than_one_hundred_thousand_inherited_files() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format, 100_001, false);
        assert_eq!(
            f.read(MergeObjectLimits::default()).unwrap().objects,
            f.added
        );
        assert_eq!(f.source.bodies.borrow().len(), 3);
        assert_eq!(f.source.headers.borrow().len(), 100_002);
    }
}

#[test]
fn shared_inherited_objects_are_checked_once_but_every_tree_edge_is_charged() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format, 32, true);
        let limits = MergeObjectLimits {
            max_edges: 35,
            ..three()
        };
        assert_eq!(f.read(limits).unwrap().objects, f.added);
        assert_eq!(f.source.headers.borrow().len(), 2);
        resource_refusal(f.read(MergeObjectLimits {
            max_edges: 34,
            ..limits
        }));
        let exact = MergeObjectLimits {
            max_total_bytes: f.body_bytes(),
            ..limits
        };
        assert_eq!(f.read(exact).unwrap().objects, f.added);
        resource_refusal(f.read(MergeObjectLimits {
            max_total_bytes: exact.max_total_bytes - 1,
            ..exact
        }));
    }
}

#[test]
fn declined_optional_headers_reserve_body_work_and_bytes_before_loading() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, 32, false);
        f.source.fallback.insert(f.inherited);
        resource_refusal(f.read(three()));
        assert!(f.source.bodies.borrow().len() <= 3);
        f.source.reset_reads();
        let limits = MergeObjectLimits {
            max_objects: 4,
            ..three()
        };
        assert_eq!(f.read(limits).unwrap().objects, f.added);
        assert_eq!(f.source.bodies.borrow().len(), 4);
        assert!(f.source.bodies.borrow().contains(&f.inherited));
        resource_refusal(f.read(MergeObjectLimits {
            max_total_bytes: f.body_bytes(),
            ..limits
        }));
        f.source.fallback.extend(f.frontier.iter().copied());
        f.source.reset_reads();
        resource_refusal(f.read(limits));
        assert!(f.source.bodies.borrow().len() <= limits.max_objects);
    }
}

#[test]
fn inherited_header_identity_kind_size_and_availability_remain_mandatory() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, 8, false);
        for fault in [&f.source.wrong_kind, &f.source.wrong_identity] {
            fault.set(Some(f.inherited));
            assert!(matches!(
                f.read(three()),
                Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))
            ));
            fault.set(None);
            assert_eq!(f.read(three()).unwrap().objects, f.added);
        }
        f.source.oversized.set(Some(f.inherited));
        resource_refusal(f.read(three()));
        f.source.oversized.set(None);
        f.source.objects.remove(&f.inherited);
        assert!(matches!(
            f.read(three()),
            Err(ProjectionFailure::Unavailable(RefusalCode::EvidenceMissing))
        ));
    }
}

#[test]
fn frontier_membership_cannot_bypass_candidate_hashing_or_conflicting_edge_kinds() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, 8, false);
        f.frontier.insert(f.candidate);
        assert_eq!(f.read(three()).unwrap().objects, f.added);
        assert!(!f.source.headers.borrow().contains(&f.candidate));
        f.source.objects.get_mut(&f.candidate).unwrap().1.push(b'!');
        assert!(matches!(
            f.read(three()),
            Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))
        ));
        let mut f = Fixture::new(format, 8, false);
        f.entries
            .push(("zz-directory".into(), 0o040000, f.inherited));
        let tree = f.source.tree(&f.entries);
        f.candidate = f.source.commit(tree, Some(f.parent), "conflicting kinds");
        assert!(matches!(
            f.read(three()),
            Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))
        ));
    }
}

#[test]
fn cancellation_at_each_checkpoint_discards_the_entire_wide_candidate() {
    let f = Fixture::new(GitHashAlgorithm::Sha256, 8, false);
    let mut checkpoints = 0;
    validate_commit_closure_above(
        &f.source,
        f.candidate,
        ObjectFrontier::with_headers(&f.frontier, &f.source),
        three(),
        &mut || {
            checkpoints += 1;
            true
        },
    )
    .unwrap();
    for stop in 0..checkpoints {
        let mut calls = 0;
        let result = validate_commit_closure_above(
            &f.source,
            f.candidate,
            ObjectFrontier::with_headers(&f.frontier, &f.source),
            three(),
            &mut || {
                let live = calls < stop;
                calls += 1;
                live
            },
        );
        assert!(matches!(
            result,
            Err(ProjectionFailure::Unavailable(
                RefusalCode::CancellationInProgress
            ))
        ));
    }
}
