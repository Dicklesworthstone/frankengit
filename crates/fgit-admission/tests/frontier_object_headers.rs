//! Pure native validator fixtures, not repository authority or storage evidence.
#![forbid(unsafe_code)]
use fgit_admission::merge::native::objects::{
    CanonicalObjectHeader, FrontierObjectHeaders, MAX_REUSED_BLOB_BYTES, MergeObjectLimits,
    ObjectFrontier, validate_workspace_objects_above,
};
use fgit_admission::{ProjectionFailure, ValidatedClosure};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_pack::{CanonicalObjectSource, CanonicalPackObject, PackError, PackWriteError};
use fgit_types::{GitHashAlgorithm, GitOid, RefusalCode};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

struct Source {
    bodies: BTreeMap<GitOid, (GitObjectKind, Vec<u8>)>,
    reads: RefCell<Vec<GitOid>>,
}
impl CanonicalObjectSource for Source {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        self.reads.borrow_mut().push(*id);
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
impl Source {
    fn put(&mut self, format: GitHashAlgorithm, kind: GitObjectKind, body: Vec<u8>) -> GitOid {
        let id = git_object_id(format, kind, &body);
        self.bodies.insert(id, (kind, body));
        id
    }
}
struct Headers {
    entries: BTreeMap<GitOid, CanonicalObjectHeader>,
    reads: RefCell<Vec<GitOid>>,
    decline: bool,
    fail: bool,
    cancelled: Cell<bool>,
    cancel_on_read: bool,
}
impl FrontierObjectHeaders for Headers {
    fn load_header(&self, id: &GitOid) -> Result<Option<CanonicalObjectHeader>, PackWriteError> {
        self.reads.borrow_mut().push(*id);
        if self.cancel_on_read {
            self.cancelled.set(true);
        }
        if self.fail {
            return Err(PackError::DeadlineExceeded.into());
        }
        if self.decline {
            return Ok(None);
        }
        self.entries
            .get(id)
            .copied()
            .map(Some)
            .ok_or(PackWriteError::MissingCanonicalObject(*id))
    }
}
struct Fixture {
    source: Source,
    headers: Headers,
    selected: BTreeSet<GitOid>,
    parent: GitOid,
    candidate: GitOid,
    shared: GitOid,
    tree: GitOid,
    new_blob: GitOid,
    fresh_bytes: usize,
}
fn fixture(format: GitHashAlgorithm) -> Fixture {
    let mut source = Source {
        bodies: BTreeMap::new(),
        reads: RefCell::new(Vec::new()),
    };
    let shared = source.put(format, GitObjectKind::Blob, vec![b'x'; 4096]);
    let old_tree = source.put(
        format,
        GitObjectKind::Tree,
        [b"100644 shared\0".as_slice(), shared.as_bytes()].concat(),
    );
    let commit = |tree, parents: &[GitOid], message| {
        let mut text = format!("tree {tree}\n");
        for parent in parents {
            text.push_str(&format!("parent {parent}\n"));
        }
        text.push_str(&format!("author A <a@example.invalid> 1 +0000\ncommitter A <a@example.invalid> 1 +0000\n\n{message}\n"));
        text.into_bytes()
    };
    let parent = source.put(format, GitObjectKind::Commit, commit(old_tree, &[], "base"));
    let new_blob = source.put(format, GitObjectKind::Blob, b"new\n".to_vec());
    let tree = source.put(
        format,
        GitObjectKind::Tree,
        [
            b"100644 new\0".as_slice(),
            new_blob.as_bytes(),
            b"100644 shared\0",
            shared.as_bytes(),
        ]
        .concat(),
    );
    let candidate = source.put(
        format,
        GitObjectKind::Commit,
        commit(tree, &[parent], "candidate"),
    );
    let selected = BTreeSet::from([parent, old_tree, shared]);
    let entries = selected
        .iter()
        .map(|id| {
            let (kind, body) = &source.bodies[id];
            (
                *id,
                CanonicalObjectHeader {
                    id: *id,
                    object_type: *kind,
                    body_bytes: body.len(),
                },
            )
        })
        .collect();
    let headers = Headers {
        entries,
        reads: RefCell::new(Vec::new()),
        decline: false,
        fail: false,
        cancelled: Cell::new(false),
        cancel_on_read: false,
    };
    let fresh_bytes = [candidate, tree, new_blob]
        .iter()
        .map(|id| source.bodies[id].1.len())
        .sum();
    Fixture {
        source,
        headers,
        selected,
        parent,
        candidate,
        shared,
        tree,
        new_blob,
        fresh_bytes,
    }
}
fn validate(f: &Fixture, limits: MergeObjectLimits) -> Result<ValidatedClosure, ProjectionFailure> {
    validate_workspace_objects_above(
        &f.source,
        f.candidate,
        f.parent,
        ObjectFrontier::with_headers(&f.selected, &f.headers),
        limits,
        &mut || !f.headers.cancelled.get(),
    )
}
const fn budget() -> ProjectionFailure {
    ProjectionFailure::Unavailable(RefusalCode::ResourceBudgetExceeded)
}

#[test]
fn metadata_reuse_keeps_exact_decision_closure_without_materializing_inherited_payloads() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = fixture(format);
        let limits = MergeObjectLimits {
            max_total_bytes: f.fresh_bytes,
            ..Default::default()
        };
        let result = validate(&f, limits).unwrap();
        assert_eq!(
            result.objects,
            BTreeSet::from([f.parent, f.candidate, f.tree, f.new_blob])
        );
        assert_eq!(
            f.source
                .reads
                .borrow()
                .iter()
                .copied()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([f.candidate, f.tree, f.new_blob])
        );
        assert_eq!(
            f.headers
                .reads
                .borrow()
                .iter()
                .copied()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([f.parent, f.shared])
        );
        let legacy = validate_workspace_objects_above(
            &f.source,
            f.candidate,
            f.parent,
            &f.selected,
            MergeObjectLimits::default(),
            &mut || true,
        )
        .unwrap();
        assert_eq!(result.objects, legacy.objects);
        assert_eq!(result.object_closure_root, legacy.object_closure_root);
        assert_eq!(
            validate_workspace_objects_above(
                &f.source,
                f.candidate,
                f.parent,
                &f.selected,
                limits,
                &mut || true
            )
            .unwrap_err(),
            budget()
        );
    }
}
#[test]
fn absent_metadata_support_retains_full_read_budget_and_never_implies_free_evidence() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = fixture(format);
        f.headers.decline = true;
        assert_eq!(
            validate(
                &f,
                MergeObjectLimits {
                    max_total_bytes: f.fresh_bytes,
                    ..Default::default()
                }
            )
            .unwrap_err(),
            budget()
        );
        assert!(validate(&f, MergeObjectLimits::default()).is_ok());
        assert!(f.source.reads.borrow().contains(&f.shared));
    }
}
#[test]
fn corrupt_ids_kinds_and_oversized_headers_refuse_beside_matching_headers() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = fixture(format);
        let correct = f.headers.entries[&f.shared];
        for bad in [
            CanonicalObjectHeader {
                id: f.parent,
                ..correct
            },
            CanonicalObjectHeader {
                object_type: GitObjectKind::Tree,
                ..correct
            },
            CanonicalObjectHeader {
                body_bytes: MergeObjectLimits::default().max_object_bytes + 1,
                ..correct
            },
        ] {
            f.headers.entries.insert(f.shared, bad);
            assert!(validate(&f, MergeObjectLimits::default()).is_err());
            f.headers.entries.insert(f.shared, correct);
            assert!(validate(&f, MergeObjectLimits::default()).is_ok());
        }
    }
}
#[test]
fn selected_candidate_still_requires_its_exact_native_body() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = fixture(format);
        f.selected.insert(f.candidate);
        assert!(validate(&f, MergeObjectLimits::default()).is_ok());
        assert!(!f.headers.reads.borrow().contains(&f.candidate));
        f.source.bodies.get_mut(&f.candidate).unwrap().1.push(b'!');
        assert!(validate(&f, MergeObjectLimits::default()).is_err());
        assert!(!f.headers.reads.borrow().contains(&f.candidate));
    }
}
#[test]
fn unselected_objects_never_acquire_trust_from_a_metadata_provider() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = fixture(format);
        f.selected.remove(&f.shared);
        assert!(validate(&f, MergeObjectLimits::default()).is_ok());
        assert!(!f.headers.reads.borrow().contains(&f.shared));
        f.source.bodies.get_mut(&f.shared).unwrap().1.push(b'!');
        assert!(validate(&f, MergeObjectLimits::default()).is_err());
        assert!(!f.headers.reads.borrow().contains(&f.shared));
    }
}
#[test]
fn metadata_errors_and_cancellation_never_trigger_a_full_body_fallback() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = fixture(format);
        f.headers.fail = true;
        let failure = ProjectionFailure::Unavailable(RefusalCode::CancellationInProgress);
        assert_eq!(
            validate(&f, MergeObjectLimits::default()).unwrap_err(),
            failure
        );
        assert!(!f.source.reads.borrow().contains(&f.shared));
        f.headers.fail = false;
        f.headers.cancel_on_read = true;
        assert_eq!(
            validate(&f, MergeObjectLimits::default()).unwrap_err(),
            failure
        );
        f.headers.cancel_on_read = false;
        f.headers.cancelled.set(false);
        assert!(validate(&f, MergeObjectLimits::default()).is_ok());
    }
}
#[test]
fn full_candidate_byte_and_individual_object_bounds_remain_exact() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = fixture(format);
        assert!(
            validate(
                &f,
                MergeObjectLimits {
                    max_total_bytes: f.fresh_bytes,
                    ..Default::default()
                }
            )
            .is_ok()
        );
        assert_eq!(
            validate(
                &f,
                MergeObjectLimits {
                    max_total_bytes: f.fresh_bytes - 1,
                    ..Default::default()
                }
            )
            .unwrap_err(),
            budget()
        );
        assert_eq!(
            validate(
                &f,
                MergeObjectLimits {
                    max_reused_blob_bytes: 4095,
                    ..Default::default()
                }
            )
            .unwrap_err(),
            budget()
        );
        assert!(
            validate(
                &f,
                MergeObjectLimits {
                    max_reused_blob_bytes: 4096,
                    ..Default::default()
                }
            )
            .is_ok()
        );
    }
}

#[test]
fn reused_blob_headers_have_an_independent_limit_but_loaded_bodies_do_not() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = fixture(format);
        let limits = MergeObjectLimits {
            max_object_bytes: 1024,
            max_reused_blob_bytes: 4096,
            ..Default::default()
        };
        assert!(validate(&f, limits).is_ok());
        assert!(!f.source.reads.borrow().contains(&f.shared));
        assert_eq!(
            validate(
                &f,
                MergeObjectLimits {
                    max_reused_blob_bytes: 4095,
                    ..limits
                }
            )
            .unwrap_err(),
            budget()
        );
        assert_eq!(
            validate(
                &f,
                MergeObjectLimits {
                    max_object_bytes: f.source.bodies[&f.candidate].1.len() - 1,
                    ..limits
                }
            )
            .unwrap_err(),
            budget()
        );
        let parent = f.headers.entries[&f.parent];
        f.headers.entries.get_mut(&f.parent).unwrap().body_bytes = 1025;
        assert_eq!(validate(&f, limits).unwrap_err(), budget());
        f.headers.entries.insert(f.parent, parent);
        assert!(validate(&f, limits).is_ok());

        // The same admitted identity, when supplied as an actual body, is
        // still subject to the small allocation cap.
        f.headers.decline = true;
        assert_eq!(validate(&f, limits).unwrap_err(), budget());
        assert!(f.source.reads.borrow().contains(&f.shared));
        f.headers.decline = false;
        f.selected.remove(&f.shared);
        assert_eq!(validate(&f, limits).unwrap_err(), budget());
    }
}

#[test]
fn a_declined_selected_overlap_must_match_its_native_identity() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = fixture(format);
        f.headers.decline = true;
        assert!(validate(&f, MergeObjectLimits::default()).is_ok());
        f.source.bodies.get_mut(&f.shared).unwrap().1[0] ^= 1;
        assert_eq!(
            validate(&f, MergeObjectLimits::default()).unwrap_err(),
            ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid)
        );
        f.source.bodies.get_mut(&f.shared).unwrap().1[0] ^= 1;
        assert!(validate(&f, MergeObjectLimits::default()).is_ok());
    }
}

#[test]
fn explicit_large_reuse_is_bounded_before_any_source_work() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = fixture(format);
        let large = 32 * 1024 * 1024 + 1;
        f.headers.entries.get_mut(&f.shared).unwrap().body_bytes = large;
        assert_eq!(
            validate(&f, MergeObjectLimits::default()).unwrap_err(),
            budget()
        );
        let limits = MergeObjectLimits {
            max_reused_blob_bytes: large,
            ..Default::default()
        };
        assert!(validate(&f, limits).is_ok());
        assert!(!f.source.reads.borrow().contains(&f.shared));
        let mut refused = vec![0];
        if let Ok(too_large) = usize::try_from(MAX_REUSED_BLOB_BYTES + 1) {
            refused.push(too_large);
        }
        for maximum in refused {
            f.source.reads.borrow_mut().clear();
            f.headers.reads.borrow_mut().clear();
            assert_eq!(
                validate(
                    &f,
                    MergeObjectLimits {
                        max_reused_blob_bytes: maximum,
                        ..limits
                    }
                )
                .unwrap_err(),
                budget()
            );
            assert!(f.source.reads.borrow().is_empty());
            assert!(f.headers.reads.borrow().is_empty());
        }
    }
}
