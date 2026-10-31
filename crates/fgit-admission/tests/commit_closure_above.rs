#![forbid(unsafe_code)]
//! Native validator fixtures. The source does not represent repository authority.
use fgit_admission::merge::native::objects::{
    CanonicalObjectHeader, FrontierObjectHeaders, MergeObjectLimits, ObjectFrontier,
    validate_commit_closure, validate_commit_closure_above,
};
use fgit_admission::{ProjectionFailure, ValidatedClosure};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_pack::{CanonicalObjectSource, CanonicalPackObject, PackError, PackWriteError};
use fgit_types::{GitHashAlgorithm, GitOid, RefusalCode};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

#[derive(Default)]
struct Source {
    objects: BTreeMap<GitOid, (GitObjectKind, Vec<u8>)>,
    reads: RefCell<Vec<GitOid>>,
}
impl CanonicalObjectSource for Source {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        self.reads.borrow_mut().push(*id);
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
impl Source {
    fn put(&mut self, format: GitHashAlgorithm, kind: GitObjectKind, body: Vec<u8>) -> GitOid {
        let id = git_object_id(format, kind, &body);
        self.objects.insert(id, (kind, body));
        id
    }
}
struct Headers(BTreeMap<GitOid, CanonicalObjectHeader>);
impl FrontierObjectHeaders for Headers {
    fn load_header(&self, id: &GitOid) -> Result<Option<CanonicalObjectHeader>, PackWriteError> {
        self.0
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
    candidate: GitOid,
    shared: GitOid,
    fresh: BTreeSet<GitOid>,
}
fn fixture(format: GitHashAlgorithm, count: usize, selected_count: usize) -> Fixture {
    let mut source = Source::default();
    let shared = source.put(format, GitObjectKind::Blob, vec![b'x'; 4096]);
    let mut parent = None;
    let mut selected = BTreeSet::new();
    for index in 0..count {
        let blob = source.put(
            format,
            GitObjectKind::Blob,
            format!("step {index}\n").into_bytes(),
        );
        let tree = source.put(
            format,
            GitObjectKind::Tree,
            [
                b"100644 file\0".as_slice(),
                blob.as_bytes(),
                b"100644 shared\0",
                shared.as_bytes(),
            ]
            .concat(),
        );
        let mut body = format!("tree {tree}\n");
        if let Some(parent) = parent {
            writeln!(body, "parent {parent}").expect("writing to a String cannot fail");
        }
        writeln!(body, "author A <a@example.invalid> 1 +0000\ncommitter A <a@example.invalid> 2 +0000\n\n{index}").expect("writing to a String cannot fail");
        parent = Some(source.put(format, GitObjectKind::Commit, body.into_bytes()));
        if index + 1 == selected_count {
            selected = source.objects.keys().copied().collect();
        }
    }
    let candidate = parent.unwrap();
    let fresh = source
        .objects
        .keys()
        .filter(|id| !selected.contains(id))
        .copied()
        .collect();
    let headers = Headers(
        selected
            .iter()
            .map(|id| {
                let (kind, body) = &source.objects[id];
                (
                    *id,
                    CanonicalObjectHeader {
                        id: *id,
                        object_type: *kind,
                        body_bytes: body.len(),
                    },
                )
            })
            .collect(),
    );
    Fixture {
        source,
        headers,
        selected,
        candidate,
        shared,
        fresh,
    }
}
fn validate(f: &Fixture, limits: MergeObjectLimits) -> Result<ValidatedClosure, ProjectionFailure> {
    validate_commit_closure_above(
        &f.source,
        f.candidate,
        ObjectFrontier::with_headers(&f.selected, &f.headers),
        limits,
        &mut || true,
    )
}
#[test]
fn multi_commit_frontiers_match_complete_native_closure_without_reading_inherited_payloads() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for count in [2, 3, 9, 33] {
            for cut in [1, count / 2, count - 1] {
                let f = fixture(format, count, cut);
                let full = validate_commit_closure(
                    &f.source,
                    f.candidate,
                    Default::default(),
                    &mut || true,
                )
                .unwrap();
                let expected: BTreeSet<_> = full.objects.difference(&f.selected).copied().collect();
                f.source.reads.borrow_mut().clear();
                let result = validate(&f, Default::default()).unwrap();
                assert_eq!(result.objects, expected);
                assert_eq!(result.objects, f.fresh);
                assert!(
                    f.source
                        .reads
                        .borrow()
                        .iter()
                        .all(|id| !f.selected.contains(id))
                );
                let legacy = validate_commit_closure_above(
                    &f.source,
                    f.candidate,
                    &f.selected,
                    Default::default(),
                    &mut || true,
                )
                .unwrap();
                assert_eq!(result, legacy);
            }
        }
    }
}
#[test]
fn an_empty_frontier_preserves_full_validation_and_the_exact_closure_root() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = fixture(format, 5, 0);
        assert_eq!(
            validate(&f, Default::default()).unwrap(),
            validate_commit_closure(&f.source, f.candidate, Default::default(), &mut || true)
                .unwrap()
        );
    }
}
#[test]
fn selected_root_still_requires_the_complete_correct_native_body() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = fixture(format, 4, 4);
        let result = validate(&f, Default::default()).unwrap();
        assert_eq!(result.objects, BTreeSet::from([f.candidate]));
        assert_eq!(*f.source.reads.borrow(), vec![f.candidate]);
        f.source.objects.get_mut(&f.candidate).unwrap().1.push(b'!');
        assert!(validate(&f, Default::default()).is_err());
    }
}
#[test]
fn original_headers_must_match_identity_kind_and_size_without_fallback() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = fixture(format, 4, 1);
        let good = f.headers.0[&f.shared];
        for bad in [
            CanonicalObjectHeader {
                id: f.candidate,
                ..good
            },
            CanonicalObjectHeader {
                object_type: GitObjectKind::Tree,
                ..good
            },
            CanonicalObjectHeader {
                body_bytes: MergeObjectLimits::default().max_object_bytes + 1,
                ..good
            },
        ] {
            f.headers.0.insert(f.shared, bad);
            assert!(validate(&f, Default::default()).is_err());
            f.headers.0.insert(f.shared, good);
            assert!(validate(&f, Default::default()).is_ok());
        }
        f.headers.0.remove(&f.shared);
        f.source.reads.borrow_mut().clear();
        assert!(validate(&f, Default::default()).is_err());
        assert!(!f.source.reads.borrow().contains(&f.shared));
    }
}
#[test]
fn newly_traversed_bytes_have_an_inclusive_budget_not_one_allowance_per_commit() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = fixture(format, 6, 1);
        let bytes: usize = f.fresh.iter().map(|id| f.source.objects[id].1.len()).sum();
        for (allowance, succeeds) in [(bytes - 1, false), (bytes, true)] {
            let result = validate(
                &f,
                MergeObjectLimits {
                    max_total_bytes: allowance,
                    ..Default::default()
                },
            );
            if succeeds {
                assert_eq!(result.unwrap().objects, f.fresh);
            } else {
                assert_eq!(
                    result.unwrap_err(),
                    ProjectionFailure::Unavailable(RefusalCode::ResourceBudgetExceeded)
                );
            }
        }
    }
}
#[test]
fn cancellation_at_every_checkpoint_never_returns_partial_closure() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = fixture(format, 4, 1);
        let mut finished = false;
        for allowance in 0..1000 {
            let mut calls = 0;
            let result = validate_commit_closure_above(
                &f.source,
                f.candidate,
                ObjectFrontier::with_headers(&f.selected, &f.headers),
                Default::default(),
                &mut || {
                    calls += 1;
                    calls <= allowance
                },
            );
            if let Ok(value) = result {
                assert_eq!(value.objects, f.fresh);
                finished = true;
                break;
            }
            assert_eq!(
                result.unwrap_err(),
                ProjectionFailure::Unavailable(RefusalCode::CancellationInProgress)
            );
        }
        assert!(finished);
    }
}
#[test]
fn metadata_provider_errors_and_zero_commit_do_not_become_success() {
    struct Failed;
    impl FrontierObjectHeaders for Failed {
        fn load_header(&self, _: &GitOid) -> Result<Option<CanonicalObjectHeader>, PackWriteError> {
            Err(PackError::DeadlineExceeded.into())
        }
    }
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = fixture(format, 2, 1);
        assert!(
            validate_commit_closure_above(
                &f.source,
                f.candidate,
                ObjectFrontier::with_headers(&f.selected, &Failed),
                Default::default(),
                &mut || true
            )
            .is_err()
        );
        let zero = GitOid::from_hex(format, &"0".repeat(format.digest_len() * 2)).unwrap();
        assert!(
            validate_commit_closure_above(
                &f.source,
                zero,
                &f.selected,
                Default::default(),
                &mut || true
            )
            .is_err()
        );
        assert!(validate(&f, Default::default()).is_ok());
    }
}
