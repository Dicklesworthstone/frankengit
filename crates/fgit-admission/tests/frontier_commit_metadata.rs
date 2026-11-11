#![forbid(unsafe_code)]
//! Native ancestry validation with optional reusable parsing work. The fixture
//! is an object source, not a substitute for repository selection or authority.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use fgit_admission::merge::native::objects::{
    CanonicalObjectHeader, FrontierCommitMetadata, FrontierObjectHeaders, MergeObjectLimits,
    ObjectFrontier, validate_fast_forward_objects_above, validate_merge_objects_above,
    validate_squash_objects_above,
};
use fgit_admission::{ProjectionFailure, ValidatedClosure};
use fgit_crypto::git_object_id;
use fgit_forge::event::NativeMerge;
use fgit_git_object::{ObjectType, ParseLimits};
use fgit_pack::{CanonicalObjectSource, CanonicalPackObject, PackWriteError};
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RefusalCode};

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

    fn commit(&mut self, tree: GitOid, parents: &[GitOid], time: u64, label: &str) -> GitOid {
        let mut body = format!("tree {tree}\n");
        for parent in parents {
            writeln!(body, "parent {parent}").unwrap();
        }
        write!(
            body,
            "author Test <test@example.invalid> {time} +0000\ncommitter Test <test@example.invalid> {time} +0000\n\n{label}\n"
        )
        .unwrap();
        self.put(tree.algorithm(), ObjectType::Commit, body.into_bytes())
    }
}
impl CanonicalObjectSource for Objects {
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

fn metadata(id: GitOid, body: &[u8]) -> FrontierCommitMetadata {
    FrontierCommitMetadata::verify(id, body, &ParseLimits::default())
        .unwrap()
        .0
}

struct Metadata<'a> {
    source: &'a Objects,
    rows: RefCell<BTreeMap<GitOid, FrontierCommitMetadata>>,
    lookups: RefCell<Vec<GitOid>>,
    observed: RefCell<Vec<GitOid>>,
    enabled: bool,
    cancelled: Cell<bool>,
    cancel_on_lookup: bool,
}
impl<'a> Metadata<'a> {
    fn new(source: &'a Objects, enabled: bool) -> Self {
        Self {
            source,
            rows: RefCell::default(),
            lookups: RefCell::default(),
            observed: RefCell::default(),
            enabled,
            cancelled: Cell::new(false),
            cancel_on_lookup: false,
        }
    }

    fn warm(&self) {
        self.warm_with_limits(&ParseLimits::default());
    }

    fn warm_with_limits(&self, limits: &ParseLimits) {
        for (id, (kind, body)) in &self.source.bodies {
            if *kind == ObjectType::Commit {
                let (verified, _) = FrontierCommitMetadata::verify(*id, body, limits).unwrap();
                self.rows.borrow_mut().insert(*id, verified);
            }
        }
    }
}
impl FrontierObjectHeaders for Metadata<'_> {
    fn load_header(&self, id: &GitOid) -> Result<Option<CanonicalObjectHeader>, PackWriteError> {
        let (kind, body) = self
            .source
            .bodies
            .get(id)
            .ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        Ok(Some(CanonicalObjectHeader {
            id: *id,
            object_type: *kind,
            body_bytes: body.len(),
        }))
    }

    fn load_commit_metadata(
        &self,
        id: &GitOid,
        _limits: &ParseLimits,
    ) -> Result<Option<FrontierCommitMetadata>, ProjectionFailure> {
        self.lookups.borrow_mut().push(*id);
        if self.cancel_on_lookup {
            self.cancelled.set(true);
        }
        Ok(if self.enabled {
            self.rows.borrow().get(id).cloned()
        } else {
            None
        })
    }

    fn remember_commit_metadata(&self, id: &GitOid, body: &[u8], _limits: &ParseLimits) {
        self.observed.borrow_mut().push(*id);
        if self.enabled {
            self.rows.borrow_mut().insert(*id, metadata(*id, body));
        }
    }
}

struct Fixture {
    objects: Objects,
    selected: BTreeSet<GitOid>,
    merge: NativeMerge,
    squash: NativeMerge,
    forward: NativeMerge,
}
fn fixture(format: GitHashAlgorithm) -> Fixture {
    fixture_with_history(format, "", "base")
}

fn fixture_with_history(format: GitHashAlgorithm, extra_headers: &str, message: &str) -> Fixture {
    let mut objects = Objects::default();
    let tree = objects.put(format, ObjectType::Tree, Vec::new());
    let base = objects.put(format, ObjectType::Commit, format!(
        "tree {tree}\n{extra_headers}author Test <test@example.invalid> 10 +0000\ncommitter Test <test@example.invalid> 10 +0000\n\n{message}\n"
    ).into_bytes());
    let left = objects.commit(tree, &[base], 20, "main");
    // Repeated historical parent headers must retain the simple-graph result.
    let right = objects.commit(tree, &[base, base], 30, "topic");
    let selected = objects.bodies.keys().copied().collect();
    let candidate = objects.commit(tree, &[left, right], 40, "merge");
    let squash = objects.commit(tree, &[left], 40, "squash");
    let merge = NativeMerge {
        source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
        source_tip: right,
        base_tip: base,
        target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
        target_tip_before: left,
        merge_commit: candidate,
    };
    Fixture {
        objects,
        selected,
        squash: NativeMerge {
            merge_commit: squash,
            ..merge.clone()
        },
        forward: NativeMerge {
            source_tip: left,
            target_tip_before: base,
            merge_commit: left,
            ..merge.clone()
        },
        merge,
    }
}

fn validate(
    fixture: &Fixture,
    metadata: &Metadata<'_>,
    method: usize,
    limits: MergeObjectLimits,
) -> Result<ValidatedClosure, ProjectionFailure> {
    let frontier = ObjectFrontier::with_headers(&fixture.selected, metadata);
    let mut live = || !metadata.cancelled.get();
    match method {
        0 => validate_merge_objects_above(
            &fixture.objects,
            &fixture.merge,
            frontier,
            limits,
            &mut live,
        ),
        1 => validate_squash_objects_above(
            &fixture.objects,
            &fixture.squash,
            frontier,
            limits,
            &mut live,
        ),
        _ => validate_fast_forward_objects_above(
            &fixture.objects,
            &fixture.forward,
            frontier,
            limits,
            &mut live,
        ),
    }
}

#[test]
fn merge_squash_and_fast_forward_keep_exact_closures_with_warm_cold_and_disabled_metadata() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = fixture(format);
        for method in 0..3 {
            let disabled = Metadata::new(&fixture.objects, false);
            let expected =
                validate(&fixture, &disabled, method, MergeObjectLimits::default()).unwrap();
            let cold_reads = fixture.objects.reads.replace(Vec::new());
            let cache = Metadata::new(&fixture.objects, true);
            let cold = validate(&fixture, &cache, method, MergeObjectLimits::default()).unwrap();
            assert_eq!(cold.objects, expected.objects);
            assert_eq!(cold.object_closure_root, expected.object_closure_root);
            assert!(!cache.observed.borrow().is_empty());
            fixture.objects.reads.borrow_mut().clear();
            cache.observed.borrow_mut().clear();
            let warm = validate(&fixture, &cache, method, MergeObjectLimits::default()).unwrap();
            assert_eq!(warm.objects, expected.objects);
            assert_eq!(warm.object_closure_root, expected.object_closure_root);
            assert!(
                cache.observed.borrow().is_empty(),
                "all ancestry parses were reused"
            );
            assert!(fixture.objects.reads.borrow().len() < cold_reads.len());
            assert!(!cache.lookups.borrow().contains(&fixture.merge.merge_commit));
            assert!(
                !cache
                    .lookups
                    .borrow()
                    .contains(&fixture.squash.merge_commit)
            );
            fixture.objects.reads.borrow_mut().clear();
        }
    }
}

#[test]
fn cached_parent_metadata_cannot_extend_the_selected_frontier() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut fixture = fixture(format);
        fixture.selected.remove(&fixture.merge.base_tip);
        let cache = Metadata::new(&fixture.objects, true);
        cache.warm();
        assert_eq!(
            validate(&fixture, &cache, 2, MergeObjectLimits::default()).unwrap_err(),
            ProjectionFailure::Refuse(RefusalCode::ObjectClosureIncomplete),
        );
        assert!(!cache.lookups.borrow().contains(&fixture.merge.base_tip));
        assert!(
            !fixture
                .objects
                .reads
                .borrow()
                .contains(&fixture.merge.base_tip)
        );
    }
}

#[test]
fn native_metadata_rejects_fabricated_identity_bytes_and_parent_edges() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = fixture(format);
        let id = fixture.merge.base_tip;
        let body = &fixture.objects.bodies[&id].1;
        let invalid = ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid);
        let zero = GitOid::from_hex(format, &"0".repeat(format.digest_len() * 2)).unwrap();
        for claimed in [zero, fixture.merge.source_tip] {
            assert_eq!(
                FrontierCommitMetadata::verify(claimed, body, &ParseLimits::default()).unwrap_err(),
                invalid
            );
        }
        let mut altered = body.clone();
        altered.push(b'x');
        assert_eq!(
            FrontierCommitMetadata::verify(id, &altered, &ParseLimits::default()).unwrap_err(),
            invalid
        );
        let other_format = match format {
            GitHashAlgorithm::Sha1 => GitHashAlgorithm::Sha256,
            GitHashAlgorithm::Sha256 => GitHashAlgorithm::Sha1,
        };
        let foreign = git_object_id(other_format, ObjectType::Commit, b"foreign parent");
        let tree = git_object_id(format, ObjectType::Tree, b"");
        let malformed = format!("tree {tree}\nparent {foreign}\n\nwrong width\n");
        let malformed_id = git_object_id(format, ObjectType::Commit, malformed.as_bytes());
        assert_eq!(
            FrontierCommitMetadata::verify(
                malformed_id,
                malformed.as_bytes(),
                &ParseLimits::default()
            )
            .unwrap_err(),
            invalid
        );
        // Preserve native identity refusal even when the offered body also
        // violates a parser limit, as the original node cache did.
        let too_small = ParseLimits {
            max_object_bytes: 0,
            ..ParseLimits::default()
        };
        assert_eq!(
            FrontierCommitMetadata::verify(fixture.merge.source_tip, body, &too_small).unwrap_err(),
            invalid
        );
        let verified = metadata(id, body);
        assert_eq!(verified.id(), id);
        assert!(verified.parents().is_empty());
        assert_eq!(verified.body_bytes(), body.len());
        assert_eq!(verified.order_hint(), Some(10));
    }
}

#[test]
fn certificates_for_another_key_cannot_replace_selected_commit_adjacency() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = fixture(format);
        let cache = Metadata::new(&fixture.objects, true);
        cache.warm();
        let unrelated = cache.rows.borrow()[&fixture.merge.source_tip].clone();
        cache
            .rows
            .borrow_mut()
            .insert(fixture.merge.base_tip, unrelated);
        assert_eq!(
            validate(&fixture, &cache, 2, MergeObjectLimits::default()).unwrap_err(),
            ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid),
        );
    }
}

#[test]
fn warm_metadata_preserves_real_body_header_and_traversal_limits() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let parse_limits = ParseLimits::default();
        let histories = [
            (String::new(), "long message".repeat(256)),
            (
                "extra value\n".repeat(parse_limits.max_header_lines + 1),
                "base".to_owned(),
            ),
            (
                format!(
                    "extra {}\n",
                    "x".repeat(parse_limits.max_header_line_bytes + 1)
                ),
                "base".to_owned(),
            ),
        ];
        for (index, (headers, message)) in histories.iter().enumerate() {
            let fixture = fixture_with_history(format, headers, message);
            let cache = Metadata::new(&fixture.objects, true);
            cache.warm_with_limits(&ParseLimits {
                max_header_lines: parse_limits.max_header_lines * 2,
                max_header_line_bytes: parse_limits.max_header_line_bytes * 2,
                ..parse_limits.clone()
            });
            let limits = if index == 0 {
                MergeObjectLimits {
                    max_object_bytes: 2048,
                    ..MergeObjectLimits::default()
                }
            } else {
                MergeObjectLimits::default()
            };
            let disabled = Metadata::new(&fixture.objects, false);
            let expected = ProjectionFailure::Unavailable(RefusalCode::ResourceBudgetExceeded);
            assert_eq!(validate(&fixture, &cache, 2, limits).unwrap_err(), expected);
            assert_eq!(
                validate(&fixture, &disabled, 2, limits).unwrap_err(),
                expected
            );
        }
        let fixture = fixture(format);
        let cache = Metadata::new(&fixture.objects, true);
        cache.warm();
        validate(&fixture, &cache, 2, MergeObjectLimits::default()).unwrap();
        let disabled = Metadata::new(&fixture.objects, false);
        let narrow = MergeObjectLimits {
            max_objects: 1,
            ..MergeObjectLimits::default()
        };
        assert_eq!(
            validate(&fixture, &cache, 2, narrow).unwrap_err(),
            validate(&fixture, &disabled, 2, narrow).unwrap_err(),
        );
    }
}

#[test]
fn cancellation_during_metadata_lookup_returns_no_partial_closure() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = fixture(format);
        let mut cache = Metadata::new(&fixture.objects, true);
        cache.warm();
        cache.cancel_on_lookup = true;
        assert_eq!(
            validate(&fixture, &cache, 0, MergeObjectLimits::default()).unwrap_err(),
            ProjectionFailure::Unavailable(RefusalCode::CancellationInProgress),
        );
        cache.cancel_on_lookup = false;
        cache.cancelled.set(false);
        validate(&fixture, &cache, 0, MergeObjectLimits::default()).unwrap();
    }
}

#[test]
fn cached_candidate_metadata_never_replaces_the_supplied_candidate_bytes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut fixture = fixture(format);
        let metadata_before_corruption = {
            let cache = Metadata::new(&fixture.objects, true);
            cache.warm();
            cache.rows.into_inner()
        };
        fixture
            .objects
            .bodies
            .get_mut(&fixture.merge.merge_commit)
            .unwrap()
            .1
            .push(b'x');
        let cache = Metadata::new(&fixture.objects, true);
        cache.rows.replace(metadata_before_corruption);
        assert_eq!(
            validate(&fixture, &cache, 0, MergeObjectLimits::default()).unwrap_err(),
            ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid),
        );
        assert!(!cache.lookups.borrow().contains(&fixture.merge.merge_commit));
    }
}
