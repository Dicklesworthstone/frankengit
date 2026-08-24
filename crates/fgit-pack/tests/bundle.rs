//! Full Bundle V2 materialization behaviour for FG-052.
//!
//! The fixture supplies canonical objects and explicit closure edges to the
//! real pack planner.  The bundle writer then owns only the Git bundle header
//! and refuses an intentionally selected-but-incomplete plan before pack work.

use fgit_crypto::{git_object_id, sha256_digest};
use fgit_git_object::ObjectType;
use fgit_pack::{
    BundleProfile, BundleReference, BundleSource, BundleV2, BundleV2Limits, BundleV2Refusal,
    CanonicalObjectSource, CanonicalPackObject, ObjectFormat, ObjectId, PackLimits, PackPlanner,
    PackWriteError, PackWriteProfile, PackWriter,
};
use fgit_types::{
    CodecVersion, DigestAlgorithmId, DigestBytes, GitOidSha256, RefName, RepositoryCommitId,
    RepositoryId,
};
use std::collections::BTreeMap;

const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0x8044;

#[derive(Clone, Default)]
struct FixtureSource {
    objects: BTreeMap<ObjectId, CanonicalPackObject>,
}

impl FixtureSource {
    fn insert(&mut self, object: CanonicalPackObject) {
        self.objects.insert(object.id(), object);
    }
}

impl CanonicalObjectSource for FixtureSource {
    fn load(&self, id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
        self.objects
            .get(id)
            .cloned()
            .ok_or(PackWriteError::MissingCanonicalObject(*id))
    }
}

fn rcr_id() -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("fixture code point is nonzero"),
        CodecVersion::new(1, 0),
        DigestBytes::try_new(&[0x44; 32]).expect("fixture digest is long enough"),
    )
}

const fn repository_id() -> RepositoryId {
    RepositoryId::from_bytes([0x81; 16])
}

fn object(kind: ObjectType, body: &[u8], references: Vec<ObjectId>) -> CanonicalPackObject {
    let id = git_object_id(ObjectFormat::Sha1, kind, body);
    CanonicalPackObject::new(id, kind, body.to_vec(), references, 0, 0)
}

fn source_with_commit_and_tree() -> (FixtureSource, ObjectId) {
    let mut source = FixtureSource::default();
    let tree = object(ObjectType::Tree, b"", Vec::new());
    let commit_body = format!(
        "tree {}\nauthor Bundle Test <bundle@example.invalid> 0 +0000\ncommitter Bundle Test <bundle@example.invalid> 0 +0000\n\ninitial\n",
        tree.id()
    );
    let commit = object(ObjectType::Commit, commit_body.as_bytes(), vec![tree.id()]);
    let commit_id = commit.id();
    source.insert(tree);
    source.insert(commit);
    (source, commit_id)
}

fn source(commit: ObjectId) -> BundleSource {
    BundleSource::new(repository_id(), rcr_id(), commit)
        .expect("fixture uses a nonzero SHA-1 source commit")
}

fn reference(commit: ObjectId) -> BundleReference {
    named_reference(commit, b"refs/heads/main")
}

fn named_reference(commit: ObjectId, name: &[u8]) -> BundleReference {
    BundleReference::new(
        commit,
        RefName::try_new(name).expect("fixture ref is valid"),
    )
}

fn plan(source: &FixtureSource, roots: &[ObjectId]) -> fgit_pack::PackPlan {
    let mut live = || true;
    PackPlanner::new(
        ObjectFormat::Sha1,
        PackWriteProfile::STORED_V1,
        PackLimits::default(),
    )
    .plan(source, roots, &mut live)
    .expect("fixture closure is valid")
}

#[test]
fn full_bundle_v2_is_byte_stable_and_receipted_to_its_source() {
    let (objects, commit) = source_with_commit_and_tree();
    let plan = plan(&objects, &[commit]);
    let writer = PackWriter::new(PackLimits::default());
    let mut first_live = || true;
    let first = BundleV2::write_full(
        source(commit),
        &[reference(commit)],
        &plan,
        &writer,
        &mut first_live,
        BundleV2Limits::default(),
    )
    .expect("closure-complete SHA-1 plan renders as Bundle V2");
    let mut second_live = || true;
    let second = BundleV2::write_full(
        source(commit),
        &[reference(commit)],
        &plan,
        &writer,
        &mut second_live,
        BundleV2Limits::default(),
    )
    .expect("the same source, refs, and plan reproduce bundle bytes");

    assert_eq!(first, second);
    let expected_header = format!("# v2 git bundle\n{commit} refs/heads/main\n\n");
    assert!(first.bytes().starts_with(expected_header.as_bytes()));
    assert_eq!(
        first.receipt().header_sha256(),
        &sha256_digest(expected_header.as_bytes())
    );
    assert_eq!(first.receipt().source().repository_id(), repository_id());
    assert_eq!(first.receipt().source().source_rcr_id(), rcr_id());
    assert_eq!(first.receipt().source().source_commit_oid(), &commit);
    assert_eq!(first.receipt().profile(), BundleProfile::FullV2Sha1);
    assert_eq!(first.receipt().reference_count(), 1);
    assert_eq!(first.receipt().output_bytes(), first.bytes().len());
    let pack = &first.bytes()[expected_header.len()..];
    assert!(pack.starts_with(b"PACK\0\0\0\x02"));
    assert_eq!(
        pack.len(),
        first.receipt().pack_receipt().output_bytes,
        "bundle pack bytes carry the writer's exact immutable receipt"
    );
}

#[test]
fn full_bundle_v2_refuses_a_selected_plan_with_a_missing_closure_edge() {
    let (objects, commit) = source_with_commit_and_tree();
    let mut live = || true;
    let selected = PackPlanner::new(
        ObjectFormat::Sha1,
        PackWriteProfile::STORED_V1,
        PackLimits::default(),
    )
    .plan_selected(&objects, &[commit], &mut live)
    .expect("selected plans deliberately allow an authenticated omission");
    let writer = PackWriter::new(PackLimits::default());
    let mut bundle_live = || true;
    assert!(matches!(
        BundleV2::write_full(
            source(commit),
            &[reference(commit)],
            &selected,
            &writer,
            &mut bundle_live,
            BundleV2Limits::default(),
        ),
        Err(BundleV2Refusal::ClosureEdgeMissing { source, .. }) if source == commit
    ));
}

#[test]
fn full_bundle_v2_refuses_zero_sha256_and_tight_header_twins() {
    let sha256 = ObjectId::from(GitOidSha256::from_bytes([0x55; 32]));
    assert!(matches!(
        BundleSource::new(repository_id(), rcr_id(), sha256),
        Err(BundleV2Refusal::ObjectFormatUnsupported { .. })
    ));

    let (objects, commit) = source_with_commit_and_tree();
    let plan = plan(&objects, &[commit]);
    let writer = PackWriter::new(PackLimits::default());
    let header_len = format!("# v2 git bundle\n{commit} refs/heads/main\n\n").len();
    let mut too_small_live = || true;
    assert_eq!(
        BundleV2::write_full(
            source(commit),
            &[reference(commit)],
            &plan,
            &writer,
            &mut too_small_live,
            BundleV2Limits {
                max_header_bytes: header_len - 1,
                ..BundleV2Limits::default()
            },
        ),
        Err(BundleV2Refusal::HeaderBytesExceeded {
            observed: header_len,
            limit: header_len - 1,
        })
    );

    let mut output_too_small_live = || true;
    assert_eq!(
        BundleV2::write_full(
            source(commit),
            &[reference(commit)],
            &plan,
            &writer,
            &mut output_too_small_live,
            BundleV2Limits {
                max_output_bytes: header_len - 1,
                ..BundleV2Limits::default()
            },
        ),
        Err(BundleV2Refusal::OutputBytesExceeded {
            observed: header_len,
            limit: header_len - 1,
        })
    );

    let mut exact_live = || true;
    assert!(
        BundleV2::write_full(
            source(commit),
            &[reference(commit)],
            &plan,
            &writer,
            &mut exact_live,
            BundleV2Limits {
                max_header_bytes: header_len,
                ..BundleV2Limits::default()
            },
        )
        .is_ok(),
        "the one-byte-larger header-bound twin proceeds"
    );
}

#[test]
fn quarantined_bundle_inspection_preserves_the_canonical_header_and_pack_boundary() {
    let (objects, commit) = source_with_commit_and_tree();
    let plan = plan(&objects, &[commit]);
    let writer = PackWriter::new(PackLimits::default());
    let references = [
        named_reference(commit, b"refs/heads/a"),
        named_reference(commit, b"refs/heads/z"),
    ];
    let mut live = || true;
    let bundle = BundleV2::write_full(
        source(commit),
        &references,
        &plan,
        &writer,
        &mut live,
        BundleV2Limits::default(),
    )
    .expect("fixture plan writes a canonical full bundle");

    let inspection = BundleV2::inspect_quarantined_full_sha1(
        bundle.bytes(),
        BundleV2Limits::default(),
        &PackLimits::default(),
    )
    .expect("writer output crosses the bounded quarantine header and checksum checks");
    let expected_header =
        format!("# v2 git bundle\n{commit} refs/heads/a\n{commit} refs/heads/z\n\n");
    assert_eq!(inspection.references(), &references);
    assert_eq!(inspection.header_bytes(), expected_header.as_bytes());
    assert_eq!(
        inspection.header_sha256(),
        &sha256_digest(expected_header.as_bytes())
    );
    assert_eq!(
        inspection.pack_bytes(),
        &bundle.bytes()[expected_header.len()..]
    );
    assert_eq!(
        inspection.pack_checksum(),
        bundle.receipt().pack_receipt().checksum,
        "checksum inspection does not turn the pack into admitted objects"
    );
}

#[test]
fn quarantined_bundle_inspection_refuses_noncanonical_headers_corruption_and_bound_twins() {
    let (objects, commit) = source_with_commit_and_tree();
    let plan = plan(&objects, &[commit]);
    let writer = PackWriter::new(PackLimits::default());
    let references = [
        named_reference(commit, b"refs/heads/a"),
        named_reference(commit, b"refs/heads/z"),
    ];
    let mut live = || true;
    let bundle = BundleV2::write_full(
        source(commit),
        &references,
        &plan,
        &writer,
        &mut live,
        BundleV2Limits::default(),
    )
    .expect("fixture plan writes a canonical full bundle");
    let canonical_header =
        format!("# v2 git bundle\n{commit} refs/heads/a\n{commit} refs/heads/z\n\n");
    let pack = &bundle.bytes()[canonical_header.len()..];
    let reversed_header =
        format!("# v2 git bundle\n{commit} refs/heads/z\n{commit} refs/heads/a\n\n");
    let mut reordered = reversed_header.into_bytes();
    reordered.extend_from_slice(pack);
    assert!(matches!(
        BundleV2::inspect_quarantined_full_sha1(
            &reordered,
            BundleV2Limits::default(),
            &PackLimits::default(),
        ),
        Err(BundleV2Refusal::NonCanonicalReferenceOrder { .. })
    ));

    let mut corrupted = bundle.bytes().to_vec();
    let last = corrupted
        .last_mut()
        .expect("a complete bundle contains a pack trailer");
    *last ^= 1;
    assert_eq!(
        BundleV2::inspect_quarantined_full_sha1(
            &corrupted,
            BundleV2Limits::default(),
            &PackLimits::default(),
        ),
        Err(BundleV2Refusal::PackChecksumMismatch)
    );

    assert_eq!(
        BundleV2::inspect_quarantined_full_sha1(
            bundle.bytes(),
            BundleV2Limits {
                max_output_bytes: bundle.bytes().len() - 1,
                ..BundleV2Limits::default()
            },
            &PackLimits::default(),
        ),
        Err(BundleV2Refusal::InputBytesExceeded {
            observed: bundle.bytes().len(),
            limit: bundle.bytes().len() - 1,
        })
    );

    assert!(
        BundleV2::inspect_quarantined_full_sha1(
            bundle.bytes(),
            BundleV2Limits {
                max_output_bytes: bundle.bytes().len(),
                ..BundleV2Limits::default()
            },
            &PackLimits::default(),
        )
        .is_ok(),
        "the one-byte-larger input-bound twin proceeds"
    );
}

/// The third `BundleV2Limits` bound, which had neither half of the pair (mwbo).
///
/// `max_header_bytes` and `max_output_bytes` are each bracketed from both sides
/// in this file -- a refusal one byte under and a twin at the exact value, in
/// tests whose names end in "twins". `max_references` had neither: no test
/// overrode the field, and `ReferenceLimitExceeded` appeared nowhere outside
/// `src/`. So the bound that stands between a caller and an unbounded reference
/// vector was the one bound nothing asserted.
///
/// BOTH GUARDS ARE DRIVEN, because they are different code reached differently:
///
/// * `canonical_references` (`bundle.rs:561`) compares `offered.len() > limit`
///   on an already-materialised slice, on the WRITE path;
/// * the reference parse loop (`bundle.rs:634`) compares
///   `references.len() >= limit` before pushing, on the DECODE path.
///
/// Those two operators are equivalent rather than an off-by-one -- the loop
/// tests before pushing, so holding `limit` already means the next push would
/// reach `limit + 1`, and it reports `len() + 1` accordingly. But equivalent is
/// not the same as jointly covered: a twin on one path says nothing about the
/// other, so each is asserted where it lives.
#[test]
fn bundle_v2_brackets_the_reference_limit_on_both_the_write_and_decode_paths() {
    let (objects, commit) = source_with_commit_and_tree();
    let plan = plan(&objects, &[commit]);
    let writer = PackWriter::new(PackLimits::default());

    // Strictly ascending names: `canonical_references` refuses
    // `NonCanonicalReferenceOrder`, so the ordering is what makes this fixture
    // valid rather than an incidental detail.
    let references = [
        named_reference(commit, b"refs/heads/a"),
        named_reference(commit, b"refs/heads/b"),
        named_reference(commit, b"refs/heads/c"),
    ];
    let count = references.len();

    // --- write path, bundle.rs:561 ------------------------------------------
    // Exactly the limit is admitted. This is the half a `>=` would break.
    let mut exact_live = || true;
    let exact = BundleV2::write_full(
        source(commit),
        &references,
        &plan,
        &writer,
        &mut exact_live,
        BundleV2Limits {
            max_references: count,
            ..BundleV2Limits::default()
        },
    )
    .expect("exactly max_references references must be admitted on the write path");

    // One under: refused, naming both sides of the comparison, which is what
    // pins the guard to the count rather than to some larger quantity.
    let mut tight_live = || true;
    assert_eq!(
        BundleV2::write_full(
            source(commit),
            &references,
            &plan,
            &writer,
            &mut tight_live,
            BundleV2Limits {
                max_references: count - 1,
                ..BundleV2Limits::default()
            },
        ),
        Err(BundleV2Refusal::ReferenceLimitExceeded {
            observed: count,
            limit: count - 1,
        })
    );

    // --- decode path, bundle.rs:634 -----------------------------------------
    // Asserted on the decoded references, not on `is_ok()`: a parse that
    // silently dropped one would still be `Ok` and would prove nothing.
    let inspection = BundleV2::inspect_quarantined_full_sha1(
        exact.bytes(),
        BundleV2Limits {
            max_references: count,
            ..BundleV2Limits::default()
        },
        &PackLimits::default(),
    )
    .expect("exactly max_references references must be admitted on the decode path");
    assert_eq!(
        inspection.references(),
        &references,
        "the exact-limit bundle must decode back to every reference it carried"
    );

    assert_eq!(
        BundleV2::inspect_quarantined_full_sha1(
            exact.bytes(),
            BundleV2Limits {
                max_references: count - 1,
                ..BundleV2Limits::default()
            },
            &PackLimits::default(),
        ),
        Err(BundleV2Refusal::ReferenceLimitExceeded {
            observed: count,
            limit: count - 1,
        })
    );
}
