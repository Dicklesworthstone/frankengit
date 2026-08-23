#![forbid(unsafe_code)]

//! FG-052 bundle-URI V1 materialization tests.
//!
//! Entries own clones of one completed Full Bundle V2 generated through the
//! real pack planner/writer.  The list writer is therefore tested at its real
//! artifact seam, not against a stand-in URI-to-bytes map.

use fgit_crypto::{git_object_id, sha256_digest};
use fgit_git_object::ObjectType;
use fgit_pack::{
    BundleReference, BundleSource, BundleUriEntry, BundleUriLimits, BundleUriListV1,
    BundleUriRefusal, BundleV2, BundleV2Limits, CanonicalObjectSource, CanonicalPackObject,
    ObjectFormat, ObjectId, PackLimits, PackPlanner, PackWriteError, PackWriteProfile, PackWriter,
};
use fgit_types::{
    CodecVersion, DigestAlgorithmId, DigestBytes, RefName, RepositoryCommitId, RepositoryId,
};
use std::collections::BTreeMap;

#[derive(Clone, Default)]
struct FixtureSource {
    objects: BTreeMap<ObjectId, CanonicalPackObject>,
}

impl CanonicalObjectSource for FixtureSource {
    fn load(&self, id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
        self.objects
            .get(id)
            .cloned()
            .ok_or(PackWriteError::MissingCanonicalObject(*id))
    }
}

const fn repository_id() -> RepositoryId {
    RepositoryId::from_bytes([0x55; 16])
}

fn rcr_id() -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        DigestAlgorithmId::try_new(0x8055).expect("fixture code point is nonzero"),
        CodecVersion::new(1, 0),
        DigestBytes::try_new(&[0x55; 32]).expect("fixture digest is long enough"),
    )
}

fn source(commit: ObjectId) -> BundleSource {
    BundleSource::new(repository_id(), rcr_id(), commit)
        .expect("fixture source is a nonzero SHA-1 commit")
}

fn completed_bundle() -> (BundleV2, ObjectId) {
    let tree_body = Vec::new();
    let tree_id = git_object_id(ObjectFormat::Sha1, ObjectType::Tree, &tree_body);
    let commit_body = format!(
        "tree {tree_id}\nauthor Bundle URI <uri@invalid> 0 +0000\ncommitter Bundle URI <uri@invalid> 0 +0000\n\ninitial\n"
    );
    let commit_id = git_object_id(
        ObjectFormat::Sha1,
        ObjectType::Commit,
        commit_body.as_bytes(),
    );
    let tree = CanonicalPackObject::new(tree_id, ObjectType::Tree, tree_body, Vec::new(), 0, 0);
    let commit = CanonicalPackObject::new(
        commit_id,
        ObjectType::Commit,
        commit_body.into_bytes(),
        vec![tree_id],
        0,
        0,
    );
    let mut objects = BTreeMap::new();
    objects.insert(tree_id, tree);
    objects.insert(commit_id, commit);
    let fixture = FixtureSource { objects };
    let mut plan_live = || true;
    let plan = PackPlanner::new(
        ObjectFormat::Sha1,
        PackWriteProfile::STORED_V1,
        PackLimits::default(),
    )
    .plan(&fixture, &[commit_id], &mut plan_live)
    .expect("fixture is a closed canonical object graph");
    let reference = BundleReference::new(
        commit_id,
        RefName::try_new(b"refs/heads/main").expect("fixture ref is valid"),
    );
    let mut live = || true;
    let bundle = BundleV2::write_full(
        source(commit_id),
        &[reference],
        &plan,
        &PackWriter::new(PackLimits::default()),
        &mut live,
        BundleV2Limits::default(),
    )
    .expect("closure-complete plan renders a completed Full Bundle V2");
    (bundle, commit_id)
}

fn entry(name: &str, uri: &str, bundle: BundleV2) -> BundleUriEntry {
    BundleUriEntry::new(name.to_owned(), uri.to_owned(), bundle)
        .expect("fixture URI and bundle-list name are valid")
}

#[test]
fn bundle_uri_v1_sorts_exact_completed_bundle_mirrors_and_receipts_bytes() {
    let (bundle, commit) = completed_bundle();
    let entries = [
        entry(
            "zeta",
            "https://cdn-z.example.invalid/repo.bundle",
            bundle.clone(),
        ),
        entry("alpha", "https://cdn-a.example.invalid/repo.bundle", bundle),
    ];
    let mut live = || true;
    let list = BundleUriListV1::write(
        source(commit),
        &entries,
        BundleUriLimits::default(),
        &mut live,
    )
    .expect("two mirrors of exactly one completed bundle are permitted");
    let expected = concat!(
        "[bundle]\nversion = 1\nmode = any\n",
        "\n[bundle \"alpha\"]\nuri = https://cdn-a.example.invalid/repo.bundle\n",
        "\n[bundle \"zeta\"]\nuri = https://cdn-z.example.invalid/repo.bundle\n",
    );
    assert_eq!(list.bytes(), expected.as_bytes());
    assert_eq!(list.receipt().entry_count(), 2);
    assert_eq!(list.receipt().source(), &source(commit));
    assert_eq!(
        list.receipt().list_sha256(),
        &sha256_digest(expected.as_bytes())
    );
    assert_eq!(
        list.receipt().bundle_output_bytes(),
        entries[0].bundle().bytes().len()
    );
    assert_eq!(
        list.receipt().bundle_pack_checksum(),
        &entries[0].bundle().receipt().pack_receipt().checksum
    );
}

#[test]
fn bundle_uri_v1_refuses_config_injection_duplicate_mirror_and_output_boundary() {
    let (bundle, commit) = completed_bundle();
    assert!(matches!(
        BundleUriEntry::new(
            "bad name".to_owned(),
            "https://cdn.example.invalid/repo.bundle".to_owned(),
            bundle.clone(),
        ),
        Err(BundleUriRefusal::InvalidName { .. })
    ));
    assert!(matches!(
        BundleUriEntry::new(
            "safe".to_owned(),
            "file:///tmp/not-a-bundle-uri".to_owned(),
            bundle.clone(),
        ),
        Err(BundleUriRefusal::InvalidUri { .. })
    ));
    let duplicate = [
        entry(
            "a",
            "https://cdn.example.invalid/repo.bundle",
            bundle.clone(),
        ),
        entry(
            "b",
            "https://cdn.example.invalid/repo.bundle",
            bundle.clone(),
        ),
    ];
    let mut duplicate_live = || true;
    assert!(matches!(
        BundleUriListV1::write(
            source(commit),
            &duplicate,
            BundleUriLimits::default(),
            &mut duplicate_live
        ),
        Err(BundleUriRefusal::DuplicateUri { .. })
    ));
    let only = [entry(
        "only",
        "https://cdn.example.invalid/repo.bundle",
        bundle,
    )];
    let mut live = || true;
    let complete =
        BundleUriListV1::write(source(commit), &only, BundleUriLimits::default(), &mut live)
            .expect("single complete-bundle mirror is permitted");
    let mut limits = BundleUriLimits::default();
    limits.max_output_bytes = complete.bytes().len() - 1;
    let mut bounded_live = || true;
    assert!(matches!(
        BundleUriListV1::write(source(commit), &only, limits, &mut bounded_live),
        Err(BundleUriRefusal::OutputBytesExceeded { .. })
    ));
}
