#![forbid(unsafe_code)]
//! FG-058 / decision D3: the object-format matrix at the node's public boundary.
//!
//! These tests pin that a repository's configured object format decides the
//! identity every admitted object takes, and that the two formats are not
//! interchangeable. Each SHA-256 case is paired with a near-identical SHA-1
//! case over the *same bytes*, because a format assertion that only ever sees
//! one format cannot tell "derives SHA-256 correctly" from "derives whatever
//! the default is".
//!
//! The expected identities are golden values derived from the Git object
//! format itself -- `sha1(b"blob <len>\0" + body)` and the SHA-256 equivalent --
//! not captured from a run of this code. The empty-blob SHA-1 constant below is
//! the published `e69de29b...` that every Git implementation agrees on, and it
//! is included precisely so the derivation method is checkable: if the header
//! construction used here were wrong, that control would not match, and the
//! SHA-256 goldens derived the same way would be worthless.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_git_object::ObjectType;
use fgit_node::{NodeConfig, OneNode};
use fgit_types::{GitHashAlgorithm, GitOid, RepositoryId, TenantId};

static NEXT_SCRATCH_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct ScratchDirectory(PathBuf);

impl ScratchDirectory {
    fn new() -> Self {
        let sequence = NEXT_SCRATCH_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "frankengit-sha256-format-matrix-{}-{sequence}",
            std::process::id()
        )))
    }
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn config(root: PathBuf, object_format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(
        root,
        TenantId::from_bytes([0x11; 16]),
        RepositoryId::from_bytes([0x22; 16]),
    )
    .with_object_format(object_format)
}

/// The fixture body shared by both formats. Its content is irrelevant; what
/// matters is that both halves of the matrix hash the *same* bytes.
const FIXTURE_BODY: &[u8] = b"fg058 sha256 fixture\n";

const FIXTURE_SHA1: &str = "2323efc54783af3846367955935033c7df24b4c7";
const FIXTURE_SHA256: &str = "11ba0679d3f1c51cbb92a2976c8408169d5e853f536e552b58ea79f9850cbce8";

/// The published empty-blob identities. These are not this project's values --
/// they are the ones upstream Git produces -- and they exist here as a control
/// on the derivation used for `FIXTURE_*` above.
const EMPTY_BLOB_SHA1: &str = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391";
const EMPTY_BLOB_SHA256: &str = "473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813";

/// Admits one blob into a freshly initialized node of the given format and
/// returns the identity the node derived for it.
fn stored_blob_identity(object_format: GitHashAlgorithm, body: &[u8]) -> GitOid {
    let scratch = ScratchDirectory::new();
    let (node, _initialization) = OneNode::init(config(scratch.0.clone(), object_format))
        .expect("a node initializes for the configured object format");
    let stored = node
        .put_git_object(ObjectType::Blob, body.to_vec())
        .expect("a well-formed blob is admitted to the object fabric");
    let identity = stored.identity();
    let _ = node.shutdown();
    identity
}

#[test]
fn a_sha256_repository_derives_the_sha256_object_identity() {
    let identity = stored_blob_identity(GitHashAlgorithm::Sha256, FIXTURE_BODY);

    assert_eq!(
        identity,
        GitOid::from_hex(GitHashAlgorithm::Sha256, FIXTURE_SHA256)
            .expect("the SHA-256 golden parses as a SHA-256 identity"),
        "a SHA-256 repository must name this blob by its SHA-256 Git identity"
    );
    assert_eq!(
        identity.algorithm(),
        GitHashAlgorithm::Sha256,
        "the derived identity carries the repository's configured format"
    );
}

/// The permitted twin. Same bytes, same call, different configured format --
/// so a failure here separates "the node ignores the configured format" from
/// "the node derives SHA-256 incorrectly".
#[test]
fn a_sha1_repository_derives_the_sha1_object_identity() {
    let identity = stored_blob_identity(GitHashAlgorithm::Sha1, FIXTURE_BODY);

    assert_eq!(
        identity,
        GitOid::from_hex(GitHashAlgorithm::Sha1, FIXTURE_SHA1)
            .expect("the SHA-1 golden parses as a SHA-1 identity"),
        "a SHA-1 repository must name this blob by its SHA-1 Git identity"
    );
    assert_eq!(
        identity.algorithm(),
        GitHashAlgorithm::Sha1,
        "the derived identity carries the repository's configured format"
    );
}

/// The discriminating case: the configured format, not the body, decides the
/// identity. Asserting only that the two differ would pass against a node that
/// derived two *wrong* identities, so both are pinned to their published values
/// above and this test pins that they are actually distinct as well.
#[test]
fn one_body_takes_a_distinct_identity_under_each_configured_format() {
    let sha1 = stored_blob_identity(GitHashAlgorithm::Sha1, FIXTURE_BODY);
    let sha256 = stored_blob_identity(GitHashAlgorithm::Sha256, FIXTURE_BODY);

    assert_ne!(
        sha1.algorithm(),
        sha256.algorithm(),
        "the same bytes must not land in the same format domain"
    );
    assert_ne!(
        sha1.to_string(),
        sha256.to_string(),
        "digest-byte aliasing across formats is banned by the compatibility matrix"
    );
}

/// Control on the derivation method itself. `EMPTY_BLOB_SHA1` is the constant
/// every Git implementation publishes; if this fails, the header construction
/// assumed by the `FIXTURE_*` goldens is wrong and those goldens prove nothing.
#[test]
fn the_empty_blob_matches_the_published_identity_in_both_formats() {
    assert_eq!(
        stored_blob_identity(GitHashAlgorithm::Sha1, b""),
        GitOid::from_hex(GitHashAlgorithm::Sha1, EMPTY_BLOB_SHA1)
            .expect("the published empty-blob SHA-1 parses"),
        "the empty blob must take Git's published SHA-1 identity"
    );
    assert_eq!(
        stored_blob_identity(GitHashAlgorithm::Sha256, b""),
        GitOid::from_hex(GitHashAlgorithm::Sha256, EMPTY_BLOB_SHA256)
            .expect("the published empty-blob SHA-256 parses"),
        "the empty blob must take Git's published SHA-256 identity"
    );
}

/// Re-admitting identical bytes is an idempotent placement, not a second
/// object, and the identity is stable across the repeat. Pinned per format so
/// a format-dependent regression in the already-present path cannot hide.
#[test]
fn re_admitting_the_same_body_is_idempotent_in_both_formats() {
    for object_format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new();
        let (node, _initialization) = OneNode::init(config(scratch.0.clone(), object_format))
            .expect("a node initializes for the configured object format");

        let first = node
            .put_git_object(ObjectType::Blob, FIXTURE_BODY.to_vec())
            .expect("the first placement is admitted");
        let second = node
            .put_git_object(ObjectType::Blob, FIXTURE_BODY.to_vec())
            .expect("re-offering identical bytes is admitted");

        assert_eq!(
            first.identity(),
            second.identity(),
            "identical bytes keep one identity under {object_format:?}"
        );
        assert_eq!(
            first.identity().algorithm(),
            object_format,
            "the repeated placement stays in the configured format"
        );

        let _ = node.shutdown();
    }
}
