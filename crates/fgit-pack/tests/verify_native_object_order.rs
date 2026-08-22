#![forbid(unsafe_code)]

//! frankengit-qc2q: the order of `verify_native_object`'s three guards.
//!
//! This is the function that decides whether bytes arriving in a pack really
//! are the Git object they claim to be. AGENTS.md §6 requires native Git object
//! identity to be preserved exactly and treats SHA-1 and SHA-256 as distinct
//! typed domains; §4 forbids accepting a decoder result without its original
//! commitments. Three checks run in sequence:
//!
//! ```text
//! verify.rs:58  expected_oid.algorithm() != format  -> ObjectFormatMismatch
//! verify.rs:65  parse_object_body fails             -> ObjectParse
//! verify.rs:68  recomputed oid != expected_oid      -> NativeObjectIdMismatch
//! ```
//!
//! The crate's in-src module already covers the happy path and the third guard.
//! The first two had no test, and neither did the ORDER between them and the
//! third.
//!
//! # Why the ordering is the interesting half
//!
//! Every probe below hands in an `expected_oid` that also fails the identity
//! check, so each input fails TWO guards at once. Which refusal comes back is
//! then decided purely by sequence, and the three say different things to a
//! caller: your hash algorithm is wrong, your bytes are not a well-formed
//! object, or your bytes are a fine object but not the one you named. A test
//! that only ever failed one guard at a time could not tell the orders apart.

use fgit_git_object::{AcceptanceProfile, ObjectError, ObjectType, ParseLimits, ParsedObject};
use fgit_pack::{ObjectFormat, ObjectId, PackError, verify_native_object};
use fgit_types::native::{GitOidSha1, GitOidSha256};

/// A well-formed blob body and the SHA-1 identity it really has.
const BODY: &[u8] = b"payload";

/// A commit body with no blank line between headers and message. Strict
/// creation refuses it structurally; import tolerance accepts it.
const MALFORMED_COMMIT: &[u8] = b"this is not a commit body";

fn true_sha1_oid() -> ObjectId {
    fgit_crypto::git_object_id(ObjectFormat::Sha1, ObjectType::Blob, BODY)
}

fn wrong_sha1_oid() -> ObjectId {
    GitOidSha1::from_bytes([0x11; GitOidSha1::LEN]).into()
}

fn sha256_oid() -> ObjectId {
    GitOidSha256::from_bytes([0x22; GitOidSha256::LEN]).into()
}

fn verify(
    format: ObjectFormat,
    object_type: ObjectType,
    content: &[u8],
    expected: &ObjectId,
) -> Result<ParsedObject, PackError> {
    verify_with(
        format,
        object_type,
        content,
        expected,
        AcceptanceProfile::GitCompatibleImport,
    )
}

fn verify_with(
    format: ObjectFormat,
    object_type: ObjectType,
    content: &[u8],
    expected: &ObjectId,
    profile: AcceptanceProfile,
) -> Result<ParsedObject, PackError> {
    verify_native_object(
        format,
        object_type,
        content,
        expected,
        profile,
        &ParseLimits::default(),
    )
}

/// An identity from the wrong hash domain is refused, and named as such.
///
/// The oid is a SHA-256 value offered against a SHA-1 verification, so it
/// ALSO fails the identity check at the end — but the format guard runs first
/// and that is what a caller must be told. §6 makes the two hash domains
/// distinct types precisely so this is not a silent reinterpretation.
#[test]
fn an_identity_from_the_wrong_hash_domain_is_refused_first() {
    let refusal = verify(ObjectFormat::Sha1, ObjectType::Blob, BODY, &sha256_oid())
        .expect_err("a SHA-256 identity cannot verify a SHA-1 object");

    assert_eq!(
        refusal,
        PackError::ObjectFormatMismatch {
            expected: ObjectFormat::Sha1,
            actual: ObjectFormat::Sha256,
        },
        "the domain mismatch must be reported as such, not as an identity mismatch",
    );
}

/// Under STRICT creation, content that is not a well-formed commit is refused
/// at the parse, before the identity is recomputed.
///
/// The oid supplied is a valid SHA-1 value that does NOT match the content, so
/// the identity guard would also fire — the parse guard running first is the
/// only reason this reports `ObjectParse`. That distinguishes "these bytes are
/// not a commit" from "these bytes are the wrong commit", which are different
/// diagnoses for a corrupt pack.
#[test]
fn malformed_content_is_refused_at_the_parse_under_strict_creation() {
    let refusal = verify_with(
        ObjectFormat::Sha1,
        ObjectType::Commit,
        MALFORMED_COMMIT,
        &wrong_sha1_oid(),
        AcceptanceProfile::StrictCreate,
    )
    .expect_err("a body with no header/message separator is not a commit");

    assert!(
        matches!(
            refusal,
            PackError::ObjectParse(ObjectError::MissingHeaderMessageSeparator)
        ),
        "strict creation must name the structural fault; got {refusal:?}",
    );
}

/// The SAME bytes reach the IDENTITY check under import tolerance.
///
/// This is the measured half, and it was not what I assumed before running it.
/// `GitCompatibleImport` exists to preserve "historically tolerated structures
/// that have a bounded, unambiguous parse", and this body is one of them — it
/// parses, so the parse guard never fires and the identity guard is what
/// refuses.
///
/// The pair matters because it shows the guard ORDER is not the whole story:
/// which guard a given input reaches also depends on the acceptance profile the
/// caller passed. A pack import and a local create can be handed identical
/// bytes and be told different things about them, and both answers are correct
/// for their profile.
#[test]
fn the_same_body_reaches_the_identity_check_under_import_tolerance() {
    let refusal = verify(
        ObjectFormat::Sha1,
        ObjectType::Commit,
        MALFORMED_COMMIT,
        &wrong_sha1_oid(),
    )
    .expect_err("the body parses under import tolerance but is not the named object");

    assert_eq!(
        refusal,
        PackError::NativeObjectIdMismatch,
        "import tolerance accepts this structure, so the identity check is what \
         must refuse it",
    );
}

/// The permitted twin: correct domain, well-formed body, matching identity.
///
/// The in-src module has an equivalent, but keeping one here makes this file's
/// refusals self-contained — three probes that only ever see `Err` would pass
/// against a `verify_native_object` that refused unconditionally.
#[test]
fn a_matching_object_verifies() {
    let parsed = verify(ObjectFormat::Sha1, ObjectType::Blob, BODY, &true_sha1_oid())
        .expect("the object is exactly what its identity claims");

    assert!(matches!(parsed, ParsedObject::Blob(body) if body == BODY));
}

/// A well-formed object of the right domain, named by the wrong identity, is
/// refused at the identity check.
///
/// The third guard, already covered in-src, repeated here as the ordering
/// anchor: this input passes format and parse and fails only the identity, so
/// it is what proves the earlier two probes are reporting EARLIER guards rather
/// than this one.
#[test]
fn a_well_formed_object_named_by_the_wrong_identity_is_refused_last() {
    let refusal = verify(
        ObjectFormat::Sha1,
        ObjectType::Blob,
        BODY,
        &wrong_sha1_oid(),
    )
    .expect_err("a blob that is not the named blob must refuse");

    assert_eq!(refusal, PackError::NativeObjectIdMismatch);
}
