#![forbid(unsafe_code)]
//! Strict-create header refusals paired with their import semantics.
//!
//! The import assertion in each strict-only pair is intentional: it proves the
//! byte sequence has a bounded, unambiguous parse and that the refusal is a
//! creation policy, not an accidental parser failure.

use fgit_git_object::{AcceptanceProfile, ObjectError, ParseLimits, parse_commit, parse_tag};

const SHA1_HEX: &str = "0000000000000000000000000000000000000000";

type HeaderParser = fn(&[u8], AcceptanceProfile, &ParseLimits) -> Result<(), ObjectError>;

fn commit_result(
    body: &[u8],
    profile: AcceptanceProfile,
    limits: &ParseLimits,
) -> Result<(), ObjectError> {
    parse_commit(body, profile, limits).map(|_| ())
}

fn tag_result(
    body: &[u8],
    profile: AcceptanceProfile,
    limits: &ParseLimits,
) -> Result<(), ObjectError> {
    parse_tag(body, profile, limits).map(|_| ())
}

fn assert_profile_independent_refusal(
    parser: HeaderParser,
    body: &[u8],
    expected: ObjectError,
    case: &str,
) {
    let limits = ParseLimits::default();
    for profile in [
        AcceptanceProfile::StrictCreate,
        AcceptanceProfile::GitCompatibleImport,
    ] {
        assert_eq!(
            parser(body, profile, &limits),
            Err(expected.clone()),
            "{case} must refuse under {profile:?}",
        );
    }
}

fn assert_strict_refusal_import_accepts(
    parser: HeaderParser,
    body: &[u8],
    expected: ObjectError,
    case: &str,
) {
    let limits = ParseLimits::default();
    assert_eq!(
        parser(body, AcceptanceProfile::StrictCreate, &limits),
        Err(expected),
        "{case} must remain forbidden for newly-created objects",
    );
    assert_eq!(
        parser(body, AcceptanceProfile::GitCompatibleImport, &limits),
        Ok(()),
        "{case} must remain importable as bounded, unambiguous historical bytes",
    );
}

fn valid_commit() -> String {
    format!(
        "tree {SHA1_HEX}\nauthor A <a@example.com> 1 +0000\ncommitter C <c@example.com> 1 +0000\n\nmessage"
    )
}

fn valid_tag() -> String {
    format!(
        "object {SHA1_HEX}\ntype commit\ntag release\ntagger T <t@example.com> 1 +0000\n\nmessage"
    )
}

#[test]
fn profile_independent_header_syntax_refusals_hold_for_commit_and_tag() {
    for parser in [commit_result as HeaderParser, tag_result as HeaderParser] {
        assert_profile_independent_refusal(
            parser,
            b"header-without-a-space\n\nmessage",
            ObjectError::MalformedHeader,
            "a header without its name/value separator",
        );
        assert_profile_independent_refusal(
            parser,
            b" orphan-continuation\n\nmessage",
            ObjectError::OrphanHeaderContinuation,
            "a leading continuation without a preceding header",
        );
    }
}

#[test]
fn leading_space_precedes_the_empty_header_name_guard() {
    // `parse_headers` classifies every line starting with ASCII space as a
    // continuation before it searches for a name/value separator. Therefore
    // the apparent empty-name spelling `b" \n"` reaches the reachable
    // `OrphanHeaderContinuation` guard, not `MalformedHeader`. This pins that
    // ordering instead of manufacturing a fixture for an unreachable arm.
    for parser in [commit_result as HeaderParser, tag_result as HeaderParser] {
        assert_profile_independent_refusal(
            parser,
            b" \n\nmessage",
            ObjectError::OrphanHeaderContinuation,
            "an empty-name spelling routed through continuation handling",
        );
    }
}

#[test]
fn strict_header_name_refusal_has_an_import_twin() {
    let body = b"X-Experimental retained-import-header\n\nmessage";
    // Mutation target: making the StrictCreate name guard unconditional makes
    // this import assertion fail, while the profile-independent syntax probes
    // above remain refusing under both profiles.
    assert_strict_refusal_import_accepts(
        tag_result,
        body,
        ObjectError::InvalidStrictHeaderName,
        "an uppercase header name",
    );
}

#[test]
fn strict_commit_header_requirements_have_import_twins() {
    assert_strict_refusal_import_accepts(
        commit_result,
        b"\n\nmessage",
        ObjectError::MissingOrDuplicateCommitTree,
        "a commit with no headers",
    );

    let duplicate_author = format!(
        "tree {SHA1_HEX}\nauthor A <a@example.com> 1 +0000\nauthor B <b@example.com> 2 +0000\ncommitter C <c@example.com> 3 +0000\n\nmessage"
    );
    assert_strict_refusal_import_accepts(
        commit_result,
        duplicate_author.as_bytes(),
        ObjectError::MissingOrDuplicateCommitIdentity,
        "a commit with duplicate author headers",
    );

    let missing_identity = format!("tree {SHA1_HEX}\n\nmessage");
    assert_strict_refusal_import_accepts(
        commit_result,
        missing_identity.as_bytes(),
        ObjectError::MissingOrDuplicateCommitIdentity,
        "a commit with no author or committer",
    );
}

#[test]
fn late_commit_identities_are_an_order_refusal_with_an_import_twin() {
    let late_identity = format!(
        "tree {SHA1_HEX}\ncommitter C <c@example.com> 1 +0000\nauthor A <a@example.com> 1 +0000\n\nmessage"
    );
    // `validate_strict_commit` deliberately reports the later identity as an
    // ordering problem before it would report an identity-count problem.
    assert_strict_refusal_import_accepts(
        commit_result,
        late_identity.as_bytes(),
        ObjectError::StrictCommitHeaderOrder,
        "a commit with author and committer after the required order boundary",
    );
}

#[test]
fn strict_tag_header_requirements_have_import_twins() {
    let missing_tag =
        format!("object {SHA1_HEX}\ntype commit\ntagger T <t@example.com> 1 +0000\n\nmessage");
    assert_strict_refusal_import_accepts(
        tag_result,
        missing_tag.as_bytes(),
        ObjectError::MissingOrDuplicateTagHeader,
        "an annotated tag without a tag header",
    );

    let duplicate_tag = format!(
        "object {SHA1_HEX}\ntype commit\ntag release\ntag release-duplicate\ntagger T <t@example.com> 1 +0000\n\nmessage"
    );
    assert_strict_refusal_import_accepts(
        tag_result,
        duplicate_tag.as_bytes(),
        ObjectError::MissingOrDuplicateTagHeader,
        "an annotated tag with duplicate tag headers",
    );
}

#[test]
fn invalid_strict_tag_name_has_an_import_twin() {
    let invalid_name = format!(
        "object {SHA1_HEX}\ntype commit\ntag release\x01candidate\ntagger T <t@example.com> 1 +0000\n\nmessage"
    );
    assert_strict_refusal_import_accepts(
        tag_result,
        invalid_name.as_bytes(),
        ObjectError::InvalidTagName,
        "an annotated tag name containing a control byte",
    );
}

#[test]
fn well_formed_commit_and_tag_are_permitted_under_both_profiles() {
    for (parser, body, object_kind) in [
        (commit_result as HeaderParser, valid_commit(), "commit"),
        (tag_result as HeaderParser, valid_tag(), "tag"),
    ] {
        let limits = ParseLimits::default();
        for profile in [
            AcceptanceProfile::StrictCreate,
            AcceptanceProfile::GitCompatibleImport,
        ] {
            assert_eq!(
                parser(body.as_bytes(), profile, &limits),
                Ok(()),
                "the well-formed {object_kind} must be accepted under {profile:?}",
            );
        }
    }
}
