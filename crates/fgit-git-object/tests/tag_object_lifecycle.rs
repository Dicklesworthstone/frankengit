#![forbid(unsafe_code)]
//! Annotated-tag semantics layered on the byte-preserving object parser.

use fgit_git_object::{
    AcceptanceProfile, ObjectError, TagSignature, TagTargetType, parse_annotated_tag,
};
use fgit_types::GitHashAlgorithm;

fn sha1_limits() -> fgit_git_object::ParseLimits {
    fgit_git_object::ParseLimits::default()
}

fn sha256_limits() -> fgit_git_object::ParseLimits {
    fgit_git_object::ParseLimits {
        tree_reference_bytes: 32,
        ..fgit_git_object::ParseLimits::default()
    }
}

fn body(oid: &str, target_type: &str) -> Vec<u8> {
    format!(
        "object {oid}\ntype {target_type}\ntag v1.2.3\ntagger Tagger <tagger@invalid.example> 1700000002 +0000\n\nrelease\n"
    )
    .into_bytes()
}

#[test]
fn a_sha1_annotated_tag_keeps_its_exact_oracle_corpus_bytes_and_typed_target() {
    // `tag.body` is exercised by the pinned-Git differential corpus; this
    // assertion makes the typed tag view part of that same byte-exact path.
    let bytes = include_bytes!("corpus/tag.body");
    let tag = parse_annotated_tag(
        bytes,
        GitHashAlgorithm::Sha1,
        AcceptanceProfile::StrictCreate,
        &sha1_limits(),
    )
    .expect("the checked-in pinned-oracle tag body has a typed SHA-1 target");

    assert_eq!(tag.as_bytes(), bytes, "parse retains original tag bytes");
    assert_eq!(
        tag.emit(&sha1_limits()).expect("bounded emission succeeds"),
        bytes,
        "emit must not reconstruct or normalize a parsed tag"
    );
    assert_eq!(tag.target().object_type, TagTargetType::Commit);
    assert_eq!(tag.target().oid.algorithm(), GitHashAlgorithm::Sha1);
    assert_eq!(tag.signature(), TagSignature::Absent);
}

#[test]
fn sha256_target_cannot_alias_the_same_text_in_the_sha1_domain() {
    let oid = "a".repeat(64);
    let tag = parse_annotated_tag(
        &body(&oid, "tree"),
        GitHashAlgorithm::Sha256,
        AcceptanceProfile::StrictCreate,
        &sha256_limits(),
    )
    .expect("a 64-hex target is valid only in the SHA-256 domain");
    assert_eq!(tag.target().oid.algorithm(), GitHashAlgorithm::Sha256);

    assert_eq!(
        parse_annotated_tag(
            &body(&oid, "tree"),
            GitHashAlgorithm::Sha1,
            AcceptanceProfile::StrictCreate,
            &sha1_limits(),
        ),
        Err(ObjectError::MalformedObjectReference),
        "a same-looking hexadecimal spelling must not cross an OID domain"
    );
}

#[test]
fn strict_creation_refuses_out_of_order_mandatory_headers_but_import_retains_them() {
    let oid = "b".repeat(40);
    let hostile = format!(
        "type commit\nobject {oid}\ntag v1\ntagger Tagger <tagger@invalid.example> 1 +0000\n\nbody\n"
    );
    assert_eq!(
        parse_annotated_tag(
            hostile.as_bytes(),
            GitHashAlgorithm::Sha1,
            AcceptanceProfile::StrictCreate,
            &sha1_limits(),
        ),
        Err(ObjectError::StrictTagHeaderOrder),
        "new tags use Git's mandatory object/type/tag/tagger prefix order"
    );
    let imported = parse_annotated_tag(
        hostile.as_bytes(),
        GitHashAlgorithm::Sha1,
        AcceptanceProfile::GitCompatibleImport,
        &sha1_limits(),
    )
    .expect("bounded import preserves a historical but unambiguous header order");
    assert_eq!(imported.as_bytes(), hostile.as_bytes());
}

#[test]
fn wrong_declared_target_type_is_refused_before_a_tag_can_be_peeled() {
    let oid = "c".repeat(40);
    assert_eq!(
        parse_annotated_tag(
            &body(&oid, "future-object"),
            GitHashAlgorithm::Sha1,
            AcceptanceProfile::StrictCreate,
            &sha1_limits(),
        ),
        Err(ObjectError::InvalidTagTargetType),
        "a peeled target never relies on a caller-supplied or unknown type"
    );
}

#[test]
fn signature_looking_bytes_are_opaque_and_unverifiable_not_trusted() {
    let oid = "d".repeat(40);
    let bytes = format!(
        "object {oid}\ntype commit\ntag signed\ntagger Tagger <tagger@invalid.example> 1 +0000\ngpgsig -----BEGIN PGP SIGNATURE-----\n opaque-header-material\n\nnotes\n-----BEGIN PGP SIGNATURE-----\nopaque-message-material\n"
    );
    let tag = parse_annotated_tag(
        bytes.as_bytes(),
        GitHashAlgorithm::Sha1,
        AcceptanceProfile::StrictCreate,
        &sha1_limits(),
    )
    .expect("opaque signature-shaped bytes are still byte-preserving tag data");
    assert!(matches!(
        tag.signature(),
        TagSignature::OpaqueUnverifiable(bytes) if bytes.starts_with(b"-----BEGIN PGP SIGNATURE-----")
    ));
    assert_eq!(
        tag.emit(&sha1_limits()).expect("bounded emit"),
        bytes.as_bytes()
    );
}

#[test]
fn domain_and_parser_width_mismatch_refuses_before_header_allocation() {
    let oid = "e".repeat(40);
    assert_eq!(
        parse_annotated_tag(
            &body(&oid, "commit"),
            GitHashAlgorithm::Sha256,
            AcceptanceProfile::StrictCreate,
            &sha1_limits(),
        ),
        Err(ObjectError::TagReferenceAlgorithmMismatch {
            configured_width: 20,
            requested_width: 32,
        })
    );
}
