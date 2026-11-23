#![forbid(unsafe_code)]

use fgit_git_object::{
    AcceptanceProfile, ObjectError, ObjectType, ParseLimits, ParsedObject, emit_object_body,
    identify_object_body, parse_object_body,
};
use fgit_types::GitHashAlgorithm;

#[test]
fn derived_names_and_structural_bytes_match_owned_parsing_in_both_formats() {
    for (format, width) in [(GitHashAlgorithm::Sha1, 20), (GitHashAlgorithm::Sha256, 32)] {
        let limits = ParseLimits {
            tree_reference_bytes: width,
            ..ParseLimits::default()
        };
        let hex = "21".repeat(width);
        let mut tree = b"100644 file\0".to_vec();
        tree.extend(vec![0x21; width]);
        let commit =
            format!("tree {hex}\nauthor A <a@b> 1 +0000\ncommitter A <a@b> 1 +0000\n\nmessage\n");
        let tag = format!("object {hex}\ntype commit\ntag v1\ntagger A <a@b> 1 +0000\n\nrelease\n");
        for (kind, bytes) in [
            (ObjectType::Blob, b"hello\n".as_slice()),
            (ObjectType::Tree, tree.as_slice()),
            (ObjectType::Commit, commit.as_bytes()),
            (ObjectType::Tag, tag.as_bytes()),
        ] {
            for profile in [
                AcceptanceProfile::StrictCreate,
                AcceptanceProfile::GitCompatibleImport,
            ] {
                let (id, structure) =
                    identify_object_body(format, kind, bytes, profile, &limits).unwrap();
                assert_eq!(id, fgit_crypto::git_object_id(format, kind, bytes));
                let parsed = parse_object_body(kind, bytes, profile, &limits).unwrap();
                if kind == ObjectType::Blob {
                    assert_eq!(structure, None);
                    assert_eq!(parsed, ParsedObject::Blob(bytes.to_vec()));
                } else {
                    assert_eq!(structure.as_ref(), Some(&parsed));
                    assert_eq!(emit_object_body(&parsed, profile, &limits).unwrap(), bytes);
                }
            }
        }
    }
}

#[test]
fn identification_preserves_size_and_profile_refusals() {
    let format = GitHashAlgorithm::Sha1;
    let profile = AcceptanceProfile::GitCompatibleImport;
    let limits = ParseLimits {
        max_object_bytes: 3,
        ..ParseLimits::default()
    };
    assert!(
        identify_object_body(format, ObjectType::Blob, b"123", profile, &limits)
            .unwrap()
            .1
            .is_none()
    );
    for kind in [
        ObjectType::Blob,
        ObjectType::Tree,
        ObjectType::Commit,
        ObjectType::Tag,
    ] {
        assert_eq!(
            identify_object_body(format, kind, b"1234", profile, &limits),
            Err(ObjectError::ObjectTooLarge { limit: 3 })
        );
    }
    let limits = ParseLimits::default();
    let epoch = b"tree 1111111111111111111111111111111111111111\nauthor A <a@b> 0 +0000\ncommitter A <a@b> 0 +0000\n\nepoch";
    assert_eq!(
        identify_object_body(
            format,
            ObjectType::Commit,
            epoch,
            AcceptanceProfile::StrictCreate,
            &limits
        ),
        Err(ObjectError::MalformedSignatureDate)
    );
    assert!(identify_object_body(format, ObjectType::Commit, epoch, profile, &limits).is_ok());
    for (kind, malformed) in [
        (ObjectType::Tree, b"100644 incomplete".as_slice()),
        (ObjectType::Commit, b" continuation\n"),
        (ObjectType::Tag, b" continuation\n"),
    ] {
        for profile in [
            AcceptanceProfile::GitCompatibleImport,
            AcceptanceProfile::StrictCreate,
        ] {
            assert_eq!(
                identify_object_body(format, kind, malformed, profile, &limits).unwrap_err(),
                parse_object_body(kind, malformed, profile, &limits).unwrap_err()
            );
        }
    }
}
