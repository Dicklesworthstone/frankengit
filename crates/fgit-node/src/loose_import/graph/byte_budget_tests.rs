//! Small exact-boundary twins for the production reachable-closure envelope.
use super::*;
use std::cell::Cell;

fn object(format: GitHashAlgorithm, byte: u8) -> (GitOid, LooseObject) {
    let body = vec![byte; 16];
    let id = fgit_crypto::git_object_id(format, ObjectType::Blob, &body);
    (
        id,
        LooseObject {
            object_type: ObjectType::Blob,
            declared_size: body.len(),
            body,
        },
    )
}

#[test]
fn reachable_profile_supports_multi_hundred_mib_without_expanding_pack_caches() {
    assert_eq!(Limits::default().bytes, 512 * 1024 * 1024);
    assert_eq!(
        super::super::MAX_IMPORT_TOTAL_OBJECT_BYTES,
        128 * 1024 * 1024
    );
    assert_eq!(super::super::MAX_IMPORT_PACK_BYTES, 64 * 1024 * 1024);
    assert_eq!(Limits::default().objects, MAX_IMPORT_OBJECTS);
}

#[test]
fn exact_byte_limit_admits_and_one_byte_less_refuses_in_both_hash_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (first_id, first) = object(format, 1);
        let (second_id, second) = object(format, 2);
        for limit in [31, 32, 33] {
            let loads = Cell::new(0);
            let result = validate(
                [first_id, second_id, first_id],
                format,
                &ParseLimits::default(),
                Limits {
                    bytes: limit,
                    ..Limits::default()
                },
                |id| {
                    loads.set(loads.get() + 1);
                    Ok(if id == first_id {
                        first.clone()
                    } else {
                        second.clone()
                    })
                },
            );
            assert_eq!(
                loads.get(),
                2,
                "duplicate roots must not inflate the byte charge"
            );
            if limit < 32 {
                assert!(matches!(
                    result,
                    Err(LooseGitImportRefusal::TotalObjectBytesExceeded {
                        limit: 31,
                        observed: 32
                    })
                ));
            } else {
                let verified = result.unwrap();
                assert_eq!(verified.total_bytes, 32);
                assert_eq!(verified.objects.len(), 2);
            }
        }
    }
}

#[test]
fn an_overlarge_profile_refuses_before_loading_and_reports_the_byte_dimension() {
    let format = GitHashAlgorithm::Sha256;
    let (id, body) = object(format, 1);
    for limit in [MAX_EXPLICIT_OBJECT_BYTES + 1, u64::MAX] {
        let loads = Cell::new(0);
        let result = validate(
            [id],
            format,
            &ParseLimits::default(),
            Limits {
                bytes: limit,
                ..Limits::default()
            },
            |_| {
                loads.set(loads.get() + 1);
                Ok(body.clone())
            },
        );
        assert_eq!(loads.get(), 0);
        assert!(
            matches!(result, Err(LooseGitImportRefusal::TotalObjectBytesExceeded { limit: MAX_EXPLICIT_OBJECT_BYTES, observed }) if observed == limit)
        );
    }
    let verified = validate(
        [id],
        format,
        &ParseLimits::default(),
        Limits::default(),
        |_| Ok(body.clone()),
    )
    .unwrap();
    assert_eq!(verified.total_bytes, 16);
}

#[test]
fn zero_byte_limit_admits_an_empty_blob_but_not_a_nonempty_blob() {
    let format = GitHashAlgorithm::Sha256;
    let empty = LooseObject {
        object_type: ObjectType::Blob,
        declared_size: 0,
        body: Vec::new(),
    };
    let id = fgit_crypto::git_object_id(format, ObjectType::Blob, &empty.body);
    let limits = Limits {
        bytes: 0,
        ..Limits::default()
    };
    assert_eq!(
        validate([id], format, &ParseLimits::default(), limits, |_| Ok(
            empty.clone()
        ))
        .unwrap()
        .total_bytes,
        0
    );
    let (id, body) = object(format, 1);
    assert!(matches!(
        validate([id], format, &ParseLimits::default(), limits, |_| Ok(
            body.clone()
        )),
        Err(LooseGitImportRefusal::TotalObjectBytesExceeded {
            limit: 0,
            observed: 16
        })
    ));
}

#[test]
fn opaque_blob_leaf_matches_the_native_parser_at_every_body_boundary() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for length in [0_usize, 1, 16, 4096] {
            let body: Vec<u8> = (0..length).map(|i| (i % 256) as u8).collect();
            let id = fgit_crypto::git_object_id(format, ObjectType::Blob, &body);
            for maximum in [0, length.saturating_sub(1), length, length + 1] {
                let parser = ParseLimits {
                    max_object_bytes: maximum,
                    ..ParseLimits::default()
                };
                let expected = parse_object_body(
                    ObjectType::Blob,
                    &body,
                    AcceptanceProfile::GitCompatibleImport,
                    &parser,
                );
                let result = validate([id], format, &parser, Limits::default(), |_| {
                    Ok(LooseObject {
                        object_type: ObjectType::Blob,
                        declared_size: length,
                        body: body.clone(),
                    })
                });
                match (expected, result) {
                    (Ok(ParsedObject::Blob(parsed)), Ok(verified)) => {
                        assert_eq!(verified.total_bytes, length as u64);
                        assert_eq!(verified.objects[&id].body, parsed);
                    }
                    (
                        Err(fgit_git_object::ObjectError::ObjectTooLarge { limit: expected }),
                        Err(LooseGitImportRefusal::ObjectStructure(actual)),
                    ) => {
                        assert!(
                            matches!(*actual, fgit_git_object::ObjectError::ObjectTooLarge { limit } if limit == expected)
                        );
                    }
                    (expected, actual) => {
                        panic!("blob parser disagreement: {expected:?}; {actual:?}")
                    }
                }
            }
        }
    }
}

#[test]
fn opaque_blob_leaf_still_authenticates_the_complete_native_body() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (id, mut body) = object(format, 1);
        body.body[15] ^= 1;
        assert!(
            matches!(validate([id], format, &ParseLimits::default(), Limits::default(), |_| Ok(body.clone())), Err(LooseGitImportRefusal::ObjectIdentityMismatch { expected, .. }) if expected == id)
        );
    }
}
