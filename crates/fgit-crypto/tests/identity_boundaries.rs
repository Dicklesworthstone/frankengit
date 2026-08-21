//! The separation boundaries this crate exists to enforce, each forbidden
//! case paired with the near-identical permitted case that proceeds.

use fgit_crypto::{
    ALGORITHM_REGISTRY, AlgorithmUsage, CodecVersion, DERIVED_ID_DOMAINS, DOMAIN_REGISTRY,
    DigestAlgorithm, DigestBytes, GIT_PAYLOAD_SCHEMA, GitHashError, GitObjectFormat, GitObjectKind,
    GitOid, IdentityDomain, InternalDigestAlgorithm, InternalIdentityError, InternalObjectId,
    NativeObjectIdentity, RowStatus, SchemaFamily, SchemaId, Sha1, Sha256, git_object_id,
    git_payload_body, git_payload_commitment, internal_digest_in_domain,
    internal_digest_over_parts, internal_digest_value, internal_object_id, parse_git_oid,
    verify_internal_object_id,
};

const EMPTY_BLOB_SHA1: &str = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391";
const EMPTY_BLOB_SHA256: &str = "473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813";

fn schema(family: &str) -> SchemaId {
    SchemaId::new(
        SchemaFamily::try_new(family.as_bytes()).expect("a test family is a canonical label"),
        1,
        0,
    )
}

// --- registry closure -------------------------------------------------------

#[test]
fn domain_rows_match_the_enumeration() {
    assert_eq!(DOMAIN_REGISTRY.len(), IdentityDomain::ALL.len());
    for (index, domain) in IdentityDomain::ALL.iter().copied().enumerate() {
        let row = &DOMAIN_REGISTRY[index];
        assert_eq!(row.domain, domain, "row {index} names its own domain");
        assert_eq!(domain.index(), index, "the discriminant is the row index");
        assert_eq!(
            usize::from(row.registry_id),
            index + 1,
            "registry identifiers are dense and one-based"
        );
        assert_eq!(row.tag, domain.tag());
        assert_eq!(row.domain_tag.as_str(), domain.tag());
        assert_eq!(row.status, RowStatus::Active);
        assert_eq!(
            IdentityDomain::from_tag(domain.tag()),
            Some(domain),
            "every tag resolves back to its domain"
        );
    }
}

#[test]
fn domain_tags_are_unique() {
    for (index, row) in DOMAIN_REGISTRY.iter().enumerate() {
        for other in DOMAIN_REGISTRY.iter().skip(index + 1) {
            assert_ne!(row.tag, other.tag, "two domains must not share a tag");
            assert_ne!(row.registry_id, other.registry_id);
        }
    }
}

#[test]
fn domain_registry_covers_every_derived_identity_domain() {
    // `fgit-types` pins a domain tag on each of its derived identities. If one
    // of those tags had no row here, an identity shell would exist that this
    // registry could not produce or verify.
    for tag in DERIVED_ID_DOMAINS {
        let domain = IdentityDomain::from_tag(tag).unwrap_or_else(|| {
            panic!("`{tag}` is pinned by fgit-types but absent from the registry")
        });
        assert_eq!(domain.tag(), *tag);
        assert!(
            domain.derived_identity().is_some(),
            "`{tag}` must be marked as pinned by a derived identity"
        );
    }
    let pinned = DOMAIN_REGISTRY
        .iter()
        .filter(|row| row.derived_identity.is_some())
        .count();
    assert_eq!(
        pinned,
        DERIVED_ID_DOMAINS.len(),
        "no row may claim a derived identity that fgit-types does not pin"
    );
}

#[test]
fn algorithm_rows_match_the_enumeration() {
    assert_eq!(ALGORITHM_REGISTRY.len(), DigestAlgorithm::ALL.len());
    for (index, algorithm) in DigestAlgorithm::ALL.iter().copied().enumerate() {
        let row = &ALGORITHM_REGISTRY[index];
        assert_eq!(row.algorithm, algorithm);
        assert_eq!(row.code_point, algorithm.code_point());
        assert_eq!(row.name, algorithm.name());
        assert_eq!(row.digest_len, algorithm.digest_len());
        assert_eq!(row.usage, algorithm.usage());
        assert_eq!(
            DigestAlgorithm::from_name(algorithm.name()),
            Some(algorithm)
        );
        assert_eq!(DigestAlgorithm::from_id(algorithm.id()), Some(algorithm));
        assert_eq!(
            DigestAlgorithm::from_git_object_format(algorithm.git_object_format()),
            algorithm
        );
    }
}

#[test]
fn code_points_agree_with_the_declared_object_format() {
    for format in GitObjectFormat::ALL.iter().copied() {
        let algorithm = DigestAlgorithm::from_git_object_format(format);
        assert_eq!(algorithm.code_point(), format.code_point());
        assert_eq!(algorithm.name(), format.as_str());
        assert_eq!(algorithm.digest_len(), format.digest_len());
    }
}

// --- SHA-1 is never an internal identity ------------------------------------

#[test]
fn sha1_is_refused_as_an_internal_identity_construction() {
    assert_eq!(
        DigestAlgorithm::Sha1.usage(),
        AlgorithmUsage::GitIdentityOnly
    );
    assert_eq!(DigestAlgorithm::Sha1.internal_identity_algorithm(), None);
}

#[test]
fn sha256_is_permitted_as_an_internal_identity_construction() {
    assert_eq!(
        DigestAlgorithm::Sha256.usage(),
        AlgorithmUsage::GitAndInternalIdentity
    );
    assert_eq!(
        DigestAlgorithm::Sha256.internal_identity_algorithm(),
        Some(InternalDigestAlgorithm::Sha256)
    );
    for domain in IdentityDomain::ALL.iter().copied() {
        assert_eq!(domain.algorithm(), InternalDigestAlgorithm::Sha256);
        assert_eq!(domain.algorithm().digest_len(), 32);
    }
}

// --- cross-domain replay ----------------------------------------------------

#[test]
fn an_identity_verifies_under_its_own_domain() {
    let body = b"identical body bytes";
    let schema = schema("frankengit.canonical-body");
    let identity = internal_object_id(
        IdentityDomain::RefTransaction,
        schema,
        CodecVersion::new(1, 0),
        body,
    );
    assert_eq!(
        verify_internal_object_id(
            &identity,
            IdentityDomain::RefTransaction,
            schema,
            CodecVersion::new(1, 0),
            body
        ),
        Ok(())
    );
}

#[test]
fn presenting_an_identity_under_another_domain_is_a_typed_mismatch() {
    let body = b"identical body bytes";
    let schema = schema("frankengit.canonical-body");
    let identity = internal_object_id(
        IdentityDomain::RefTransaction,
        schema,
        CodecVersion::new(1, 0),
        body,
    );
    let refusal = verify_internal_object_id(
        &identity,
        IdentityDomain::TransactionSeal,
        schema,
        CodecVersion::new(1, 0),
        body,
    )
    .expect_err("a foreign domain must not verify");
    match refusal {
        InternalIdentityError::DomainMismatch { expected, actual } => {
            assert_eq!(expected, IdentityDomain::TransactionSeal.tag());
            assert_eq!(actual, IdentityDomain::RefTransaction.tag());
        }
        other => panic!("expected a domain mismatch, got {other}"),
    }
}

#[test]
fn replaying_a_digest_under_a_forged_domain_tag_is_a_typed_mismatch() {
    // The strongest form of the replay: an attacker relabels the shell so the
    // domain check passes, and only the recomputed digest catches it.
    let body = b"identical body bytes";
    let schema = schema("frankengit.canonical-body");
    let honest = internal_object_id(
        IdentityDomain::RefTransaction,
        schema,
        CodecVersion::new(1, 0),
        body,
    );
    let forged = InternalObjectId::new(
        IdentityDomain::TransactionSeal.algorithm().id(),
        IdentityDomain::TransactionSeal.domain_tag(),
        CodecVersion::new(1, 0),
        *honest.digest(),
    );
    let refusal = verify_internal_object_id(
        &forged,
        IdentityDomain::TransactionSeal,
        schema,
        CodecVersion::new(1, 0),
        body,
    )
    .expect_err("a relabelled digest must not verify");
    assert!(
        matches!(refusal, InternalIdentityError::DigestMismatch { .. }),
        "expected a digest mismatch, got {refusal}"
    );
}

#[test]
fn identical_bodies_have_different_identities_in_every_domain() {
    let body = b"identical body bytes";
    let schema = schema("frankengit.canonical-body");
    let mut digests: Vec<Vec<u8>> = IdentityDomain::ALL
        .iter()
        .copied()
        .map(|domain| internal_digest_in_domain(domain, schema, body))
        .collect();
    let total = digests.len();
    digests.sort_unstable();
    digests.dedup();
    assert_eq!(
        digests.len(),
        total,
        "one body must not share a digest across two domains"
    );
}

#[test]
fn a_changed_schema_version_changes_the_identity() {
    let body = b"identical body bytes";
    let family =
        SchemaFamily::try_new(b"frankengit.canonical-body").expect("a canonical family label");
    let first = internal_digest_in_domain(
        IdentityDomain::RefTransaction,
        SchemaId::new(family, 1, 0),
        body,
    );
    let major = internal_digest_in_domain(
        IdentityDomain::RefTransaction,
        SchemaId::new(family, 2, 0),
        body,
    );
    let minor = internal_digest_in_domain(
        IdentityDomain::RefTransaction,
        SchemaId::new(family, 1, 1),
        body,
    );
    assert_ne!(first, major);
    assert_ne!(first, minor);
    assert_ne!(major, minor);
}

#[test]
fn a_changed_codec_version_is_a_typed_mismatch_without_changing_the_digest() {
    // The codec version is carried in the identity but not hashed, so a
    // version disagreement must be caught by the explicit check rather than
    // by the digest comparison.
    let body = b"identical body bytes";
    let schema = schema("frankengit.canonical-body");
    let identity = internal_object_id(
        IdentityDomain::RefTransaction,
        schema,
        CodecVersion::new(1, 0),
        body,
    );
    let refusal = verify_internal_object_id(
        &identity,
        IdentityDomain::RefTransaction,
        schema,
        CodecVersion::new(2, 0),
        body,
    )
    .expect_err("a foreign codec version must not verify");
    assert!(
        matches!(refusal, InternalIdentityError::CodecVersionMismatch { .. }),
        "expected a codec version mismatch, got {refusal}"
    );
}

#[test]
fn an_identity_naming_the_wrong_construction_is_a_typed_mismatch() {
    let body = b"identical body bytes";
    let schema = schema("frankengit.canonical-body");
    let honest = internal_object_id(
        IdentityDomain::RefTransaction,
        schema,
        CodecVersion::new(1, 0),
        body,
    );
    let mislabelled = InternalObjectId::new(
        DigestAlgorithm::Sha1.id(),
        IdentityDomain::RefTransaction.domain_tag(),
        CodecVersion::new(1, 0),
        *honest.digest(),
    );
    let refusal = verify_internal_object_id(
        &mislabelled,
        IdentityDomain::RefTransaction,
        schema,
        CodecVersion::new(1, 0),
        body,
    )
    .expect_err("an internal identity must not claim SHA-1");
    match refusal {
        InternalIdentityError::AlgorithmMismatch { expected, actual } => {
            assert_eq!(expected, DigestAlgorithm::Sha256);
            assert_eq!(actual, DigestAlgorithm::Sha1.code_point());
        }
        other => panic!("expected an algorithm mismatch, got {other}"),
    }
}

#[test]
fn a_tampered_body_is_a_typed_digest_mismatch() {
    let schema = schema("frankengit.canonical-body");
    let identity = internal_object_id(
        IdentityDomain::ObjectEnvelope,
        schema,
        CodecVersion::new(1, 0),
        b"original body",
    );
    let refusal = verify_internal_object_id(
        &identity,
        IdentityDomain::ObjectEnvelope,
        schema,
        CodecVersion::new(1, 0),
        b"tampered body",
    )
    .expect_err("a changed body must not verify");
    assert!(matches!(
        refusal,
        InternalIdentityError::DigestMismatch { .. }
    ));
}

#[test]
fn every_identity_carries_its_domain_and_construction() {
    let schema = schema("frankengit.canonical-body");
    for domain in IdentityDomain::ALL.iter().copied() {
        let identity = internal_object_id(domain, schema, CodecVersion::new(1, 0), b"body");
        assert_eq!(identity.domain(), domain.domain_tag());
        assert_eq!(identity.algorithm(), DigestAlgorithm::Sha256.id());
        assert_eq!(identity.digest().len(), 32);
        assert_eq!(
            DigestBytes::try_new(identity.digest().as_bytes()).expect("a well-formed digest body"),
            *identity.digest()
        );
    }
}

// --- native identity boundaries ---------------------------------------------

#[test]
fn the_declared_length_is_committed_before_any_content_byte() {
    let content = b"hello world\n";
    let mut hasher = GitOid::<Sha1>::object_hasher(GitObjectKind::Blob, 12);
    hasher.update(content).expect("exactly the declared length");
    let streamed = hasher.finish().expect("the object is complete");
    assert_eq!(
        streamed,
        GitOid::<Sha1>::of_object(GitObjectKind::Blob, content)
    );
}

#[test]
fn content_beyond_the_declared_length_is_refused() {
    let mut hasher = GitOid::<Sha1>::object_hasher(GitObjectKind::Blob, 4);
    assert_eq!(
        hasher.update(b"five!"),
        Err(GitHashError::DeclaredLengthOverrun {
            declared: 4,
            received: 5
        })
    );
    assert_eq!(hasher.received(), 0, "a refused chunk is not absorbed");
}

#[test]
fn content_short_of_the_declared_length_is_refused() {
    let mut hasher = GitOid::<Sha256>::object_hasher(GitObjectKind::Blob, 8);
    hasher
        .update(b"four")
        .expect("a chunk within the declared length");
    assert_eq!(
        hasher.finish(),
        Err(GitHashError::DeclaredLengthShortfall {
            declared: 8,
            received: 4
        })
    );
}

#[test]
fn hex_parsing_in_the_named_algorithm_round_trips() {
    let narrow = parse_git_oid::<Sha1>(EMPTY_BLOB_SHA1).expect("a canonical SHA-1 identity");
    assert_eq!(narrow.to_string(), EMPTY_BLOB_SHA1);
    assert_eq!(narrow, GitOid::<Sha1>::of_object(GitObjectKind::Blob, b""));

    let wide = parse_git_oid::<Sha256>(EMPTY_BLOB_SHA256).expect("a canonical SHA-256 identity");
    assert_eq!(wide.to_string(), EMPTY_BLOB_SHA256);
    assert_eq!(wide, GitOid::<Sha256>::of_object(GitObjectKind::Blob, b""));
}

#[test]
fn hex_parsing_refuses_the_other_algorithms_width() {
    assert!(
        parse_git_oid::<Sha256>(EMPTY_BLOB_SHA1).is_err(),
        "a 40-character identity is not a SHA-256 identity"
    );
    assert!(
        parse_git_oid::<Sha1>(EMPTY_BLOB_SHA256).is_err(),
        "a 64-character identity is not a SHA-1 identity"
    );
}

#[test]
fn hex_parsing_refuses_a_non_canonical_spelling() {
    assert!(
        parse_git_oid::<Sha1>(&EMPTY_BLOB_SHA1.to_uppercase()).is_err(),
        "uppercase is not the canonical spelling"
    );
    assert!(parse_git_oid::<Sha1>("zz").is_err());
}

#[test]
fn the_erased_form_requires_the_format_and_keeps_the_domains_apart() {
    let narrow = git_object_id(GitObjectFormat::Sha1, GitObjectKind::Blob, b"");
    let wide = git_object_id(GitObjectFormat::Sha256, GitObjectKind::Blob, b"");
    assert_eq!(narrow.algorithm(), GitObjectFormat::Sha1);
    assert_eq!(wide.algorithm(), GitObjectFormat::Sha256);
    assert_ne!(narrow, wide);
    assert_eq!(narrow.to_string(), EMPTY_BLOB_SHA1);
    assert_eq!(wide.to_string(), EMPTY_BLOB_SHA256);
    assert_eq!(
        narrow,
        GitOid::<Sha1>::of_object(GitObjectKind::Blob, b"").erase()
    );
    assert!(narrow.require_sha256().is_err());
    assert!(narrow.require_sha1().is_ok());
}

#[test]
fn object_kinds_cover_gits_canonical_type_codes() {
    for (index, kind) in GitObjectKind::ALL.iter().copied().enumerate() {
        assert_eq!(usize::from(kind.type_code()), index + 1);
        assert_eq!(GitObjectKind::from_label(kind.label()), Some(kind));
    }
    assert_eq!(GitObjectKind::from_label("ofs_delta"), None);
}

#[test]
fn two_object_types_over_the_same_content_have_different_identities() {
    let content = b"";
    let blob = GitOid::<Sha1>::of_object(GitObjectKind::Blob, content);
    let tree = GitOid::<Sha1>::of_object(GitObjectKind::Tree, content);
    assert_ne!(blob, tree);
}

// --- the strong internal payload commitment ---------------------------------

#[test]
fn the_payload_commitment_binds_type_length_and_exact_bytes() {
    let codec = CodecVersion::new(1, 0);
    let commitment = git_payload_commitment(GitObjectKind::Blob, b"hello world\n", codec);
    assert_eq!(
        commitment.domain(),
        IdentityDomain::GitPayloadCommitment.domain_tag()
    );
    assert_eq!(
        verify_internal_object_id(
            &commitment,
            IdentityDomain::GitPayloadCommitment,
            GIT_PAYLOAD_SCHEMA,
            codec,
            &git_payload_body(GitObjectKind::Blob, b"hello world\n")
        ),
        Ok(())
    );

    // The same bytes under a different object type, and the same type with a
    // different length, are different commitments.
    assert_ne!(
        commitment,
        git_payload_commitment(GitObjectKind::Blob, b"hello world", codec)
    );
    assert_ne!(
        commitment,
        git_payload_commitment(GitObjectKind::Tag, b"hello world\n", codec)
    );
}

#[test]
fn the_payload_commitment_does_not_replace_the_native_identity() {
    let codec = CodecVersion::new(1, 0);
    let native = GitOid::<Sha1>::of_object(GitObjectKind::Blob, b"");
    let commitment = git_payload_commitment(GitObjectKind::Blob, b"", codec);
    assert_eq!(native.to_string(), EMPTY_BLOB_SHA1);
    assert_ne!(
        commitment.digest().as_bytes(),
        native.as_bytes().as_slice(),
        "the stronger digest is additional evidence, never the visible identity"
    );
    assert_eq!(commitment.digest().len(), 32);
}

// --- allocation-free digest entry points ------------------------------------

#[test]
fn streaming_parts_match_the_materialised_preimage() {
    // `internal_digest_over_parts` must be bit-identical to hashing the
    // concatenation, or a Merkle builder and a verifier would disagree.
    let schema = schema("frankengit.microsegment");
    let splits: &[&[&[u8]]] = &[
        &[],
        &[b""],
        &[b"record bytes"],
        &[b"record", b" bytes"],
        &[b"r", b"e", b"cord bytes"],
        &[b"record bytes", b""],
        &[b"", b"record bytes"],
    ];
    for domain in [IdentityDomain::MerkleLeaf, IdentityDomain::MerkleNode] {
        for parts in splits {
            let joined: Vec<u8> = parts.iter().flat_map(|part| part.iter().copied()).collect();
            assert_eq!(
                internal_digest_over_parts(domain, schema, parts)
                    .as_bytes()
                    .to_vec(),
                internal_digest_in_domain(domain, schema, &joined),
                "{domain} split into {} parts",
                parts.len()
            );
            assert_eq!(
                internal_digest_value(domain, schema, &joined),
                internal_digest_over_parts(domain, schema, parts)
            );
        }
    }
}

#[test]
fn merkle_leaves_and_nodes_are_separate_domains() {
    // Sharing one domain between leaves and interior nodes is the classic
    // second-preimage construction against an unseparated Merkle tree: an
    // interior node's preimage could be presented as a leaf.
    let schema = schema("frankengit.microsegment");
    let record = b"record bytes";
    let leaf = internal_digest_value(IdentityDomain::MerkleLeaf, schema, record);
    let node = internal_digest_value(IdentityDomain::MerkleNode, schema, record);
    assert_ne!(leaf, node);

    // And a two-child node is built without concatenating the children.
    let left = internal_digest_value(IdentityDomain::MerkleLeaf, schema, b"left");
    let right = internal_digest_value(IdentityDomain::MerkleLeaf, schema, b"right");
    let parent = internal_digest_over_parts(
        IdentityDomain::MerkleNode,
        schema,
        &[left.as_bytes(), right.as_bytes()],
    );
    let swapped = internal_digest_over_parts(
        IdentityDomain::MerkleNode,
        schema,
        &[right.as_bytes(), left.as_bytes()],
    );
    assert_ne!(parent, swapped, "child order is part of the commitment");
}

#[test]
fn the_digest_value_shell_carries_the_registry_width() {
    let schema = schema("frankengit.canonical-body");
    for domain in IdentityDomain::ALL.iter().copied() {
        let value = internal_digest_value(domain, schema, b"body");
        assert_eq!(value.len(), domain.algorithm().digest_len());
        assert_eq!(value.len(), 32);
    }
}
