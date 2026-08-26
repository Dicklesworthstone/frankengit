#![forbid(unsafe_code)]
//! Planted negative test suite for FG-060: Artifact fabric, namespace race collisions,
//! and provenance chain breaks.

use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_object_fabric::artifact::{
    ArtifactEntry, ArtifactIdentity, ArtifactManifest, ArtifactPayloadKind, ArtifactRefusal,
    MediaType, RetentionProfile,
};
use fgit_object_fabric::package::{
    ExpectedNamespaceBasis, PackageNamespace, PackageRefusal, PackageRegistry, PackageVersion,
    PublishIntent, YankIntent,
};
use fgit_object_fabric::provenance::{
    EvidenceClass, ProvenanceError, ProvenanceGraph, ProvenanceNode,
};
use fgit_types::{Digest, DigestAlgorithmId, DigestBytes};

fn sha256_digest(data: &[u8]) -> Digest {
    let mut hasher = Sha256Hasher::new();
    DigestHasher::update(&mut hasher, data);
    let raw = DigestHasher::finish(hasher);
    let bytes = DigestBytes::try_new(&raw).expect("32 bytes is valid");
    Digest::new(
        DigestAlgorithmId::try_new(2).expect("SHA-256 is code point 2"),
        bytes,
    )
}

#[test]
fn planted_negative_payload_tamper_detected() {
    let raw_payload = b"original valid payload bytes";
    let payload_digest = sha256_digest(raw_payload);
    let identity = ArtifactIdentity::new(
        payload_digest,
        raw_payload.len() as u64,
        MediaType::parse("text/plain").unwrap(),
        ArtifactPayloadKind::BuildLog,
        None,
        None,
        None,
        RetentionProfile::StandardLog { retain_days: 30 },
    );

    // 1. Bit flip in payload
    let mut tampered_payload = raw_payload.to_vec();
    tampered_payload[0] ^= 0xFF;

    let err = identity.verify_payload(&tampered_payload).unwrap_err();
    assert!(matches!(err, ArtifactRefusal::PayloadDigestMismatch { .. }));

    // 2. Length truncation
    let truncated_payload = &raw_payload[..raw_payload.len() - 1];
    let err_trunc = identity.verify_payload(truncated_payload).unwrap_err();
    assert!(matches!(
        err_trunc,
        ArtifactRefusal::PayloadLengthMismatch { .. }
    ));
}

#[test]
fn planted_negative_manifest_path_traversal_refused() {
    let identity = ArtifactIdentity::new(
        sha256_digest(b"dummy"),
        5,
        MediaType::parse("application/octet-stream").unwrap(),
        ArtifactPayloadKind::ReleaseAsset,
        None,
        None,
        None,
        RetentionProfile::ReleasePermanent,
    );

    // Path traversal forbidden
    assert!(matches!(
        ArtifactEntry::new("../secret/key.pem", &identity).unwrap_err(),
        ArtifactRefusal::PathTraversalForbidden
    ));

    // Absolute path forbidden
    assert!(matches!(
        ArtifactEntry::new("/etc/shadow", &identity).unwrap_err(),
        ArtifactRefusal::AbsolutePathForbidden
    ));

    // Dot component forbidden
    assert!(matches!(
        ArtifactEntry::new("foo/./bar", &identity).unwrap_err(),
        ArtifactRefusal::DotComponentForbidden
    ));

    // Empty path forbidden
    assert!(matches!(
        ArtifactEntry::new("", &identity).unwrap_err(),
        ArtifactRefusal::EmptyLogicalPath
    ));
}

#[test]
fn planted_negative_manifest_duplicate_paths_refused() {
    let id1 = ArtifactIdentity::new(
        sha256_digest(b"payload_1"),
        9,
        MediaType::parse("text/plain").unwrap(),
        ArtifactPayloadKind::BuildLog,
        None,
        None,
        None,
        RetentionProfile::ReleasePermanent,
    );
    let id2 = ArtifactIdentity::new(
        sha256_digest(b"payload_2"),
        9,
        MediaType::parse("text/plain").unwrap(),
        ArtifactPayloadKind::BuildLog,
        None,
        None,
        None,
        RetentionProfile::ReleasePermanent,
    );

    let entry1 = ArtifactEntry::new("duplicate/path.txt", &id1).unwrap();
    let entry2 = ArtifactEntry::new("duplicate/path.txt", &id2).unwrap();

    let err = ArtifactManifest::new(vec![entry1, entry2]).unwrap_err();
    assert!(matches!(err, ArtifactRefusal::DuplicateLogicalPath(_)));
}

#[test]
fn planted_negative_namespace_race_collision_typed_refusal() {
    let registry = PackageRegistry::new();
    let namespace = PackageNamespace::parse("pkg:generic/org/app").unwrap();
    let version = PackageVersion::parse("2.0.0").unwrap();

    let winner_art = sha256_digest(b"winner_artifact");
    let loser_art = sha256_digest(b"loser_artifact");

    // Publisher 1 wins
    registry
        .publish(PublishIntent {
            namespace: namespace.clone(),
            version: version.clone(),
            artifact_id: winner_art,
            expected_basis: ExpectedNamespaceBasis::MustNotExist,
            retention_profile: RetentionProfile::ReleasePermanent,
            publisher: "publisher-1".to_string(),
            timestamp_unix_secs: 1700000000,
        })
        .unwrap();

    // Publisher 2 races to publish same version: MUST fail closed with VersionAlreadyExists
    let err = registry
        .publish(PublishIntent {
            namespace: namespace.clone(),
            version: version.clone(),
            artifact_id: loser_art,
            expected_basis: ExpectedNamespaceBasis::MustNotExist,
            retention_profile: RetentionProfile::ReleasePermanent,
            publisher: "publisher-2".to_string(),
            timestamp_unix_secs: 1700000001,
        })
        .unwrap_err();

    match err {
        PackageRefusal::VersionAlreadyExists {
            namespace: ns,
            version: ver,
            existing_artifact_id,
        } => {
            assert_eq!(ns, "pkg:generic/org/app");
            assert_eq!(ver, "2.0.0");
            assert_eq!(existing_artifact_id, winner_art);
        }
        other => panic!("expected VersionAlreadyExists, got {other:?}"),
    }
}

#[test]
fn planted_negative_yank_precondition_and_double_yank_refused() {
    let registry = PackageRegistry::new();
    let namespace = PackageNamespace::parse("pkg:generic/org/lib").unwrap();
    let version = PackageVersion::parse("1.0.0").unwrap();
    let correct_art = sha256_digest(b"real_artifact");
    let fake_art = sha256_digest(b"wrong_artifact");

    // Publish
    registry
        .publish(PublishIntent {
            namespace: namespace.clone(),
            version: version.clone(),
            artifact_id: correct_art,
            expected_basis: ExpectedNamespaceBasis::MustNotExist,
            retention_profile: RetentionProfile::ReleasePermanent,
            publisher: "ci".to_string(),
            timestamp_unix_secs: 1700000000,
        })
        .unwrap();

    // 1. Yank with mismatched artifact ID fails
    let err_precond = registry
        .yank(YankIntent {
            namespace: namespace.clone(),
            version: version.clone(),
            expected_artifact_id: fake_art,
            reason: "malware".to_string(),
            yanked_by: "admin".to_string(),
            timestamp_unix_secs: 1700000100,
        })
        .unwrap_err();

    assert!(matches!(
        err_precond,
        PackageRefusal::StatePreconditionFailed { .. }
    ));

    // 2. Successful yank
    registry
        .yank(YankIntent {
            namespace: namespace.clone(),
            version: version.clone(),
            expected_artifact_id: correct_art,
            reason: "malware".to_string(),
            yanked_by: "admin".to_string(),
            timestamp_unix_secs: 1700000200,
        })
        .unwrap();

    // 3. Second yank fails with VersionAlreadyYanked
    let err_double = registry
        .yank(YankIntent {
            namespace: namespace.clone(),
            version: version.clone(),
            expected_artifact_id: correct_art,
            reason: "duplicate request".to_string(),
            yanked_by: "admin".to_string(),
            timestamp_unix_secs: 1700000300,
        })
        .unwrap_err();

    assert!(matches!(
        err_double,
        PackageRefusal::VersionAlreadyYanked { .. }
    ));
}

#[test]
fn planted_negative_broken_provenance_chain_fails_closed() {
    let mut graph = ProvenanceGraph::new();

    let real_source_rcr = sha256_digest(b"real_commit_rcr");
    let forged_source_rcr = sha256_digest(b"forged_commit_rcr");
    let capsule = sha256_digest(b"capsule_1");
    let target_manifest = sha256_digest(b"manifest_1");

    // Real chain links: real_source_rcr -> capsule -> target_manifest
    graph
        .add_edge(
            ProvenanceNode::SourceCommit(real_source_rcr),
            ProvenanceNode::BuildCapsule(capsule),
            EvidenceClass::E1DeterministicDerivation,
            "build step 1",
        )
        .unwrap();

    graph
        .add_edge(
            ProvenanceNode::BuildCapsule(capsule),
            ProvenanceNode::ReleaseManifest(target_manifest),
            EvidenceClass::E4SignedAttestation,
            "release sign",
        )
        .unwrap();

    // Verification against forged source MUST fail with BrokenProvenanceChain
    let err = graph
        .verify_provenance_closure(&target_manifest, &forged_source_rcr)
        .unwrap_err();

    match err {
        ProvenanceError::BrokenProvenanceChain {
            target,
            expected_source,
        } => {
            assert_eq!(target, target_manifest);
            assert_eq!(expected_source, forged_source_rcr);
        }
        other => panic!("expected BrokenProvenanceChain, got {other:?}"),
    }
}
