#![forbid(unsafe_code)]
//! Conformance test suite for FG-060: Artifact payload fabric, namespace publication,
//! and provenance chain verification.

use std::collections::BTreeSet;

use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_object_fabric::artifact::{
    ArtifactEntry, ArtifactIdentity, ArtifactManifest, ArtifactPayloadKind, MediaType,
    RetentionProfile,
};
use fgit_object_fabric::package::{
    ExpectedNamespaceBasis, PackageNamespace, PackageRegistry, PackageVersion, PublishIntent,
    YankIntent,
};
use fgit_object_fabric::provenance::{EvidenceClass, ProvenanceGraph, ProvenanceNode};
use fgit_object_fabric::retention::ArtifactRetentionRegistry;
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
fn artifact_identity_and_payload_verification() {
    let raw_payload = b"tar.gz binary data payload contents 12345";
    let payload_digest = sha256_digest(raw_payload);
    let media_type = MediaType::parse("application/x-tar").unwrap();
    let capsule_id = sha256_digest(b"build_capsule_001");
    let check_receipt = sha256_digest(b"check_receipt_001");
    let source_rcr = sha256_digest(b"source_commit_rcr_001");

    let identity = ArtifactIdentity::new(
        payload_digest,
        raw_payload.len() as u64,
        media_type.clone(),
        ArtifactPayloadKind::ReleaseAsset,
        Some(capsule_id),
        Some(check_receipt),
        Some(source_rcr),
        RetentionProfile::ReleasePermanent,
    );

    // Verified payload matches
    assert!(identity.verify_payload(raw_payload).is_ok());

    assert_eq!(identity.payload_len(), raw_payload.len() as u64);
    assert_eq!(identity.payload_digest(), &payload_digest);
    assert_eq!(identity.payload_kind(), ArtifactPayloadKind::ReleaseAsset);
    assert_eq!(identity.media_type(), &media_type);
    assert_eq!(identity.build_capsule_id(), Some(&capsule_id));
    assert_eq!(identity.check_receipt_id(), Some(&check_receipt));
    assert_eq!(identity.source_rcr(), Some(&source_rcr));
    assert!(identity.retention_profile().is_permanent());
}

#[test]
fn artifact_manifest_canonical_ordering_and_lookup() {
    let payload1 = b"binary-x86_64";
    let id1 = ArtifactIdentity::new(
        sha256_digest(payload1),
        payload1.len() as u64,
        MediaType::parse("application/octet-stream").unwrap(),
        ArtifactPayloadKind::ReleaseAsset,
        None,
        None,
        None,
        RetentionProfile::ReleasePermanent,
    );

    let payload2 = b"checksums.txt";
    let id2 = ArtifactIdentity::new(
        sha256_digest(payload2),
        payload2.len() as u64,
        MediaType::parse("text/plain").unwrap(),
        ArtifactPayloadKind::Signature,
        None,
        None,
        None,
        RetentionProfile::ReleasePermanent,
    );

    let payload3 = b"spdx-sbom.json";
    let id3 = ArtifactIdentity::new(
        sha256_digest(payload3),
        payload3.len() as u64,
        MediaType::parse("application/json").unwrap(),
        ArtifactPayloadKind::Sbom,
        None,
        None,
        None,
        RetentionProfile::ReleasePermanent,
    );

    // Create entries in unsorted order
    let entry_bin = ArtifactEntry::new("dist/app-x86_64", &id1).unwrap();
    let entry_sha = ArtifactEntry::new("dist/SHA256SUMS", &id2).unwrap();
    let entry_sbom = ArtifactEntry::new("sbom/spdx.json", &id3).unwrap();

    let manifest = ArtifactManifest::new(vec![entry_bin, entry_sha, entry_sbom]).unwrap();

    // Entries must be canonically sorted by logical path:
    // 1. "dist/SHA256SUMS"
    // 2. "dist/app-x86_64"
    // 3. "sbom/spdx.json"
    assert_eq!(manifest.entries().len(), 3);
    assert_eq!(manifest.entries()[0].logical_path(), "dist/SHA256SUMS");
    assert_eq!(manifest.entries()[1].logical_path(), "dist/app-x86_64");
    assert_eq!(manifest.entries()[2].logical_path(), "sbom/spdx.json");

    // Lookup
    let found = manifest.find_entry("dist/app-x86_64").unwrap();
    assert_eq!(found.artifact_id(), id1.artifact_id());
    assert_eq!(found.payload_kind(), ArtifactPayloadKind::ReleaseAsset);
}

#[test]
fn package_namespace_publication_and_yank_lifecycle() {
    let registry = PackageRegistry::new();
    let namespace = PackageNamespace::parse("pkg:generic/acme/my-tool").unwrap();
    let ver_1_0_0 = PackageVersion::parse("1.0.0").unwrap();
    let ver_1_1_0 = PackageVersion::parse("1.1.0").unwrap();

    let art_1_0 = sha256_digest(b"artifact_v1.0.0");
    let art_1_1 = sha256_digest(b"artifact_v1.1.0");

    // 1. Publish 1.0.0
    let pub_event_1 = registry
        .publish(PublishIntent {
            namespace: namespace.clone(),
            version: ver_1_0_0.clone(),
            artifact_id: art_1_0,
            expected_basis: ExpectedNamespaceBasis::MustNotExist,
            retention_profile: RetentionProfile::ReleasePermanent,
            publisher: "ci-runner-1".to_string(),
            timestamp_unix_secs: 1700000000,
        })
        .unwrap();

    assert_eq!(
        registry
            .get_version(&namespace, &ver_1_0_0)
            .unwrap()
            .unwrap()
            .artifact_id,
        art_1_0
    );

    // 2. Publish 1.1.0
    registry
        .publish(PublishIntent {
            namespace: namespace.clone(),
            version: ver_1_1_0.clone(),
            artifact_id: art_1_1,
            expected_basis: ExpectedNamespaceBasis::MustNotExist,
            retention_profile: RetentionProfile::ReleasePermanent,
            publisher: "ci-runner-1".to_string(),
            timestamp_unix_secs: 1700003600,
        })
        .unwrap();

    let versions = registry.list_versions(&namespace).unwrap();
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].0.as_str(), "1.0.0");
    assert_eq!(versions[1].0.as_str(), "1.1.0");

    // 3. Yank 1.0.0 due to security flaw
    let yank_event = registry
        .yank(YankIntent {
            namespace: namespace.clone(),
            version: ver_1_0_0.clone(),
            expected_artifact_id: art_1_0,
            reason: "CVE-2026-9999 critical vulnerability".to_string(),
            yanked_by: "security-team".to_string(),
            timestamp_unix_secs: 1700007200,
        })
        .unwrap();

    let record_1_0 = registry
        .get_version(&namespace, &ver_1_0_0)
        .unwrap()
        .unwrap();
    assert!(record_1_0.state.is_yanked());
    assert_eq!(record_1_0.history_events.len(), 2);
    assert_eq!(
        record_1_0.history_events[0].event_id(),
        pub_event_1.event_id()
    );
    assert_eq!(
        record_1_0.history_events[1].event_id(),
        yank_event.event_id()
    );

    // 4. Live artifact IDs calculation
    let live_ids = registry.collect_live_artifact_ids().unwrap();
    assert!(live_ids.contains(&art_1_0));
    assert!(live_ids.contains(&art_1_1));
}

#[test]
fn provenance_chain_end_to_end_query_and_verification() {
    let mut graph = ProvenanceGraph::new();

    let source_rcr = sha256_digest(b"commit_rcr_main_abc");
    let capsule = sha256_digest(b"build_input_capsule_123");
    let check_rcpt = sha256_digest(b"workflow_check_receipt_456");
    let binary_art = sha256_digest(b"artifact_frankengit_linux");
    let sbom_art = sha256_digest(b"artifact_spdx_sbom");
    let release_manifest = sha256_digest(b"release_manifest_v1.0.0");

    let node_source = ProvenanceNode::SourceCommit(source_rcr);
    let node_capsule = ProvenanceNode::BuildCapsule(capsule);
    let node_check = ProvenanceNode::CheckReceipt(check_rcpt);
    let node_bin = ProvenanceNode::Artifact {
        artifact_id: binary_art,
        kind: ArtifactPayloadKind::ReleaseAsset,
    };
    let node_sbom = ProvenanceNode::Artifact {
        artifact_id: sbom_art,
        kind: ArtifactPayloadKind::Sbom,
    };
    let node_rel = ProvenanceNode::ReleaseManifest(release_manifest);

    // Build the DAG edges:
    // Source -> Capsule (E1)
    graph
        .add_edge(
            node_source.clone(),
            node_capsule.clone(),
            EvidenceClass::E1DeterministicDerivation,
            "Runner snapshot assembled from source tree",
        )
        .unwrap();

    // Capsule -> CheckReceipt (E2)
    graph
        .add_edge(
            node_capsule.clone(),
            node_check.clone(),
            EvidenceClass::E2MeasuredUsage,
            "Isolated container build completed with test pass",
        )
        .unwrap();

    // CheckReceipt -> Binary Artifact (E1)
    graph
        .add_edge(
            node_check.clone(),
            node_bin.clone(),
            EvidenceClass::E1DeterministicDerivation,
            "Produced release binary target",
        )
        .unwrap();

    // CheckReceipt -> SBOM Artifact (E1)
    graph
        .add_edge(
            node_check.clone(),
            node_sbom.clone(),
            EvidenceClass::E1DeterministicDerivation,
            "Generated SPDX 2.3 SBOM",
        )
        .unwrap();

    // Binary Artifact -> Release Manifest (E4)
    graph
        .add_edge(
            node_bin.clone(),
            node_rel.clone(),
            EvidenceClass::E4SignedAttestation,
            "Signed release manifest published",
        )
        .unwrap();

    // SBOM Artifact -> Release Manifest (E4)
    graph
        .add_edge(
            node_sbom.clone(),
            node_rel.clone(),
            EvidenceClass::E4SignedAttestation,
            "Signed release manifest published",
        )
        .unwrap();

    // Query upstream chain from ReleaseManifest
    let upstream_edges = graph.query_upstream_chain(&release_manifest).unwrap();
    assert_eq!(upstream_edges.len(), 6);

    // Verify end-to-end provenance closure back to source RCR
    let receipt = graph
        .verify_provenance_closure(&release_manifest, &source_rcr)
        .unwrap();

    assert_eq!(receipt.target_digest, release_manifest);
    assert_eq!(receipt.source_rcr, source_rcr);
    assert_eq!(receipt.edge_count, 6);
    assert_eq!(receipt.unique_nodes_count, 6);
}

#[test]
fn retention_root_and_gc_sweep_lifecycle() {
    let mut retention_reg = ArtifactRetentionRegistry::new();

    let art_perm = sha256_digest(b"permanent_release_binary");
    let art_hold = sha256_digest(b"compliance_audit_log");
    let art_ephemeral_fresh = sha256_digest(b"ci_scratch_fresh");
    let art_ephemeral_stale = sha256_digest(b"ci_scratch_stale");

    let id_perm = ArtifactIdentity::new(
        art_perm,
        1000,
        MediaType::parse("application/octet-stream").unwrap(),
        ArtifactPayloadKind::ReleaseAsset,
        None,
        None,
        None,
        RetentionProfile::ReleasePermanent,
    );

    let id_hold = ArtifactIdentity::new(
        art_hold,
        2000,
        MediaType::parse("text/plain").unwrap(),
        ArtifactPayloadKind::BuildLog,
        None,
        None,
        None,
        RetentionProfile::LegalHold {
            hold_id: 42,
            reason: "Audit case #2026-A".to_string(),
        },
    );

    let id_fresh = ArtifactIdentity::new(
        art_ephemeral_fresh,
        500,
        MediaType::parse("application/x-tar").unwrap(),
        ArtifactPayloadKind::CiArtifact,
        None,
        None,
        None,
        RetentionProfile::HotEphemeral { ttl_seconds: 3600 },
    );

    let id_stale = ArtifactIdentity::new(
        art_ephemeral_stale,
        500,
        MediaType::parse("application/x-tar").unwrap(),
        ArtifactPayloadKind::CiArtifact,
        None,
        None,
        None,
        RetentionProfile::HotEphemeral { ttl_seconds: 3600 },
    );

    let current_time = 1700000000;
    retention_reg.register_artifact(id_perm.clone(), current_time);
    retention_reg.register_artifact(id_hold.clone(), current_time);
    retention_reg.register_artifact(id_fresh.clone(), current_time - 1800); // 30 mins old (fresh < 1hr)
    retention_reg.register_artifact(id_stale.clone(), current_time - 7200); // 2 hours old (expired > 1hr)

    let active_packages = BTreeSet::new();
    let retention_root = retention_reg.compute_retention_root(&active_packages, current_time);

    // art_perm, art_hold, art_ephemeral_fresh should be retained
    // art_ephemeral_stale should NOT be retained
    assert!(retention_root.is_retained(id_perm.artifact_id()));
    assert!(retention_root.is_retained(id_hold.artifact_id()));
    assert!(retention_root.is_retained(id_fresh.artifact_id()));
    assert!(!retention_root.is_retained(id_stale.artifact_id()));

    // Run GC sweep
    let pruned = retention_reg.sweep(&retention_root);
    assert_eq!(pruned.len(), 1);
    assert_eq!(&pruned[0], id_stale.artifact_id());
}
