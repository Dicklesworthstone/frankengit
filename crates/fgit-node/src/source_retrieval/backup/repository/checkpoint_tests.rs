//! Bounded transport codec checks; native authority selection is exercised by
//! checkpoint_restore_tests, not replaced by this isolated envelope fixture.
use super::*;
use fgit_chronicle::OutcomeIndexLeafArchive;
use fgit_types::{GitHashAlgorithm, RepositoryId, RepositoryIncarnationId, TenantId};

fn identity(format: GitHashAlgorithm) -> Identity {
    Identity {
        tenant: TenantId::from_bytes([1; 16]),
        repository: RepositoryId::from_bytes([2; 16]),
        incarnation: RepositoryIncarnationId::from_bytes([3; 16]),
        format,
    }
}
fn evidence(identity: Identity) -> CheckpointEvidence {
    let leaves =
        OutcomeIndexLeafArchive::prepare(identity.repository, identity.format, &[]).unwrap();
    let placement = PlacementReceipt::new(
        PlacementBackend::LocalFilesystem,
        OpaqueHandle::new(b"original-locator").unwrap(),
        OpaqueHandle::new(b"source-domain").unwrap(),
        OpaqueHandle::new(b"source-key").unwrap(),
    );
    CheckpointEvidence {
        root: Digest::new(
            DigestAlgorithmId::try_new(1).unwrap(),
            DigestBytes::try_new(&[7; 32]).unwrap(),
        ),
        manifest: leaves.manifest(vec![placement.clone()]).unwrap(),
        objects: leaves
            .objects()
            .iter()
            .map(|object| WholeObjectRead {
                object: object.clone(),
                placement: placement.clone(),
            })
            .collect(),
    }
}

#[test]
fn original_envelopes_manifest_and_receipts_roundtrip_in_both_native_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let identity = identity(format);
        let original = evidence(identity);
        let bytes = original.encode().unwrap();
        let decoded = CheckpointEvidence::decode(&bytes, identity).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.encode().unwrap(), bytes);
        assert_eq!(decoded.manifest.identity(), original.manifest.identity());
        assert_eq!(
            decoded.objects[0].object.envelope().encode(),
            original.objects[0].object.envelope().encode()
        );
    }
}

#[test]
fn valid_original_envelope_metadata_is_preserved_instead_of_resealing_the_leaf() {
    use fgit_object_fabric::{
        CryptoDigest, MicrosegmentBuilder, MicrosegmentReader, SegmentRecordInput,
    };
    let identity = identity(GitHashAlgorithm::Sha256);
    let mut original = evidence(identity);
    let limits = SegmentLimits::default();
    let plain = original.objects[0].object.envelope();
    let envelope = ObjectEnvelope::new(
        plain.namespace().to_vec(),
        plain.object_identity(),
        plain.object_kind(),
        plain.declared_length(),
        plain.payload_commitment(),
        plain.codec_namespace().to_vec(),
        plain.logical_content_identity(),
        Some([0x71; 32]),
        &limits,
    )
    .unwrap();
    let object =
        VerifiedObject::new(envelope, original.objects[0].object.payload().to_vec()).unwrap();
    let digest = CryptoDigest;
    let mut builder = MicrosegmentBuilder::new(&digest, limits.clone());
    builder
        .push(SegmentRecordInput {
            envelope: object.envelope().clone(),
            payload: object.payload().to_vec(),
        })
        .unwrap();
    let segment = builder.build().unwrap();
    let reader = MicrosegmentReader::open(segment.as_bytes(), &digest, &limits).unwrap();
    original.manifest = SegmentManifest::from_verified_segment(
        &reader,
        vec![original.objects[0].placement.clone()],
        &ManifestLimits::default(),
    )
    .unwrap();
    original.objects[0].object = object;
    let bytes = original.encode().unwrap();
    let decoded = CheckpointEvidence::decode(&bytes, identity).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(decoded.manifest.identity(), original.manifest.identity());
    assert_ne!(
        decoded.manifest.identity(),
        evidence(identity).manifest.identity()
    );
    assert_eq!(
        decoded.objects[0].object.envelope().manifest_reference(),
        Some([0x71; 32])
    );
}

#[test]
fn truncated_extra_missing_foreign_or_swapped_evidence_refuses() {
    let identity = identity(GitHashAlgorithm::Sha256);
    let original = evidence(identity);
    let bytes = original.encode().unwrap();
    for end in 0..bytes.len() {
        assert!(
            CheckpointEvidence::decode(&bytes[..end], identity).is_err(),
            "{end}"
        );
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(
        CheckpointEvidence::decode(&extra, identity)
            .unwrap_err()
            .contains("trailing")
    );
    for objects in [
        vec![],
        vec![original.objects[0].clone(), original.objects[0].clone()],
    ] {
        let malformed = CheckpointEvidence {
            objects,
            ..original.clone()
        };
        assert!(CheckpointEvidence::decode(&malformed.encode().unwrap(), identity).is_err());
    }
    let foreign = evidence(Identity {
        repository: RepositoryId::from_bytes([9; 16]),
        ..identity
    });
    assert!(CheckpointEvidence::decode(&foreign.encode().unwrap(), identity).is_err());
    let swapped = CheckpointEvidence {
        objects: foreign.objects,
        ..original
    };
    assert!(CheckpointEvidence::decode(&swapped.encode().unwrap(), identity).is_err());
    let mut input = Cursor(&bytes);
    input.take(2).unwrap();
    let length = input.array::<1>().unwrap()[0];
    input.take(length as usize).unwrap();
    input.bytes(MAX_MANIFEST_BYTES).unwrap();
    input.take(4).unwrap();
    input
        .bytes(SegmentLimits::default().max_envelope_bytes)
        .unwrap();
    input.take(8).unwrap();
    let at = bytes.len() - input.0.len();
    let mut corrupt = bytes;
    corrupt[at] ^= 1;
    assert!(CheckpointEvidence::decode(&corrupt, identity).is_err());
}

#[test]
fn independent_byte_limits_refuse_before_untrusted_record_allocation() {
    let identity = identity(GitHashAlgorithm::Sha1);
    let original = evidence(identity);
    let mut bytes = original.encode().unwrap();
    let manifest_at = 3 + original.root.bytes().len();
    bytes[manifest_at..manifest_at + 8].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(
        CheckpointEvidence::decode(&bytes, identity)
            .unwrap_err()
            .contains("byte limit")
    );
    let mut buffer = Buffer(Vec::new());
    buffer.push(&vec![0; MAX_EVIDENCE_BYTES]).unwrap();
    assert!(buffer.push(&[0]).is_err());
    assert_eq!(buffer.0.len(), MAX_EVIDENCE_BYTES);
    assert!(CheckpointEvidence::decode(&vec![0; MAX_EVIDENCE_BYTES + 1], identity).is_err());
}
