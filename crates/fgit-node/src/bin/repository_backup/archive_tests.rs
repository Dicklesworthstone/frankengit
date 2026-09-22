use super::*;
use fgit_authority::{StoreInstanceId, HeadGeneration};
use fgit_authority_fsqlite::{ExportedHead, ExportedIssuance, IssuanceSequence,
    SCHEMA_VERSION, export_bundle, mint_token};

fn authority() -> Vec<u8> {
    let token = mint_token(StoreInstanceId::from_raw(41), IssuanceSequence::FIRST).to_opaque_bytes().to_vec();
    export_bundle(&ExportBundle {
        schema_version: SCHEMA_VERSION, instance: 41, bodies: vec![],
        head: Some(ExportedHead { key: b"head".to_vec(), token: token.clone(),
            generation: HeadGeneration::FIRST.get(), body: b"head body".to_vec() }),
        issuance: vec![ExportedIssuance { token, sequence: 1, head_key: b"head".to_vec(),
            generation: 1, body: b"head body".to_vec() }],
    }).unwrap()
}
fn identity(format: GitHashAlgorithm) -> Identity {
    Identity { tenant: TenantId::from_bytes([1; 16]), repository: RepositoryId::from_bytes([2; 16]),
        incarnation: RepositoryIncarnationId::from_bytes([3; 16]), format }
}
fn commitment(kind: GitObjectKind, body: &[u8]) -> [u8; 32] {
    git_payload_commitment(kind, body, CANONICAL_CODEC_VERSION).digest().as_bytes().try_into().unwrap()
}
fn sample(format: GitHashAlgorithm) -> Vec<u8> {
    let body = b"exact\0payload\xff\n";
    let kind = GitObjectKind::Blob;
    let id = git_object_id(format, kind, body);
    let mut encoder = Encoder::new(identity(format), &authority(), 1).unwrap();
    encoder.object(id, kind, body, &commitment(kind, body)).unwrap();
    encoder.finish().unwrap()
}
#[test]
fn exact_binary_payloads_and_native_domains_round_trip_deterministically() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let bytes = sample(format);
        assert_eq!(sample(format), bytes);
        let parsed = decode(&bytes, || Ok(())).unwrap();
        assert_eq!(parsed.identity, identity(format));
        assert_eq!(export_bundle(&parsed.authority).unwrap(), authority());
        assert_eq!(parsed.records.len(), 1);
        assert_eq!(parsed.records[0].kind, GitObjectKind::Blob);
        assert_eq!(parsed.records[0].payload, b"exact\0payload\xff\n");
        assert_eq!(parsed.records[0].oid.algorithm(), format);
        assert_eq!(&bytes[..8], b"FGSRC001");
        assert_eq!(&bytes[8..24], &[1; 16]);
        assert_eq!(&bytes[24..40], &[2; 16]);
        assert_eq!(&bytes[40..56], &[3; 16]);
    }
}
#[test]
fn every_truncation_and_any_trailing_data_refuses() {
    let bytes = sample(GitHashAlgorithm::Sha1);
    for length in 0..bytes.len() {
        assert!(decode(&bytes[..length], || Ok(())).is_err(), "truncation {length}");
    }
    let mut suffix = bytes.clone(); suffix.push(0);
    assert!(decode(&suffix, || Ok(())).unwrap_err().contains("trailing"));
    assert!(decode(&bytes, || Ok(())).is_ok());
}
#[test]
fn wrong_identity_and_original_commitment_are_independent_refusals() {
    let original = sample(GitHashAlgorithm::Sha256);
    let record = 8 + 16 * 3 + 1 + 8 + authority().len() + 8;
    let mut payload = original.clone(); *payload.last_mut().unwrap() ^= 1;
    assert!(decode(&payload, || Ok(())).unwrap_err().contains("identity mismatch"));
    let mut commitment = original.clone(); commitment[record + 32 + 1 + 8] ^= 1;
    assert!(decode(&commitment, || Ok(())).unwrap_err().contains("commitment mismatch"));
    let mut oid = original.clone(); oid[record] ^= 1;
    assert!(decode(&oid, || Ok(())).unwrap_err().contains("identity mismatch"));
    let mut kind = original; kind[record + 32] = 5;
    assert!(decode(&kind, || Ok(())).unwrap_err().contains("non-Git"));
}
#[test]
fn unsupported_versions_formats_counts_and_sizes_refuse_before_reservation() {
    let original = sample(GitHashAlgorithm::Sha1);
    let mut version = original.clone(); version[7] = b'2';
    assert!(decode(&version, || Ok(())).is_err());
    let mut format = original.clone(); format[56] = 0;
    assert!(decode(&format, || Ok(())).is_err());
    let mut bytes = original.clone(); bytes[57..65].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(decode(&bytes, || Ok(())).is_err());
    let count_at = 65 + authority().len();
    let mut count = original.clone(); count[count_at..count_at + 8].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(decode(&count, || Ok(())).is_err());
    count[count_at..count_at + 8].copy_from_slice(&(MAX_OBJECTS as u64).to_be_bytes());
    assert!(decode(&count, || Ok(())).unwrap_err().contains("truncated"));
    let object_len = count_at + 8 + 20 + 1;
    let mut body = original; body[object_len..object_len + 8].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(decode(&body, || Ok(())).is_err());
}
#[test]
fn empty_selection_is_valid_but_underfilled_duplicate_and_mixed_domains_are_not() {
    let format = GitHashAlgorithm::Sha1;
    let empty = Encoder::new(identity(format), &authority(), 0).unwrap().finish().unwrap();
    assert!(decode(&empty, || Ok(())).unwrap().records.is_empty());
    assert!(Encoder::new(identity(format), &authority(), 1).unwrap().finish().is_err());
    assert!(Encoder::new(identity(format), &authority(), MAX_OBJECTS + 1).is_err());
    let id = git_object_id(format, GitObjectKind::Blob, b"");
    let proof = commitment(GitObjectKind::Blob, b"");
    let mut two = Encoder::new(identity(format), &authority(), 2).unwrap();
    two.object(id, GitObjectKind::Blob, b"", &proof).unwrap();
    assert!(two.object(id, GitObjectKind::Blob, b"", &proof).is_err());
    let mut other = Encoder::new(identity(GitHashAlgorithm::Sha256), &authority(), 1).unwrap();
    assert!(other.object(id, GitObjectKind::Blob, b"", &proof).is_err());
}
#[test]
fn cancellation_never_yields_a_partial_archive() {
    let bytes = sample(GitHashAlgorithm::Sha1);
    let mut total = 0;
    decode(&bytes, || { total += 1; Ok(()) }).unwrap();
    assert!(total >= 4);
    for stopped in 1..=total {
        let mut step = 0;
        let error = decode(&bytes, || {
            step += 1;
            if step == stopped { Err("cancelled-test".into()) } else { Ok(()) }
        }).unwrap_err();
        assert_eq!(error, "cancelled-test");
    }
}
