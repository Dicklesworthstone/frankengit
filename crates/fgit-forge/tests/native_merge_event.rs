#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use fgit_codec::{CanonicalBody, CryptoBodyIdentity, DecodeLimits, Encoder, decode_body, encode_body};
use fgit_forge::aggregate::{AggregateId, AggregateVersion, PullRequestNumber};
use fgit_forge::event::{ForgeEvent, ForgeEventBatch, ForgeEventPayload, NativeMerge, event_id};
use fgit_forge::snapshot::{PullRequestState, apply_forge_event_to_prs};
use fgit_types::{Digest, GitHashAlgorithm, GitOid, RefName};
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};

fn oid(format: GitHashAlgorithm, byte: &str) -> GitOid {
    let width = match format { GitHashAlgorithm::Sha1 => 20, GitHashAlgorithm::Sha256 => 32 };
    GitOid::from_hex(format, &byte.repeat(width)).unwrap()
}
fn native(format: GitHashAlgorithm) -> NativeMerge {
    NativeMerge {
        source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
        source_tip: oid(format, "11"), base_tip: oid(format, "22"),
        target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
        target_tip_before: oid(format, "33"), merge_commit: oid(format, "44"),
    }
}
fn event(merge: NativeMerge) -> ForgeEvent {
    ForgeEvent {
        aggregate: AggregateId::PullRequest(PullRequestNumber::FIRST),
        version: AggregateVersion::try_new(2).unwrap(),
        payload: ForgeEventPayload::MergeCommittedNative(merge),
    }
}
fn digest(byte: u8) -> Digest {
    Digest::new(DigestAlgorithmId::try_new(1).unwrap(), DigestBytes::try_new(&[byte; 32]).unwrap())
}

#[test]
fn native_merge_round_trips_both_formats_without_internal_digest_conversion() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let original = event(native(format));
        let encoded = encode_body(&original).unwrap();
        assert_eq!(decode_body::<ForgeEvent>(&encoded, DecodeLimits::DEFAULT).unwrap(), original);
        let batch = ForgeEventBatch::of_one(original);
        assert_eq!(decode_body::<ForgeEventBatch>(&encode_body(&batch).unwrap(), DecodeLimits::DEFAULT).unwrap(), batch);
    }
}

#[test]
fn native_event_identity_binds_the_source_and_base_not_only_the_target_change() {
    let original = native(GitHashAlgorithm::Sha1);
    let id = event_id(&CryptoBodyIdentity, &event(original.clone())).unwrap();
    let mut different_source = original.clone();
    different_source.source_tip = oid(GitHashAlgorithm::Sha1, "55");
    let mut different_base = original.clone();
    different_base.base_tip = oid(GitHashAlgorithm::Sha1, "66");
    let mut different_branch = original;
    different_branch.source_ref = RefName::try_new(b"refs/heads/other").unwrap();
    for altered in [different_source, different_base, different_branch] {
        assert_ne!(id, event_id(&CryptoBodyIdentity, &event(altered)).unwrap());
    }
}

#[test]
fn native_event_refuses_mixed_formats_zero_identities_and_non_transitions() {
    let original = native(GitHashAlgorithm::Sha1);
    let mut mixed = original.clone(); mixed.source_tip = oid(GitHashAlgorithm::Sha256, "11");
    let mut zero = original.clone(); zero.base_tip = oid(GitHashAlgorithm::Sha1, "00");
    let mut unchanged = original.clone(); unchanged.merge_commit = unchanged.target_tip_before;
    let mut same_branch = original.clone(); same_branch.source_ref = same_branch.target_ref.clone();
    for invalid in [mixed, zero, unchanged, same_branch] {
        assert!(encode_body(&event(invalid)).is_err());
    }
    assert!(encode_body(&event(original)).is_ok());
}

#[test]
fn legacy_merge_payload_encoding_is_unchanged_and_native_projection_keeps_domains_distinct() {
    let legacy = ForgeEvent {
        aggregate: AggregateId::PullRequest(PullRequestNumber::FIRST),
        version: AggregateVersion::FIRST,
        payload: ForgeEventPayload::MergeCommitted {
            merge_commit: digest(4), target_ref: b"refs/heads/main".to_vec(),
            target_tip_before: digest(3), target_tip_after: digest(4),
        },
    };
    let mut expected = Encoder::new();
    expected.write_scalar(1_u64);
    expected.write_scalar(1_u64);
    expected.write_scalar(3_u32);
    expected.write_digest(&digest(4)).unwrap();
    expected.write_bytes("target_ref", b"refs/heads/main").unwrap();
    expected.write_digest(&digest(3)).unwrap();
    expected.write_digest(&digest(4)).unwrap();
    let mut actual = Encoder::new(); legacy.write_payload(&mut actual).unwrap();
    assert_eq!(actual.as_bytes(), expected.as_bytes());

    let opened = ForgeEvent {
        aggregate: legacy.aggregate, version: AggregateVersion::FIRST,
        payload: ForgeEventPayload::PullRequestOpened {
            source_ref: b"refs/heads/topic".to_vec(), target_ref: b"refs/heads/main".to_vec(),
            source_tip: digest(1), target_tip: digest(3),
        },
    };
    let mut prs = BTreeMap::new();
    apply_forge_event_to_prs(&mut prs, &opened);
    let merge = native(GitHashAlgorithm::Sha1);
    apply_forge_event_to_prs(&mut prs, &event(merge.clone()));
    let projected = &prs[&PullRequestNumber::FIRST];
    assert_eq!(projected.source_tip, digest(1));
    assert_eq!(projected.target_tip, digest(3));
    assert_eq!(projected.state, PullRequestState::MergedNative { merge });
    assert_eq!(projected.version.get(), 2);
}
