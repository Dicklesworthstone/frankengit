use super::*;
use crate::event::workflow_check::{
    MAX_CHECK_EVIDENCE_BYTES, MAX_CHECK_JOB_BYTES, NativeWorkflowCheck, WorkflowCheckConclusion,
};
use crate::{ForgeEventBatch, snapshot::apply_forge_event_to_prs};
use fgit_codec::{CryptoBodyIdentity, DecodeLimits, decode_body, encode_body};
use fgit_types::GitOid;

fn oid(format: GitHashAlgorithm, byte: u8) -> GitOid {
    GitOid::from_hex(format, &format!("{byte:02x}").repeat(format.digest_len())).unwrap()
}
fn record(format: GitHashAlgorithm) -> CandidateWorkflowCheckRecord {
    let check = super::super::tests::record(format);
    CandidateWorkflowCheckRecord {
        subject: ReviewSubject {
            pull_request: PullRequestNumber::try_new(42).unwrap(),
            pull_request_version: AggregateVersion::try_new(3).unwrap(),
            source_ref: RefName::try_new(b"refs/heads/feature").unwrap(),
            target_ref: check.source_ref.clone(),
            source_tip: oid(format, 9),
            target_tip: oid(format, 8),
            policy_epoch: PolicyEpoch::try_new(4).unwrap(),
        },
        candidate: CandidateBinding {
            merge_base: oid(format, 6),
            commit: check.source_commit,
        },
        bundle_sha256: [5; 32],
        check,
    }
}
fn event(record: &CandidateWorkflowCheckRecord) -> ForgeEvent {
    record
        .proposed_event(
            PrincipalId::from_bytes([4; 16]),
            record.candidate.commit.algorithm(),
        )
        .unwrap()
}

#[test]
fn every_terminal_result_roundtrips_for_both_native_hash_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for conclusion in [
            WorkflowCheckConclusion::ActionRequired,
            WorkflowCheckConclusion::Success,
            WorkflowCheckConclusion::Failure,
            WorkflowCheckConclusion::Cancelled,
            WorkflowCheckConclusion::TimedOut,
        ] {
            let mut record = record(format);
            record.check.conclusion = conclusion;
            let expected = event(&record);
            assert_eq!(expected.payload.kind(), 20);
            assert_eq!(expected.version, AggregateVersion::FIRST);
            let bytes = encode_body(&expected).unwrap();
            let decoded = decode_body::<ForgeEvent>(&bytes, DecodeLimits::DEFAULT).unwrap();
            assert_eq!(decoded, expected);
            assert_eq!(encode_body(&decoded).unwrap(), bytes);
            let batch = ForgeEventBatch::of_one(expected);
            let bytes = encode_body(&batch).unwrap();
            assert_eq!(
                decode_body::<ForgeEventBatch>(&bytes, DecodeLimits::DEFAULT).unwrap(),
                batch
            );
        }
    }
}

#[test]
fn candidate_and_branch_profiles_share_one_immutable_execution_identity() {
    let input = record(GitHashAlgorithm::Sha1);
    let original = event(&input);
    let ordinary = input
        .check
        .proposed_event(PrincipalId::from_bytes([4; 16]), GitHashAlgorithm::Sha1)
        .unwrap();
    assert_eq!(ordinary.aggregate, original.aggregate);
    assert_ne!(
        encode_body(&ordinary).unwrap(),
        encode_body(&original).unwrap()
    );
    let original_id = crate::event::event_id(&CryptoBodyIdentity, &original).unwrap();
    for field in 0..9 {
        let mut changed = input.clone();
        match field {
            0 => {
                changed.subject.pull_request_version =
                    changed.subject.pull_request_version.next().unwrap()
            }
            1 => changed.subject.policy_epoch = changed.subject.policy_epoch.next().unwrap(),
            2 => changed.subject.source_tip = oid(GitHashAlgorithm::Sha1, 10),
            3 => changed.subject.target_tip = oid(GitHashAlgorithm::Sha1, 11),
            4 => changed.candidate.merge_base = oid(GitHashAlgorithm::Sha1, 12),
            5 => {
                changed.candidate.commit = oid(GitHashAlgorithm::Sha1, 13);
                changed.check.source_commit = changed.candidate.commit;
            }
            6 => changed.bundle_sha256[31] ^= 1,
            7 => changed.check.conclusion = WorkflowCheckConclusion::Failure,
            _ => changed.check.evidence.push(99),
        }
        let changed = event(&changed);
        assert_eq!(
            changed.aggregate, original.aggregate,
            "field {field} minted another execution"
        );
        assert_ne!(
            crate::event::event_id(&CryptoBodyIdentity, &changed).unwrap(),
            original_id
        );
    }
    let mut prs = std::collections::BTreeMap::new();
    apply_forge_event_to_prs(&mut prs, &original);
    assert!(prs.is_empty());
}

#[test]
fn candidate_coordinates_and_original_subjects_are_not_interchangeable() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for field in 0..8 {
            let mut invalid = record(format);
            match field {
                0 => invalid.check.source_ref = invalid.subject.source_ref.clone(),
                1 => invalid.check.source_commit = invalid.subject.source_tip,
                2 => invalid.subject.source_ref = invalid.subject.target_ref.clone(),
                3 => invalid.subject.source_tip = invalid.subject.target_tip,
                4 => invalid.candidate.commit = invalid.subject.target_tip,
                5 => invalid.candidate.merge_base = oid(format, 0),
                6 => invalid.subject.target_ref = RefName::try_new(b"refs/tags/v1").unwrap(),
                _ => {
                    invalid.candidate.merge_base = oid(
                        if format == GitHashAlgorithm::Sha1 {
                            GitHashAlgorithm::Sha256
                        } else {
                            GitHashAlgorithm::Sha1
                        },
                        6,
                    )
                }
            }
            assert!(invalid.validate().is_err(), "field {field}");
        }
        let mut fast_forward = record(format);
        fast_forward.candidate.commit = fast_forward.subject.source_tip;
        fast_forward.check.source_commit = fast_forward.subject.source_tip;
        fast_forward.candidate.merge_base = fast_forward.subject.target_tip;
        assert!(fast_forward.validate().is_ok());
        fast_forward.candidate.merge_base = oid(format, 12);
        assert!(fast_forward.validate().is_err());
    }
    assert!(
        record(GitHashAlgorithm::Sha1)
            .proposed_event(PrincipalId::from_bytes([4; 16]), GitHashAlgorithm::Sha256)
            .is_err()
    );
}

#[test]
fn original_limits_apply_to_candidate_jobs_before_encoding() {
    let mut bounded = record(GitHashAlgorithm::Sha256);
    bounded.check.job = "x".repeat(MAX_CHECK_JOB_BYTES);
    bounded.check.evidence = vec![0; MAX_CHECK_EVIDENCE_BYTES];
    let expected = event(&bounded);
    let bytes = encode_body(&expected).unwrap();
    assert_eq!(
        decode_body::<ForgeEvent>(&bytes, DecodeLimits::DEFAULT).unwrap(),
        expected
    );
    bounded.check.job.push('x');
    assert!(bounded.validate().is_err());
    bounded.check.job.pop();
    bounded.check.evidence.push(0);
    assert!(bounded.validate().is_err());
    for job in ["", "bad\njob", "bad\0job"] {
        let mut invalid = record(GitHashAlgorithm::Sha1);
        invalid.check.job = job.into();
        assert!(invalid.validate().is_err());
    }
}

#[test]
fn decoder_rejects_truncation_invalid_counters_and_forged_execution_identity() {
    let expected = event(&record(GitHashAlgorithm::Sha1));
    let frame = encode_body(&expected).unwrap();
    for end in 0..frame.len() {
        assert!(decode_body::<ForgeEvent>(&frame[..end], DecodeLimits::DEFAULT).is_err());
    }
    let mut trailing = frame;
    trailing.push(0);
    assert!(decode_body::<ForgeEvent>(&trailing, DecodeLimits::DEFAULT).is_err());
    for field in 0..3 {
        let mut invalid = expected.clone();
        match field {
            0 => invalid.aggregate = AggregateId::PullRequest(PullRequestNumber::FIRST),
            1 => {
                invalid.aggregate = AggregateId::WorkflowCheck(WorkflowCheckId::from_bytes([0; 32]))
            }
            _ => invalid.version = AggregateVersion::FIRST.next().unwrap(),
        }
        assert!(encode_body(&invalid).is_err());
    }
    let ForgeEventPayload::CandidateWorkflowCheckObservedNative(change) = expected.payload else {
        panic!("candidate fixture")
    };
    let mut out = Encoder::new();
    change.write(&mut out).unwrap();
    let body = out.into_bytes();
    // These fixed-width counters immediately follow the reporting principal.
    for offset in [16, 24] {
        let mut bad = body.clone();
        bad[offset..offset + 8].fill(0);
        assert!(
            NativeCandidateWorkflowCheck::read(&mut Decoder::new(&bad, DecodeLimits::DEFAULT))
                .is_err()
        );
    }
    let mut unknown = body.clone();
    let offset = unknown.len() - change.record.check.evidence.len() - 8;
    unknown[offset..offset + 4].copy_from_slice(&6_u32.to_be_bytes());
    assert!(
        NativeCandidateWorkflowCheck::read(&mut Decoder::new(&unknown, DecodeLimits::DEFAULT))
            .is_err()
    );
}

#[test]
fn historical_branch_check_body_is_byte_identical_to_its_frozen_fields() {
    let old = NativeWorkflowCheck {
        actor: PrincipalId::from_bytes([4; 16]),
        record: super::super::tests::record(GitHashAlgorithm::Sha1),
    };
    let mut expected = vec![4; 16];
    expected.extend_from_slice(&15_u32.to_be_bytes());
    expected.extend_from_slice(b"refs/heads/main");
    expected.extend_from_slice(&1_u16.to_be_bytes()); // Native SHA-1 code point.
    expected.extend_from_slice(&[7; 20]);
    for bytes in [[1; 32], [2; 32], [3; 32]] {
        expected.extend_from_slice(&32_u32.to_be_bytes());
        expected.extend_from_slice(&bytes);
    }
    expected.extend_from_slice(&11_u32.to_be_bytes());
    expected.extend_from_slice(b"build/linux");
    expected.extend_from_slice(&1_u32.to_be_bytes()); // ActionRequired.
    let evidence = b"original normalized job observation\0\xff";
    expected.extend_from_slice(&(evidence.len() as u32).to_be_bytes());
    expected.extend_from_slice(evidence);
    let mut out = Encoder::new();
    old.write(&mut out).unwrap();
    assert_eq!(out.into_bytes(), expected);
    let mut input = Decoder::new(&expected, DecodeLimits::DEFAULT);
    assert_eq!(NativeWorkflowCheck::read(&mut input).unwrap(), old);
    input.finish().unwrap();
}
