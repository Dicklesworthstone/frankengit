use super::*;
use fgit_codec::{DecodeLimits, CryptoBodyIdentity};
use fgit_codec::wire::{canonical_body_bytes, decode_body, encode_body};
use fgit_types::{AsciiSlug, GitOidSha1, GitOidSha256};
use crate::{ForgeEventBatch, PullRequestNumber};

pub(super) fn record(format: GitHashAlgorithm) -> WorkflowCheckRecord {
    WorkflowCheckRecord {
        source_ref: RefName::try_new(b"refs/heads/main").unwrap(),
        source_commit: match format {
            GitHashAlgorithm::Sha1 => GitOid::Sha1(GitOidSha1::from_bytes([7; 20])),
            GitHashAlgorithm::Sha256 => GitOid::Sha256(GitOidSha256::from_bytes([7; 32])),
        },
        run_id: [1; 32],
        attempt_id: [2; 32],
        graph_root: [3; 32],
        job: "build/linux".to_owned(),
        conclusion: WorkflowCheckConclusion::ActionRequired,
        evidence: b"original normalized job observation\0\xff".to_vec(),
    }
}
fn event() -> ForgeEvent {
    record(GitHashAlgorithm::Sha1).proposed_event(
        PrincipalId::from_bytes([4; 16]), GitHashAlgorithm::Sha1,
    ).unwrap()
}
fn change(event: &ForgeEvent) -> &NativeWorkflowCheck {
    match &event.payload {
        ForgeEventPayload::WorkflowCheckObservedNative(value) => value,
        _ => panic!("wrong fixture kind"),
    }
}

#[test]
fn codec_roundtrips_both_native_domains_and_every_nongreen_conclusion() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for conclusion in [WorkflowCheckConclusion::ActionRequired, WorkflowCheckConclusion::Failure,
            WorkflowCheckConclusion::Cancelled, WorkflowCheckConclusion::TimedOut]
        {
            let mut input = record(format);
            input.conclusion = conclusion;
            let event = input.proposed_event(PrincipalId::from_bytes([4;16]), format).unwrap();
            let encoded = encode_body(&event).unwrap();
            assert_eq!(decode_body::<ForgeEvent>(&encoded, DecodeLimits::DEFAULT).unwrap(), event);
            let batch = ForgeEventBatch::of_one(event.clone());
            let bytes = encode_body(&batch).unwrap();
            assert_eq!(decode_body::<ForgeEventBatch>(&bytes, DecodeLimits::DEFAULT).unwrap(), batch);
            assert_eq!(event.payload.kind(), 11);
            assert_eq!(event.version, AggregateVersion::FIRST);
            assert_eq!(change(&event).record, input);
        }
    }
}

#[test]
fn full_digest_labels_are_canonical_and_preserve_every_bit() {
    let zero = WorkflowCheckId::from_bytes([0;32]);
    assert_eq!(zero.to_string(), format!("check/{}", "0".repeat(52)));
    for bit in 0..256 {
        let mut bytes = [0;32];
        bytes[bit / 8] = 1 << (bit % 8);
        let id = WorkflowCheckId::from_bytes(bytes);
        let label = id.to_string();
        assert_eq!(label.len(), 58);
        assert!(AsciiSlug::try_new("workflow_check", label.as_bytes()).is_ok());
        assert_eq!(WorkflowCheckId::from_label(&label), Some(id));
        assert_ne!(id, zero);
    }
    let all = WorkflowCheckId::from_bytes([255;32]);
    assert_eq!(all.to_string(), format!("check/{}g", "v".repeat(51)));
    for invalid in [all.to_string().to_uppercase(), format!("{}0", all),
        format!("check/{}h", "v".repeat(51)), "check/a".to_owned(),
        format!("other/{}", "0".repeat(52))]
    {
        assert!(WorkflowCheckId::from_label(&invalid).is_none(), "{invalid}");
    }
}

#[test]
fn publisher_run_attempt_and_exact_job_name_have_independent_identities() {
    let initial = change(&event()).clone();
    let mut ids = std::collections::BTreeSet::from([initial.id()]);
    for field in 0..4 {
        let mut other = initial.clone();
        match field {
            0 => other.actor = PrincipalId::from_bytes([5;16]),
            1 => other.record.run_id[31] ^= 1,
            2 => other.record.attempt_id[0] ^= 1,
            _ => other.record.job.push('x'),
        }
        assert!(ids.insert(other.id()));
    }
    let mut accent = initial.clone();
    accent.record.job = "caf\u{e9}".to_owned();
    let mut combining = accent.clone();
    combining.record.job = "cafe\u{301}".to_owned();
    assert_ne!(accent.id(), combining.id());
}

#[test]
fn changed_evidence_or_subject_cannot_mint_a_second_job_stream() {
    let original = event();
    let root = crate::event::event_id(&CryptoBodyIdentity, &original).unwrap();
    let first = change(&original).clone();
    for field in 0..4 {
        let mut next = first.record.clone();
        match field {
            0 => next.evidence.push(99),
            1 => next.conclusion = WorkflowCheckConclusion::Failure,
            2 => next.source_ref = RefName::try_new(b"refs/heads/other").unwrap(),
            _ => next.graph_root[31] ^= 1,
        }
        let other = next.proposed_event(first.actor, GitHashAlgorithm::Sha1).unwrap();
        assert_eq!(original.aggregate, other.aggregate);
        assert_ne!(crate::event::event_id(&CryptoBodyIdentity, &other).unwrap(), root);
    }
}

#[test]
fn mismatched_aggregate_forged_identity_and_later_versions_refuse() {
    for field in 0..3 {
        let mut invalid = event();
        match field {
            0 => invalid.aggregate = AggregateId::PullRequest(PullRequestNumber::FIRST),
            1 => invalid.aggregate = AggregateId::WorkflowCheck(WorkflowCheckId::from_bytes([0;32])),
            _ => invalid.version = AggregateVersion::FIRST.next().unwrap(),
        }
        assert!(encode_body(&invalid).is_err());
    }
    let mut wrong_kind = event();
    wrong_kind.payload = ForgeEventPayload::PullRequestClosed { withdrawn: false };
    assert!(encode_body(&wrong_kind).is_err());
    // The decoder independently checks identities and versions, not just the writer.
    let bytes = canonical_body_bytes(&event()).unwrap();
    for offset in [12, 51] {
        let mut bad = bytes.clone();
        bad[offset] ^= 1;
        let mut decoder = Decoder::new(&bad, DecodeLimits::DEFAULT);
        assert!(super::super::read_event(&mut decoder).is_err());
    }
}

#[test]
fn exact_resource_bounds_succeed_and_the_next_byte_refuses() {
    let mut input = record(GitHashAlgorithm::Sha1);
    input.job = "x".repeat(MAX_CHECK_JOB_BYTES);
    input.evidence = vec![0;MAX_CHECK_EVIDENCE_BYTES];
    let good = input.proposed_event(PrincipalId::from_bytes([4;16]), GitHashAlgorithm::Sha1).unwrap();
    let encoded = encode_body(&good).unwrap();
    assert_eq!(decode_body::<ForgeEvent>(&encoded, DecodeLimits::DEFAULT).unwrap(), good);
    input.job.push('x');
    assert!(input.validate().is_err());
    input.job.pop();
    input.evidence.push(0);
    assert!(input.validate().is_err());
    for job in ["", "bad\njob", "bad\0job"] {
        let mut invalid = record(GitHashAlgorithm::Sha1);
        invalid.job = job.to_owned();
        assert!(invalid.validate().is_err());
    }
    let mut invalid = record(GitHashAlgorithm::Sha1);
    invalid.evidence.clear();
    assert!(invalid.validate().is_err());
    invalid = record(GitHashAlgorithm::Sha1);
    invalid.source_ref = RefName::try_new(b"refs/tags/v1").unwrap();
    assert!(invalid.validate().is_err());
    assert!(record(GitHashAlgorithm::Sha1).proposed_event(
        PrincipalId::from_bytes([4;16]), GitHashAlgorithm::Sha256,
    ).is_err());
}

#[test]
fn every_truncation_and_an_unknown_conclusion_refuses_decode() {
    let event = event();
    let bytes = canonical_body_bytes(&event).unwrap();
    for end in 0..bytes.len() {
        assert!(super::super::read_event(&mut Decoder::new(&bytes[..end], DecodeLimits::DEFAULT)).is_err());
    }
    let mut bad = bytes.clone();
    // The conclusion precedes the length-prefixed original evidence.
    let offset = bytes.len() - change(&event).record.evidence.len() - 4 - 4;
    bad[offset..offset+4].copy_from_slice(&5_u32.to_be_bytes());
    assert!(super::super::read_event(&mut Decoder::new(&bad, DecodeLimits::DEFAULT)).is_err());
    let mut framed = encode_body(&event).unwrap();
    framed.push(0);
    assert!(decode_body::<ForgeEvent>(&framed, DecodeLimits::DEFAULT).is_err());
}

#[test]
fn legacy_closed_event_bytes_and_pr_projection_stay_unchanged() {
    let legacy = ForgeEvent { aggregate: AggregateId::PullRequest(PullRequestNumber::FIRST),
        version: AggregateVersion::FIRST,
        payload: ForgeEventPayload::PullRequestClosed { withdrawn: true } };
    let mut expected = Vec::new();
    expected.extend_from_slice(&1_u64.to_be_bytes());
    expected.extend_from_slice(&1_u64.to_be_bytes());
    expected.extend_from_slice(&4_u32.to_be_bytes());
    expected.push(1);
    assert_eq!(canonical_body_bytes(&legacy).unwrap(), expected);
    let mut prs = std::collections::BTreeMap::new();
    crate::snapshot::apply_forge_event_to_prs(&mut prs, &event());
    assert!(prs.is_empty());
}
