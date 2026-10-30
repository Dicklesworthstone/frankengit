use super::*;
use crate::AggregateVersion;
use crate::event::pull_request_comment::{
    MAX_COMMENT_BYTES, SourceCommentComparison, SourceCommentSide,
};
use fgit_codec::{DecodeLimits, decode_body, encode_body};
use fgit_types::{GitHashAlgorithm, GitOid, RefName};
use std::collections::BTreeSet;

fn oid(format: GitHashAlgorithm, digit: char) -> GitOid {
    GitOid::from_hex(format, &digit.to_string().repeat(format.digest_len() * 2)).unwrap()
}

fn anchor(format: GitHashAlgorithm) -> SourceCommentAnchor {
    SourceCommentAnchor {
        pull_request_version: AggregateVersion::try_new(3).unwrap(),
        source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
        target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
        source_tip: oid(format, '2'),
        target_tip: oid(format, '1'),
        compared_base: oid(format, '1'),
        comparison: SourceCommentComparison::MergeBase,
        path: b"src/text".to_vec(),
        side: SourceCommentSide::After,
        blob: oid(format, '3'),
        mode: 0o100644,
        byte_start: 8,
        byte_end: 16,
        line_start: 2,
        line_count: 1,
    }
}

fn command(anchor: Option<SourceCommentAnchor>) -> PullRequestAppendCommentCommand {
    PullRequestAppendCommentCommand {
        number: PullRequestNumber::FIRST,
        body: "  Original UTF-8 é\r\n<script>inert</script> 🦀\n".into(),
        anchor,
    }
}

#[test]
fn append_templates_reuse_plain_and_anchored_bytes_without_submitting_a_predecessor() {
    let actor = PrincipalId::from_bytes([7; 16]);
    for anchor in [
        None,
        Some(anchor(GitHashAlgorithm::Sha1)),
        Some(anchor(GitHashAlgorithm::Sha256)),
    ] {
        let input = command(anchor);
        input.validate().unwrap();
        let template = input.commitment_event(actor).unwrap();
        assert_eq!(template.version, AggregateVersion::FIRST);
        assert_eq!(
            template.payload.kind(),
            if input.anchor.is_some() { 15 } else { 12 }
        );
        let mut exact = PullRequestCommentCommand {
            number: input.number,
            expected_version: ExpectedVersion::NewStream,
            body: input.body.clone(),
            anchor: input.anchor.clone(),
        };
        let bytes = encode_body(&template).unwrap();
        assert_eq!(
            bytes,
            encode_body(&exact.proposed_event(actor).unwrap()).unwrap()
        );
        assert_eq!(
            decode_body::<ForgeEvent>(&bytes, DecodeLimits::DEFAULT).unwrap(),
            template
        );
        exact.expected_version = ExpectedVersion::Exactly(AggregateVersion::try_new(77).unwrap());
        let later = exact.proposed_event(actor).unwrap();
        assert_eq!(later.version.get(), 78);
        assert_ne!(bytes, encode_body(&later).unwrap());
        // Advancing an independently planned event never alters the original
        // template, including a source anchor's exact PR metadata version.
        assert_eq!(input.commitment_event(actor).unwrap(), template);
        assert_eq!(later.payload, template.payload);
    }
}

#[test]
fn body_validation_preserves_bytes_and_matches_the_strict_command_boundaries() {
    let actor = PrincipalId::from_bytes([7; 16]);
    let mut input = command(None);
    for body in [
        String::new(),
        " \t\r\n".into(),
        "before\0after".into(),
        "é".repeat(MAX_COMMENT_BYTES / 2 + 1),
    ] {
        input.body = body;
        assert!(input.validate().is_err());
        assert_eq!(
            input.commitment_event(actor),
            Err(RefusalCode::EvidenceInvalid)
        );
    }
    for body in [
        "é".repeat(MAX_COMMENT_BYTES / 2),
        "x".repeat(MAX_COMMENT_BYTES),
        "  exact whitespace\r\n".into(),
    ] {
        input.body = body;
        input.validate().unwrap();
        let event = input.commitment_event(actor).unwrap();
        let crate::ForgeEventPayload::PullRequestCommentedNative(comment) = event.payload else {
            panic!("native PR comment");
        };
        assert_eq!(comment.body.as_bytes(), input.body.as_bytes());
        assert_eq!(comment.actor, actor);
        assert!(comment.anchor.is_none());
    }
}

#[test]
fn every_original_comment_and_source_coordinate_changes_the_commitment() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let original = command(Some(anchor(format)));
        let mut commitments = BTreeSet::new();
        for variant in 0..20 {
            let mut input = original.clone();
            let mut actor = PrincipalId::from_bytes([7; 16]);
            match variant {
                0 => {}
                1 => input.number = PullRequestNumber::try_new(2).unwrap(),
                2 => input.body.push('!'),
                3 => actor = PrincipalId::from_bytes([8; 16]),
                4 => input.anchor = None,
                _ => {
                    let anchor = input.anchor.as_mut().unwrap();
                    match variant {
                        5 => anchor.pull_request_version = AggregateVersion::try_new(4).unwrap(),
                        6 => anchor.source_ref = RefName::try_new(b"refs/heads/other").unwrap(),
                        7 => anchor.target_ref = RefName::try_new(b"refs/heads/staging").unwrap(),
                        8 => anchor.source_tip = oid(format, '4'),
                        9 => anchor.target_tip = oid(format, '4'),
                        10 => anchor.compared_base = oid(format, '4'),
                        11 => anchor.comparison = SourceCommentComparison::Direct,
                        12 => anchor.path = b"src/\xfftext".to_vec(),
                        13 => anchor.side = SourceCommentSide::Before,
                        14 => anchor.blob = oid(format, '4'),
                        15 => anchor.mode = 0o100755,
                        16 => anchor.byte_start = 9,
                        17 => anchor.byte_end = 17,
                        18 => anchor.line_start = 3,
                        19 => anchor.line_count = 2,
                        _ => unreachable!(),
                    }
                }
            }
            input.validate().unwrap();
            let event = input.commitment_event(actor).unwrap();
            assert!(
                commitments.insert(encode_body(&event).unwrap()),
                "variant {variant}"
            );
        }
    }
}

#[test]
fn append_anchors_keep_all_structural_refusals_beside_a_permitted_twin() {
    let actor = PrincipalId::from_bytes([7; 16]);
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let original = command(Some(anchor(format)));
        for mutation in 0..8 {
            original.validate().unwrap();
            original.commitment_event(actor).unwrap();
            let mut input = original.clone();
            let anchor = input.anchor.as_mut().unwrap();
            match mutation {
                0 => anchor.source_ref = anchor.target_ref.clone(),
                1 => anchor.byte_end = anchor.byte_start,
                2 => anchor.mode = 0o100777,
                3 => {
                    let other = match format {
                        GitHashAlgorithm::Sha1 => GitHashAlgorithm::Sha256,
                        GitHashAlgorithm::Sha256 => GitHashAlgorithm::Sha1,
                    };
                    anchor.blob = oid(other, '3');
                }
                4 => anchor.source_tip = oid(format, '0'),
                5 => anchor.path = b"../outside".to_vec(),
                6 => anchor.line_count = 0,
                _ => {
                    anchor.comparison = SourceCommentComparison::Direct;
                    anchor.compared_base = oid(format, '4');
                }
            }
            assert!(input.validate().is_err(), "mutation {mutation}");
            assert_eq!(
                input.commitment_event(actor),
                Err(RefusalCode::EvidenceInvalid)
            );
        }
    }
}
