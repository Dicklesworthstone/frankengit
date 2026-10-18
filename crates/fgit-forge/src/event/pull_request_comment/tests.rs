use super::*;
use fgit_codec::{DecodeLimits, decode_body, encode_body};
use std::collections::{BTreeMap, BTreeSet};

fn command() -> PullRequestCommentCommand {
    PullRequestCommentCommand {
        number: PullRequestNumber::FIRST,
        expected_version: ExpectedVersion::NewStream,
        body: "Original discussion\n<script>inert</script> é 🦀".into(),
    }
}

fn actor() -> PrincipalId {
    PrincipalId::from_bytes([7; 16])
}

#[test]
fn conversation_event_roundtrip_preserves_original_text_actor_and_version() {
    let mut command = command();
    for version in 1..=3 {
        let event = command.proposed_event(actor()).unwrap();
        assert_eq!(
            event.aggregate,
            AggregateId::PullRequestConversation(command.number)
        );
        assert_eq!(event.aggregate.to_string(), "conversation/1");
        assert_eq!(event.version.get(), version);
        assert_eq!(event.payload.kind(), 12);
        let frame = encode_body(&event).unwrap();
        assert_eq!(
            decode_body::<ForgeEvent>(&frame, DecodeLimits::DEFAULT).unwrap(),
            event
        );
        assert_eq!(
            encode_body(&command.proposed_event(actor()).unwrap()).unwrap(),
            frame
        );
        let ForgeEventPayload::PullRequestCommentedNative(comment) = event.payload else {
            panic!("conversation event")
        };
        assert_eq!(comment.actor, actor());
        assert_eq!(comment.body, command.body);
        command.expected_version = ExpectedVersion::Exactly(event.version);
    }
}

#[test]
fn body_boundary_twins_are_exact_utf8_byte_limits_and_text_is_not_trimmed() {
    let mut input = command();
    for body in [
        " ".repeat(3),
        String::new(),
        "\t\n".into(),
        "before\0after".into(),
        "é".repeat(MAX_COMMENT_BYTES / 2 + 1),
    ] {
        input.body = body;
        assert!(input.proposed_event(actor()).is_err());
    }
    for body in [
        "é".repeat(MAX_COMMENT_BYTES / 2),
        "x".repeat(MAX_COMMENT_BYTES),
        "  retained text\n".into(),
    ] {
        input.body = body;
        let event = input.proposed_event(actor()).unwrap();
        let bytes = encode_body(&event).unwrap();
        assert_eq!(
            decode_body::<ForgeEvent>(&bytes, DecodeLimits::DEFAULT).unwrap(),
            event
        );
    }
    input.body.push('x');
    input.expected_version = ExpectedVersion::Exactly(AggregateVersion::try_new(u64::MAX).unwrap());
    assert_eq!(
        input.proposed_event(actor()),
        Err(RefusalCode::ResourceBudgetExceeded)
    );
    input.expected_version =
        ExpectedVersion::Exactly(AggregateVersion::try_new(u64::MAX - 1).unwrap());
    assert_eq!(
        input.proposed_event(actor()).unwrap().version.get(),
        u64::MAX
    );
}

#[test]
fn each_submitted_semantic_field_changes_the_event_and_other_streams_cannot_alias_it() {
    let original = command();
    let mut bytes = BTreeSet::new();
    for variant in 0..5 {
        let mut input = original.clone();
        let mut author = actor();
        match variant {
            0 => {}
            1 => input.number = PullRequestNumber::try_new(2).unwrap(),
            2 => input.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST),
            3 => input.body.push('!'),
            _ => author = PrincipalId::from_bytes([8; 16]),
        }
        assert!(bytes.insert(encode_body(&input.proposed_event(author).unwrap()).unwrap()));
    }
    let original = original.proposed_event(actor()).unwrap();
    for aggregate in [
        AggregateId::PullRequest(PullRequestNumber::FIRST),
        AggregateId::Issue(crate::IssueNumber::FIRST),
        AggregateId::ReviewProtection,
    ] {
        let mut wrong = original.clone();
        wrong.aggregate = aggregate;
        assert!(encode_body(&wrong).is_err());
    }
    let mut wrong = original;
    wrong.payload = ForgeEventPayload::PullRequestClosed { withdrawn: true };
    assert!(encode_body(&wrong).is_err());
}

#[test]
fn bare_comment_codec_has_a_literal_and_refuses_every_truncation() {
    let comment = NativePullRequestComment {
        actor: PrincipalId::from_bytes([1; 16]),
        body: "hi".into(),
    };
    let mut encoder = Encoder::new();
    comment.write(&mut encoder).unwrap();
    let literal =
        b"\0\0\0\x10\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\0\0\0\x02hi";
    assert_eq!(encoder.as_bytes(), literal);
    let mut decoder = Decoder::new(literal, DecodeLimits::DEFAULT);
    assert_eq!(
        NativePullRequestComment::read(&mut decoder).unwrap(),
        comment
    );
    decoder.finish().unwrap();
    for end in 0..literal.len() {
        assert!(
            NativePullRequestComment::read(&mut Decoder::new(
                &literal[..end],
                DecodeLimits::DEFAULT
            ))
            .is_err()
        );
    }
    let mut malformed = literal.to_vec();
    *malformed.last_mut().unwrap() = 0xff;
    assert!(
        NativePullRequestComment::read(&mut Decoder::new(&malformed, DecodeLimits::DEFAULT))
            .is_err()
    );
}

#[test]
fn comment_never_creates_or_changes_a_legacy_pr_projection() {
    let event = command().proposed_event(actor()).unwrap();
    let mut rows = BTreeMap::new();
    crate::apply_forge_event_to_prs(&mut rows, &event);
    assert!(rows.is_empty());
    // The aggregate gate itself prevents a conversation from posing as PR metadata.
    let mut invalid = event;
    invalid.aggregate = AggregateId::PullRequest(PullRequestNumber::FIRST);
    assert!(encode_body(&invalid).is_err());
}
