use super::*;
use fgit_codec::{DecodeLimits, decode_body, encode_body};

fn intent(body: impl Into<String>) -> IssueCommentIntent {
    IssueCommentIntent {
        number: IssueNumber::FIRST,
        body: body.into(),
    }
}

#[test]
fn append_commitment_reuses_legacy_comment_bytes_at_a_fixed_non_open_position() {
    let actor = PrincipalId::from_bytes([7; 16]);
    let intent = intent("Exact UTF-8 é\r\ncomment text");
    let template = intent.commitment_event(actor).unwrap();
    assert_eq!(template.version.get(), 2);
    let legacy = IssueCommand {
        number: intent.number,
        expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
        action: IssueAction::Comment {
            body: intent.body.clone(),
        },
    }
    .proposed_event(actor)
    .unwrap();
    let bytes = encode_body(&template).unwrap();
    assert_eq!(bytes, encode_body(&legacy).unwrap());
    assert_eq!(
        decode_body::<ForgeEvent>(&bytes, DecodeLimits::DEFAULT).unwrap(),
        template
    );
    let mut invalid = template;
    invalid.version = AggregateVersion::FIRST;
    assert!(encode_body(&invalid).is_err());
}

#[test]
fn additive_and_exact_comments_share_the_same_text_bounds() {
    for body in [
        String::new(),
        " \r\n\t".into(),
        "embedded\0nul".into(),
        "x".repeat(super::super::MAX_BODY_BYTES + 1),
    ] {
        let intent = intent(body);
        assert!(intent.validate().is_err());
        assert_eq!(
            intent.commitment_event(PrincipalId::from_bytes([1; 16])),
            Err(RefusalCode::EvidenceInvalid)
        );
    }
    for body in ["é\r\ntext".into(), "x".repeat(super::super::MAX_BODY_BYTES)] {
        let intent = intent(body);
        intent.validate().unwrap();
        assert!(
            encode_body(
                &intent
                    .commitment_event(PrincipalId::from_bytes([1; 16]))
                    .unwrap()
            )
            .is_ok()
        );
    }
}
