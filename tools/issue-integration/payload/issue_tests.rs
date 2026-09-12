use super::*;
use fgit_codec::{DecodeLimits, decode_body, encode_body};
fn actor(byte: u8) -> PrincipalId { PrincipalId::from_bytes([byte; 16]) }
fn opening() -> IssueCommand {
    IssueCommand { number: IssueNumber::FIRST, expected_version: ExpectedVersion::NewStream,
        action: IssueAction::Open { title: "Unicode issue é".into(), body: "<script>\r\nexact bytes\n".into(), labels: vec!["bug".into(), "triage".into()] } }
}
fn follow(state: &IssueSnapshot, action: IssueAction) -> ForgeEvent {
    IssueCommand { number: state.number, expected_version: ExpectedVersion::Exactly(state.version), action }
        .proposed_event(actor(2)).unwrap()
}
#[test]
fn complete_lifecycle_roundtrips_and_rebuilds_without_losing_text_or_opener() {
    let first = opening().proposed_event(actor(1)).unwrap();
    let mut state = apply_event(None, &first).unwrap();
    let mut events = vec![first];
    for action in [IssueAction::Edit(IssueEdit { title: Some("Revised".into()), ..Default::default() }),
        IssueAction::Comment { body: "comment é\r\nno final newline".into() }, IssueAction::Close,
        IssueAction::Comment { body: "closed discussion continues".into() },
        IssueAction::Edit(IssueEdit { labels: Some(vec![]), ..Default::default() }), IssueAction::Reopen] {
        let event = follow(&state, action);
        let frame = encode_body(&event).unwrap();
        assert_eq!(decode_body::<ForgeEvent>(&frame, DecodeLimits::DEFAULT).unwrap(), event);
        state = apply_event(Some(&state), &event).unwrap(); events.push(event);
    }
    let mut rebuilt = None;
    for event in events { rebuilt = Some(apply_event(rebuilt.as_ref(), &event).unwrap()); }
    assert_eq!(rebuilt.as_ref(), Some(&state));
    assert_eq!(state.opened_by, actor(1)); assert_eq!(state.last_actor, actor(2));
    assert_eq!(state.state, IssueState::Open); assert_eq!(state.comments, 2);
    assert_eq!(state.body, "<script>\r\nexact bytes\n"); assert!(state.labels.is_empty());
}
#[test]
fn close_reopen_edit_and_comment_bind_only_explicit_stable_semantics() {
    let mut command = opening();
    let original = encode_body(&command.proposed_event(actor(1)).unwrap()).unwrap();
    command.number = IssueNumber::try_new(2).unwrap();
    assert_ne!(encode_body(&command.proposed_event(actor(1)).unwrap()).unwrap(), original);
    assert_ne!(encode_body(&opening().proposed_event(actor(2)).unwrap()).unwrap(), original);
    let state = apply_event(None, &opening().proposed_event(actor(1)).unwrap()).unwrap();
    let close = follow(&state, IssueAction::Close);
    assert_ne!(encode_body(&close).unwrap(), encode_body(&follow(&state, IssueAction::Reopen)).unwrap());
    let preserve = follow(&state, IssueAction::Edit(IssueEdit { title: Some("Other".into()), ..Default::default() }));
    let clear = follow(&state, IssueAction::Edit(IssueEdit { title: Some("Other".into()), body: Some(String::new()), labels: Some(vec![]) }));
    assert_ne!(encode_body(&preserve).unwrap(), encode_body(&clear).unwrap());
    assert_eq!(apply_event(Some(&state), &preserve).unwrap().body, state.body);
    assert!(apply_event(Some(&state), &clear).unwrap().body.is_empty());
}
#[test]
fn stale_gaps_cross_issue_and_illegal_state_transitions_refuse() {
    let first = opening().proposed_event(actor(1)).unwrap();
    let state = apply_event(None, &first).unwrap();
    assert_eq!(apply_event(Some(&state), &first), Err(RefusalCode::EvidenceStale));
    assert!(apply_event(Some(&state), &follow(&state, IssueAction::Reopen)).is_err());
    let close = follow(&state, IssueAction::Close);
    let closed = apply_event(Some(&state), &close).unwrap();
    assert!(apply_event(Some(&closed), &follow(&closed, IssueAction::Close)).is_err());
    let mut wrong = follow(&state, IssueAction::Comment { body: "x".into() });
    wrong.aggregate = AggregateId::Issue(IssueNumber::try_new(2).unwrap());
    assert_eq!(apply_event(Some(&state), &wrong), Err(RefusalCode::EvidenceStale));
    wrong.aggregate = first.aggregate; wrong.version = AggregateVersion::try_new(3).unwrap();
    assert_eq!(apply_event(Some(&state), &wrong), Err(RefusalCode::EvidenceStale));
    assert!(apply_event(None, &close).is_err());
    assert_eq!(state.version, AggregateVersion::FIRST);
}
#[test]
fn every_truncation_and_cross_aggregate_encoding_is_rejected() {
    let mut event = opening().proposed_event(actor(1)).unwrap();
    let frame = encode_body(&event).unwrap();
    for end in 0..frame.len() { assert!(decode_body::<ForgeEvent>(&frame[..end], DecodeLimits::DEFAULT).is_err()); }
    event.aggregate = AggregateId::PullRequest(crate::PullRequestNumber::FIRST);
    assert!(encode_body(&event).is_err());
    event.aggregate = AggregateId::Issue(IssueNumber::FIRST);
    event.payload = ForgeEventPayload::PullRequestClosed { withdrawn: false };
    assert!(encode_body(&event).is_err());
}
#[test]
fn field_and_collection_bounds_have_inclusive_permitted_twins() {
    let valid = IssueAction::Open { title: "x".repeat(MAX_TITLE_BYTES), body: "x".repeat(MAX_BODY_BYTES),
        labels: (0..MAX_LABELS).map(|i| format!("{i:02}-{}", "x".repeat(MAX_LABEL_BYTES-3))).collect() };
    valid.validate().unwrap();
    let IssueAction::Open { title, body, labels } = valid else { unreachable!() };
    for invalid in [IssueAction::Open { title: format!("{title}x"), body: body.clone(), labels: labels.clone() },
        IssueAction::Open { title: title.clone(), body: format!("{body}x"), labels: labels.clone() },
        IssueAction::Open { title: title.clone(), body: body.clone(), labels: [labels.clone(), vec!["zz".into()]].concat() },
        IssueAction::Edit(IssueEdit::default()), IssueAction::Comment { body: " \r\n".into() },
        IssueAction::Edit(IssueEdit { title: Some("line\nfeed".into()), ..Default::default() }),
        IssueAction::Comment { body: "nul\0".into() }] { assert!(invalid.validate().is_err()); }
    for labels in [vec!["same".into(), "same".into()], vec!["z".into(), "a".into()], vec!["\t".into()]] {
        assert!(IssueAction::Edit(IssueEdit { labels: Some(labels), ..Default::default() }).validate().is_err());
    }
}
#[test]
fn issue_identity_and_version_exhaustion_cannot_alias_a_pull_request() {
    assert!(IssueNumber::try_new(0).is_none());
    assert_eq!(AggregateId::Issue(IssueNumber::FIRST).to_string(), "issue/1");
    assert_ne!(AggregateId::Issue(IssueNumber::FIRST), AggregateId::PullRequest(crate::PullRequestNumber::FIRST));
    let mut command = opening();
    command.expected_version = ExpectedVersion::Exactly(AggregateVersion::try_new(u64::MAX).unwrap());
    command.action = IssueAction::Close;
    assert_eq!(command.proposed_event(actor(1)), Err(RefusalCode::ResourceBudgetExceeded));
    command.expected_version = ExpectedVersion::NewStream;
    assert_eq!(command.proposed_event(actor(1)), Err(RefusalCode::EvidenceInvalid));
}
