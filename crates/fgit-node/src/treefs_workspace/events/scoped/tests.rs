use super::*;
use fgit_admission::merge::native::feed::ForgeEventEnvelope;
use fgit_forge::event::issue::{IssueAction, NativeIssueEvent};
use fgit_forge::event::pull_request::{NativePullRequestEvent, PullRequestAction, PullRequestData};
use fgit_types::{GitOid, RefName};
use fgit_forge::{IssueNumber, PullRequestNumber};
use fgit_types::{CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, PrincipalId};
use std::cell::Cell;

fn digest(byte: u8) -> DigestBytes { DigestBytes::try_new(&[byte; 32]).unwrap() }
fn head() -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(1).unwrap(), CANONICAL_CODEC_VERSION, digest(1),
    )
}
fn issue(body: &str) -> ForgeEvent {
    ForgeEvent {
        aggregate: AggregateId::Issue(IssueNumber::try_new(1).unwrap()),
        version: AggregateVersion::FIRST,
        payload: ForgeEventPayload::IssueChangedNative(NativeIssueEvent {
            actor: PrincipalId::from_bytes([0x35; 16]),
            action: IssueAction::Open { title: "fixture".into(), body: body.into(), labels: vec![] },
        }),
    }
}
fn pull() -> ForgeEvent {
    ForgeEvent {
        aggregate: AggregateId::PullRequest(PullRequestNumber::FIRST),
        version: AggregateVersion::try_new(2).unwrap(),
        payload: ForgeEventPayload::PullRequestChangedNative(NativePullRequestEvent {
            action: PullRequestAction::Close,
            actor: PrincipalId::from_bytes([0x36; 16]),
            data: PullRequestData {
                source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
                target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
                source_tip: GitOid::from_hex(GitHashAlgorithm::Sha1, &"ab".repeat(20)).unwrap(),
                target_tip: GitOid::from_hex(GitHashAlgorithm::Sha1, &"cd".repeat(20)).unwrap(),
                title: "PR fixture".into(), body: "PR body".into(),
            },
        }),
    }
}
fn envelope(sequence: u64, event: ForgeEvent) -> ForgeEventEnvelope {
    ForgeEventEnvelope {
        cursor: ForgeEventCursor::new(sequence, 0).unwrap(),
        tx_id: TxId::from_digest(
            DigestAlgorithmId::try_new(1).unwrap(), CANONICAL_CODEC_VERSION, digest(7),
        ),
        policy_epoch: PolicyEpoch::FIRST,
        event,
    }
}
fn page(events: Vec<ForgeEventEnvelope>, more: bool) -> ForgeEventPage {
    ForgeEventPage {
        source_head: head(),
        next_after: if more { events.last().map(|e| e.cursor) } else { None },
        events,
    }
}
fn empty(issues: bool, pulls: bool, after: Option<(u64, u32)>) -> ScopedForgeEventPage {
    ScopedForgeEventPage {
        tenant: TenantId::from_bytes([1; 16]), repository: RepositoryId::from_bytes([2; 16]),
        incarnation: RepositoryIncarnationId::from_bytes([3; 16]), format: GitHashAlgorithm::Sha1,
        source_head: head(), issues_read: issues, pulls_read: pulls,
        events: Vec::new(), next_after: None, resume_after: after,
    }
}
fn selected(raw: ForgeEventPage, issues: bool, pulls: bool, after: Option<(u64, u32)>) -> ScopedForgeEventPage {
    let mut result = empty(issues, pulls, after);
    project(&mut result, raw, after, 100, &|_| false, &|| false).unwrap();
    result
}

#[test]
fn exact_cursor_grammar_roundtrips_full_integer_ranges() {
    let parse = OneNode::parse_forge_event_feed_cursor;
    assert_eq!(parse("0").unwrap(), None);
    assert_eq!(parse("1:0").unwrap(), Some((1, 0)));
    assert_eq!(parse("18446744073709551615:4294967295").unwrap(), Some((u64::MAX, u32::MAX)));
    for value in ["", "00", "0:0", "01:0", "1:00", "1:-1", "-1:0", "+1:0", "1:+1",
        "1:0:0", "1", "1:", ":0", "1: 0", "1:0\n", "１:0", "1:4294967296",
        "18446744073709551616:0", "../../secret", "1e3:0"]
    {
        assert!(matches!(parse(value), Err(ForgeEventReadRefusal::InvalidCursor)), "{value:?}");
    }
}

#[test]
fn independent_grants_disclose_only_matching_aggregate_and_payload_pairs() {
    let raw = page(vec![envelope(1, issue("secret issue")), envelope(2, pull())], false);
    let only_issue = selected(raw.clone(), true, false, None);
    let only_pull = selected(raw.clone(), false, true, None);
    let both = selected(raw, true, true, None);
    assert_eq!(only_issue.events().len(), 1);
    assert_eq!(only_issue.events()[0].kind(), 8);
    assert_eq!(only_pull.events().len(), 1);
    assert_eq!(only_pull.events()[0].kind(), 6);
    assert_eq!(both.events().len(), 2);
    assert_eq!(only_issue.events()[0].frame_hex(), hex(&encode_body(&issue("secret issue")).unwrap()).unwrap());
    assert_eq!(only_pull.events()[0].frame_hex(), hex(&encode_body(&pull()).unwrap()).unwrap());
    let mut mismatched = issue("not a PR");
    mismatched.aggregate = AggregateId::PullRequest(PullRequestNumber::FIRST);
    assert!(!permitted(&mismatched, true, true, &|_| false));
    assert!(!permitted(&issue("hidden"), false, false, &|_| false));
    assert!(!permitted(&pull(), false, false, &|_| false));
}

#[test]
fn denied_payload_is_not_encoded_or_exposed_even_when_its_codec_would_refuse() {
    let raw = page(vec![envelope(1, issue("invalid\0secret")), envelope(2, pull())], false);
    let permitted_twin = page(vec![envelope(1, issue("valid secret")), envelope(2, pull())], false);
    let hidden = selected(raw.clone(), false, true, None);
    assert_eq!(hidden.events().len(), 1);
    assert!(!hidden.to_json().unwrap().contains(&hex(b"invalid\0secret").unwrap()));
    let mut granted = empty(true, true, None);
    assert!(matches!(project(&mut granted, raw, None, 100, &|_| false, &|| false), Err(ForgeEventReadRefusal::InvalidPage)));
    assert_eq!(selected(permitted_twin, true, true, None).events().len(), 2);
}

#[test]
fn an_empty_filtered_page_advances_and_eof_preserves_the_poll_watermark() {
    let hidden = selected(page(vec![envelope(1, issue("private"))], true), false, true, None);
    assert!(hidden.events().is_empty());
    assert_eq!(hidden.next_after(), Some((1, 0)));
    assert_eq!(hidden.resume_after(), Some((1, 0)));
    let next = selected(page(vec![envelope(2, pull()), envelope(3, issue("also private"))], false), false, true, hidden.next_after());
    assert_eq!(next.events().len(), 1);
    assert_eq!(next.events()[0].cursor(), (2, 0));
    assert_eq!(next.next_after(), None);
    assert_eq!(next.resume_after(), Some((3, 0)));
    let eof = selected(page(vec![], false), false, true, next.resume_after());
    assert_eq!(eof.resume_after(), Some((3, 0)));
    assert!(eof.to_json().unwrap().contains("\"complete\":true"));
    let initial = selected(page(vec![], false), true, false, None);
    assert_eq!(initial.resume_after(), None);
}

#[test]
fn bounded_frames_split_without_skipping_or_repeating_the_next_event() {
    let body = "x".repeat(fgit_forge::event::issue::MAX_BODY_BYTES);
    let entries: Vec<_> = (1..=12).map(|n| envelope(n, issue(&body))).collect();
    let first = selected(page(entries.clone(), false), true, false, None);
    assert!(!first.events().is_empty());
    assert!(first.events().len() < entries.len());
    assert_eq!(first.next_after(), first.resume_after());
    let resume = first.resume_after().unwrap();
    let remaining = entries.into_iter().filter(|e| position(e.cursor) > resume).collect();
    let second = selected(page(remaining, false), true, false, Some(resume));
    let positions: Vec<_> = first.events().iter().chain(second.events().iter()).map(ScopedForgeEvent::cursor).collect();
    assert_eq!(positions, (1..=12).map(|n| (n, 0)).collect::<Vec<_>>());
    assert!(first.to_json().unwrap().len() <= MAX_JSON_BYTES);
    assert!(second.to_json().unwrap().len() <= MAX_JSON_BYTES);
    assert_eq!(second.next_after(), None);
}

#[test]
fn exact_resource_edges_refuse_oversized_frames_without_advancing_the_charge() {
    let mut bytes = 0;
    assert!(charge_frame(&mut bytes, MAX_FRAME_BYTES).unwrap());
    assert!(charge_frame(&mut bytes, MAX_FRAME_BYTES).unwrap());
    assert_eq!(bytes, MAX_PAGE_FRAME_BYTES);
    assert!(!charge_frame(&mut bytes, 1).unwrap());
    assert_eq!(bytes, MAX_PAGE_FRAME_BYTES);
    assert!(matches!(charge_frame(&mut 0, MAX_FRAME_BYTES + 1), Err(ForgeEventReadRefusal::ResponseLimit)));
    assert!(matches!(charge_frame(&mut usize::MAX, 1), Err(ForgeEventReadRefusal::ResponseLimit)));
    let mut json = "x".repeat(MAX_JSON_BYTES - 1);
    append(&mut json, "x").unwrap();
    assert!(matches!(append(&mut json, "x"), Err(ForgeEventReadRefusal::ResponseLimit)));
    assert_eq!(json.len(), MAX_JSON_BYTES);
}

#[test]
fn invalid_page_order_bounds_head_and_continuation_fail_closed() {
    let valid = page(vec![envelope(1, issue("one")), envelope(2, pull())], true);
    assert_eq!(selected(valid.clone(), true, true, None).events().len(), 2);
    for mode in 0..6 {
        let mut raw = valid.clone();
        let mut result = empty(true, true, None);
        let (after, limit) = match mode {
            0 => { raw.events.reverse(); (None, 100) }
            1 => { raw.events[1].cursor = raw.events[0].cursor; (None, 100) }
            2 => { raw.next_after = Some(ForgeEventCursor::new(99, 0).unwrap()); (None, 100) }
            3 => (None, 1),
            4 => (Some((1, 0)), 100),
            _ => {
                raw.source_head = RepositoryAuthorityHeadId::from_digest(
                    DigestAlgorithmId::try_new(1).unwrap(), CANONICAL_CODEC_VERSION, digest(2),
                );
                (None, 100)
            }
        };
        assert!(matches!(project(&mut result, raw, after, limit, &|_| false, &|| false), Err(ForgeEventReadRefusal::InvalidPage)), "mode={mode}");
    }
}

#[test]
fn cancellation_refuses_before_and_during_output_and_live_twin_is_deterministic() {
    let raw = page(vec![envelope(1, issue("one")), envelope(2, pull())], false);
    for at in 0..=3 {
        let checks = Cell::new(0usize);
        let mut result = empty(true, true, None);
        let cancelled = || { let n = checks.get(); checks.set(n + 1); n == at };
        assert!(matches!(project(&mut result, raw.clone(), None, 100, &|_| false, &cancelled), Err(ForgeEventReadRefusal::Cancelled)));
    }
    let a = selected(raw.clone(), true, true, None).to_json().unwrap();
    let b = selected(raw, true, true, None).to_json().unwrap();
    assert_eq!(a, b);
    assert!(a.contains("\"cursor_discloses_repository_activity\":true"));
    assert!(a.contains("\"omits_other_event_families\":true"));
}

#[test]
fn current_hidden_ref_policy_and_legacy_ambiguity_cannot_disclose_pr_coordinates() {
    for concealed in [b"refs/heads/topic".as_slice(), b"refs/heads/main".as_slice()] {
        let mut result = empty(true, true, None);
        project(&mut result, page(vec![envelope(1, pull()), envelope(2, issue("visible"))], false),
            None, 100, &|reference| reference == concealed, &|| false).unwrap();
        assert_eq!(result.events().len(), 1);
        assert_eq!(result.events()[0].kind(), 8);
        assert_eq!(result.resume_after(), Some((2, 0)));
        assert!(!result.to_json().unwrap().contains(&hex(b"PR body").unwrap()));
    }
    assert!(permitted(&pull(), false, true, &|_| false));
    let mut legacy = pull();
    legacy.payload = ForgeEventPayload::PullRequestClosed { withdrawn: true };
    assert!(!permitted(&legacy, true, true, &|_| false));
    assert!(selected(page(vec![envelope(1, legacy)], false), true, true, None).events().is_empty());
}
