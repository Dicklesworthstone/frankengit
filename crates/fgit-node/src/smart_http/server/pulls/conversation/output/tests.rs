use super::*;
use crate::PullRequestCommentView;
use fgit_forge::{AggregateVersion, PullRequestNumber};
use fgit_wire::smart_http::{HttpLimits, head};

fn fixture() -> PullRequestCommentsPage {
    PullRequestCommentsPage {
        number: PullRequestNumber::FIRST,
        source_head: super::super::super::super::issues::parse_snapshot(&format!(
            "alg:1:{}",
            "ab".repeat(32)
        ))
        .unwrap(),
        discussion_version: Some(AggregateVersion::FIRST),
        comments: vec![PullRequestCommentView {
            version: AggregateVersion::FIRST,
            actor: PrincipalId::from_bytes([7; 16]),
            body: "**Review** <script>bad()</script>\n\"é\"".into(),
        }],
        next_after: None,
    }
}

#[test]
fn pages_preserve_untrusted_text_and_derive_only_source_bound_safe_markdown() {
    let bytes =
        b"GET /repo.git/api/v1/pulls/1/comments?render=html_safe HTTP/1.1\r\nHost: local\r\n\r\n";
    let envelope = head::parse(bytes, HttpLimits::default()).unwrap().unwrap();
    let request = Request::parse(&envelope).unwrap().unwrap();
    let page = fixture();
    let body = page_with_binding(
        "\"schema_version\":1",
        &request,
        Some(&page),
        MAX_REPLY_BYTES,
        &mut || true,
    )
    .unwrap();
    assert!(body.contains("\"discussion_version\":1"));
    assert!(body.contains("\"merge_permission\":null"));
    assert!(body.contains(&format!("\"body\":{}", quote(&page.comments[0].body))));
    assert!(body.contains("\"body_rendered\":{"));
    assert!(body.contains("&lt;script&gt;"));
    assert!(body.contains("\"profile\":\"html_safe\""));
    assert!(body.contains(&format!(
        "\"snapshot_token\":{}",
        quote(&token(page.source_head))
    )));
}

#[test]
fn a_page_never_reports_truncated_corrupt_or_cancelled_results_as_complete() {
    let bytes = b"GET /repo.git/api/v1/pulls/1/comments HTTP/1.1\r\nHost: local\r\n\r\n";
    let envelope = head::parse(bytes, HttpLimits::default()).unwrap().unwrap();
    let request = Request::parse(&envelope).unwrap().unwrap();
    let page = fixture();
    let body = page_with_binding(
        "\"schema_version\":1",
        &request,
        Some(&page),
        MAX_REPLY_BYTES,
        &mut || true,
    )
    .unwrap();
    assert_eq!(
        page_with_binding(
            "\"schema_version\":1",
            &request,
            Some(&page),
            body.len(),
            &mut || true
        )
        .unwrap(),
        body
    );
    assert_eq!(
        page_with_binding(
            "\"schema_version\":1",
            &request,
            Some(&page),
            body.len() - 1,
            &mut || true
        )
        .unwrap_err()
        .status,
        Status::TooLarge
    );
    assert_eq!(
        page_with_binding(
            "\"schema_version\":1",
            &request,
            Some(&page),
            MAX_REPLY_BYTES,
            &mut || false
        )
        .unwrap_err()
        .status,
        Status::Timeout
    );
    let mut corrupt = page.clone();
    corrupt.number = PullRequestNumber::try_new(2).unwrap();
    assert!(
        page_with_binding(
            "\"schema_version\":1",
            &request,
            Some(&corrupt),
            MAX_REPLY_BYTES,
            &mut || true
        )
        .is_err()
    );
    let mut corrupt = page;
    corrupt.discussion_version = Some(AggregateVersion::try_new(2).unwrap());
    assert!(
        page_with_binding(
            "\"schema_version\":1",
            &request,
            Some(&corrupt),
            MAX_REPLY_BYTES,
            &mut || true
        )
        .is_err()
    );
}

#[test]
fn absent_pr_and_existing_empty_discussion_are_distinct_without_hidden_metadata() {
    let bytes = b"GET /repo.git/api/v1/pulls/1/comments HTTP/1.1\r\nHost: local\r\n\r\n";
    let envelope = head::parse(bytes, HttpLimits::default()).unwrap().unwrap();
    let request = Request::parse(&envelope).unwrap().unwrap();
    let missing = page_with_binding(
        "\"schema_version\":1",
        &request,
        None,
        MAX_REPLY_BYTES,
        &mut || true,
    )
    .unwrap();
    assert!(missing.contains("\"found\":false"));
    assert!(missing.contains("\"source_head\":null"));
    assert!(missing.contains("\"discussion_version\":null"));
    let mut empty = fixture();
    empty.discussion_version = None;
    empty.comments.clear();
    let present = page_with_binding(
        "\"schema_version\":1",
        &request,
        Some(&empty),
        MAX_REPLY_BYTES,
        &mut || true,
    )
    .unwrap();
    assert!(present.contains("\"found\":true"));
    assert!(present.contains("\"discussion_version\":0"));
    assert!(present.contains("\"comments\":[]"));
}
