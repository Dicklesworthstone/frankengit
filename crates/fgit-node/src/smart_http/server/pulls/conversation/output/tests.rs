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
            anchor: None,
            anchor_status: None,
        }],
        next_after: None,
    }
}

#[test]
fn anchored_pages_emit_original_identity_and_explicit_status_without_retargeting() {
    use fgit_forge::event::pull_request_comment::{
        SourceCommentComparison, SourceCommentSide, SourceCommentStatus,
    };
    use fgit_types::{GitHashAlgorithm, GitOid, RefName};
    let bytes = b"GET /repo.git/api/v1/pulls/1/comments HTTP/1.1\r\nHost: local\r\n\r\n";
    let envelope = head::parse(bytes, HttpLimits::default()).unwrap().unwrap();
    let request = Request::parse(&envelope).unwrap().unwrap();
    let mut page = fixture();
    let plain = page_with_binding(
        "\"schema_version\":1",
        &request,
        Some(&page),
        MAX_REPLY_BYTES,
        &mut || true,
    )
    .unwrap();
    assert!(!plain.contains("\"anchor\""));
    assert!(!plain.contains("anchor_status"));
    let oid =
        |byte| GitOid::from_hex(GitHashAlgorithm::Sha1, &format!("{byte:02x}").repeat(20)).unwrap();
    page.comments[0].anchor = Some(SourceCommentAnchor {
        pull_request_version: AggregateVersion::FIRST,
        source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
        target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
        source_tip: oid(0x11),
        target_tip: oid(0x22),
        compared_base: oid(0x22),
        comparison: SourceCommentComparison::Direct,
        path: b"src/\xff.rs".to_vec(),
        side: SourceCommentSide::After,
        blob: oid(0x33),
        mode: 0o100755,
        byte_start: 0,
        byte_end: 6,
        line_start: 0,
        line_count: 1,
    });
    page.comments[0].anchor_status = Some(SourceCommentStatus::Exact);
    let exact = page_with_binding(
        "\"schema_version\":1",
        &request,
        Some(&page),
        MAX_REPLY_BYTES,
        &mut || true,
    )
    .unwrap();
    assert!(exact.contains("\"anchor_status\":\"exact\""));
    assert!(exact.contains("\"line_start\":0"));
    assert!(exact.contains("\"path_hex\":\"7372632fff2e7273\""));
    assert!(exact.contains(SOURCE_COMMENT_PROFILE));
    page.comments[0].anchor_status = Some(SourceCommentStatus::Outdated);
    let outdated = page_with_binding(
        "\"schema_version\":1",
        &request,
        Some(&page),
        MAX_REPLY_BYTES,
        &mut || true,
    )
    .unwrap();
    assert_eq!(
        outdated,
        exact.replace(
            "\"anchor_status\":\"exact\"",
            "\"anchor_status\":\"outdated\""
        )
    );
    page.comments[0].anchor_status = None;
    assert!(
        page_with_binding(
            "\"schema_version\":1",
            &request,
            Some(&page),
            MAX_REPLY_BYTES,
            &mut || true
        )
        .is_err()
    );
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
