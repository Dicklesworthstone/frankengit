use super::*;
use fgit_authority::{HeadKey, IdempotencyKey};
use fgit_forge::ExpectedVersion;
use fgit_types::{GitHashAlgorithm, RepositoryId, TenantId};

fn context() -> AdmissionContext {
    AdmissionContext {
        head_key: HeadKey::new(b"conversation-test/head".to_vec()).unwrap(),
        tenant_id: TenantId::from_bytes([1; 16]),
        repository_id: RepositoryId::from_bytes([2; 16]),
        principal_id: PrincipalId::from_bytes([3; 16]),
        idempotency_key: IdempotencyKey::new(b"conversation-first".to_vec()).unwrap(),
        object_format: GitHashAlgorithm::Sha1,
    }
}

#[test]
fn comment_seal_binds_every_command_field_without_a_pr_metadata_version() {
    let context = context();
    let command = PullRequestCommentCommand {
        number: PullRequestNumber::FIRST,
        expected_version: ExpectedVersion::NewStream,
        body: "An exact discussion comment".into(),
        anchor: None,
    };
    let expected = proposal(&context, &command).unwrap();
    assert!(expected.1.request.atomic());
    assert!(expected.1.request.ref_commands().is_empty());
    assert_eq!(proposal(&context, &command).unwrap(), expected);
    let original = expected.1.derive().unwrap().0;
    for field in 0..6 {
        let mut context = context.clone();
        let mut command = command.clone();
        match field {
            0 => command.body.push('!'),
            1 => command.number = PullRequestNumber::try_new(2).unwrap(),
            2 => command.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST),
            3 => context.principal_id = PrincipalId::from_bytes([4; 16]),
            4 => context.idempotency_key = IdempotencyKey::new(b"another-key".to_vec()).unwrap(),
            _ => context.object_format = GitHashAlgorithm::Sha256,
        }
        assert_ne!(
            proposal(&context, &command).unwrap().1.derive().unwrap().0,
            original
        );
    }
}

fn page() -> PullRequestCommentsPage {
    let head = fgit_codec::harness::genesis_head();
    PullRequestCommentsPage {
        number: PullRequestNumber::FIRST,
        source_head: fgit_authority::authority_head_identity(&head).unwrap(),
        discussion_version: AggregateVersion::try_new(5),
        comments: (2..=3)
            .map(|version| PullRequestCommentView {
                version: AggregateVersion::try_new(version).unwrap(),
                actor: context().principal_id,
                body: format!("Comment {version}"),
                anchor: None,
                anchor_status: None,
            })
            .collect(),
        next_after: Some(3),
    }
}

#[test]
fn source_anchor_seals_every_coordinate_and_page_pairs_cannot_be_fabricated() {
    use fgit_forge::event::pull_request_comment::{SourceCommentComparison, SourceCommentSide};
    use fgit_types::{GitOid, RefName};
    let id = |n: &str| GitOid::from_hex(GitHashAlgorithm::Sha1, &n.repeat(20)).unwrap();
    let anchor = SourceCommentAnchor {
        pull_request_version: AggregateVersion::FIRST,
        source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
        target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
        source_tip: id("11"),
        target_tip: id("22"),
        compared_base: id("22"),
        comparison: SourceCommentComparison::Direct,
        path: b"src/main.rs".to_vec(),
        side: SourceCommentSide::After,
        blob: id("33"),
        mode: 0o100644,
        byte_start: 0,
        byte_end: 4,
        line_start: 0,
        line_count: 1,
    };
    let plain = PullRequestCommentCommand {
        number: PullRequestNumber::FIRST,
        expected_version: ExpectedVersion::NewStream,
        body: "Review this source".into(),
        anchor: None,
    };
    let mut command = plain.clone();
    command.anchor = Some(anchor.clone());
    let original = proposal(&context(), &command).unwrap();
    assert_ne!(
        original.1.derive().unwrap().0,
        proposal(&context(), &plain).unwrap().1.derive().unwrap().0
    );
    for field in 0..14 {
        let mut changed = command.clone();
        let a = changed.anchor.as_mut().unwrap();
        match field {
            0 => a.pull_request_version = AggregateVersion::try_new(2).unwrap(),
            1 => a.source_ref = RefName::try_new(b"refs/heads/other-topic").unwrap(),
            2 => a.target_ref = RefName::try_new(b"refs/heads/other-main").unwrap(),
            3 => a.source_tip = id("44"),
            4 => {
                a.target_tip = id("44");
                a.compared_base = a.target_tip;
            }
            5 => a.comparison = SourceCommentComparison::MergeBase,
            6 => {
                a.comparison = SourceCommentComparison::MergeBase;
                a.compared_base = id("44");
            }
            7 => a.path = b"src/lib.rs".to_vec(),
            8 => a.side = SourceCommentSide::Before,
            9 => a.blob = id("44"),
            10 => a.mode = 0o100755,
            11 => a.byte_end = 5,
            12 => {
                a.byte_start = 1;
                a.line_start = 1;
            }
            _ => a.line_count = 2,
        }
        assert_ne!(
            original.1.derive().unwrap().0,
            proposal(&context(), &changed)
                .unwrap()
                .1
                .derive()
                .unwrap()
                .0,
            "field {field}"
        );
    }
    let mut page = page();
    page.comments[0].anchor = Some(anchor);
    assert_eq!(
        page.validate_window(1, 2),
        Err(RefusalCode::EvidenceInvalid)
    );
    page.comments[0].anchor_status = Some(SourceCommentStatus::Exact);
    page.validate_window(1, 2).unwrap();
    page.comments[0].anchor = None;
    assert_eq!(
        page.validate_window(1, 2),
        Err(RefusalCode::EvidenceInvalid)
    );
    page.comments[0].anchor_status = None;
    page.validate_window(1, 2).unwrap();
    let mut wrong_format = context();
    wrong_format.object_format = GitHashAlgorithm::Sha256;
    assert!(proposal(&wrong_format, &command).is_err());
}

#[test]
fn page_window_requires_contiguous_exact_versions_and_truthful_continuation() {
    let valid = page();
    assert_eq!(valid.validate_window(1, 2), Ok(()));
    for change in 0..7 {
        let mut altered = valid.clone();
        match change {
            0 => {
                altered.comments.remove(0);
            }
            1 => altered.comments.reverse(),
            2 => altered.comments[1].version = AggregateVersion::try_new(4).unwrap(),
            3 => altered.discussion_version = None,
            4 => altered.next_after = Some(2),
            5 => altered.next_after = None,
            _ => altered.comments[0].body.clear(),
        }
        assert_eq!(
            altered.validate_window(1, 2),
            Err(RefusalCode::EvidenceInvalid)
        );
    }
    for limit in [0, 101, u16::MAX] {
        assert_eq!(
            valid.validate_window(1, limit),
            Err(RefusalCode::ResourceBudgetExceeded)
        );
    }
    let mut complete = valid;
    complete.discussion_version = AggregateVersion::try_new(3);
    complete.next_after = None;
    assert_eq!(complete.validate_window(1, 2), Ok(()));
    complete.comments.clear();
    assert_eq!(complete.validate_window(u64::MAX, 2), Ok(()));
    complete.discussion_version = None;
    assert_eq!(complete.validate_window(0, 2), Ok(()));
}

fn comment(version: u64, anchor: Option<SourceCommentAnchor>) -> ForgeEvent {
    PullRequestCommentCommand {
        number: PullRequestNumber::FIRST,
        expected_version: if version == 1 {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(AggregateVersion::try_new(version - 1).unwrap())
        },
        body: format!("Comment {version}"),
        anchor,
    }
    .proposed_event(context().principal_id)
    .unwrap()
}

#[test]
fn retired_conversation_delivery_preserves_exact_page_windows() {
    use super::super::replay_tests::{Fixture, event};
    let mut fixture = Fixture::new(vec![ForgeEventBatch {
        events: vec![
            event(1, 1, GitHashAlgorithm::Sha1, 0),
            comment(1, None),
            comment(2, None),
            comment(3, None),
        ],
    }]);
    let original = fixture
        .comments_page(0, 2, &|_, _| true, &|| false)
        .unwrap()
        .unwrap();
    fixture.select_outbox(Vec::new());
    let recovered = fixture
        .comments_page(0, 2, &|_, _| true, &|| false)
        .unwrap()
        .unwrap();
    assert_ne!(recovered.source_head, original.source_head);
    assert_eq!(recovered.comments, original.comments);
    assert_eq!(recovered.discussion_version, original.discussion_version);
    assert_eq!(recovered.next_after, Some(2));
    recovered.validate_window(0, 2).unwrap();
    let tail = fixture
        .comments_page(2, 2, &|_, _| true, &|| false)
        .unwrap()
        .unwrap();
    assert_eq!(tail.comments.len(), 1);
    assert_eq!(tail.comments[0].body, "Comment 3");
    assert_eq!(tail.comments[0].version.get(), 3);
    assert_eq!(tail.next_after, None);
    tail.validate_window(2, 2).unwrap();
}

#[test]
fn retired_conversation_still_refuses_gaps_and_hides_older_private_anchors() {
    use super::super::replay_tests::{Fixture, event};
    use fgit_forge::event::pull_request_comment::{SourceCommentComparison, SourceCommentSide};
    use fgit_types::{GitOid, RefName};

    let mut gap = Fixture::new(vec![
        ForgeEventBatch::of_one(event(1, 1, GitHashAlgorithm::Sha1, 0)),
        ForgeEventBatch::of_one(comment(1, None)),
        ForgeEventBatch::of_one(comment(2, None)),
    ]);
    gap.select_outbox(Vec::new());
    // The first comment still exists, but this genesis's selected latest
    // frontier and empty outbox do not authenticate its missing prefix.
    assert!(matches!(
        gap.comments_page(1, 1, &|_, _| true, &|| false),
        Err(AdmissionError::AsyncProjectionUnavailable(
            RefusalCode::EvidenceMissing
        ))
    ));

    let id = |n: &str| GitOid::from_hex(GitHashAlgorithm::Sha1, &n.repeat(20)).unwrap();
    let anchor = SourceCommentAnchor {
        pull_request_version: AggregateVersion::FIRST,
        source_ref: RefName::try_new(b"refs/heads/private-source").unwrap(),
        target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
        source_tip: id("11"),
        target_tip: id("22"),
        compared_base: id("22"),
        comparison: SourceCommentComparison::Direct,
        path: b"src/main.rs".to_vec(),
        side: SourceCommentSide::After,
        blob: id("33"),
        mode: 0o100644,
        byte_start: 0,
        byte_end: 4,
        line_start: 0,
        line_count: 1,
    };
    let mut fixture = Fixture::new(vec![ForgeEventBatch {
        events: vec![
            event(1, 1, GitHashAlgorithm::Sha1, 0),
            comment(1, Some(anchor)),
            comment(2, None),
        ],
    }]);
    fixture.select_outbox(Vec::new());
    let permitted = fixture
        .comments_page(1, 1, &|_, _| true, &|| false)
        .unwrap()
        .unwrap();
    assert_eq!(permitted.comments.len(), 1);
    assert_eq!(permitted.comments[0].body, "Comment 2");
    // Neither the current PR refs nor this page reveal the older private
    // anchor. Its recovered event still makes the whole conversation hidden.
    assert!(
        fixture
            .comments_page(
                1,
                1,
                &|source, _| source.as_bytes() != b"refs/heads/private-source",
                &|| false,
            )
            .unwrap()
            .is_none()
    );
}
