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
            })
            .collect(),
        next_after: Some(3),
    }
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
