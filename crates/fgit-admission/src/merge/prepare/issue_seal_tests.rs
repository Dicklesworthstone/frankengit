use super::*;
use crate::merge::native::issues::{append_proposal, proposal};
use fgit_authority::{HeadKey, IdempotencyKey, SemanticRequest};
use fgit_forge::event::issue::{IssueAction, IssueCommand, IssueCommentIntent, IssueEdit};
use fgit_forge::{AggregateId, AggregateVersion, ExpectedVersion, IssueNumber};
use fgit_types::{GitHashAlgorithm, PrincipalId, RepositoryId, TenantId};

fn context() -> AdmissionContext {
    AdmissionContext {
        head_key: HeadKey::new(b"issue-seal/head".to_vec()).unwrap(),
        tenant_id: TenantId::from_bytes([1; 16]),
        repository_id: RepositoryId::from_bytes([2; 16]),
        principal_id: PrincipalId::from_bytes([3; 16]),
        idempotency_key: IdempotencyKey::new(b"original-key".to_vec()).unwrap(),
        object_format: GitHashAlgorithm::Sha1,
    }
}
fn comment() -> IssueCommentIntent {
    IssueCommentIntent {
        number: IssueNumber::FIRST,
        body: "Original comment".into(),
    }
}

#[test]
fn all_legacy_issue_actions_bind_the_exact_event_and_predecessor() {
    let context = context();
    for action in [
        IssueAction::Open {
            title: "Original issue".into(),
            body: "Original body".into(),
            labels: vec!["one".into()],
        },
        IssueAction::Edit(IssueEdit {
            title: Some("Changed title".into()),
            body: Some("Changed body".into()),
            labels: Some(vec!["two".into()]),
        }),
        IssueAction::Close,
        IssueAction::Reopen,
        IssueAction::Comment {
            body: "Strict comment".into(),
        },
        IssueAction::Assign {
            assignees: vec![context.principal_id],
        },
        IssueAction::Unassign {
            assignees: vec![context.principal_id],
        },
    ] {
        let command = IssueCommand {
            number: IssueNumber::FIRST,
            expected_version: if matches!(action, IssueAction::Open { .. }) {
                ExpectedVersion::NewStream
            } else {
                ExpectedVersion::Exactly(AggregateVersion::FIRST)
            },
            action,
        };
        let (event, seal) = proposal(&context, &command).unwrap();
        assert_eq!(verify_issue_seal(&context, &event, &seal), Ok(()));
        let changed = ForgeEvent {
            version: event.version.next().unwrap(),
            ..event
        };
        assert_eq!(
            verify_issue_seal(&context, &changed, &seal),
            Err(RefusalCode::EvidenceInvalid)
        );
    }
}

#[test]
fn only_explicit_append_seals_allow_a_different_non_open_event_position() {
    let context = context();
    let (template, seal) = append_proposal(&context, &comment()).unwrap();
    for version in [2, 3, 28, u64::MAX] {
        let event = ForgeEvent {
            version: AggregateVersion::try_new(version).unwrap(),
            ..template.clone()
        };
        assert_eq!(verify_issue_seal(&context, &event, &seal), Ok(()));
    }
    let invalid = ForgeEvent {
        version: AggregateVersion::FIRST,
        ..template
    };
    assert_eq!(
        verify_issue_seal(&context, &invalid, &seal),
        Err(RefusalCode::EvidenceInvalid)
    );
}

#[test]
fn append_seals_cannot_substitute_actor_issue_body_action_scope_or_request_profile() {
    let context = context();
    let (template, seal) = append_proposal(&context, &comment()).unwrap();
    for field in 0..5 {
        let mut event = template.clone();
        let mut changed_context = context.clone();
        let ForgeEventPayload::IssueChangedNative(change) = &mut event.payload else {
            unreachable!()
        };
        match field {
            0 => change.actor = PrincipalId::from_bytes([4; 16]),
            1 => event.aggregate = AggregateId::Issue(IssueNumber::try_new(2).unwrap()),
            2 => {
                change.action = IssueAction::Comment {
                    body: "Substituted body".into(),
                }
            }
            3 => change.action = IssueAction::Close,
            _ => changed_context.repository_id = RepositoryId::from_bytes([5; 16]),
        }
        assert_eq!(
            verify_issue_seal(&changed_context, &event, &seal),
            Err(RefusalCode::EvidenceInvalid),
            "field {field}"
        );
    }
    let unrelated = SemanticRequest::build(
        fgit_authority::RECEIVE_ADMISSION_SCHEMA,
        context.object_format,
        true,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    let changed = SealAttempt {
        request: unrelated,
        ..seal
    };
    assert_eq!(
        verify_issue_seal(&context, &template, &changed),
        Err(RefusalCode::EvidenceInvalid)
    );
}
