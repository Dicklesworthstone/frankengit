use super::*;
use crate::merge::native::issues::{
    append_proposal, assignees_proposal, labels_proposal, proposal,
};
use fgit_authority::{HeadKey, IdempotencyKey, SemanticRequest};
use fgit_forge::event::issue::{
    IssueAction, IssueAssigneesIntent, IssueCommand, IssueCommentIntent, IssueEdit,
    IssueLabelsIntent,
};
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
        IssueAction::Lock,
        IssueAction::Unlock,
        IssueAction::SetMilestone {
            milestone: fgit_forge::MilestoneNumber::FIRST,
            expected_milestone_version: AggregateVersion::FIRST,
        },
        IssueAction::ClearMilestone,
        IssueAction::AddLabels {
            labels: vec!["triage".into()],
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
fn membership_seals_bind_the_selected_milestone_and_its_exact_version() {
    let context = context();
    let command = IssueCommand {
        number: IssueNumber::FIRST,
        expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
        action: IssueAction::SetMilestone {
            milestone: fgit_forge::MilestoneNumber::FIRST,
            expected_milestone_version: AggregateVersion::FIRST,
        },
    };
    let (event, seal) = proposal(&context, &command).unwrap();
    for (number, version) in [(2, 1), (1, 2)] {
        let mut changed = command.clone();
        changed.action = IssueAction::SetMilestone {
            milestone: fgit_forge::MilestoneNumber::try_new(number).unwrap(),
            expected_milestone_version: AggregateVersion::try_new(version).unwrap(),
        };
        assert_eq!(
            verify_issue_seal(
                &context,
                &changed.proposed_event(context.principal_id).unwrap(),
                &seal
            ),
            Err(RefusalCode::EvidenceInvalid)
        );
    }
    assert_eq!(verify_issue_seal(&context, &event, &seal), Ok(()));
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

#[test]
fn only_explicit_addition_seals_allow_assignment_at_a_fresh_non_open_position() {
    let context = context();
    let intent = IssueAssigneesIntent {
        number: IssueNumber::FIRST,
        assignees: vec![PrincipalId::from_bytes([7; 16])],
    };
    let (template, seal) = assignees_proposal(&context, &intent).unwrap();
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
fn addition_seals_reject_substituted_sets_removals_context_keys_and_other_profiles() {
    let context = context();
    let intent = IssueAssigneesIntent {
        number: IssueNumber::FIRST,
        assignees: vec![PrincipalId::from_bytes([7; 16])],
    };
    let (template, seal) = assignees_proposal(&context, &intent).unwrap();
    for field in 0..7 {
        let mut event = template.clone();
        let mut changed_context = context.clone();
        let ForgeEventPayload::IssueChangedNative(change) = &mut event.payload else {
            unreachable!()
        };
        match field {
            0 => change.actor = PrincipalId::from_bytes([4; 16]),
            1 => event.aggregate = AggregateId::Issue(IssueNumber::try_new(2).unwrap()),
            2 => {
                change.action = IssueAction::Assign {
                    assignees: vec![PrincipalId::from_bytes([8; 16])],
                };
            }
            3 => {
                change.action = IssueAction::Unassign {
                    assignees: intent.assignees.clone(),
                };
            }
            4 => changed_context.repository_id = RepositoryId::from_bytes([5; 16]),
            5 => changed_context.tenant_id = TenantId::from_bytes([6; 16]),
            _ => {
                changed_context.idempotency_key =
                    IdempotencyKey::new(b"substituted-key".to_vec()).unwrap();
            }
        }
        assert_eq!(
            verify_issue_seal(&changed_context, &event, &seal),
            Err(RefusalCode::EvidenceInvalid),
            "field {field}"
        );
    }
    let (_, comment_seal) = append_proposal(&context, &comment()).unwrap();
    assert_eq!(
        verify_issue_seal(&context, &template, &comment_seal),
        Err(RefusalCode::EvidenceInvalid)
    );
    let changed = SealAttempt {
        request: SemanticRequest::build(
            fgit_authority::RECEIVE_ADMISSION_SCHEMA,
            context.object_format,
            true,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .unwrap(),
        ..seal
    };
    assert_eq!(
        verify_issue_seal(&context, &template, &changed),
        Err(RefusalCode::EvidenceInvalid)
    );
}

#[test]
fn only_the_explicit_label_addition_seal_admits_a_fresh_position_with_identical_semantics() {
    let context = context();
    let intent = IssueLabelsIntent {
        number: IssueNumber::FIRST,
        labels: vec!["triage".into()],
    };
    let (template, seal) = labels_proposal(&context, &intent).unwrap();
    for version in [2, 3, 28, u64::MAX] {
        let event = ForgeEvent {
            version: AggregateVersion::try_new(version).unwrap(),
            ..template.clone()
        };
        assert_eq!(verify_issue_seal(&context, &event, &seal), Ok(()));
    }
    for field in 0..9 {
        let mut event = template.clone();
        let mut changed_context = context.clone();
        let ForgeEventPayload::IssueChangedNative(change) = &mut event.payload else {
            unreachable!()
        };
        match field {
            0 => event.version = AggregateVersion::FIRST,
            1 => change.actor = PrincipalId::from_bytes([4; 16]),
            2 => event.aggregate = AggregateId::Issue(IssueNumber::try_new(2).unwrap()),
            3 => {
                change.action = IssueAction::AddLabels {
                    labels: vec!["substituted".into()],
                }
            }
            4 => {
                change.action = IssueAction::Edit(IssueEdit {
                    labels: Some(intent.labels.clone()),
                    ..Default::default()
                })
            }
            5 => changed_context.repository_id = RepositoryId::from_bytes([5; 16]),
            6 => changed_context.tenant_id = TenantId::from_bytes([6; 16]),
            7 => changed_context.object_format = GitHashAlgorithm::Sha256,
            _ => {
                changed_context.idempotency_key =
                    IdempotencyKey::new(b"changed-key".to_vec()).unwrap()
            }
        }
        assert_eq!(
            verify_issue_seal(&changed_context, &event, &seal),
            Err(RefusalCode::EvidenceInvalid),
            "field {field}"
        );
    }
    for other in [
        append_proposal(&context, &comment()).unwrap().1,
        assignees_proposal(
            &context,
            &IssueAssigneesIntent {
                number: intent.number,
                assignees: vec![context.principal_id],
            },
        )
        .unwrap()
        .1,
    ] {
        assert_eq!(
            verify_issue_seal(&context, &template, &other),
            Err(RefusalCode::EvidenceInvalid)
        );
    }
}
