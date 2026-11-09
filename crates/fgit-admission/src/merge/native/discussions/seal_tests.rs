use super::*;
use fgit_authority::{HeadKey, IdempotencyKey};
use fgit_forge::event::discussion::{DiscussionAction, DiscussionEdit};
use fgit_types::{GitHashAlgorithm, PrincipalId, RepositoryId, TenantId};

fn context() -> AdmissionContext {
    AdmissionContext {
        head_key: HeadKey::new(b"discussion-seal/head".to_vec()).unwrap(),
        tenant_id: TenantId::from_bytes([1; 16]),
        repository_id: RepositoryId::from_bytes([2; 16]),
        principal_id: PrincipalId::from_bytes([3; 16]),
        idempotency_key: IdempotencyKey::new(b"exact-discussion-key".to_vec()).unwrap(),
        object_format: GitHashAlgorithm::Sha1,
    }
}
fn command(action: DiscussionAction) -> DiscussionCommand {
    DiscussionCommand {
        number: DiscussionNumber::FIRST,
        expected_version: if matches!(action, DiscussionAction::Open { .. }) {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(AggregateVersion::FIRST)
        },
        action,
    }
}

#[test]
fn exact_discussion_seals_bind_every_action_actor_and_predecessor() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut context = context();
        context.object_format = format;
        for action in [
            DiscussionAction::Open {
                title: "Release".into(),
                body: "exact\r\nbody".into(),
            },
            DiscussionAction::Edit(DiscussionEdit {
                title: Some("Revised".into()),
                body: Some(String::new()),
            }),
            DiscussionAction::Close,
            DiscussionAction::Reopen,
            DiscussionAction::Comment {
                body: "Exact comment é\r\n".into(),
            },
            DiscussionAction::Lock,
            DiscussionAction::Unlock,
        ] {
            let (event, attempt) = proposal(&context, &command(action)).unwrap();
            assert_eq!(verify_event_seal(&context, &event, &attempt), Ok(()));
            let mut changed = event.clone();
            changed.version = changed.version.next().unwrap();
            assert_eq!(
                verify_event_seal(&context, &changed, &attempt),
                Err(RefusalCode::EvidenceInvalid)
            );
            changed = event.clone();
            changed.aggregate = AggregateId::Discussion(DiscussionNumber::try_new(2).unwrap());
            assert_eq!(
                verify_event_seal(&context, &changed, &attempt),
                Err(RefusalCode::EvidenceInvalid)
            );
            changed = event.clone();
            let ForgeEventPayload::DiscussionChangedNative(change) = &mut changed.payload else {
                unreachable!()
            };
            change.actor = PrincipalId::from_bytes([4; 16]);
            assert_eq!(
                verify_event_seal(&context, &changed, &attempt),
                Err(RefusalCode::EvidenceInvalid)
            );
            for index in 0..5 {
                let mut scope = context.clone();
                match index {
                    0 => scope.tenant_id = TenantId::from_bytes([9; 16]),
                    1 => scope.repository_id = RepositoryId::from_bytes([9; 16]),
                    2 => scope.principal_id = PrincipalId::from_bytes([9; 16]),
                    3 => {
                        scope.idempotency_key =
                            IdempotencyKey::new(b"changed-key".to_vec()).unwrap()
                    }
                    _ => {
                        scope.object_format = if format == GitHashAlgorithm::Sha1 {
                            GitHashAlgorithm::Sha256
                        } else {
                            GitHashAlgorithm::Sha1
                        }
                    }
                }
                assert_eq!(
                    verify_event_seal(&scope, &event, &attempt),
                    Err(RefusalCode::EvidenceInvalid)
                );
            }
        }
    }
}

#[test]
fn preserved_cleared_and_replaced_bodies_have_distinct_seals_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut context = context();
        context.object_format = format;
        let proposals: Vec<_> = [None, Some(String::new()), Some("é\r\n".into())]
            .into_iter()
            .map(|body| {
                proposal(
                    &context,
                    &command(DiscussionAction::Edit(DiscussionEdit {
                        title: Some("preserved title".into()),
                        body,
                    })),
                )
                .unwrap()
            })
            .collect();
        for (index, (event, _)) in proposals.iter().enumerate() {
            for (other, (_, attempt)) in proposals.iter().enumerate() {
                assert_eq!(
                    verify_event_seal(&context, event, attempt).is_ok(),
                    index == other
                );
            }
        }
    }
}

#[test]
fn empty_extra_or_replaced_request_scopes_cannot_authorize_a_discussion_event() {
    let context = context();
    let (event, original) = proposal(&context, &command(DiscussionAction::Close)).unwrap();
    let root = storage::root(&ForgeEventBatch::of_one(event.clone())).unwrap();
    let entry = |name| {
        ScopedEntry::new(
            AsciiSlug::from_static("forge"),
            AsciiSlug::from_static(name),
            root.bytes().as_bytes(),
        )
        .unwrap()
    };
    for scoped in [
        vec![],
        vec![entry("issue.event-batch-root.v1")],
        vec![entry("milestone.event-batch-root.v1")],
        vec![entry("issue.append-comment.v1")],
        vec![entry("discussion.event-batch-root.v1"), entry("unrelated")],
    ] {
        let attempt = SealAttempt {
            request: SemanticRequest::build(
                fgit_authority::RECEIVE_ADMISSION_SCHEMA,
                context.object_format,
                true,
                Vec::new(),
                Vec::new(),
                scoped,
            )
            .unwrap(),
            ..original.clone()
        };
        assert_eq!(
            verify_event_seal(&context, &event, &attempt),
            Err(RefusalCode::EvidenceInvalid)
        );
    }
}
