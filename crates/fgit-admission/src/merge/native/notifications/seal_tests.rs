use super::*;
use fgit_authority::{HeadKey, IdempotencyKey};
use fgit_forge::event::notification::NotificationMode;
use fgit_forge::{AggregateId, DiscussionNumber, IssueNumber, PullRequestNumber};
use fgit_types::{GitHashAlgorithm, PrincipalId, RepositoryId, TenantId};

fn context() -> AdmissionContext {
    AdmissionContext {
        head_key: HeadKey::new(b"notification-seal/head".to_vec()).unwrap(),
        tenant_id: TenantId::from_bytes([1; 16]),
        repository_id: RepositoryId::from_bytes([2; 16]),
        principal_id: PrincipalId::from_bytes([3; 16]),
        idempotency_key: IdempotencyKey::new(b"original-key".to_vec()).unwrap(),
        object_format: GitHashAlgorithm::Sha1,
    }
}
fn command(action: NotificationAction, version: u64) -> NotificationCommand {
    NotificationCommand {
        target: NotificationTarget::Issue(IssueNumber::FIRST),
        expected_version: if version == 0 {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(AggregateVersion::try_new(version).unwrap())
        },
        action,
    }
}

#[test]
fn sealed_self_preferences_bind_every_action_identity_and_exact_predecessor() {
    let context = context();
    for action in [
        NotificationAction::SetMode(NotificationMode::Participating),
        NotificationAction::SetMode(NotificationMode::Subscribed),
        NotificationAction::SetMode(NotificationMode::Muted),
        NotificationAction::SetReadThrough(None),
        NotificationAction::SetReadThrough(Some(AggregateVersion::FIRST)),
    ] {
        for before in [0, 7] {
            let (event, attempt) = proposal(&context, &command(action, before)).unwrap();
            assert_eq!(verify_event_seal(&context, &event, &attempt), Ok(()));
            let mut version = event.clone();
            version.version = version.version.next().unwrap();
            assert_eq!(
                verify_event_seal(&context, &version, &attempt),
                Err(RefusalCode::EvidenceInvalid)
            );
            let mut number = event.clone();
            number.aggregate = AggregateId::NotificationPreference {
                principal: context.principal_id,
                issue: IssueNumber::try_new(2).unwrap(),
            };
            assert_eq!(
                verify_event_seal(&context, &number, &attempt),
                Err(RefusalCode::EvidenceInvalid)
            );
            let mut actor = event.clone();
            let ForgeEventPayload::NotificationPreferenceChangedNative(change) = &mut actor.payload
            else {
                unreachable!()
            };
            change.actor = PrincipalId::from_bytes([4; 16]);
            assert_eq!(
                verify_event_seal(&context, &actor, &attempt),
                Err(RefusalCode::EvidenceInvalid)
            );
            actor.aggregate = AggregateId::NotificationPreference {
                principal: PrincipalId::from_bytes([4; 16]),
                issue: IssueNumber::FIRST,
            };
            assert_eq!(
                verify_event_seal(&context, &actor, &attempt),
                Err(RefusalCode::EvidenceInvalid)
            );
            for changed in 0..5 {
                let mut scope = context.clone();
                match changed {
                    0 => scope.tenant_id = TenantId::from_bytes([9; 16]),
                    1 => scope.repository_id = RepositoryId::from_bytes([9; 16]),
                    2 => scope.principal_id = PrincipalId::from_bytes([9; 16]),
                    3 => {
                        scope.idempotency_key =
                            IdempotencyKey::new(b"another-key".to_vec()).unwrap()
                    }
                    _ => scope.object_format = GitHashAlgorithm::Sha256,
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
fn read_clear_prefixes_and_delivery_modes_never_alias_one_seal() {
    let context = context();
    let mut identities = BTreeSet::new();
    let proposals: Vec<_> = [
        NotificationAction::SetMode(NotificationMode::Participating),
        NotificationAction::SetMode(NotificationMode::Subscribed),
        NotificationAction::SetMode(NotificationMode::Muted),
        NotificationAction::SetReadThrough(None),
        NotificationAction::SetReadThrough(Some(AggregateVersion::FIRST)),
        NotificationAction::SetReadThrough(Some(AggregateVersion::try_new(2).unwrap())),
    ]
    .into_iter()
    .map(|action| proposal(&context, &command(action, 0)).unwrap())
    .collect();
    for (index, (event, _)) in proposals.iter().enumerate() {
        assert!(identities.insert(fgit_codec::encode_body(event).unwrap()));
        for (other, (_, attempt)) in proposals.iter().enumerate() {
            assert_eq!(
                verify_event_seal(&context, event, attempt).is_ok(),
                index == other
            );
        }
    }
    let (event, original) = &proposals[0];
    let root = storage::root(&ForgeEventBatch::of_one(event.clone())).unwrap();
    for scopes in [
        vec![],
        vec![
            ScopedEntry::new(
                AsciiSlug::from_static("forge"),
                AsciiSlug::from_static("issue.event-batch-root.v1"),
                root.bytes().as_bytes(),
            )
            .unwrap(),
        ],
    ] {
        let mut changed = original.clone();
        changed.request = SemanticRequest::build(
            fgit_authority::RECEIVE_ADMISSION_SCHEMA,
            context.object_format,
            true,
            Vec::new(),
            Vec::new(),
            scopes,
        )
        .unwrap();
        assert_eq!(
            verify_event_seal(&context, event, &changed),
            Err(RefusalCode::EvidenceInvalid)
        );
    }
}

#[test]
fn discussion_seals_bind_kind_number_owner_predecessor_and_action() {
    let context = context();
    for action in [
        NotificationAction::SetMode(NotificationMode::Participating),
        NotificationAction::SetMode(NotificationMode::Subscribed),
        NotificationAction::SetMode(NotificationMode::Muted),
        NotificationAction::SetReadThrough(None),
        NotificationAction::SetReadThrough(Some(AggregateVersion::FIRST)),
    ] {
        for before in [0, 7] {
            let mut discussion = command(action, before);
            discussion.target = NotificationTarget::Discussion(DiscussionNumber::FIRST);
            let (event, attempt) = proposal(&context, &discussion).unwrap();
            assert_eq!(verify_event_seal(&context, &event, &attempt), Ok(()));
            let (issue, issue_attempt) = proposal(&context, &command(action, before)).unwrap();
            assert_ne!(attempt, issue_attempt);
            assert_eq!(
                verify_event_seal(&context, &issue, &attempt),
                Err(RefusalCode::EvidenceInvalid)
            );
            assert_eq!(
                verify_event_seal(&context, &event, &issue_attempt),
                Err(RefusalCode::EvidenceInvalid)
            );
            for changed in 0..4 {
                let mut different = discussion.clone();
                let mut scope = context.clone();
                match changed {
                    0 => {
                        different.target =
                            NotificationTarget::Discussion(DiscussionNumber::try_new(2).unwrap())
                    }
                    1 => scope.principal_id = PrincipalId::from_bytes([4; 16]),
                    2 => different.expected_version = ExpectedVersion::Exactly(event.version),
                    _ => {
                        different.action = if action == NotificationAction::SetReadThrough(None) {
                            NotificationAction::SetMode(NotificationMode::Subscribed)
                        } else {
                            NotificationAction::SetReadThrough(None)
                        }
                    }
                }
                let (forged, _) = proposal(&scope, &different).unwrap();
                assert_eq!(
                    verify_event_seal(&context, &forged, &attempt),
                    Err(RefusalCode::EvidenceInvalid)
                );
            }
        }
    }
}

#[test]
fn pull_request_activity_seal_never_aliases_an_issue_discussion_or_other_recipient() {
    let context = context();
    let mut pull = command(
        NotificationAction::SetReadThrough(Some(AggregateVersion::try_new(8).unwrap())),
        3,
    );
    pull.target = NotificationTarget::PullRequest(PullRequestNumber::FIRST);
    let (event, attempt) = proposal(&context, &pull).unwrap();
    assert_eq!(verify_event_seal(&context, &event, &attempt), Ok(()));
    for changed in 0..6 {
        let mut command = pull.clone();
        let mut owner = context.clone();
        match changed {
            0 => command.target = NotificationTarget::Issue(IssueNumber::FIRST),
            1 => command.target = NotificationTarget::Discussion(DiscussionNumber::FIRST),
            2 => {
                command.target =
                    NotificationTarget::PullRequest(PullRequestNumber::try_new(2).unwrap())
            }
            3 => owner.principal_id = PrincipalId::from_bytes([7; 16]),
            4 => {
                command.expected_version =
                    ExpectedVersion::Exactly(AggregateVersion::try_new(4).unwrap())
            }
            _ => {
                command.action =
                    NotificationAction::SetReadThrough(Some(AggregateVersion::try_new(9).unwrap()))
            }
        }
        let (other, seal) = proposal(&owner, &command).unwrap();
        assert_ne!(seal.derive().unwrap().0, attempt.derive().unwrap().0);
        assert_eq!(
            verify_event_seal(&context, &other, &attempt),
            Err(RefusalCode::EvidenceInvalid)
        );
    }
}
