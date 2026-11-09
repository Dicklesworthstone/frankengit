use super::*;
use fgit_authority::{HeadKey, IdempotencyKey};
use fgit_forge::event::milestone::{MilestoneAction, MilestoneEdit};
use fgit_types::{GitHashAlgorithm, PrincipalId, RepositoryId, TenantId};

fn context() -> AdmissionContext {
    AdmissionContext {
        head_key: HeadKey::new(b"milestone-seal/head".to_vec()).unwrap(),
        tenant_id: TenantId::from_bytes([1; 16]),
        repository_id: RepositoryId::from_bytes([2; 16]),
        principal_id: PrincipalId::from_bytes([3; 16]),
        idempotency_key: IdempotencyKey::new(b"exact-milestone-key".to_vec()).unwrap(),
        object_format: GitHashAlgorithm::Sha1,
    }
}
fn command(action: MilestoneAction) -> MilestoneCommand {
    MilestoneCommand {
        number: MilestoneNumber::FIRST,
        expected_version: if matches!(action, MilestoneAction::Open { .. }) {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(AggregateVersion::FIRST)
        },
        action,
    }
}

#[test]
fn exact_milestone_seals_bind_every_action_actor_and_predecessor() {
    let context = context();
    for action in [
        MilestoneAction::Open {
            title: "Release".into(),
            body: "exact\r\nbody".into(),
            due_at: Some(0),
        },
        MilestoneAction::Edit(MilestoneEdit {
            title: Some("Revised".into()),
            body: Some(String::new()),
            due_at: Some(None),
        }),
        MilestoneAction::Close,
        MilestoneAction::Reopen,
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
        changed.aggregate = AggregateId::Milestone(MilestoneNumber::try_new(2).unwrap());
        assert_eq!(
            verify_event_seal(&context, &changed, &attempt),
            Err(RefusalCode::EvidenceInvalid)
        );
        changed = event.clone();
        let ForgeEventPayload::MilestoneChangedNative(change) = &mut changed.payload else {
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
                3 => scope.idempotency_key = IdempotencyKey::new(b"changed-key".to_vec()).unwrap(),
                _ => scope.object_format = GitHashAlgorithm::Sha256,
            }
            assert_eq!(
                verify_event_seal(&scope, &event, &attempt),
                Err(RefusalCode::EvidenceInvalid)
            );
        }
    }
}

#[test]
fn date_preservation_clear_and_epoch_are_different_sealed_edits() {
    let context = context();
    let mut identities = BTreeSet::new();
    let mut proposals = Vec::new();
    for due_at in [None, Some(None), Some(Some(0)), Some(Some(42))] {
        let (event, attempt) = proposal(
            &context,
            &command(MilestoneAction::Edit(MilestoneEdit {
                body: Some("unchanged other field".into()),
                due_at,
                ..Default::default()
            })),
        )
        .unwrap();
        assert!(identities.insert(fgit_codec::encode_body(&event).unwrap()));
        proposals.push((event, attempt));
    }
    for (index, (event, _)) in proposals.iter().enumerate() {
        for (other, (_, attempt)) in proposals.iter().enumerate() {
            assert_eq!(
                verify_event_seal(&context, event, attempt).is_ok(),
                index == other
            );
        }
    }
}

#[test]
fn empty_extra_or_replaced_request_scopes_cannot_authorize_a_milestone_event() {
    let context = context();
    let (event, original) = proposal(&context, &command(MilestoneAction::Close)).unwrap();
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
        vec![entry("milestone.event-batch-root.v1"), entry("unrelated")],
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
