use super::*;
use crate::merge::native::issues::proposal;
use fgit_authority::{HeadKey, IdempotencyKey};
use fgit_codec::ForgePositionStateEntry;
use fgit_forge::event::issue::{IssueCommand, IssueEdit, MAX_BODY_BYTES};
use fgit_forge::{ExpectedVersion, IssueNumber};
use fgit_types::{GitHashAlgorithm, PrincipalId, RepositoryId, TenantId};

fn context() -> AdmissionContext {
    AdmissionContext {
        head_key: HeadKey::new(b"append-comment/head".to_vec()).unwrap(),
        tenant_id: TenantId::from_bytes([1; 16]),
        repository_id: RepositoryId::from_bytes([2; 16]),
        principal_id: PrincipalId::from_bytes([3; 16]),
        idempotency_key: IdempotencyKey::new(b"append-comment-once".to_vec()).unwrap(),
        object_format: GitHashAlgorithm::Sha1,
    }
}
fn intent() -> IssueCommentIntent {
    IssueCommentIntent {
        number: IssueNumber::FIRST,
        body: "An exact additive comment é\r\n".into(),
    }
}
// A synthetic canonical map for the pure planner, not a durable authority store.
fn positions(context: &AdmissionContext, version: u64) -> CanonicalForgePositionState {
    let entries = if version == 0 {
        Vec::new()
    } else {
        vec![
            ForgePositionStateEntry::try_new(
                AsciiSlug::from_static("issue/1"),
                version - 1,
                1,
                fgit_codec::harness::digest_of(9),
            )
            .unwrap(),
        ]
    };
    CanonicalForgePositionState::try_new(context.repository_id, entries).unwrap()
}

#[test]
fn append_seal_binds_all_semantics_and_remains_distinct_from_exact_comments() {
    let context = context();
    let intent = intent();
    let proposed = append_proposal(&context, &intent).unwrap();
    assert_eq!(append_proposal(&context, &intent).unwrap(), proposed);
    assert!(proposed.1.request.atomic());
    assert!(proposed.1.request.ref_commands().is_empty());
    assert!(proposed.1.request.push_options().is_empty());
    let strict = proposal(
        &context,
        &IssueCommand {
            number: intent.number,
            expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
            action: IssueAction::Comment {
                body: intent.body.clone(),
            },
        },
    )
    .unwrap();
    assert_eq!(strict.0, proposed.0);
    assert_ne!(strict.1.derive().unwrap().0, proposed.1.derive().unwrap().0);
    let original = proposed.1.derive().unwrap().0;
    for field in 0..7 {
        let mut changed_context = context.clone();
        let mut changed_intent = intent.clone();
        match field {
            0 => changed_intent.body.push('!'),
            1 => changed_intent.number = IssueNumber::try_new(2).unwrap(),
            2 => changed_context.principal_id = PrincipalId::from_bytes([4; 16]),
            3 => {
                changed_context.idempotency_key =
                    IdempotencyKey::new(b"another-key".to_vec()).unwrap();
            }
            4 => changed_context.object_format = GitHashAlgorithm::Sha256,
            5 => changed_context.repository_id = RepositoryId::from_bytes([5; 16]),
            _ => changed_context.tenant_id = TenantId::from_bytes([6; 16]),
        }
        assert_ne!(
            append_proposal(&changed_context, &changed_intent)
                .unwrap()
                .1
                .derive()
                .unwrap()
                .0,
            original,
            "field {field}"
        );
    }
    let mut relocated = context;
    relocated.head_key = HeadKey::new(b"another-physical-placement".to_vec()).unwrap();
    assert_eq!(append_proposal(&relocated, &intent).unwrap(), proposed);
    let mut maximum = intent;
    maximum.body = "x".repeat(MAX_BODY_BYTES);
    assert!(append_proposal(&relocated, &maximum).is_ok());
}

#[test]
fn fresh_frontiers_change_only_the_effect_position_and_never_the_original_seal() {
    let context = context();
    let intent = intent();
    let (submitted, seal) = append_proposal(&context, &intent).unwrap();
    for previous in [1, 2, 27, u64::MAX - 1] {
        let planned =
            plan_append_event(&context, &submitted, &positions(&context, previous)).unwrap();
        assert_eq!(planned.version.get(), previous + 1);
        assert_eq!(planned.aggregate, submitted.aggregate);
        assert_eq!(planned.payload, submitted.payload);
        assert_eq!(append_proposal(&context, &intent).unwrap().1, seal);
    }
    assert_eq!(submitted.version.get(), 2);
}

#[test]
fn missing_issues_exhaustion_scope_and_non_comment_templates_fail_closed() {
    let context = context();
    let (submitted, _) = append_proposal(&context, &intent()).unwrap();
    assert_eq!(
        plan_append_event(&context, &submitted, &positions(&context, 0)),
        Err(ProjectionFailure::Refuse(RefusalCode::EvidenceStale))
    );
    assert_eq!(
        plan_append_event(&context, &submitted, &positions(&context, u64::MAX)),
        Err(ProjectionFailure::Refuse(
            RefusalCode::ResourceBudgetExceeded
        ))
    );
    let other = CanonicalForgePositionState::try_new(RepositoryId::from_bytes([9; 16]), Vec::new())
        .unwrap();
    assert_eq!(
        plan_append_event(&context, &submitted, &other),
        Err(ProjectionFailure::Unavailable(
            RefusalCode::AuthorityReceiptStale
        ))
    );
    for field in 0..4 {
        let mut changed = submitted.clone();
        match field {
            0 => changed.version = AggregateVersion::try_new(3).unwrap(),
            1 => {
                let ForgeEventPayload::IssueChangedNative(change) = &mut changed.payload else {
                    unreachable!()
                };
                change.actor = PrincipalId::from_bytes([9; 16]);
            }
            2 => {
                let ForgeEventPayload::IssueChangedNative(change) = &mut changed.payload else {
                    unreachable!()
                };
                change.action = IssueAction::Edit(IssueEdit {
                    title: Some("An edit is still strict".into()),
                    ..Default::default()
                });
            }
            _ => changed.aggregate = AggregateId::ReviewProtection,
        }
        assert_eq!(
            plan_append_event(&context, &changed, &positions(&context, 2)),
            Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid)),
            "field {field}"
        );
    }
}
