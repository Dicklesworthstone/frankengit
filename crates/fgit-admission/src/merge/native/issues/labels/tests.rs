use super::*;
use crate::merge::native::issues::proposal;
use fgit_authority::{HeadKey, IdempotencyKey};
use fgit_codec::ForgePositionStateEntry;
use fgit_forge::event::issue::{IssueCommand, IssueEdit};
use fgit_forge::{ExpectedVersion, IssueNumber};
use fgit_types::{GitHashAlgorithm, PrincipalId, RepositoryId, TenantId};

fn context() -> AdmissionContext {
    AdmissionContext {
        head_key: HeadKey::new(b"add-labels/head".to_vec()).unwrap(),
        tenant_id: TenantId::from_bytes([1; 16]),
        repository_id: RepositoryId::from_bytes([2; 16]),
        principal_id: PrincipalId::from_bytes([3; 16]),
        idempotency_key: IdempotencyKey::new(b"add-labels-once".to_vec()).unwrap(),
        object_format: GitHashAlgorithm::Sha1,
    }
}
fn intent() -> IssueLabelsIntent {
    IssueLabelsIntent {
        number: IssueNumber::FIRST,
        labels: vec!["bug".into(), "triage".into()],
    }
}
// Synthetic canonical map for the pure planner, not durable-store evidence.
fn positions(context: &AdmissionContext, version: u64) -> CanonicalForgePositionState {
    let entries = if version == 0 {
        vec![]
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
fn label_seal_binds_all_semantics_and_is_distinct_from_exact_addition_and_replacement() {
    let context = context();
    let intent = intent();
    let proposed = labels_proposal(&context, &intent).unwrap();
    let original = proposed.1.derive().unwrap().0;
    assert!(proposed.1.request.atomic());
    assert!(proposed.1.request.ref_commands().is_empty());
    assert!(proposed.1.request.push_options().is_empty());
    for action in [
        IssueAction::AddLabels {
            labels: intent.labels.clone(),
        },
        IssueAction::Edit(IssueEdit {
            labels: Some(intent.labels.clone()),
            ..Default::default()
        }),
    ] {
        let strict = proposal(
            &context,
            &IssueCommand {
                number: intent.number,
                expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
                action,
            },
        )
        .unwrap();
        assert_ne!(strict.1.derive().unwrap().0, original);
    }
    for field in 0..7 {
        let mut changed_context = context.clone();
        let mut changed_intent = intent.clone();
        match field {
            0 => changed_intent.labels.push("é".into()),
            1 => changed_intent.number = IssueNumber::try_new(2).unwrap(),
            2 => changed_context.principal_id = PrincipalId::from_bytes([4; 16]),
            3 => {
                changed_context.idempotency_key =
                    IdempotencyKey::new(b"other-key".to_vec()).unwrap()
            }
            4 => changed_context.object_format = GitHashAlgorithm::Sha256,
            5 => changed_context.repository_id = RepositoryId::from_bytes([5; 16]),
            _ => changed_context.tenant_id = TenantId::from_bytes([6; 16]),
        }
        assert_ne!(
            labels_proposal(&changed_context, &changed_intent)
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
    relocated.head_key = HeadKey::new(b"different-placement".to_vec()).unwrap();
    assert_eq!(labels_proposal(&relocated, &intent).unwrap(), proposed);
}

#[test]
fn only_the_publication_position_changes_at_fresh_authenticated_frontiers() {
    let context = context();
    let (submitted, seal) = labels_proposal(&context, &intent()).unwrap();
    for previous in [1, 2, 27, u64::MAX - 1] {
        let planned =
            plan_labels_event(&context, &submitted, &positions(&context, previous)).unwrap();
        assert_eq!(planned.version.get(), previous + 1);
        assert_eq!(planned.aggregate, submitted.aggregate);
        assert_eq!(planned.payload, submitted.payload);
        assert_eq!(labels_proposal(&context, &intent()).unwrap().1, seal);
    }
    assert_eq!(
        plan_labels_event(&context, &submitted, &positions(&context, 0)),
        Err(ProjectionFailure::Refuse(RefusalCode::EvidenceStale))
    );
    assert_eq!(
        plan_labels_event(&context, &submitted, &positions(&context, u64::MAX)),
        Err(ProjectionFailure::Refuse(
            RefusalCode::ResourceBudgetExceeded
        ))
    );
    let other =
        CanonicalForgePositionState::try_new(RepositoryId::from_bytes([9; 16]), vec![]).unwrap();
    assert_eq!(
        plan_labels_event(&context, &submitted, &other),
        Err(ProjectionFailure::Unavailable(
            RefusalCode::AuthorityReceiptStale
        ))
    );
}

#[test]
fn non_addition_templates_and_altered_actor_or_coordinate_refuse() {
    let context = context();
    let (submitted, _) = labels_proposal(&context, &intent()).unwrap();
    for field in 0..6 {
        let mut changed = submitted.clone();
        let ForgeEventPayload::IssueChangedNative(change) = &mut changed.payload else {
            unreachable!()
        };
        match field {
            0 => changed.version = AggregateVersion::try_new(3).unwrap(),
            1 => change.actor = PrincipalId::from_bytes([9; 16]),
            2 => {
                change.action = IssueAction::Edit(IssueEdit {
                    labels: Some(intent().labels),
                    ..Default::default()
                })
            }
            3 => changed.aggregate = AggregateId::ReviewProtection,
            4 => change.action = IssueAction::AddLabels { labels: vec![] },
            _ => {
                change.action = IssueAction::AddLabels {
                    labels: vec!["triage".into(), "bug".into()],
                }
            }
        }
        assert_eq!(
            plan_labels_event(&context, &changed, &positions(&context, 2)),
            Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid)),
            "field {field}"
        );
    }
}
