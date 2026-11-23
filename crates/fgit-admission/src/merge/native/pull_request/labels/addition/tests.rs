use super::*;
use fgit_authority::{HeadKey, IdempotencyKey};
use fgit_types::{GitHashAlgorithm, PrincipalId, RepositoryId, TenantId};

fn context(format: GitHashAlgorithm) -> AdmissionContext {
    AdmissionContext {
        head_key: HeadKey::new(b"pr-add-labels/head".to_vec()).unwrap(),
        tenant_id: TenantId::from_bytes([1; 16]),
        repository_id: RepositoryId::from_bytes([2; 16]),
        principal_id: PrincipalId::from_bytes([3; 16]),
        idempotency_key: IdempotencyKey::new(b"pr-add-labels-once".to_vec()).unwrap(),
        object_format: format,
    }
}

#[test]
fn exhausted_frontier_never_validates_the_planners_initial_version_placeholder() {
    let context = context(GitHashAlgorithm::Sha256);
    let (mut previous, _) = addition_proposal(
        &context,
        &PullRequestLabelsIntent {
            number: PullRequestNumber::FIRST,
            labels: vec!["triage".into()],
        },
    )
    .unwrap();
    assert_eq!(next_version(None), Ok(AggregateVersion::FIRST));
    previous.version = AggregateVersion::try_new(u64::MAX - 1).unwrap();
    assert_eq!(next_version(Some(&previous)).unwrap().get(), u64::MAX);
    previous.version = AggregateVersion::try_new(u64::MAX).unwrap();
    assert_eq!(
        next_version(Some(&previous)),
        Err(RefusalCode::ResourceBudgetExceeded)
    );
    assert_eq!(
        next_version(Some(&previous)).unwrap_or(AggregateVersion::FIRST),
        AggregateVersion::FIRST
    );
    // The validator repeats the checked successor after capability/disclosure;
    // the placeholder cannot turn exhaustion into a new-stream publication.
    assert_ne!(next_version(Some(&previous)), Ok(AggregateVersion::FIRST));
}

#[test]
fn additive_seal_binds_the_original_intent_and_cannot_be_a_replacement() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let context = context(format);
        let intent = PullRequestLabelsIntent {
            number: PullRequestNumber::FIRST,
            labels: vec!["triage".into()],
        };
        let (event, seal) = addition_proposal(&context, &intent).unwrap();
        verify_event_seal(&context, &event, &seal).unwrap();
        let strict = proposal(
            &context,
            &PullRequestLabelsCommand {
                number: intent.number,
                expected_version: ExpectedVersion::NewStream,
                labels: intent.labels.clone(),
            },
        )
        .unwrap();
        assert_ne!(seal, strict.1);
        assert!(verify_event_seal(&context, &event, &strict.1).is_err());
        assert!(super::super::verify_event_seal(&context, &strict.0, &seal).is_err());
        for field in 0..7 {
            let mut changed_context = context.clone();
            let mut changed = intent.clone();
            match field {
                0 => changed.labels.push("urgent".into()),
                1 => changed.number = PullRequestNumber::try_new(2).unwrap(),
                2 => changed_context.principal_id = PrincipalId::from_bytes([4; 16]),
                3 => {
                    changed_context.idempotency_key =
                        IdempotencyKey::new(b"other-key".to_vec()).unwrap()
                }
                4 => {
                    changed_context.object_format = match format {
                        GitHashAlgorithm::Sha1 => GitHashAlgorithm::Sha256,
                        GitHashAlgorithm::Sha256 => GitHashAlgorithm::Sha1,
                    }
                }
                5 => changed_context.repository_id = RepositoryId::from_bytes([5; 16]),
                _ => changed_context.tenant_id = TenantId::from_bytes([6; 16]),
            }
            let (_, changed_seal) = addition_proposal(&changed_context, &changed).unwrap();
            assert_ne!(changed_seal, seal, "field {field}");
            assert!(verify_event_seal(&context, &event, &changed_seal).is_err());
        }
        for mutation in 0..4 {
            let mut forged = event.clone();
            if mutation == 0 {
                forged.aggregate =
                    AggregateId::PullRequestLabels(PullRequestNumber::try_new(2).unwrap());
            } else {
                let ForgeEventPayload::PullRequestLabelsAddedNative(change) = &mut forged.payload
                else {
                    unreachable!()
                };
                match mutation {
                    1 => change.actor = PrincipalId::from_bytes([9; 16]),
                    2 => {
                        change.additions = vec!["changed".into()];
                        change.labels = change.additions.clone();
                    }
                    _ => change.labels.clear(),
                }
            }
            assert!(
                verify_event_seal(&context, &forged, &seal).is_err(),
                "mutation {mutation}"
            );
        }
        let mut relocated = context.clone();
        relocated.head_key = HeadKey::new(b"new-physical-placement".to_vec()).unwrap();
        assert_eq!(
            addition_proposal(&relocated, &intent).unwrap(),
            (event, seal)
        );
    }
}
