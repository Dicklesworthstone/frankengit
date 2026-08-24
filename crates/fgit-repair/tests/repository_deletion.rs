//! FG-059: deletion wording is typed, ordered, and bound to an incarnation.

use fgit_repair::repository_deletion::{
    RepositoryDeletionRefusal, RepositoryDeletionState, RepositoryDeletionStatus,
};
use fgit_types::{RepositoryId, RepositoryIncarnationId};

const fn repository() -> RepositoryId {
    RepositoryId::from_bytes([0x59; 16])
}

const fn current_incarnation() -> RepositoryIncarnationId {
    RepositoryIncarnationId::from_bytes([0x51; 16])
}

const fn stale_incarnation() -> RepositoryIncarnationId {
    RepositoryIncarnationId::from_bytes([0x52; 16])
}

#[test]
fn every_user_visible_deletion_claim_is_distinct_and_in_plan_order() {
    let names = RepositoryDeletionState::ALL.map(RepositoryDeletionState::as_str);
    assert_eq!(
        names,
        [
            "hidden",
            "tombstoned_within_recovery_grace",
            "physical_deletion_authorized",
            "deleted_from_hot_placements",
            "expired_from_recovery_material",
            "cryptographically_erased",
        ]
    );
    for (index, state) in RepositoryDeletionState::ALL.into_iter().enumerate() {
        assert_eq!(
            state.successor(),
            RepositoryDeletionState::ALL.get(index + 1).copied(),
            "each state has exactly its next stronger claim, without an ambiguous deleted shortcut"
        );
    }
}

#[test]
fn six_state_lifecycle_requires_every_evidence_stage_before_a_stronger_claim() {
    let mut status = RepositoryDeletionStatus::hidden(repository(), current_incarnation());
    for next in RepositoryDeletionState::ALL.into_iter().skip(1) {
        status = status
            .advance(next)
            .expect("only immediate successor is accepted");
        assert_eq!(status.state(), next);
    }
    assert!(status.state().hot_placements_deleted());
    assert!(status.state().recovery_material_expired());
    assert!(status.state().key_material_erased());
    assert!(matches!(
        status.advance(RepositoryDeletionState::Hidden),
        Err(RepositoryDeletionRefusal::InvalidTransition {
            current: RepositoryDeletionState::CryptographicallyErased,
            requested: RepositoryDeletionState::Hidden,
        })
    ));
}

#[test]
fn corpus_refuses_every_skipped_or_repeated_deletion_state_claim() {
    for start_index in 0..RepositoryDeletionState::ALL.len() {
        let mut status = RepositoryDeletionStatus::hidden(repository(), current_incarnation());
        for state in RepositoryDeletionState::ALL
            .iter()
            .copied()
            .skip(1)
            .take(start_index)
        {
            status = status
                .advance(state)
                .expect("fixture advances one state at a time");
        }
        for requested in RepositoryDeletionState::ALL {
            let permitted = status.state().successor() == Some(requested);
            assert_eq!(
                status.advance(requested).is_ok(),
                permitted,
                "{} may advance only to its exact successor {}",
                status.state().as_str(),
                requested.as_str()
            );
        }
    }
}

#[test]
fn stale_deletion_token_refuses_while_the_current_incarnation_twin_proceeds() {
    let current = RepositoryDeletionStatus::hidden(repository(), current_incarnation());
    current
        .require_current_incarnation(current_incarnation())
        .expect("current incarnation record proceeds");

    let stale = RepositoryDeletionStatus::hidden(repository(), stale_incarnation());
    assert_eq!(
        stale.require_current_incarnation(current_incarnation()),
        Err(RepositoryDeletionRefusal::StaleIncarnation {
            record: stale_incarnation(),
            current: current_incarnation(),
        }),
        "a delete/recreate stale token cannot advance or describe the new incarnation"
    );
}
