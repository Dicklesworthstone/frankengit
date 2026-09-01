//! Action-scoped eligibility normalization for deterministic work frontiers.
//!
//! [`crate::WorkEligibilityInputs::independent_from`] names the run whose
//! implementation must not verify itself. That constraint belongs only to
//! verification work. Treating it as a blanket task exclusion prevents the
//! implementation run from implementing or reworking its own task merely
//! because a later gate must be independent.
//!
//! [`crate::WorkFrontier::build_action_scoped`] is the control-plane builder
//! that preserves the independence field for verification phases and clears it
//! for every other phase before invoking the closed frontier policy. No other
//! eligibility, ranking, source row, or commitment input is changed.

use crate::{
    AgentSituationReceipt, FrontierRefusal, TaskPhase, WorkEligibilityInputs, WorkFrontier,
    WorkItem,
};

impl WorkFrontier {
    /// Builds a frontier with verifier independence scoped to verification work.
    ///
    /// `independent_from` is retained for
    /// [`TaskPhase::ImplementationReady`] and
    /// [`TaskPhase::VerificationPending`]. It is cleared for implementation,
    /// rework, and terminal phases, because those actions do not claim an
    /// independent verification result.
    ///
    /// # Errors
    ///
    /// Returns the same bounded, identity, projection, and framing refusals as
    /// [`WorkFrontier::build`].
    pub fn build_action_scoped(
        situation: &AgentSituationReceipt,
        items: Vec<WorkItem>,
    ) -> Result<Self, FrontierRefusal> {
        let normalized = items.into_iter().map(scope_independence).collect();
        Self::build(situation, normalized)
    }
}

fn scope_independence(item: WorkItem) -> WorkItem {
    let eligibility = item.eligibility();
    let independent_from = match item.phase() {
        TaskPhase::ImplementationReady | TaskPhase::VerificationPending => {
            eligibility.independent_from()
        }
        TaskPhase::Open
        | TaskPhase::InProgress
        | TaskPhase::Rework
        | TaskPhase::Verified
        | TaskPhase::Closed
        | TaskPhase::Superseded => None,
    };
    WorkItem::new(
        item.task_id(),
        item.projection_generation(),
        item.phase(),
        item.ranking(),
        WorkEligibilityInputs::new(
            eligibility.blocker_count(),
            eligibility.assignee(),
            independent_from,
            eligibility.capability_allowed(),
            eligibility.conflict(),
        ),
    )
}

#[cfg(test)]
mod tests {
    use crate::{
        RunId, TaskPhase, WorkConflict, WorkEligibilityInputs, WorkItem, WorkRankingInputs,
        WorkTaskId,
    };

    use super::scope_independence;

    const GENERATION: [u8; 32] = [0x44; 32];

    fn item(phase: TaskPhase, independent_from: Option<RunId>) -> WorkItem {
        WorkItem::new(
            WorkTaskId::from_bytes([0x31; 32]),
            GENERATION,
            phase,
            WorkRankingInputs::new(1, 2, 3),
            WorkEligibilityInputs::new(
                0,
                Some(RunId::new(7)),
                independent_from,
                true,
                WorkConflict::Clear,
            ),
        )
    }

    #[test]
    fn implementation_and_rework_do_not_inherit_a_future_verifier_constraint() {
        let implementation = scope_independence(item(TaskPhase::Open, Some(RunId::new(7))));
        let rework = scope_independence(item(TaskPhase::Rework, Some(RunId::new(7))));

        assert_eq!(implementation.eligibility().independent_from(), None);
        assert_eq!(rework.eligibility().independent_from(), None);
    }

    #[test]
    fn verification_preserves_the_independence_constraint() {
        for phase in [
            TaskPhase::ImplementationReady,
            TaskPhase::VerificationPending,
        ] {
            let verification = scope_independence(item(phase, Some(RunId::new(7))));
            assert_eq!(
                verification.eligibility().independent_from(),
                Some(RunId::new(7))
            );
        }
    }

    #[test]
    fn normalization_changes_no_other_projection_input() {
        let original = item(TaskPhase::Open, Some(RunId::new(7)));
        let normalized = scope_independence(original);

        assert_eq!(normalized.task_id(), original.task_id());
        assert_eq!(
            normalized.projection_generation(),
            original.projection_generation()
        );
        assert_eq!(normalized.phase(), original.phase());
        assert_eq!(normalized.ranking(), original.ranking());
        assert_eq!(
            normalized.eligibility().blocker_count(),
            original.eligibility().blocker_count()
        );
        assert_eq!(
            normalized.eligibility().assignee(),
            original.eligibility().assignee()
        );
        assert_eq!(
            normalized.eligibility().capability_allowed(),
            original.eligibility().capability_allowed()
        );
        assert_eq!(
            normalized.eligibility().conflict(),
            original.eligibility().conflict()
        );
    }
}
