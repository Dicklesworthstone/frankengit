//! Policy rollout machinery, simulation, shadow evaluation, and canary governors.
//!
//! Provides side-effect-free simulation and shadow execution modes, canary
//! traffic routing, candidate/active policy diffs, and promotion/revert
//! transitions that prevent retroactive reinterpretation of past decisions.

use std::collections::{BTreeMap, BTreeSet};

use fgit_types::PrincipalId;

use crate::basis::{PolicyInputRoot, PolicyInstant};
use crate::content::{PolicySnapshot, PolicySnapshotId};
use crate::error::PolicyEvalRefusal;
use crate::eval::{PolicyEvaluation, evaluate};
use crate::program::{CompiledPolicy, Decision, RuleId};

/// Operational rollout execution modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RolloutMode {
    /// Decisions are binding: a denial blocks publication.
    Enforce,
    /// Policy runs and records traces/warnings, but denials do not block.
    Warn,
    /// Runs candidate policy in parallel with active policy, logging divergences.
    Shadow,
    /// Pure dry-run evaluation with no side effects or audit state mutation.
    Simulation,
}

impl RolloutMode {
    /// Stable lowercase token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::Warn => "warn",
            Self::Shadow => "shadow",
            Self::Simulation => "simulation",
        }
    }

    /// Whether this mode permits effect publication.
    #[must_use]
    pub const fn permits_publication(self) -> bool {
        matches!(self, Self::Enforce | Self::Warn)
    }

    /// Whether denials under this mode block the request.
    #[must_use]
    pub const fn is_blocking(self) -> bool {
        matches!(self, Self::Enforce)
    }
}

/// Target cohort selection for canary rollouts.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RolloutCohort {
    /// Applies to all repositories and principals.
    All,
    /// Applies to a deterministic hash percentage of repositories (0..100).
    Percentage(u8),
    /// Applies to an explicit list of repository identifiers.
    ExplicitRepositories(BTreeSet<String>),
    /// Applies to an explicit list of tenant identifiers.
    ExplicitTenants(BTreeSet<String>),
}

impl RolloutCohort {
    /// Determines whether a given repository identifier is inside this cohort.
    #[must_use]
    pub fn matches_repository(&self, repo_id: &str) -> bool {
        match self {
            Self::All => true,
            Self::Percentage(pct) => {
                if *pct == 0 {
                    return false;
                }
                if *pct >= 100 {
                    return true;
                }
                // Deterministic integer hash bucket:
                let mut hash = 5381_u64;
                for byte in repo_id.as_bytes() {
                    hash = hash.wrapping_mul(33).wrapping_add(u64::from(*byte));
                }
                (hash % 100) < u64::from(*pct)
            }
            Self::ExplicitRepositories(repos) => repos.contains(repo_id),
            Self::ExplicitTenants(_) => false,
        }
    }
}

/// A sealed configuration governing policy rollout.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RolloutConfiguration {
    /// Active policy snapshot ID in production.
    pub active_snapshot_id: PolicySnapshotId,
    /// Optional candidate policy snapshot ID being tested in shadow/canary.
    pub candidate_snapshot_id: Option<PolicySnapshotId>,
    /// Rollout execution mode.
    pub mode: RolloutMode,
    /// Target cohort for candidate evaluation.
    pub cohort: RolloutCohort,
    /// Monotonically increasing configuration revision.
    pub config_version: u64,
    /// Principal who authorized this configuration transition.
    pub authorized_by: Option<PrincipalId>,
}

/// Structural differences between two compiled policies.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PolicyDiff {
    /// Rules present in candidate but absent from active.
    pub rules_added: BTreeSet<RuleId>,
    /// Rules present in active but absent from candidate.
    pub rules_removed: BTreeSet<RuleId>,
    /// Rules present in both but with different predicates or outcomes.
    pub rules_modified: BTreeSet<RuleId>,
    /// Whether the default decision differs between policies.
    pub default_decision_changed: bool,
}

impl PolicyDiff {
    /// Computes the difference between two compiled policies.
    #[must_use]
    pub fn compute(active: &CompiledPolicy, candidate: &CompiledPolicy) -> Self {
        let active_rules: BTreeMap<_, _> = active.rules().iter().map(|r| (r.id(), r)).collect();
        let cand_rules: BTreeMap<_, _> = candidate.rules().iter().map(|r| (r.id(), r)).collect();

        let mut rules_added = BTreeSet::new();
        let mut rules_removed = BTreeSet::new();
        let mut rules_modified = BTreeSet::new();

        for (id, cand_rule) in &cand_rules {
            match active_rules.get(id) {
                None => {
                    rules_added.insert(*id);
                }
                Some(active_rule) => {
                    if cand_rule.predicate() != active_rule.predicate()
                        || cand_rule.outcome() != active_rule.outcome()
                    {
                        rules_modified.insert(*id);
                    }
                }
            }
        }

        for id in active_rules.keys() {
            if !cand_rules.contains_key(id) {
                rules_removed.insert(*id);
            }
        }

        let default_decision_changed =
            active.default_outcome().decision() != candidate.default_outcome().decision();

        Self {
            rules_added,
            rules_removed,
            rules_modified,
            default_decision_changed,
        }
    }

    /// Whether the two policies are structurally identical.
    #[must_use]
    pub fn is_identical(&self) -> bool {
        self.rules_added.is_empty()
            && self.rules_removed.is_empty()
            && self.rules_modified.is_empty()
            && !self.default_decision_changed
    }
}

/// Divergence record between active and candidate decisions for one ref.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DecisionDivergence {
    /// The ref whose decision differed.
    pub ref_name: Vec<u8>,
    /// Active policy verdict.
    pub active_decision: Decision,
    /// Candidate policy verdict.
    pub candidate_decision: Decision,
}

/// The result of executing a rollout evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RolloutEvaluation {
    /// The primary (active) evaluation result.
    pub primary: PolicyEvaluation,
    /// The candidate evaluation result (if run in shadow/canary mode).
    pub candidate: Option<PolicyEvaluation>,
    /// Any decision divergence observed between active and candidate.
    pub divergences: Vec<DecisionDivergence>,
    /// Effective decision that governs this request under the rollout mode.
    pub effective_decision: Decision,
    /// The rollout mode executed.
    pub mode: RolloutMode,
}

/// Evaluates an input root under the specified rollout configuration and snapshots.
pub fn evaluate_rollout(
    config: &RolloutConfiguration,
    active_snapshot: &PolicySnapshot,
    candidate_snapshot: Option<&PolicySnapshot>,
    input: &PolicyInputRoot,
    repo_id: &str,
) -> Result<RolloutEvaluation, PolicyEvalRefusal> {
    let primary_eval = evaluate(active_snapshot, input)?;

    let in_cohort = config.cohort.matches_repository(repo_id);

    let (candidate_eval, divergences) =
        if let (true, Some(cand_snap)) = (in_cohort, candidate_snapshot) {
            let cand_eval = evaluate(cand_snap, input)?;

            let mut diffs = Vec::new();
            for active_outcome in primary_eval.subjects() {
                let cand_outcome = cand_eval
                    .subjects()
                    .iter()
                    .find(|c| c.name() == active_outcome.name());
                if let Some(cand_outcome) = cand_outcome
                    && active_outcome.decision() != cand_outcome.decision()
                {
                    diffs.push(DecisionDivergence {
                        ref_name: active_outcome.name().to_vec(),
                        active_decision: active_outcome.decision(),
                        candidate_decision: cand_outcome.decision(),
                    });
                }
            }

            (Some(cand_eval), diffs)
        } else {
            (None, Vec::new())
        };

    let effective_decision = match config.mode {
        RolloutMode::Enforce => primary_eval.decision(),
        RolloutMode::Warn | RolloutMode::Shadow | RolloutMode::Simulation => {
            // Under non-enforcing modes, requests are permitted at the rollout layer
            Decision::Allow
        }
    };

    Ok(RolloutEvaluation {
        primary: primary_eval,
        candidate: candidate_eval,
        divergences,
        effective_decision,
        mode: config.mode,
    })
}

/// Event recorded when a canary policy is promoted or rolled back.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CanaryLifecycleEvent {
    /// A candidate policy was promoted to active production status.
    Promoted {
        new_active: PolicySnapshotId,
        previous_active: PolicySnapshotId,
        instant: PolicyInstant,
        actor: PrincipalId,
    },
    /// A rollout was rolled back to a previous known-good snapshot.
    RolledBack {
        reverted_to: PolicySnapshotId,
        rolled_back_from: PolicySnapshotId,
        instant: PolicyInstant,
        actor: PrincipalId,
        reason: String,
    },
}
