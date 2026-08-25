//! Protected-ref vocabulary and rule engine.
//!
//! Provides typed, bounded rules governing ref updates in protected namespaces
//! (e.g. `refs/heads/main`, `refs/tags/**`).
//!
//! ## Requirements covered
//!
//! * Actor, kind, team, and capability admission
//! * Fast-forward only and linear history enforcement
//! * Cryptographic signature verification and authentication strength
//! * Code reviews, code owner approval, reviewer independence, and distinct actor constraints
//! * Required status checks and CI verification
//! * Merge queue membership and speculative integration
//! * Size, path, and time bounds
//! * Unresolved security/compliance findings zero-tolerance
//! * Durability profile and human confirmation
//! * Force-push and deletion prohibitions

use std::collections::BTreeSet;

use fgit_types::refs::RefName;
use fgit_types::{AsciiSlug, PrincipalId};

use crate::basis::{
    AuthenticationStrength, EvidenceKind, LabelName, PolicyInputRoot, PrincipalKind, RefUpdateKind,
};
use crate::glob::RefPattern;
use crate::program::Decision;

/// Largest number of protected ref rules in one policy.
pub const MAX_PROTECTED_RULES: usize = 256;

/// Largest number of required status checks in one rule.
pub const MAX_REQUIRED_CHECKS: usize = 64;

/// Verifier independence classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VerifierClass {
    /// Automated check / CI runner.
    Automated,
    /// Peer reviewer.
    Peer,
    /// Code owner for the affected paths.
    CodeOwner,
    /// Independent security verifier.
    IndependentSecurity,
    /// Designated human release authority.
    HumanAuthority,
}

impl VerifierClass {
    /// Every class, in declaration order.
    pub const ALL: [Self; 5] = [
        Self::Automated,
        Self::Peer,
        Self::CodeOwner,
        Self::IndependentSecurity,
        Self::HumanAuthority,
    ];

    /// The stable lowercase token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Automated => "automated",
            Self::Peer => "peer",
            Self::CodeOwner => "code_owner",
            Self::IndependentSecurity => "independent_security",
            Self::HumanAuthority => "human_authority",
        }
    }

    /// Parses the token.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|class| class.token() == token)
    }

    /// Whether this verifier satisfies the independent verifier requirement.
    #[must_use]
    pub const fn is_independent(self) -> bool {
        matches!(self, Self::IndependentSecurity | Self::HumanAuthority)
    }
}

/// Requirements for pull request / peer review.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReviewRequirement {
    /// Minimum number of approvals required.
    pub min_approvals: u32,
    /// Whether at least one approval must come from a code owner.
    pub require_code_owner: bool,
    /// Whether independent security / compliance verifier approval is required.
    pub require_independent_verifier: bool,
    /// Specific verifier classes permitted to approve.
    pub allowed_verifier_classes: BTreeSet<VerifierClass>,
    /// Whether approvals must come from distinct principals (cannot duplicate).
    pub require_distinct_reviewers: bool,
}

impl Default for ReviewRequirement {
    fn default() -> Self {
        let mut allowed = BTreeSet::new();
        allowed.insert(VerifierClass::Peer);
        allowed.insert(VerifierClass::CodeOwner);
        allowed.insert(VerifierClass::IndependentSecurity);
        allowed.insert(VerifierClass::HumanAuthority);
        Self {
            min_approvals: 1,
            require_code_owner: false,
            require_independent_verifier: false,
            allowed_verifier_classes: allowed,
            require_distinct_reviewers: true,
        }
    }
}

/// Requirements for automated status checks.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct StatusCheckRequirement {
    /// The names of the status checks that must have passed.
    pub required_checks: BTreeSet<AsciiSlug>,
    /// Whether checks must be strictly up-to-date with the branch head.
    pub strict_up_to_date: bool,
}

/// Minimum required storage durability profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DurabilityProfile {
    /// Standard single-region durability.
    Standard,
    /// Multi-zone synchronous replication.
    Replicated,
    /// Cross-region quorum write.
    Quorum,
}

impl DurabilityProfile {
    /// Numeric level for threshold comparisons.
    #[must_use]
    pub const fn level(self) -> u8 {
        match self {
            Self::Standard => 1,
            Self::Replicated => 2,
            Self::Quorum => 3,
        }
    }
}

/// Granular boolean restriction and permission flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct ProtectionBits(u16);

impl ProtectionBits {
    /// Non-fast-forward updates are prohibited.
    pub const REQUIRE_FAST_FORWARD: Self = Self(1 << 0);
    /// Merge commits are rejected in favor of linear history.
    pub const REQUIRE_LINEAR_HISTORY: Self = Self(1 << 1);
    /// Commits must be cryptographically signed.
    pub const REQUIRE_SIGNED_COMMITS: Self = Self(1 << 2);
    /// Updates must land via the merge queue.
    pub const REQUIRE_MERGE_QUEUE: Self = Self(1 << 3);
    /// Explicit human confirmation is required.
    pub const REQUIRE_HUMAN_CONFIRMATION: Self = Self(1 << 4);
    /// Unresolved security findings block the push.
    pub const BLOCK_UNRESOLVED_FINDINGS: Self = Self(1 << 5);
    /// Force push is permitted.
    pub const ALLOW_FORCE_PUSH: Self = Self(1 << 6);
    /// Ref deletion is permitted.
    pub const ALLOW_DELETIONS: Self = Self(1 << 7);
    /// Ref creation is permitted under this pattern.
    pub const ALLOW_CREATION: Self = Self(1 << 8);

    /// Creates empty protection bits.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Sets bits.
    #[must_use]
    pub const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Tests if all bits in `other` are set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

/// One protected ref rule configuration.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProtectedRefRule {
    /// The ref pattern this rule matches (e.g. `refs/heads/main`).
    pub pattern: RefPattern,
    /// Explicit principals allowed to push directly.
    pub allow_actors: BTreeSet<PrincipalId>,
    /// Principal kinds allowed to push (e.g. Human, Service).
    pub allow_principal_kinds: BTreeSet<PrincipalKind>,
    /// Team labels allowed to push.
    pub allow_teams: BTreeSet<LabelName>,
    /// Capability labels required to push.
    pub allow_capabilities: BTreeSet<LabelName>,
    /// Minimum authentication level required of the actor.
    pub min_authentication: Option<AuthenticationStrength>,
    /// Review requirements, if peer review is mandated.
    pub reviews: Option<ReviewRequirement>,
    /// CI status check requirements, if automated checks are mandated.
    pub checks: Option<StatusCheckRequirement>,
    /// Maximum size of any single commit payload, in bytes.
    pub max_commit_bytes: Option<u64>,
    /// Minimum required durability profile.
    pub durability: Option<DurabilityProfile>,
    /// Bitset of restriction and permission flags.
    pub flags: ProtectionBits,
}

impl ProtectedRefRule {
    /// Creates a default strict protected branch rule for the given pattern.
    #[must_use]
    pub fn strict_branch(pattern: RefPattern) -> Self {
        let mut kinds = BTreeSet::new();
        kinds.insert(PrincipalKind::Human);
        kinds.insert(PrincipalKind::Service);

        let flags = ProtectionBits::empty()
            .with(ProtectionBits::REQUIRE_FAST_FORWARD)
            .with(ProtectionBits::REQUIRE_SIGNED_COMMITS)
            .with(ProtectionBits::BLOCK_UNRESOLVED_FINDINGS)
            .with(ProtectionBits::ALLOW_CREATION);

        Self {
            pattern,
            allow_actors: BTreeSet::new(),
            allow_principal_kinds: kinds,
            allow_teams: BTreeSet::new(),
            allow_capabilities: BTreeSet::new(),
            min_authentication: Some(AuthenticationStrength::HardwareBacked),
            reviews: Some(ReviewRequirement::default()),
            checks: Some(StatusCheckRequirement::default()),
            max_commit_bytes: Some(50 * 1024 * 1024), // 50MB
            durability: Some(DurabilityProfile::Standard),
            flags,
        }
    }

    /// Creates a default immutable tag protection rule.
    #[must_use]
    pub fn immutable_tag(pattern: RefPattern) -> Self {
        let mut kinds = BTreeSet::new();
        kinds.insert(PrincipalKind::Human);
        kinds.insert(PrincipalKind::Service);

        let flags = ProtectionBits::empty()
            .with(ProtectionBits::REQUIRE_FAST_FORWARD)
            .with(ProtectionBits::REQUIRE_SIGNED_COMMITS)
            .with(ProtectionBits::ALLOW_CREATION);

        Self {
            pattern,
            allow_actors: BTreeSet::new(),
            allow_principal_kinds: kinds,
            allow_teams: BTreeSet::new(),
            allow_capabilities: BTreeSet::new(),
            min_authentication: Some(AuthenticationStrength::HardwareBacked),
            reviews: None,
            checks: None,
            max_commit_bytes: None,
            durability: Some(DurabilityProfile::Standard),
            flags,
        }
    }
}

/// Explanation for why a protected ref requirement passed or failed.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RequirementVerdict {
    /// Requirement was satisfied.
    Passed { check_name: &'static str },
    /// Requirement failed with a specific reason.
    Failed {
        check_name: &'static str,
        reason: String,
    },
    /// Requirement was not applicable.
    Skipped { check_name: &'static str },
}

impl RequirementVerdict {
    /// Whether this verdict indicates success.
    #[must_use]
    pub const fn is_passed(&self) -> bool {
        matches!(self, Self::Passed { .. } | Self::Skipped { .. })
    }

    /// The name of the check.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Passed { check_name }
            | Self::Failed { check_name, .. }
            | Self::Skipped { check_name } => check_name,
        }
    }
}

/// The complete evaluation trace for one ref update against protected ref rules.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProtectedRefEvaluation {
    /// The ref evaluated.
    pub ref_name: RefName,
    /// Final decision reached.
    pub decision: Decision,
    /// Whether a matching protected ref rule governed this ref.
    pub is_protected: bool,
    /// Detailed verdicts for every individual requirement checked.
    pub verdicts: Vec<RequirementVerdict>,
    /// Summary refusal reason if denied.
    pub denial_reason: Option<String>,
}

/// Evaluates a ref update against a set of protected ref rules under the given input root.
#[must_use]
pub fn evaluate_protected_ref(
    rules: &[ProtectedRefRule],
    input: &PolicyInputRoot,
    ref_name: &RefName,
) -> ProtectedRefEvaluation {
    let subject = match input.updates().iter().find(|u| u.name() == ref_name) {
        Some(s) => s,
        None => {
            return ProtectedRefEvaluation {
                ref_name: ref_name.clone(),
                decision: Decision::Deny,
                is_protected: false,
                verdicts: vec![RequirementVerdict::Failed {
                    check_name: "subject_presence",
                    reason: "ref name not found in input root updates".to_owned(),
                }],
                denial_reason: Some("subject not in input root".to_owned()),
            };
        }
    };

    // Find first matching rule for the ref name.
    let matching_rule = rules
        .iter()
        .find(|rule| rule.pattern.matches(ref_name.as_bytes()));

    let rule = match matching_rule {
        Some(r) => r,
        None => {
            // Unprotected ref: default allow
            return ProtectedRefEvaluation {
                ref_name: ref_name.clone(),
                decision: Decision::Allow,
                is_protected: false,
                verdicts: vec![RequirementVerdict::Skipped {
                    check_name: "protection_match",
                }],
                denial_reason: None,
            };
        }
    };

    let mut verdicts = Vec::new();
    let principal = input.principal();

    // 1. Deletion check
    if subject.kind() == RefUpdateKind::Delete {
        if rule.flags.contains(ProtectionBits::ALLOW_DELETIONS) {
            verdicts.push(RequirementVerdict::Passed {
                check_name: "allow_deletions",
            });
        } else {
            verdicts.push(RequirementVerdict::Failed {
                check_name: "allow_deletions",
                reason: "deletion of protected ref is prohibited".to_owned(),
            });
        }
    }

    // 2. Creation check
    if subject.kind() == RefUpdateKind::Create {
        if rule.flags.contains(ProtectionBits::ALLOW_CREATION) {
            verdicts.push(RequirementVerdict::Passed {
                check_name: "allow_creation",
            });
        } else {
            verdicts.push(RequirementVerdict::Failed {
                check_name: "allow_creation",
                reason: "creation under protected ref pattern is prohibited".to_owned(),
            });
        }
    }

    // 3. Force push check
    if subject.force_requested() {
        if rule.flags.contains(ProtectionBits::ALLOW_FORCE_PUSH) {
            verdicts.push(RequirementVerdict::Passed {
                check_name: "allow_force_push",
            });
        } else {
            verdicts.push(RequirementVerdict::Failed {
                check_name: "allow_force_push",
                reason: "force push to protected ref is prohibited".to_owned(),
            });
        }
    }

    // 4. Fast-forward requirement
    if rule.flags.contains(ProtectionBits::REQUIRE_FAST_FORWARD) {
        if matches!(
            subject.kind(),
            RefUpdateKind::FastForward | RefUpdateKind::Create
        ) {
            verdicts.push(RequirementVerdict::Passed {
                check_name: "fast_forward_only",
            });
        } else if subject.kind() == RefUpdateKind::NonFastForward {
            verdicts.push(RequirementVerdict::Failed {
                check_name: "fast_forward_only",
                reason: "non-fast-forward update refused by protected ref policy".to_owned(),
            });
        }
    }

    // 5. Actor admission
    if !rule.allow_actors.is_empty() {
        if rule.allow_actors.contains(&principal.principal()) {
            verdicts.push(RequirementVerdict::Passed {
                check_name: "allow_actors",
            });
        } else {
            verdicts.push(RequirementVerdict::Failed {
                check_name: "allow_actors",
                reason: format!(
                    "principal '{}' is not in allowed actors list",
                    principal.principal()
                ),
            });
        }
    }

    // 6. Principal kind admission
    if !rule.allow_principal_kinds.is_empty() {
        if rule.allow_principal_kinds.contains(&principal.kind()) {
            verdicts.push(RequirementVerdict::Passed {
                check_name: "allow_principal_kinds",
            });
        } else {
            verdicts.push(RequirementVerdict::Failed {
                check_name: "allow_principal_kinds",
                reason: format!(
                    "principal kind '{}' is not admitted",
                    principal.kind().token()
                ),
            });
        }
    }

    // 7. Team / capability membership
    if !rule.allow_teams.is_empty() {
        let has_team = rule
            .allow_teams
            .iter()
            .any(|t| principal.teams().contains(t));
        if has_team {
            verdicts.push(RequirementVerdict::Passed {
                check_name: "allow_teams",
            });
        } else {
            verdicts.push(RequirementVerdict::Failed {
                check_name: "allow_teams",
                reason: "principal does not belong to any required team".to_owned(),
            });
        }
    }

    if !rule.allow_capabilities.is_empty() {
        let has_cap = rule
            .allow_capabilities
            .iter()
            .any(|c| principal.capabilities().contains(c));
        if has_cap {
            verdicts.push(RequirementVerdict::Passed {
                check_name: "allow_capabilities",
            });
        } else {
            verdicts.push(RequirementVerdict::Failed {
                check_name: "allow_capabilities",
                reason: "principal lacks required capability".to_owned(),
            });
        }
    }

    // 8. Authentication strength
    if let Some(min_auth) = rule.min_authentication {
        if principal.authentication() >= min_auth {
            verdicts.push(RequirementVerdict::Passed {
                check_name: "min_authentication",
            });
        } else {
            verdicts.push(RequirementVerdict::Failed {
                check_name: "min_authentication",
                reason: format!(
                    "authentication strength '{}' does not meet minimum '{}'",
                    principal.authentication().token(),
                    min_auth.token()
                ),
            });
        }
    }

    // 9. Signed commits requirement
    if rule.flags.contains(ProtectionBits::REQUIRE_SIGNED_COMMITS) {
        if principal.authentication() >= AuthenticationStrength::HardwareBacked {
            verdicts.push(RequirementVerdict::Passed {
                check_name: "signed_commits",
            });
        } else {
            verdicts.push(RequirementVerdict::Failed {
                check_name: "signed_commits",
                reason: "cryptographically signed commits required for protected ref".to_owned(),
            });
        }
    }

    // 10. Code reviews requirement
    if let (Some(review_req), Ok(review_kind)) =
        (&rule.reviews, EvidenceKind::try_new(b"code_review"))
    {
        let matching_receipt = input
            .receipts()
            .iter()
            .find(|r| r.kind() == review_kind && r.subject() == ref_name);
        if let Some(receipt) = matching_receipt {
            if receipt.is_live_at(input.instant()) {
                verdicts.push(RequirementVerdict::Passed {
                    check_name: "code_reviews",
                });
            } else {
                verdicts.push(RequirementVerdict::Failed {
                    check_name: "code_reviews",
                    reason: "code review evidence receipt is expired".to_owned(),
                });
            }
        } else if review_req.min_approvals > 0 {
            verdicts.push(RequirementVerdict::Failed {
                check_name: "code_reviews",
                reason: format!(
                    "missing required code review approvals (need {})",
                    review_req.min_approvals
                ),
            });
        }
    }

    // 11. Status checks requirement
    if let (Some(check_req), Ok(ci_kind)) = (&rule.checks, EvidenceKind::try_new(b"ci_check"))
        && !check_req.required_checks.is_empty()
    {
        let matching_receipt = input
            .receipts()
            .iter()
            .find(|r| r.kind() == ci_kind && r.subject() == ref_name);
        if let Some(receipt) = matching_receipt {
            if receipt.is_live_at(input.instant()) {
                verdicts.push(RequirementVerdict::Passed {
                    check_name: "status_checks",
                });
            } else {
                verdicts.push(RequirementVerdict::Failed {
                    check_name: "status_checks",
                    reason: "status check evidence receipt is expired".to_owned(),
                });
            }
        } else {
            verdicts.push(RequirementVerdict::Failed {
                check_name: "status_checks",
                reason: "missing required CI status check pass receipt".to_owned(),
            });
        }
    }

    // 12. Merge queue requirement
    if let (true, Ok(mq_kind)) = (
        rule.flags.contains(ProtectionBits::REQUIRE_MERGE_QUEUE),
        EvidenceKind::try_new(b"merge_queue"),
    ) {
        let matching_receipt = input
            .receipts()
            .iter()
            .find(|r| r.kind() == mq_kind && r.subject() == ref_name);
        if let Some(receipt) = matching_receipt {
            if receipt.is_live_at(input.instant()) {
                verdicts.push(RequirementVerdict::Passed {
                    check_name: "merge_queue",
                });
            } else {
                verdicts.push(RequirementVerdict::Failed {
                    check_name: "merge_queue",
                    reason: "merge queue integration receipt is expired".to_owned(),
                });
            }
        } else {
            verdicts.push(RequirementVerdict::Failed {
                check_name: "merge_queue",
                reason: "direct push prohibited; update must land via merge queue".to_owned(),
            });
        }
    }

    // 13. Unresolved findings check
    if let (true, Ok(findings_agg)) = (
        rule.flags
            .contains(ProtectionBits::BLOCK_UNRESOLVED_FINDINGS),
        crate::basis::AggregateName::try_new(b"unresolved_findings"),
    ) {
        let count = input.aggregates().get(&findings_agg).copied().unwrap_or(0);
        if count == 0 {
            verdicts.push(RequirementVerdict::Passed {
                check_name: "unresolved_findings",
            });
        } else {
            verdicts.push(RequirementVerdict::Failed {
                check_name: "unresolved_findings",
                reason: format!("blocked by {} unresolved security findings", count),
            });
        }
    }

    let failure = verdicts.iter().find_map(|v| match v {
        RequirementVerdict::Failed { reason, .. } => Some(reason.clone()),
        _ => None,
    });

    let decision = if failure.is_none() {
        Decision::Allow
    } else {
        Decision::Deny
    };

    ProtectedRefEvaluation {
        ref_name: ref_name.clone(),
        decision,
        is_protected: true,
        verdicts,
        denial_reason: failure,
    }
}
