//! Break-glass emergency override protocol and evaluation.
//!
//! Provides a cryptographically-verifiable, bounded, auditable mechanism to
//! override policy denials during declared operational emergencies.
//!
//! ## Invariants enforced
//!
//! * Narrow scope: override applies strictly to matching ref patterns.
//! * Strong authentication: must meet or exceed required authentication strength.
//! * Threshold approval: M-of-N distinct approvers required; self-approval prohibited.
//! * Bounded duration: hard maximum TTL (default: 4 hours / 14,400s).
//! * Displaced-state retention: exact pre-override OID is committed into the intent and receipt.
//! * Unremovable audit: generates a content-addressed audit token and post-review obligation.
//! * Cannot erase or bypass audit records.

use std::collections::BTreeSet;

use fgit_crypto::DigestHasher;
use fgit_types::native::GitOid;
use fgit_types::refs::RefName;
use fgit_types::{AsciiSlug, PrincipalId};

use crate::basis::{AuthenticationStrength, PolicyInputRoot, PolicyInstant};
use crate::glob::RefPattern;

/// Hard maximum duration for any break-glass emergency window, in seconds (4 hours).
pub const MAX_BREAK_GLASS_DURATION_SECS: u64 = 14_400;

/// Maximum length of a break-glass reason string, in bytes.
pub const MAX_BREAK_GLASS_REASON_LEN: usize = 256;

/// Typed refusals for the break-glass evaluation protocol.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BreakGlassRefusal {
    /// Reason string was empty.
    ReasonEmpty,
    /// Reason string exceeded the length bound.
    ReasonTooLong { len: usize, max: usize },
    /// Current instant is before the intent's active window.
    NotYetActive {
        current: PolicyInstant,
        issued_at: PolicyInstant,
    },
    /// Break-glass intent has expired.
    Expired {
        current: PolicyInstant,
        expires_at: PolicyInstant,
    },
    /// Requested duration exceeded the maximum allowable bound.
    DurationExceedsMax { duration_secs: u64, max_secs: u64 },
    /// Actor does not possess the required authentication strength.
    InsufficientAuthentication {
        actual: AuthenticationStrength,
        required: AuthenticationStrength,
    },
    /// Approvals count is below the required threshold.
    InsufficientApprovals { actual: usize, required: usize },
    /// Actor attempted to approve their own break-glass request.
    SelfApprovalForbidden { actor: PrincipalId },
    /// Requested ref is outside the narrow pattern of this break-glass intent.
    ScopeMismatch { ref_name: String, pattern: String },
    /// The current ref tip does not match the displaced state recorded in the intent.
    DisplacedStateMismatch { actual: GitOid, expected: GitOid },
    /// The audit token provided in the intent does not match the content-addressed derivation.
    AuditTokenMismatch { actual: GitOid, expected: GitOid },
}

impl core::fmt::Display for BreakGlassRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ReasonEmpty => write!(f, "break-glass reason must not be empty"),
            Self::ReasonTooLong { len, max } => {
                write!(f, "break-glass reason length {len} exceeds maximum {max}")
            }
            Self::NotYetActive { current, issued_at } => {
                write!(
                    f,
                    "break-glass not active yet (current: {current}, issued_at: {issued_at})"
                )
            }
            Self::Expired {
                current,
                expires_at,
            } => {
                write!(
                    f,
                    "break-glass expired at {expires_at} (current: {current})"
                )
            }
            Self::DurationExceedsMax {
                duration_secs,
                max_secs,
            } => {
                write!(
                    f,
                    "break-glass duration {duration_secs}s exceeds max {max_secs}s"
                )
            }
            Self::InsufficientAuthentication { actual, required } => {
                write!(
                    f,
                    "break-glass requires {} auth, observed {}",
                    required.token(),
                    actual.token()
                )
            }
            Self::InsufficientApprovals { actual, required } => {
                write!(f, "break-glass requires {required} approvals, got {actual}")
            }
            Self::SelfApprovalForbidden { actor } => {
                write!(
                    f,
                    "actor {actor} cannot approve their own break-glass request"
                )
            }
            Self::ScopeMismatch { ref_name, pattern } => {
                write!(
                    f,
                    "ref '{ref_name}' is outside break-glass pattern '{pattern}'"
                )
            }
            Self::DisplacedStateMismatch { actual, expected } => {
                write!(
                    f,
                    "displaced state mismatch: expected current {expected}, observed {actual}"
                )
            }
            Self::AuditTokenMismatch { actual, expected } => {
                write!(
                    f,
                    "break-glass audit token mismatch: expected {expected}, observed {actual}"
                )
            }
        }
    }
}

/// A sealed, structured intent to execute an emergency break-glass override.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BreakGlassIntent {
    /// Human-readable operational reason explaining the emergency.
    pub reason: String,
    /// The principal requesting the break-glass override.
    pub actor: PrincipalId,
    /// The narrow ref pattern this intent is restricted to.
    pub scope: RefPattern,
    /// The specific target ref to update.
    pub target_ref: RefName,
    /// The current OID being displaced (retained for audit and rollback).
    pub displaced_state: GitOid,
    /// The proposed new OID being installed under break-glass.
    pub proposed_oid: GitOid,
    /// Distinct principals who approved this break-glass override.
    pub approvers: BTreeSet<PrincipalId>,
    /// Instant when this intent became active.
    pub issued_at: PolicyInstant,
    /// Instant when this intent strictly expires.
    pub expires_at: PolicyInstant,
    /// Unique content-addressed audit token.
    pub audit_token: GitOid,
}

impl BreakGlassIntent {
    /// Computes the deterministic content-addressed audit token for this intent.
    #[must_use]
    pub fn compute_audit_token(&self) -> GitOid {
        let mut hasher = fgit_crypto::Sha256Hasher::new();
        hasher.update(b"frankengit/break-glass-intent/v1\n");
        hasher.update(self.reason.as_bytes());
        hasher.update(b"\n");
        hasher.update(self.actor.as_bytes());
        hasher.update(b"\n");
        hasher.update(self.scope.as_str().as_bytes());
        hasher.update(b"\n");
        hasher.update(self.target_ref.as_bytes());
        hasher.update(b"\n");
        hasher.update(self.displaced_state.as_bytes());
        hasher.update(b"\n");
        hasher.update(self.proposed_oid.as_bytes());
        hasher.update(b"\n");
        for approver in &self.approvers {
            hasher.update(approver.as_bytes());
            hasher.update(b"\n");
        }
        hasher.update(&self.issued_at.seconds().to_be_bytes());
        hasher.update(&self.expires_at.seconds().to_be_bytes());
        let digest = hasher.finish();
        match self.displaced_state {
            GitOid::Sha1(_) => {
                let mut sha1_hasher = fgit_crypto::Sha1Hasher::new();
                sha1_hasher.update(&digest);
                let sha1_digest = sha1_hasher.finish();
                GitOid::Sha1(fgit_types::native::GitOidSha1::from_bytes(sha1_digest))
            }
            GitOid::Sha256(_) => {
                GitOid::Sha256(fgit_types::native::GitOidSha256::from_bytes(digest))
            }
        }
    }

    /// Constructs a new break-glass intent with its content-addressed audit token.
    #[must_use]
    pub fn new(
        reason: String,
        actor: PrincipalId,
        scope: RefPattern,
        target_ref: RefName,
        displaced_state: GitOid,
        proposed_oid: GitOid,
        approvers: BTreeSet<PrincipalId>,
        issued_at: PolicyInstant,
        expires_at: PolicyInstant,
    ) -> Self {
        let dummy = match displaced_state {
            GitOid::Sha1(_) => GitOid::Sha1(fgit_types::native::GitOidSha1::from_bytes([0u8; 20])),
            GitOid::Sha256(_) => {
                GitOid::Sha256(fgit_types::native::GitOidSha256::from_bytes([0u8; 32]))
            }
        };
        let mut intent = Self {
            reason,
            actor,
            scope,
            target_ref,
            displaced_state,
            proposed_oid,
            approvers,
            issued_at,
            expires_at,
            audit_token: dummy,
        };
        intent.audit_token = intent.compute_audit_token();
        intent
    }

    /// Validates internal structural bounds on the intent.
    pub fn validate_bounds(&self) -> Result<(), BreakGlassRefusal> {
        if self.reason.trim().is_empty() {
            return Err(BreakGlassRefusal::ReasonEmpty);
        }
        if self.reason.len() > MAX_BREAK_GLASS_REASON_LEN {
            return Err(BreakGlassRefusal::ReasonTooLong {
                len: self.reason.len(),
                max: MAX_BREAK_GLASS_REASON_LEN,
            });
        }
        let duration = self.expires_at.saturating_since(self.issued_at);
        if duration > MAX_BREAK_GLASS_DURATION_SECS {
            return Err(BreakGlassRefusal::DurationExceedsMax {
                duration_secs: duration,
                max_secs: MAX_BREAK_GLASS_DURATION_SECS,
            });
        }
        Ok(())
    }
}

/// An immutable, verifiable receipt certifying an executed break-glass override.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BreakGlassReceipt {
    /// The original validated intent.
    pub intent: BreakGlassIntent,
    /// Instant when the override was verified and applied.
    pub evaluated_at: PolicyInstant,
    /// The post-incident review obligation identifier created by this action.
    pub post_review_obligation_id: AsciiSlug,
}

/// Evaluates a break-glass override intent against the input root and current state.
pub fn evaluate_break_glass(
    intent: &BreakGlassIntent,
    input: &PolicyInputRoot,
    current_ref_oid: &GitOid,
    required_approvals: usize,
    min_auth: AuthenticationStrength,
) -> Result<BreakGlassReceipt, BreakGlassRefusal> {
    // 1. Structural validity
    intent.validate_bounds()?;

    // 2. Audit token content-addressing verification
    let expected_audit_token = intent.compute_audit_token();
    if intent.audit_token != expected_audit_token {
        return Err(BreakGlassRefusal::AuditTokenMismatch {
            actual: intent.audit_token,
            expected: expected_audit_token,
        });
    }

    // 3. Active time window check
    let now = input.instant();
    if now < intent.issued_at {
        return Err(BreakGlassRefusal::NotYetActive {
            current: now,
            issued_at: intent.issued_at,
        });
    }
    if now > intent.expires_at {
        return Err(BreakGlassRefusal::Expired {
            current: now,
            expires_at: intent.expires_at,
        });
    }

    // 3. Scope match
    if !intent.scope.matches(intent.target_ref.as_bytes()) {
        return Err(BreakGlassRefusal::ScopeMismatch {
            ref_name: intent.target_ref.to_string(),
            pattern: intent.scope.as_str().to_owned(),
        });
    }

    // 4. Displaced state verification
    if current_ref_oid != &intent.displaced_state {
        return Err(BreakGlassRefusal::DisplacedStateMismatch {
            actual: *current_ref_oid,
            expected: intent.displaced_state,
        });
    }

    // 5. Authentication strength
    let principal = input.principal();
    if principal.authentication() < min_auth {
        return Err(BreakGlassRefusal::InsufficientAuthentication {
            actual: principal.authentication(),
            required: min_auth,
        });
    }

    // 6. Threshold approval count
    if intent.approvers.len() < required_approvals {
        return Err(BreakGlassRefusal::InsufficientApprovals {
            actual: intent.approvers.len(),
            required: required_approvals,
        });
    }

    // 7. Self-approval prohibition (when approval threshold >= 1)
    if required_approvals > 0 && intent.approvers.contains(&intent.actor) {
        return Err(BreakGlassRefusal::SelfApprovalForbidden {
            actor: intent.actor,
        });
    }

    // 8. Generate post-review obligation
    let obligation_slug = AsciiSlug::try_new("PostReviewObligation", b"post-incident-review")
        .map_err(|_| BreakGlassRefusal::ReasonEmpty)?;

    Ok(BreakGlassReceipt {
        intent: intent.clone(),
        evaluated_at: now,
        post_review_obligation_id: obligation_slug,
    })
}
