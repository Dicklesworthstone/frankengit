#![forbid(unsafe_code)]
//! Privilege elevation and step-up re-authentication verification.
//!
//! High-impact actions (such as mutating protected refs, publishing releases,
//! registering deploy keys, or modifying organizational policy) require fresh,
//! step-up authentication within a narrow time window (e.g. 5 minutes), rather
//! than relying indefinitely on an ambient long-lived session.
//!
//! # Invariants
//!
//! * Narrow validity window (maximum allowable elevation duration enforced);
//! * Elevation is bound to a specific [`PrivilegeAction`] and [`PrincipalId`];
//! * Authentication strength must meet or exceed the action's threshold;
//! * Single-use option for sensitive mutations.

use core::fmt::{self, Display, Formatter};
use fgit_types::PrincipalId;

use crate::session::AuthenticationStrength;

/// Default maximum elevation window in seconds (e.g. 300s / 5 minutes).
pub const MAX_ELEVATION_WINDOW_SECONDS: u64 = 300;

/// High-impact actions that demand step-up re-authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum PrivilegeAction {
    /// Mutating a protected reference or branch.
    ProtectedRefMutation,
    /// Signing or publishing an authoritative release asset.
    ReleaseSigning,
    /// Adding, rotating, or revoking deploy keys.
    DeployKeyManagement,
    /// Modifying security policies or break-glass rules.
    SecurityPolicyUpdate,
    /// Managing organization membership and roles.
    OrgAdmin,
}

impl PrivilegeAction {
    /// Returns the minimum authentication strength required for this action.
    #[must_use]
    pub const fn required_strength(self) -> AuthenticationStrength {
        match self {
            Self::ProtectedRefMutation | Self::ReleaseSigning | Self::SecurityPolicyUpdate => {
                AuthenticationStrength::MultiFactor
            }
            Self::DeployKeyManagement | Self::OrgAdmin => AuthenticationStrength::SingleFactor,
        }
    }
}

impl Display for PrivilegeAction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProtectedRefMutation => f.write_str("protected ref mutation"),
            Self::ReleaseSigning => f.write_str("release signing"),
            Self::DeployKeyManagement => f.write_str("deploy key management"),
            Self::SecurityPolicyUpdate => f.write_str("security policy update"),
            Self::OrgAdmin => f.write_str("organization administration"),
        }
    }
}

/// A time-bounded, action-specific privilege elevation grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElevationToken {
    token_id: u64,
    principal: PrincipalId,
    action: PrivilegeAction,
    strength: AuthenticationStrength,
    elevated_at: u64,
    expires_at: u64,
    used: bool,
}

impl ElevationToken {
    /// Issues a new privilege elevation token after fresh authentication.
    ///
    /// # Errors
    ///
    /// [`ReauthRefusal::WindowExceeded`] if `expires_at > elevated_at + MAX_ELEVATION_WINDOW_SECONDS`.
    /// [`ReauthRefusal::StrengthInsufficient`] if `strength < action.required_strength()`.
    pub fn issue(
        token_id: u64,
        principal: PrincipalId,
        action: PrivilegeAction,
        strength: AuthenticationStrength,
        elevated_at: u64,
        expires_at: u64,
    ) -> Result<Self, ReauthRefusal> {
        if token_id == 0 {
            return Err(ReauthRefusal::InvalidTokenId);
        }
        let required = action.required_strength();
        if strength < required {
            return Err(ReauthRefusal::StrengthInsufficient {
                established: strength,
                required,
            });
        }
        if expires_at > elevated_at.saturating_add(MAX_ELEVATION_WINDOW_SECONDS) {
            return Err(ReauthRefusal::WindowExceeded {
                requested_duration: expires_at.saturating_sub(elevated_at),
                max_allowed: MAX_ELEVATION_WINDOW_SECONDS,
            });
        }

        Ok(Self {
            token_id,
            principal,
            action,
            strength,
            elevated_at,
            expires_at,
            used: false,
        })
    }

    /// The elevation token ID.
    #[must_use]
    pub const fn token_id(&self) -> u64 {
        self.token_id
    }

    /// The principal this elevation belongs to.
    #[must_use]
    pub const fn principal(&self) -> PrincipalId {
        self.principal
    }

    /// The action permitted by this elevation.
    #[must_use]
    pub const fn action(&self) -> PrivilegeAction {
        self.action
    }

    /// The established authentication strength.
    #[must_use]
    pub const fn strength(&self) -> AuthenticationStrength {
        self.strength
    }

    /// Expiration deadline.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Verifies and consumes the elevation token for `action` at `now`.
    ///
    /// # Errors
    ///
    /// [`ReauthRefusal`] on any mismatch, expiry, or reuse.
    pub fn consume(
        &mut self,
        principal: PrincipalId,
        action: PrivilegeAction,
        now: u64,
    ) -> Result<(), ReauthRefusal> {
        if self.used {
            return Err(ReauthRefusal::AlreadyConsumed);
        }
        if self.principal != principal {
            return Err(ReauthRefusal::PrincipalMismatch);
        }
        if self.action != action {
            return Err(ReauthRefusal::ActionMismatch);
        }
        if now >= self.expires_at {
            return Err(ReauthRefusal::ElevationExpired {
                expires_at: self.expires_at,
                now,
            });
        }

        self.used = true;
        Ok(())
    }
}

/// Every way a step-up re-authentication or elevation is refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReauthRefusal {
    /// Token ID must be non-zero.
    InvalidTokenId,
    /// Requested elevation window exceeded the maximum allowed duration.
    WindowExceeded {
        /// Requested duration in seconds.
        requested_duration: u64,
        /// Maximum allowed duration in seconds.
        max_allowed: u64,
    },
    /// The established authentication strength does not meet the action's threshold.
    StrengthInsufficient {
        /// Strength established.
        established: AuthenticationStrength,
        /// Strength required.
        required: AuthenticationStrength,
    },
    /// The elevation token expired before consumption.
    ElevationExpired {
        /// Expiration deadline.
        expires_at: u64,
        /// Evaluation timestamp.
        now: u64,
    },
    /// The elevation token was already consumed.
    AlreadyConsumed,
    /// The presenting principal does not match the token's principal.
    PrincipalMismatch,
    /// The action attempted does not match the token's authorized action.
    ActionMismatch,
}

impl Display for ReauthRefusal {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTokenId => f.write_str("elevation token ID must be non-zero"),
            Self::WindowExceeded {
                requested_duration,
                max_allowed,
            } => write!(
                f,
                "elevation window of {requested_duration}s exceeds maximum {max_allowed}s"
            ),
            Self::StrengthInsufficient {
                established,
                required,
            } => write!(
                f,
                "authentication strength {established} is insufficient: {required} required"
            ),
            Self::ElevationExpired { expires_at, now } => write!(
                f,
                "privilege elevation expired at {expires_at}, asked at {now}"
            ),
            Self::AlreadyConsumed => {
                f.write_str("privilege elevation token has already been consumed")
            }
            Self::PrincipalMismatch => {
                f.write_str("presenting principal does not match elevation token")
            }
            Self::ActionMismatch => f.write_str("action does not match elevated privilege scope"),
        }
    }
}

impl core::error::Error for ReauthRefusal {}
