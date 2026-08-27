#![forbid(unsafe_code)]
//! Delay-and-notify account recovery state machine.
//!
//! Account recovery is a high-risk operational path susceptible to account takeover.
//! This module enforces strict constitutional invariants:
//!
//! * Mandatory delay before recovery activation, giving legitimate account holders
//!   sufficient notice to intervene;
//! * Notification dispatch requirement: recovery cannot proceed without recorded
//!   evidence of notification to existing trusted endpoints;
//! * Immediate revocation/cancellation by any existing active session belonging
//!   to the principal;
//! * Honest authentication strength: sessions established via recovery are strictly
//!   [`AuthenticationStrength::SingleFactor`]; recovery can NEVER masquerade
//!   as multi-factor, passkey, or biometric authentication.

use core::fmt::{self, Display, Formatter};
use fgit_types::{PrincipalId, RepositoryId};

use crate::session::{AuthenticationStrength, Session, SessionId};

/// Minimum mandatory recovery delay in seconds (e.g. 24 hours / 86400s).
pub const MIN_RECOVERY_DELAY_SECONDS: u64 = 86_400;

/// Identifier for an account recovery request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RecoveryId(u64);

impl RecoveryId {
    /// Constructs a new `RecoveryId`, refusing zero.
    #[must_use]
    pub const fn try_new(val: u64) -> Option<Self> {
        if val == 0 { None } else { Some(Self(val)) }
    }

    /// The wire scalar.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Display for RecoveryId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "recovery-{}", self.0)
    }
}

/// Lifecycle state of a recovery request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryState {
    /// Pending the required delay period.
    Pending,
    /// Successfully completed and redeemed.
    Completed {
        /// Timestamp when completed.
        completed_at: u64,
    },
    /// Cancelled by the legitimate holder.
    Cancelled {
        /// Timestamp when cancelled.
        cancelled_at: u64,
    },
}

/// An initiated account recovery request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRequest {
    id: RecoveryId,
    principal: PrincipalId,
    repository: RepositoryId,
    requested_at: u64,
    unlock_at: u64,
    notification_dispatched: bool,
    state: RecoveryState,
}

impl RecoveryRequest {
    /// Initiates a new account recovery request with enforced minimum delay and notification requirement.
    ///
    /// # Errors
    ///
    /// [`RecoveryRefusal::DelayTooShort`] if `unlock_at < requested_at + MIN_RECOVERY_DELAY_SECONDS`.
    /// [`RecoveryRefusal::NotificationRequired`] if notification was not dispatched.
    pub const fn initiate(
        id: RecoveryId,
        principal: PrincipalId,
        repository: RepositoryId,
        requested_at: u64,
        unlock_at: u64,
        notification_dispatched: bool,
    ) -> Result<Self, RecoveryRefusal> {
        if !notification_dispatched {
            return Err(RecoveryRefusal::NotificationRequired);
        }
        if unlock_at < requested_at.saturating_add(MIN_RECOVERY_DELAY_SECONDS) {
            return Err(RecoveryRefusal::DelayTooShort {
                provided: unlock_at.saturating_sub(requested_at),
                minimum_required: MIN_RECOVERY_DELAY_SECONDS,
            });
        }

        Ok(Self {
            id,
            principal,
            repository,
            requested_at,
            unlock_at,
            notification_dispatched,
            state: RecoveryState::Pending,
        })
    }

    /// The recovery request ID.
    #[must_use]
    pub const fn id(&self) -> RecoveryId {
        self.id
    }

    /// The principal undergoing recovery.
    #[must_use]
    pub const fn principal(&self) -> PrincipalId {
        self.principal
    }

    /// The repository context.
    #[must_use]
    pub const fn repository(&self) -> RepositoryId {
        self.repository
    }

    /// When recovery was initiated.
    #[must_use]
    pub const fn requested_at(&self) -> u64 {
        self.requested_at
    }

    /// When the delay window elapses and recovery becomes eligible for completion.
    #[must_use]
    pub const fn unlock_at(&self) -> u64 {
        self.unlock_at
    }

    /// Current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> RecoveryState {
        self.state
    }

    /// Cancels the recovery request (e.g. initiated by an existing active session or verified email link).
    ///
    /// # Errors
    ///
    /// [`RecoveryRefusal::AlreadyCompleted`] or [`RecoveryRefusal::AlreadyCancelled`].
    pub const fn cancel(&mut self, now: u64) -> Result<(), RecoveryRefusal> {
        match self.state {
            RecoveryState::Pending => {
                self.state = RecoveryState::Cancelled { cancelled_at: now };
                Ok(())
            }
            RecoveryState::Completed { .. } => Err(RecoveryRefusal::AlreadyCompleted),
            RecoveryState::Cancelled { .. } => Err(RecoveryRefusal::AlreadyCancelled),
        }
    }

    /// Completes the recovery request after the delay period has elapsed.
    ///
    /// Crucially, the resulting session is established with [`AuthenticationStrength::SingleFactor`].
    /// Recovery never yields `MultiFactor` strength.
    ///
    /// # Errors
    ///
    /// [`RecoveryRefusal::DelayNotElapsed`], [`RecoveryRefusal::AlreadyCompleted`], or
    /// [`RecoveryRefusal::AlreadyCancelled`].
    pub const fn complete(
        &mut self,
        session_id: SessionId,
        session_expires_at: u64,
        now: u64,
    ) -> Result<Session, RecoveryRefusal> {
        match self.state {
            RecoveryState::Pending => {
                if now < self.unlock_at {
                    return Err(RecoveryRefusal::DelayNotElapsed {
                        unlock_at: self.unlock_at,
                        now,
                    });
                }
                self.state = RecoveryState::Completed { completed_at: now };

                // Recovery establishes a SingleFactor session only.
                Ok(Session::establish(
                    session_id,
                    self.principal,
                    self.repository,
                    AuthenticationStrength::SingleFactor,
                    session_expires_at,
                ))
            }
            RecoveryState::Completed { .. } => Err(RecoveryRefusal::AlreadyCompleted),
            RecoveryState::Cancelled { .. } => Err(RecoveryRefusal::AlreadyCancelled),
        }
    }
}

/// Every way a recovery action is refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryRefusal {
    /// Recovery requires dispatching notifications to all registered channels.
    NotificationRequired,
    /// Enforced delay was less than the required minimum.
    DelayTooShort {
        /// Provided delay duration in seconds.
        provided: u64,
        /// Minimum required duration in seconds.
        minimum_required: u64,
    },
    /// Delay period has not yet elapsed.
    DelayNotElapsed {
        /// Timestamp when recovery unlocks.
        unlock_at: u64,
        /// Current timestamp.
        now: u64,
    },
    /// Recovery request was already completed.
    AlreadyCompleted,
    /// Recovery request was cancelled.
    AlreadyCancelled,
}

impl Display for RecoveryRefusal {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotificationRequired => {
                f.write_str("account recovery cannot be initiated without notification dispatch")
            }
            Self::DelayTooShort {
                provided,
                minimum_required,
            } => write!(
                f,
                "recovery delay of {provided}s is shorter than mandatory minimum {minimum_required}s"
            ),
            Self::DelayNotElapsed { unlock_at, now } => write!(
                f,
                "recovery delay has not elapsed: unlocks at {unlock_at} (now: {now})"
            ),
            Self::AlreadyCompleted => f.write_str("recovery request has already been completed"),
            Self::AlreadyCancelled => f.write_str("recovery request has been cancelled"),
        }
    }
}

impl core::error::Error for RecoveryRefusal {}
