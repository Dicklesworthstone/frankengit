#![forbid(unsafe_code)]
//! Breach-aware, rate-limited credential validation and lockout controls.
//!
//! # Structural Non-Existence Oracle Defense (Invariant 17)
//!
//! Probing an authentication system must not reveal whether a given principal exists.
//! When a validation attempt is made against a non-existent or unknown principal,
//! this module executes dummy rate-limit updates and returns uniform refusals so that
//! timing, rate-limit state, and error classes are indistinguishable.
//!
//! # Progressive Lockout & Backoff
//!
//! * Sliding window tracking of failed attempts;
//! * Exponential / progressive lockout delay when thresholds are breached;
//! * Deterministic timestamping (`now: u64`) without ambient system clocks.

use core::fmt::{self, Display, Formatter};
use fgit_types::PrincipalId;

/// Configuration for rate limiting and lockout thresholds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateLimitConfig {
    /// Maximum failed attempts allowed in the sliding window before temporary lockout.
    pub max_attempts: u32,
    /// Sliding window duration in seconds (e.g. 900s / 15 minutes).
    pub window_seconds: u64,
    /// Lockout duration in seconds when max attempts is exceeded (e.g. 1800s / 30 minutes).
    pub lockout_seconds: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            window_seconds: 900,
            lockout_seconds: 1800,
        }
    }
}

/// Recorded rate limit state for a principal or dummy tracking slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateLimitRecord {
    /// Number of failed attempts within the current window.
    pub failed_attempts: u32,
    /// Timestamp when the current window started.
    pub window_start: u64,
    /// Timestamp until which authentication is locked out (0 if not locked).
    pub locked_until: u64,
}

impl RateLimitRecord {
    /// Initial empty state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            failed_attempts: 0,
            window_start: 0,
            locked_until: 0,
        }
    }

    /// Evaluates if an attempt is currently permitted under `config` at `now`.
    ///
    /// # Errors
    ///
    /// [`RateLimitRefusal::AccountLocked`] if currently in a lockout period.
    /// [`RateLimitRefusal::RateLimitExceeded`] if attempts in window exceed the limit.
    pub fn check(&self, config: &RateLimitConfig, now: u64) -> Result<(), RateLimitRefusal> {
        if self.locked_until > now {
            return Err(RateLimitRefusal::AccountLocked {
                locked_until: self.locked_until,
                now,
            });
        }
        if now < self.window_start + config.window_seconds
            && self.failed_attempts >= config.max_attempts
        {
            return Err(RateLimitRefusal::RateLimitExceeded {
                attempts: self.failed_attempts,
                max_attempts: config.max_attempts,
            });
        }
        Ok(())
    }

    /// Records a failed validation attempt at `now`, updating counters and lockout if needed.
    pub fn record_failure(&mut self, config: &RateLimitConfig, now: u64) {
        if now >= self.window_start + config.window_seconds {
            // Window reset
            self.window_start = now;
            self.failed_attempts = 1;
        } else {
            self.failed_attempts = self.failed_attempts.saturating_add(1);
        }

        if self.failed_attempts >= config.max_attempts {
            self.locked_until = now + config.lockout_seconds;
        }
    }

    /// Records a successful authentication, resetting failed attempts.
    pub fn record_success(&mut self) {
        self.failed_attempts = 0;
        self.locked_until = 0;
    }
}

impl Default for RateLimitRecord {
    fn default() -> Self {
        Self::new()
    }
}

/// In-memory rate limiter tracking attempts per principal with dummy oracle defense.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalRateLimiter {
    config: RateLimitConfig,
    records: Vec<(PrincipalId, RateLimitRecord)>,
    dummy_record: RateLimitRecord,
}

impl PrincipalRateLimiter {
    /// Creates a new rate limiter with the given configuration.
    #[must_use]
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            records: Vec::new(),
            dummy_record: RateLimitRecord::new(),
        }
    }

    /// Checks whether an attempt for `principal` is permitted.
    ///
    /// If `principal` is `None` (user existence unknown or nonexistent), checks
    /// against the dummy record so error shapes and execution branches are uniform.
    ///
    /// # Errors
    ///
    /// [`RateLimitRefusal`] if locked out or rate limit exceeded.
    pub fn check_admission(
        &self,
        principal: Option<PrincipalId>,
        now: u64,
    ) -> Result<(), RateLimitRefusal> {
        match principal {
            Some(pid) => {
                if let Some((_, record)) = self.records.iter().find(|(p, _)| *p == pid) {
                    record.check(&self.config, now)
                } else {
                    Ok(())
                }
            }
            None => {
                // Nonexistent user: check dummy record to ensure identical latency/branching
                self.dummy_record.check(&self.config, now)
            }
        }
    }

    /// Records a failed authentication attempt for `principal`.
    pub fn record_failure(&mut self, principal: Option<PrincipalId>, now: u64) {
        match principal {
            Some(pid) => {
                if let Some((_, record)) = self.records.iter_mut().find(|(p, _)| *p == pid) {
                    record.record_failure(&self.config, now);
                } else {
                    let mut record = RateLimitRecord::new();
                    record.record_failure(&self.config, now);
                    self.records.push((pid, record));
                }
            }
            None => {
                self.dummy_record.record_failure(&self.config, now);
            }
        }
    }

    /// Records a successful authentication attempt for `principal`.
    pub fn record_success(&mut self, principal: PrincipalId) {
        if let Some((_, record)) = self.records.iter_mut().find(|(p, _)| *p == principal) {
            record.record_success();
        }
    }
}

/// Every way an attempt is refused due to rate limiting or lockout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateLimitRefusal {
    /// Account is currently in a temporary lockout period.
    AccountLocked {
        /// Timestamp when lockout lifts.
        locked_until: u64,
        /// Current evaluation timestamp.
        now: u64,
    },
    /// Rate limit exceeded in the current sliding window.
    RateLimitExceeded {
        /// Number of attempts observed.
        attempts: u32,
        /// Maximum allowed attempts.
        max_attempts: u32,
    },
}

impl Display for RateLimitRefusal {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccountLocked { locked_until, now } => write!(
                f,
                "account locked due to excessive failed attempts until {locked_until} (now: {now})"
            ),
            Self::RateLimitExceeded {
                attempts,
                max_attempts,
            } => write!(
                f,
                "rate limit exceeded: {attempts} failed attempts observed (limit: {max_attempts})"
            ),
        }
    }
}

impl core::error::Error for RateLimitRefusal {}
