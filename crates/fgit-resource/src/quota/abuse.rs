#![forbid(unsafe_code)]
//! Abuse-control skeleton for intake surfaces (plan section 36.6), worked
//! example: pushes.
//!
//! Three pieces, all pure decisions over explicit state so the node wires
//! them without this module knowing about sockets or runtimes:
//!
//! - [`RateLimit`]: a sliding-window cap per fairness key;
//! - [`Containment`]: a REVERSIBLE throttle decision with an expiry, never
//!   a punishment — irreversible action is out of scope here by
//!   construction and requires deterministic policy plus review upstream;
//! - [`ModerationEvent`]: an immutable record of what was contained, for
//!   audit and appeal.

use crate::quota::fairness::FairnessKey;
use std::time::{Duration, Instant};

/// A per-key sliding-window rate limit.
#[derive(Clone, Copy, Debug, Default)]
pub struct RateLimit {
    /// Maximum events admitted inside any window of `window`.
    pub max_events: u32,
    /// The window length.
    pub window: Duration,
}

/// The mutable side of one key's sliding window.
#[derive(Debug, Default)]
pub struct RateWindow {
    admitted_at: Vec<Instant>,
}

/// Why a push was contained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainmentReason {
    /// The key's sliding window was full.
    RateExceeded { observed: u32, limit: u32 },
}

impl ContainmentReason {
    /// Stable machine code for the NDJSON event stream.
    pub const fn code(self) -> &'static str {
        match self {
            Self::RateExceeded { .. } => "rate_exceeded",
        }
    }
}

/// A reversible containment verdict: hold new work from this key until
/// `expires`, recording why. No data is destroyed; nothing is irreversible.
#[derive(Clone, Copy, Debug)]
pub struct Containment {
    pub reason: ContainmentReason,
    /// How long the containment holds. Zero-duration containment is the
    /// degenerate "admit but record" case and is represented by [`PushVerdict::Admitted`] instead.
    pub expires: Duration,
}

/// What the skeleton tells an intake surface to do.
#[derive(Clone, Copy, Debug)]
pub enum PushVerdict {
    /// Admit; the caller proceeds to authentication and staging gates.
    Admitted,
    /// Reversibly contain until `containment.expires`.
    Contain { containment: Containment },
}

/// Evaluates one incoming push against its key's window.
///
/// `now` is injected so the decision is deterministic under test and free of
/// ambient-clock reads.
pub fn evaluate_push(
    limit: &RateLimit,
    window: &mut RateWindow,
    key: &FairnessKey,
    now: Instant,
) -> PushVerdict {
    let _ = key; // windows are already keyed by the caller's map
    window
        .admitted_at
        .retain(|at| now.duration_since(*at) < limit.window);
    if window.admitted_at.len() < usize::try_from(limit.max_events).unwrap_or(usize::MAX) {
        window.admitted_at.push(now);
        return PushVerdict::Admitted;
    }
    PushVerdict::Contain {
        containment: Containment {
            reason: ContainmentReason::RateExceeded {
                observed: window.admitted_at.len() as u32,
                limit: limit.max_events,
            },
            expires: limit.window,
        },
    }
}

/// An immutable moderation record: what happened, to whom, when, and why.
///
/// Events are append-only evidence; appeals reference them by id. Nothing
/// here decides anything — detectors prioritize, this remembers.
#[derive(Clone, Debug)]
pub struct ModerationEvent {
    /// Monotonic sequence within the emitting surface.
    pub sequence: u64,
    /// The contained key.
    pub key: FairnessKey,
    /// When the containment started (caller-anchored).
    pub at: Instant,
    /// The containment that was applied.
    pub containment: Containment,
}

/// Emits the moderation record for a containment verdict.
///
/// Intake surfaces call this EXACTLY WHEN they apply a [`PushVerdict::Contain`]
/// so records and enforcement cannot drift apart.
#[must_use = "a moderation event is evidence; dropping it destroys the audit trail"]
pub fn record_containment(
    sequence: u64,
    key: &FairnessKey,
    at: Instant,
    containment: &Containment,
) -> ModerationEvent {
    ModerationEvent {
        sequence,
        key: *key,
        at,
        containment: *containment,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn key() -> FairnessKey {
        FairnessKey {
            tenant: fgit_types::TenantId::from_bytes([7; 16]),
            principal: fgit_types::PrincipalId::from_bytes([9; 16]),
        }
    }

    #[test]
    fn admits_up_to_limit_then_contains_within_window() {
        let limit = RateLimit {
            max_events: 3,
            window: Duration::from_secs(60),
        };
        let mut window = RateWindow::default();
        let t0 = Instant::now();
        for _ in 0..3 {
            assert!(matches!(
                evaluate_push(&limit, &mut window, &key(), t0),
                PushVerdict::Admitted
            ));
        }
        match evaluate_push(&limit, &mut window, &key(), t0 + Duration::from_secs(1)) {
            PushVerdict::Contain { containment } => {
                assert_eq!(containment.reason.code(), "rate_exceeded");
                assert_eq!(
                    containment.reason,
                    ContainmentReason::RateExceeded {
                        observed: 3,
                        limit: 3
                    }
                );
            }
            other => panic!("expected containment, got {other:?}"),
        }
    }

    #[test]
    fn window_slide_re_admits_after_expiry() {
        let limit = RateLimit {
            max_events: 1,
            window: Duration::from_secs(10),
        };
        let mut window = RateWindow::default();
        let t0 = Instant::now();
        assert!(matches!(
            evaluate_push(&limit, &mut window, &key(), t0),
            PushVerdict::Admitted
        ));
        assert!(matches!(
            evaluate_push(&limit, &mut window, &key(), t0 + Duration::from_secs(5)),
            PushVerdict::Contain { .. }
        ));
        assert!(matches!(
            evaluate_push(&limit, &mut window, &key(), t0 + Duration::from_secs(11)),
            PushVerdict::Admitted
        ));
    }

    #[test]
    fn distinct_keys_have_distinct_windows() {
        let limit = RateLimit {
            max_events: 1,
            window: Duration::from_secs(60),
        };
        let mut windows: std::collections::BTreeMap<u8, RateWindow> =
            std::collections::BTreeMap::new();
        let t0 = Instant::now();
        let mut verdicts = Vec::new();
        for tag in 1u8..=2 {
            let k = FairnessKey {
                tenant: fgit_types::TenantId::from_bytes([tag; 16]),
                principal: fgit_types::PrincipalId::from_bytes([tag; 16]),
            };
            let entry = windows.entry(tag).or_default();
            verdicts.push(evaluate_push(&limit, entry, &k, t0));
        }
        assert!(verdicts.iter().all(|v| matches!(v, PushVerdict::Admitted)));
    }

    #[test]
    fn containment_records_are_captured_with_their_reason() {
        let containment = Containment {
            reason: ContainmentReason::RateExceeded {
                observed: 5,
                limit: 5,
            },
            expires: Duration::from_secs(30),
        };
        let event = record_containment(1, &key(), Instant::now(), &containment);
        assert_eq!(event.sequence, 1);
        assert_eq!(event.containment.reason.code(), "rate_exceeded");
    }
}
