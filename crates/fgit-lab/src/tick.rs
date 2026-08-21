//! Virtual time.
//!
//! Logical time in the lab advances because a step advanced it, never because
//! a wall clock moved. That is what makes a run replayable: two runs of the
//! same schedule see the same instants, on a loaded machine or an idle one.
//!
//! The clock is monotone by construction. An attempt to move it backwards is a
//! typed refusal rather than a silently ignored write, because a regressing
//! clock in a replayed trace is a real defect — usually a step that cached an
//! instant and re-applied it — and swallowing it would hide the divergence it
//! is about to cause.

use crate::refuse::LabRefusal;

/// A logical instant, in ticks since the run began.
///
/// Ticks are abstract. A campaign decides what one tick means; the lab only
/// guarantees they are monotone and identical across replays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct LabTime(u64);

impl LabTime {
    /// The instant a run begins.
    pub const ZERO: Self = Self(0);

    /// A specific instant.
    #[must_use]
    pub const fn from_ticks(ticks: u64) -> Self {
        Self(ticks)
    }

    /// The raw tick count.
    #[must_use]
    pub const fn ticks(self) -> u64 {
        self.0
    }

    /// Ticks elapsed from `earlier` to `self`, saturating at zero.
    #[must_use]
    pub const fn since(self, earlier: Self) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

impl core::fmt::Display for LabTime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "t{}", self.0)
    }
}

/// The laboratory's only clock.
///
/// There is no constructor that reads a host clock, and no method that
/// advances time as a side effect of doing something else. Every advance is
/// explicit and is recorded, so the trace shows exactly where time moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualClock {
    now: LabTime,
    advances: u64,
}

impl VirtualClock {
    /// A clock at [`LabTime::ZERO`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            now: LabTime::ZERO,
            advances: 0,
        }
    }

    /// A clock starting at an explicit instant.
    ///
    /// Used when a campaign resumes from a recorded checkpoint rather than
    /// from the start of a run.
    #[must_use]
    pub const fn starting_at(now: LabTime) -> Self {
        Self { now, advances: 0 }
    }

    /// The current logical instant.
    #[must_use]
    pub const fn now(&self) -> LabTime {
        self.now
    }

    /// How many times this clock has been advanced.
    ///
    /// Part of trace identity: two runs that reach the same instant by a
    /// different number of advances took different paths.
    #[must_use]
    pub const fn advance_count(&self) -> u64 {
        self.advances
    }

    /// Advance by `ticks`, returning the new instant.
    ///
    /// Advancing by zero is permitted and still counts as an advance: a step
    /// that explicitly takes no time is a different observation from a step
    /// that never touched the clock.
    pub const fn advance(&mut self, ticks: u64) -> LabTime {
        self.now = LabTime(self.now.0.saturating_add(ticks));
        self.advances = self.advances.saturating_add(1);
        self.now
    }

    /// Advance to an absolute instant.
    ///
    /// # Errors
    ///
    /// [`LabRefusal::ClockRegressed`] if `target` is earlier than now.
    pub const fn advance_to(&mut self, target: LabTime) -> Result<LabTime, LabRefusal> {
        if target.0 < self.now.0 {
            return Err(LabRefusal::ClockRegressed {
                now: self.now.0,
                requested: target.0,
            });
        }
        self.now = target;
        self.advances = self.advances.saturating_add(1);
        Ok(self.now)
    }
}

impl Default for VirtualClock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_clock_starts_at_zero_and_has_not_advanced() {
        let clock = VirtualClock::new();
        assert_eq!(clock.now(), LabTime::ZERO);
        assert_eq!(clock.advance_count(), 0);
    }

    #[test]
    fn the_clock_moves_only_when_advanced() {
        let mut clock = VirtualClock::new();
        // Reading does not advance.
        for _ in 0..10 {
            assert_eq!(clock.now(), LabTime::ZERO);
        }
        assert_eq!(clock.advance_count(), 0);

        clock.advance(5);
        assert_eq!(clock.now(), LabTime::from_ticks(5));
        assert_eq!(clock.advance_count(), 1);
    }

    #[test]
    fn two_clocks_driven_by_the_same_script_agree_exactly() {
        // The determinism property, stated as a test: the clock is a pure
        // function of the advance script, with no host input.
        let script = [3_u64, 0, 17, 1, 250, 0, 9];
        let mut first = VirtualClock::new();
        let mut second = VirtualClock::new();
        for ticks in script {
            first.advance(ticks);
            second.advance(ticks);
        }
        assert_eq!(first, second);
        assert_eq!(first.now(), LabTime::from_ticks(280));
        assert_eq!(first.advance_count(), script.len() as u64);
    }

    #[test]
    fn a_zero_advance_is_an_observation_not_a_no_op() {
        let mut clock = VirtualClock::new();
        clock.advance(0);
        assert_eq!(clock.now(), LabTime::ZERO);
        // The instant is unchanged but the step is recorded, so a run that
        // took a zero-tick step is distinguishable from one that did not.
        assert_eq!(clock.advance_count(), 1);
    }

    #[test]
    fn advancing_to_an_earlier_instant_is_refused() {
        let mut clock = VirtualClock::new();
        clock.advance(10);

        let refusal = clock
            .advance_to(LabTime::from_ticks(4))
            .expect_err("logical time may not regress");
        assert_eq!(
            refusal,
            LabRefusal::ClockRegressed {
                now: 10,
                requested: 4
            }
        );
        assert!(refusal.indicts_subject());
        // The refused advance left the clock untouched.
        assert_eq!(clock.now(), LabTime::from_ticks(10));
        assert_eq!(clock.advance_count(), 1);

        // Paired permitted case: advancing to the same or a later instant.
        clock
            .advance_to(LabTime::from_ticks(10))
            .expect("advancing to now is permitted");
        clock
            .advance_to(LabTime::from_ticks(11))
            .expect("advancing forward is permitted");
        assert_eq!(clock.now(), LabTime::from_ticks(11));
        assert_eq!(clock.advance_count(), 3);
    }

    #[test]
    fn the_clock_saturates_rather_than_wrapping() {
        let mut clock = VirtualClock::starting_at(LabTime::from_ticks(u64::MAX - 2));
        clock.advance(100);
        // Wrapping would make time regress, which is the one thing this type
        // exists to prevent.
        assert_eq!(clock.now(), LabTime::from_ticks(u64::MAX));
    }

    #[test]
    fn elapsed_time_saturates_at_zero() {
        let early = LabTime::from_ticks(5);
        let late = LabTime::from_ticks(9);
        assert_eq!(late.since(early), 4);
        assert_eq!(early.since(late), 0);
    }

    #[test]
    fn instants_render_stably_for_traces() {
        assert_eq!(LabTime::ZERO.to_string(), "t0");
        assert_eq!(LabTime::from_ticks(42).to_string(), "t42");
    }
}
