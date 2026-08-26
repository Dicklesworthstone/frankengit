//! The completeness state machine.
//!
//! A projection's answer to "am I current?" must be a *state*, not a vibe.
//! [`Watermark`] models the four honest states — catching up, live, lagging,
//! refused — and refuses every transition that would make a read lie:
//! regression, gaps, or observing under a different authority head binding
//! than the one the data was folded under.
//!
//! Decision streams are append-only: a tip that shrinks between observations
//! is a contradiction, and the watermark names it as a regression instead of
//! quietly re-deriving its lag from the smaller number.

use crate::identity::ProjectionPosition;

/// Why a watermark refused an operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatermarkRefusal {
    /// Positions only move forward; `held` is what the watermark already
    /// carries and `offered` is the regressed value. For tips, `held` is the
    /// highest tip previously observed.
    Regression {
        held: ProjectionPosition,
        offered: ProjectionPosition,
    },
    /// Catch-up requires the exact successor; anything else means canonical
    /// history was skipped.
    Gap {
        expected: ProjectionPosition,
        offered: ProjectionPosition,
    },
    /// The observation names a different head binding than the fold ran with.
    HeadBindingMismatch { folded: String, observed: String },
}

impl std::fmt::Display for WatermarkRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Regression { held, offered } => {
                write!(f, "watermark regression: held {held}, offered {offered}")
            }
            Self::Gap { expected, offered } => {
                write!(f, "watermark gap: expected {expected}, offered {offered}")
            }
            Self::HeadBindingMismatch { folded, observed } => write!(
                f,
                "watermark head mismatch: folded under {folded}, observed under {observed}"
            ),
        }
    }
}

impl std::error::Error for WatermarkRefusal {}

/// Current completeness of one projection generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatermarkState {
    /// Installed; no decision folded yet.
    Fresh,
    /// Folding contiguous history toward the caller-supplied target.
    CatchingUp { position: ProjectionPosition },
    /// Caught up to the observed stream tip as of the last advance.
    Live { position: ProjectionPosition },
    /// The stream leads the fold by `behind` decisions.
    Lagging {
        position: ProjectionPosition,
        behind: u64,
    },
}

#[derive(Debug, Clone)]
pub struct Watermark {
    state: WatermarkState,
    /// Hex authority-head binding every fold and observation must agree on.
    head_binding: String,
    /// Highest stream tip ever observed under this binding. Append-only
    /// means this never decreases; a smaller offer is a typed regression.
    last_seen_tip: Option<ProjectionPosition>,
}

impl Watermark {
    #[must_use]
    pub fn fresh(head_binding: impl Into<String>) -> Self {
        Self {
            state: WatermarkState::Fresh,
            head_binding: head_binding.into(),
            last_seen_tip: None,
        }
    }

    #[must_use]
    pub const fn state(&self) -> &WatermarkState {
        &self.state
    }

    #[must_use]
    pub const fn head_binding(&self) -> &String {
        &self.head_binding
    }

    /// Fold one contiguous decision during catch-up.
    ///
    /// # Errors
    /// [`WatermarkRefusal::Gap`] unless `position` is the exact successor of
    /// the current position (or position 1 from [`WatermarkState::Fresh`]).
    pub fn catch_up(&mut self, position: ProjectionPosition) -> Result<(), WatermarkRefusal> {
        let expected = match self.state {
            WatermarkState::Fresh => ProjectionPosition::new(1),
            WatermarkState::CatchingUp { position }
            | WatermarkState::Live { position }
            | WatermarkState::Lagging { position, .. } => match position.successor() {
                Some(next) => next,
                None => {
                    return Err(WatermarkRefusal::Gap {
                        expected: position,
                        offered: position,
                    });
                }
            },
        };
        if position != expected {
            return Err(WatermarkRefusal::Gap {
                expected,
                offered: position,
            });
        }
        self.state = WatermarkState::CatchingUp { position };
        Ok(())
    }

    /// Declare the fold caught up after advancing to `position`, given the
    /// observed stream `tip`. Refuses claiming to be caught up past the tip.
    ///
    /// # Errors
    /// [`WatermarkRefusal::Regression`] when `position` exceeds `tip`, or
    /// when `tip` regresses below a previously observed tip.
    pub fn become_live(
        &mut self,
        position: ProjectionPosition,
        tip: ProjectionPosition,
    ) -> Result<(), WatermarkRefusal> {
        self.admit_tip(tip)?;
        if position.get() > tip.get() {
            return Err(WatermarkRefusal::Regression {
                held: tip,
                offered: position,
            });
        }
        self.state = if position == tip {
            WatermarkState::Live { position }
        } else {
            WatermarkState::Lagging {
                position,
                behind: tip.get() - position.get(),
            }
        };
        Ok(())
    }

    /// Observe a new stream tip. A fold that trails the tip becomes lagging
    /// by exactly the difference; an equal tip is live. Refuses tips below
    /// the highest previously observed tip (append-only streams never
    /// shrink) and positions below the fold.
    ///
    /// # Errors
    /// [`WatermarkRefusal::Regression`] on any decrease.
    pub fn observe_tip(&mut self, tip: ProjectionPosition) -> Result<(), WatermarkRefusal> {
        self.admit_tip(tip)?;
        let position = match self.state {
            WatermarkState::Fresh => return Ok(()),
            WatermarkState::CatchingUp { position }
            | WatermarkState::Live { position }
            | WatermarkState::Lagging { position, .. } => position,
        };
        if tip.get() < position.get() {
            return Err(WatermarkRefusal::Regression {
                held: position,
                offered: tip,
            });
        }
        self.state = if tip == position {
            WatermarkState::Live { position }
        } else {
            WatermarkState::Lagging {
                position,
                behind: tip.get() - position.get(),
            }
        };
        Ok(())
    }

    fn admit_tip(&mut self, tip: ProjectionPosition) -> Result<(), WatermarkRefusal> {
        match self.last_seen_tip {
            Some(seen) if tip.get() < seen.get() => {
                return Err(WatermarkRefusal::Regression {
                    held: seen,
                    offered: tip,
                });
            }
            _ => {
                self.last_seen_tip = Some(tip);
                Ok(())
            }
        }
    }

    /// Guard for reads: refuse observations made under a different head
    /// binding than the fold ran under.
    ///
    /// # Errors
    /// [`WatermarkRefusal::HeadBindingMismatch`] on any disagreement.
    pub fn admit_read(&self, observed_head: &str) -> Result<(), WatermarkRefusal> {
        if observed_head != self.head_binding {
            return Err(WatermarkRefusal::HeadBindingMismatch {
                folded: self.head_binding.clone(),
                observed: observed_head.to_owned(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ProjectionPosition;

    const HEAD: &str = "aaaa";
    const P: fn(u64) -> ProjectionPosition = ProjectionPosition::new;

    #[test]
    fn fresh_to_catching_up_requires_position_one() {
        let mut w = Watermark::fresh(HEAD);
        assert_eq!(
            w.catch_up(P(2)),
            Err(WatermarkRefusal::Gap {
                expected: P(1),
                offered: P(2)
            })
        );
        w.catch_up(P(1)).expect("first");
        assert_eq!(w.state(), &WatermarkState::CatchingUp { position: P(1) });
    }

    #[test]
    fn catch_up_is_contiguous_and_refuses_replay() {
        let mut w = Watermark::fresh(HEAD);
        for seq in 1..=3 {
            w.catch_up(P(seq)).expect("contiguous");
        }
        assert_eq!(
            w.catch_up(P(3)),
            Err(WatermarkRefusal::Gap {
                expected: P(4),
                offered: P(3)
            })
        );
    }

    #[test]
    fn becoming_live_distinguishes_live_from_lagging() {
        let mut w = Watermark::fresh(HEAD);
        w.catch_up(P(1)).expect("fold");
        w.become_live(P(1), P(3)).expect("lagging is legal");
        assert_eq!(
            w.state(),
            &WatermarkState::Lagging {
                position: P(1),
                behind: 2
            }
        );

        let mut w2 = Watermark::fresh(HEAD);
        w2.catch_up(P(1)).expect("fold");
        w2.become_live(P(1), P(1)).expect("equal tip");
        assert_eq!(&WatermarkState::Live { position: P(1) }, w2.state());
    }

    #[test]
    fn observe_tip_moves_live_to_lagging_and_back() {
        let mut w = Watermark::fresh(HEAD);
        w.catch_up(P(1)).expect("fold");
        w.become_live(P(1), P(1)).expect("live");
        w.observe_tip(P(4)).expect("stream moved");
        assert_eq!(
            w.state(),
            &WatermarkState::Lagging {
                position: P(1),
                behind: 3
            }
        );

        // Append-only: the observed tip can never shrink, even while lagging.
        assert_eq!(
            w.observe_tip(P(1)),
            Err(WatermarkRefusal::Regression {
                held: P(4),
                offered: P(1)
            })
        );

        // Folding forward under the still-standing tip of 4 returns to live.
        for seq in 2..=4 {
            w.catch_up(P(seq)).expect("contiguous catch-up");
        }
        w.observe_tip(P(4)).expect("caught up to standing tip");
        assert_eq!(&WatermarkState::Live { position: P(4) }, w.state());

        // A watermark that never saw a higher tip goes live at its own tip.
        let mut w2 = Watermark::fresh(HEAD);
        w2.catch_up(P(1)).expect("fold 1");
        w2.catch_up(P(2)).expect("fold 2");
        w2.observe_tip(P(2)).expect("tip equals fold");
        assert_eq!(&WatermarkState::Live { position: P(2) }, w2.state());
    }

    #[test]
    fn read_admission_is_binding_exact() {
        let w = Watermark::fresh(HEAD);
        w.admit_read(HEAD).expect("same binding");
        assert_eq!(
            w.admit_read("bbbb"),
            Err(WatermarkRefusal::HeadBindingMismatch {
                folded: HEAD.to_owned(),
                observed: "bbbb".to_owned(),
            })
        );
    }
}
