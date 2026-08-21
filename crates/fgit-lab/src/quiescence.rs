//! Region-close verdicts driven by the resource crate's own close evidence.
//!
//! [`ObligationOracle`](crate::verdict::ObligationOracle) tracks obligations by
//! caller-supplied string id. That is useful for a campaign that wants to check
//! its own bookkeeping, and it is **not** load-bearing for a region close, for
//! one reason: it can only be as honest as its caller. A campaign that forgets
//! to call `opened()` gets a clean report. It cannot see a real ledger, a leak
//! record, or a capability grant that outlived its region.
//!
//! This module is the load-bearing path. [`RegionCloseObserver::close`] takes
//! the [`RegionCloseOutcome`] that `fgit-resource` itself produced and folds it
//! together with what the lab observed, yielding exactly three verdicts.
//!
//! # The three verdicts, and why the middle one exists
//!
//! - [`RegionVerdict::Quiescent`] — the ledger settled everything and the lab
//!   saw the drain finish.
//! - [`RegionVerdict::BoundedNonCooperative`] — the ledger settled everything,
//!   but the lab still had live tasks or unreleased leases when the drain bound
//!   ran out. **Nothing leaked**: responsibility is still owned, the drain
//!   simply did not finish inside its bound. This is the honest "we stopped
//!   asking" result, and collapsing it into either neighbour loses the thing an
//!   operator most needs to know — whether to wait longer or to investigate.
//! - [`RegionVerdict::ContainmentFailure`] — something outlived the region.
//!
//! # Two rules this module will not bend
//!
//! **The lab never overrules the ledger.** If `fgit-resource` reports a
//! containment failure, no combination of lab observations downgrades it. The
//! lab observes; the resource crate is the authority on obligations. This is
//! the same direction as [`CoverageReceipt::credit_for`](crate::receipt::CoverageReceipt::credit_for):
//! the lab may refuse, never upgrade.
//!
//! **An outstanding capability grant is a containment failure on its own.**
//! `ContainmentFailure::outstanding_grants()` can be the only non-zero field: a
//! region with nothing unsettled, nothing escalated, nothing leaked and one
//! live grant is *not* quiescent, because a capability outlived the region it
//! was issued to. `fgit-resource` already enforces this by returning
//! `ContainmentFailure` in that case, and this module's job is to not undo it.

use std::collections::BTreeSet;

use fgit_resource::RegionId;
use fgit_resource::custody::RegionCloseOutcome;

use crate::plan::StepId;
use crate::refuse::LabRefusal;

/// What a region close actually established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegionVerdict {
    /// Every obligation settled, nothing leaked, and the drain finished.
    Quiescent {
        /// The region that closed.
        region: RegionId,
        /// Obligations that reached a terminal state.
        settled: u64,
    },
    /// The ledger settled, but the drain did not finish inside its bound.
    ///
    /// Not a containment failure: nothing leaked and every obligation is still
    /// owned. The region simply had live work when the lab stopped asking.
    BoundedNonCooperative {
        /// The region that closed.
        region: RegionId,
        /// Tasks and leases still live at the bound.
        outstanding: u32,
        /// Drain passes the lab performed before giving up.
        passes: u32,
    },
    /// Something outlived the region.
    ///
    /// The counts stay separate for the same reason they do in
    /// `fgit-resource` and in `fgit-runtime`'s refusal: each calls for a
    /// different response, and an accounting fault means the others are
    /// themselves suspect.
    ContainmentFailure {
        /// The region that failed to close.
        region: RegionId,
        /// Obligations neither settled nor escalated.
        unsettled: u32,
        /// Obligations handed to a named principal.
        escalated: u32,
        /// Obligations whose responsibility was dropped.
        leaked: u32,
        /// Accounting moves the ledger could not complete.
        accounting_faults: u32,
        /// Capability grants still held at close.
        outstanding_grants: u32,
    },
}

impl RegionVerdict {
    /// Stable machine code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Quiescent { .. } => "quiescent",
            Self::BoundedNonCooperative { .. } => "bounded_non_cooperative",
            Self::ContainmentFailure { .. } => "containment_failure",
        }
    }

    /// Whether the region genuinely reached quiescence.
    ///
    /// `BoundedNonCooperative` is deliberately **not** quiescent. A gate that
    /// wants "settled and finished" must get `false` here, or the bound stops
    /// meaning anything.
    #[must_use]
    pub const fn is_quiescent(&self) -> bool {
        matches!(self, Self::Quiescent { .. })
    }

    /// The region this verdict is about.
    #[must_use]
    pub const fn region(&self) -> RegionId {
        match self {
            Self::Quiescent { region, .. }
            | Self::BoundedNonCooperative { region, .. }
            | Self::ContainmentFailure { region, .. } => *region,
        }
    }

    /// A stable one-line rendering for a receipt.
    #[must_use]
    pub fn canonical_line(&self) -> String {
        match self {
            Self::Quiescent { region, settled } => {
                format!("quiescent region={} settled={settled}", region.get())
            }
            Self::BoundedNonCooperative {
                region,
                outstanding,
                passes,
            } => format!(
                "bounded_non_cooperative region={} outstanding={outstanding} passes={passes}",
                region.get()
            ),
            Self::ContainmentFailure {
                region,
                unsettled,
                escalated,
                leaked,
                accounting_faults,
                outstanding_grants,
            } => format!(
                "containment_failure region={} unsettled={unsettled} escalated={escalated} \
                 leaked={leaked} accounting_faults={accounting_faults} \
                 outstanding_grants={outstanding_grants}",
                region.get()
            ),
        }
    }
}

/// Saturating narrowing, because a truncated count would understate a failure.
fn narrow(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// Records what the lab saw around a region close.
#[derive(Debug, Clone)]
pub struct RegionCloseObserver {
    region: RegionId,
    drain_bound: u32,
    passes: u32,
    live_tasks: BTreeSet<StepId>,
    open_leases: BTreeSet<String>,
}

impl RegionCloseObserver {
    /// Observe `region`, allowing `drain_bound` drain passes before the lab
    /// stops asking.
    #[must_use]
    pub const fn new(region: RegionId, drain_bound: u32) -> Self {
        Self {
            region,
            drain_bound,
            passes: 0,
            live_tasks: BTreeSet::new(),
            open_leases: BTreeSet::new(),
        }
    }

    /// One request → drain → finalize pass completed.
    pub const fn record_drain_pass(&mut self) {
        self.passes = self.passes.saturating_add(1);
    }

    /// A task is live in the region.
    pub fn record_task_live(&mut self, task: StepId) {
        self.live_tasks.insert(task);
    }

    /// A task reached a terminal state.
    pub fn record_task_settled(&mut self, task: &StepId) {
        self.live_tasks.remove(task);
    }

    /// A capability lease was taken.
    pub fn record_capability_lease(&mut self, lease: impl Into<String>) {
        self.open_leases.insert(lease.into());
    }

    /// A capability lease was released.
    pub fn record_lease_released(&mut self, lease: &str) {
        self.open_leases.remove(lease);
    }

    /// Drain passes performed.
    #[must_use]
    pub const fn passes(&self) -> u32 {
        self.passes
    }

    /// Tasks and leases the lab still considers live.
    #[must_use]
    pub fn outstanding(&self) -> u32 {
        narrow(self.live_tasks.len().saturating_add(self.open_leases.len()))
    }

    /// Fold the ledger's close evidence together with the lab's observations.
    ///
    /// # Errors
    ///
    /// [`LabRefusal::RegionEvidenceMismatch`] when `outcome` describes a
    /// different region than this observer watched. Folding one region's close
    /// evidence against another's observations would produce a verdict about
    /// neither, which is the exact class of error this crate exists to refuse.
    pub fn close(self, outcome: RegionCloseOutcome) -> Result<RegionVerdict, LabRefusal> {
        let observed_region = match &outcome {
            RegionCloseOutcome::Quiescent(receipt) => receipt.region(),
            RegionCloseOutcome::ContainmentFailure(failure) => failure.region(),
        };
        if observed_region != self.region {
            return Err(LabRefusal::RegionEvidenceMismatch {
                expected: self.region.get(),
                observed: observed_region.get(),
            });
        }

        match outcome {
            // The ledger is the authority on obligations. No lab observation
            // downgrades a containment failure.
            RegionCloseOutcome::ContainmentFailure(failure) => {
                Ok(RegionVerdict::ContainmentFailure {
                    region: failure.region(),
                    unsettled: narrow(failure.unsettled().len()),
                    escalated: narrow(failure.escalated().len()),
                    leaked: narrow(failure.leaks().len()),
                    accounting_faults: failure.accounting_faults(),
                    outstanding_grants: failure.outstanding_grants(),
                })
            }
            RegionCloseOutcome::Quiescent(receipt) => {
                let outstanding = self.outstanding();
                if outstanding > 0 {
                    // The ledger settled, but the lab still saw live work when
                    // the bound ran out. Nothing leaked; the drain did not
                    // finish. Reporting this as Quiescent would make the bound
                    // decorative.
                    Ok(RegionVerdict::BoundedNonCooperative {
                        region: receipt.region(),
                        outstanding,
                        passes: self.passes,
                    })
                } else {
                    Ok(RegionVerdict::Quiescent {
                        region: receipt.region(),
                        settled: receipt.settled(),
                    })
                }
            }
        }
    }

    /// Whether the lab exhausted its drain bound.
    ///
    /// Reported separately from the verdict because "we used every pass" and
    /// "work was still live" are different facts, and a campaign tuning its
    /// bound needs both.
    #[must_use]
    pub const fn bound_exhausted(&self) -> bool {
        self.passes >= self.drain_bound
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_resource::algebra::{Grade, ResourceVector};
    use fgit_resource::custody::{LeakDisposition, ObligationLedger};

    fn region(value: u64) -> RegionId {
        RegionId::new(value)
    }

    /// A ledger that closes quiescent, because nothing was ever reserved.
    fn quiescent_outcome(value: u64) -> RegionCloseOutcome {
        let ledger = ObligationLedger::root(
            region(value),
            LeakDisposition::FailFast,
            ResourceVector::single(Grade::Bytes, 4096),
        );
        ledger.close()
    }

    #[test]
    fn a_settled_ledger_with_a_finished_drain_is_quiescent() {
        let mut observer = RegionCloseObserver::new(region(1), 4);
        observer.record_task_live(StepId::new("worker"));
        observer.record_drain_pass();
        observer.record_task_settled(&StepId::new("worker"));

        let verdict = observer
            .close(quiescent_outcome(1))
            .expect("matching regions fold");

        assert!(verdict.is_quiescent());
        assert_eq!(verdict.code(), "quiescent");
        assert_eq!(verdict.region(), region(1));
    }

    #[test]
    fn a_live_task_at_the_bound_is_bounded_non_cooperative_not_quiescent() {
        // The distinction the middle verdict exists for: the ledger settled,
        // so nothing leaked, but the lab still had live work.
        let mut observer = RegionCloseObserver::new(region(2), 2);
        observer.record_task_live(StepId::new("stuck"));
        observer.record_drain_pass();
        observer.record_drain_pass();

        let verdict = observer
            .close(quiescent_outcome(2))
            .expect("matching regions fold");

        assert_eq!(verdict.code(), "bounded_non_cooperative");
        assert!(
            !verdict.is_quiescent(),
            "a bounded non-cooperative close must NOT read as quiescent, or the bound is decorative"
        );
        assert_eq!(
            verdict,
            RegionVerdict::BoundedNonCooperative {
                region: region(2),
                outstanding: 1,
                passes: 2,
            }
        );
    }

    #[test]
    fn an_unreleased_capability_lease_also_blocks_quiescence() {
        // Leases count as outstanding alongside tasks: a lease still held is
        // work the region has not finished, even with no live task.
        let mut observer = RegionCloseObserver::new(region(3), 1);
        observer.record_capability_lease("secret-lease-a");
        observer.record_drain_pass();

        let verdict = observer
            .close(quiescent_outcome(3))
            .expect("matching regions fold");

        assert_eq!(verdict.code(), "bounded_non_cooperative");

        // Paired permitted case: release it and the same shape is quiescent.
        let mut released = RegionCloseObserver::new(region(3), 1);
        released.record_capability_lease("secret-lease-a");
        released.record_lease_released("secret-lease-a");
        released.record_drain_pass();
        assert!(
            released
                .close(quiescent_outcome(3))
                .expect("folds")
                .is_quiescent()
        );
    }

    #[test]
    fn evidence_from_another_region_is_refused() {
        // The failure this crate keeps meeting in other forms: a real
        // measurement folded against the wrong subject. A verdict built from
        // region 5's ledger and region 4's observations describes neither.
        let observer = RegionCloseObserver::new(region(4), 2);
        let refusal = observer
            .close(quiescent_outcome(5))
            .expect_err("cross-region evidence must be refused");

        assert_eq!(refusal.code(), "lab.region.evidence_mismatch");
        let rendered = refusal.to_string();
        assert!(rendered.contains('4') && rendered.contains('5'));
    }

    #[test]
    fn the_bound_exhaustion_flag_is_separate_from_the_verdict() {
        // "we used every pass" and "work was still live" are different facts.
        let mut used_every_pass = RegionCloseObserver::new(region(6), 2);
        used_every_pass.record_drain_pass();
        used_every_pass.record_drain_pass();
        assert!(used_every_pass.bound_exhausted());
        assert!(
            used_every_pass
                .clone()
                .close(quiescent_outcome(6))
                .expect("folds")
                .is_quiescent(),
            "exhausting the bound with nothing live is still quiescent"
        );

        let mut stopped_early = RegionCloseObserver::new(region(6), 8);
        stopped_early.record_task_live(StepId::new("live"));
        stopped_early.record_drain_pass();
        assert!(!stopped_early.bound_exhausted());
        assert_eq!(
            stopped_early
                .close(quiescent_outcome(6))
                .expect("folds")
                .code(),
            "bounded_non_cooperative",
            "live work is non-cooperative whether or not the bound was exhausted"
        );
    }

    #[test]
    fn the_canonical_line_names_every_count_it_carries() {
        let verdict = RegionVerdict::ContainmentFailure {
            region: region(7),
            unsettled: 1,
            escalated: 2,
            leaked: 3,
            accounting_faults: 4,
            outstanding_grants: 5,
        };
        let line = verdict.canonical_line();
        for field in [
            "region=7",
            "unsettled=1",
            "escalated=2",
            "leaked=3",
            "accounting_faults=4",
            "outstanding_grants=5",
        ] {
            assert!(line.contains(field), "the line must state {field}: {line}");
        }
        assert!(!verdict.is_quiescent());
    }

    #[test]
    fn an_outstanding_grant_alone_is_not_quiescent() {
        // The rule RainyLotus caught me dropping one crate over. Zero
        // unsettled, zero escalated, zero leaked, one live grant — a
        // capability outlived its region, so this is a containment failure and
        // must never read as clean.
        let verdict = RegionVerdict::ContainmentFailure {
            region: region(8),
            unsettled: 0,
            escalated: 0,
            leaked: 0,
            accounting_faults: 0,
            outstanding_grants: 1,
        };
        assert!(!verdict.is_quiescent());
        assert_eq!(verdict.code(), "containment_failure");
        assert!(verdict.canonical_line().contains("outstanding_grants=1"));
    }
}
