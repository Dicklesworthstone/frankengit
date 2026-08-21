//! Region quiescence and obligation oracles.
//!
//! An oracle here answers one question about a finished run: did the region
//! actually reach quiescence, and did every obligation the run took on reach a
//! terminal state? Both are counted from events the run recorded, not asserted
//! by the code under test about itself.
//!
//! The counting is deliberately simple and total. An obligation is opened, and
//! then settled exactly once as committed, aborted, or transferred; anything
//! still open at close is outstanding, and a region that closes with
//! outstanding obligations is refused. There is no "probably fine" bucket,
//! because the failure this catches is precisely the one that looks fine.

use std::collections::BTreeMap;

use crate::refuse::LabRefusal;

/// How an obligation ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Settlement {
    /// The effect was committed.
    Committed,
    /// The effect was abandoned and its reservation released.
    Aborted,
    /// Responsibility moved to a longer-lived owner, with a receipt.
    Transferred,
}

impl Settlement {
    /// Stable machine code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Aborted => "aborted",
            Self::Transferred => "transferred",
        }
    }
}

/// Tracks obligations opened and settled during a run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObligationOracle {
    open: BTreeMap<String, u64>,
    settled: BTreeMap<Settlement, u64>,
    double_settlements: Vec<String>,
}

impl ObligationOracle {
    /// A fresh oracle.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            open: BTreeMap::new(),
            settled: BTreeMap::new(),
            double_settlements: Vec::new(),
        }
    }

    /// Record that an obligation was opened.
    pub fn opened(&mut self, id: impl Into<String>) {
        *self.open.entry(id.into()).or_insert(0) += 1;
    }

    /// Record that an obligation reached a terminal state.
    ///
    /// Settling an obligation that is not open is recorded as a double
    /// settlement rather than ignored: settling twice is a real defect and
    /// silently tolerating it would let a leak hide behind a stray commit.
    pub fn settled(&mut self, id: impl Into<String>, settlement: Settlement) {
        let id = id.into();
        match self.open.get_mut(&id) {
            Some(count) if *count > 0 => {
                *count -= 1;
                if *count == 0 {
                    self.open.remove(&id);
                }
                *self.settled.entry(settlement).or_insert(0) += 1;
            }
            _ => self.double_settlements.push(id),
        }
    }

    /// How many obligations are still open.
    #[must_use]
    pub fn outstanding(&self) -> usize {
        let total: u64 = self.open.values().sum();
        usize::try_from(total).unwrap_or(usize::MAX)
    }

    /// The identifiers still open, in name order.
    #[must_use]
    pub fn outstanding_ids(&self) -> Vec<String> {
        self.open.keys().cloned().collect()
    }

    /// How many obligations settled each way.
    #[must_use]
    pub fn settlement_counts(&self) -> Vec<(Settlement, u64)> {
        self.settled
            .iter()
            .map(|(settlement, count)| (*settlement, *count))
            .collect()
    }

    /// Identifiers that were settled while not open.
    #[must_use]
    pub fn double_settlements(&self) -> &[String] {
        &self.double_settlements
    }

    /// Whether the run settled everything it opened, exactly once each.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.open.is_empty() && self.double_settlements.is_empty()
    }
}

/// Checks that a region reached quiescence before closing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuiescenceOracle {
    active_tasks: i64,
    peak_tasks: i64,
    closed: bool,
}

impl QuiescenceOracle {
    /// A fresh oracle.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            active_tasks: 0,
            peak_tasks: 0,
            closed: false,
        }
    }

    /// Record a task entering the region.
    pub const fn task_started(&mut self) {
        self.active_tasks = self.active_tasks.saturating_add(1);
        if self.active_tasks > self.peak_tasks {
            self.peak_tasks = self.active_tasks;
        }
    }

    /// Record a task leaving the region, however it ended.
    pub const fn task_finished(&mut self) {
        self.active_tasks = self.active_tasks.saturating_sub(1);
    }

    /// Tasks still running.
    #[must_use]
    pub const fn active(&self) -> i64 {
        self.active_tasks
    }

    /// The most tasks that were ever running at once.
    #[must_use]
    pub const fn peak(&self) -> i64 {
        self.peak_tasks
    }

    /// Whether the region has been closed.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Close the region, requiring quiescence.
    ///
    /// # Errors
    ///
    /// [`LabRefusal::RegionNotQuiescent`] when tasks are still running or
    /// obligations remain outstanding. Region close reports zero unresolved
    /// obligations or a typed containment failure — never a shrug.
    pub fn close(&mut self, obligations: &ObligationOracle) -> Result<OracleReport, LabRefusal> {
        let outstanding = obligations.outstanding();
        let leftover_tasks = usize::try_from(self.active_tasks.max(0)).unwrap_or(usize::MAX);
        if leftover_tasks > 0 || outstanding > 0 || !obligations.is_clean() {
            return Err(LabRefusal::RegionNotQuiescent {
                outstanding: outstanding.saturating_add(leftover_tasks),
            });
        }
        self.closed = true;
        Ok(OracleReport {
            peak_tasks: self.peak_tasks,
            settlements: obligations.settlement_counts(),
        })
    }
}

/// What the oracles observed over a completed run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleReport {
    peak_tasks: i64,
    settlements: Vec<(Settlement, u64)>,
}

impl OracleReport {
    /// The most tasks running at once.
    #[must_use]
    pub const fn peak_tasks(&self) -> i64 {
        self.peak_tasks
    }

    /// Settlement counts by kind.
    #[must_use]
    pub fn settlements(&self) -> &[(Settlement, u64)] {
        &self.settlements
    }

    /// A canonical, stable, single-line rendering.
    #[must_use]
    pub fn canonical_line(&self) -> String {
        let mut parts = vec![
            "fgit-lab-oracle-v1".to_owned(),
            format!("peak_tasks={}", self.peak_tasks),
        ];
        for (settlement, count) in &self.settlements {
            parts.push(format!("{}={}", settlement.code(), count));
        }
        parts.join("|")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clean_run_closes_quiescent() {
        let mut obligations = ObligationOracle::new();
        let mut region = QuiescenceOracle::new();

        region.task_started();
        obligations.opened("outbox/1");
        obligations.settled("outbox/1", Settlement::Committed);
        region.task_finished();

        assert!(obligations.is_clean());
        let report = region
            .close(&obligations)
            .expect("nothing outstanding, so the region is quiescent");
        assert!(region.is_closed());
        assert_eq!(report.peak_tasks(), 1);
        assert_eq!(report.settlements(), &[(Settlement::Committed, 1)][..]);
        assert_eq!(
            report.canonical_line(),
            "fgit-lab-oracle-v1|peak_tasks=1|committed=1"
        );
    }

    #[test]
    fn closing_with_an_outstanding_obligation_is_refused() {
        let mut obligations = ObligationOracle::new();
        let mut region = QuiescenceOracle::new();

        obligations.opened("secret-lease/7");
        obligations.opened("runner-slot/2");
        obligations.settled("runner-slot/2", Settlement::Aborted);

        let refusal = region
            .close(&obligations)
            .expect_err("one obligation is still open");
        assert_eq!(refusal, LabRefusal::RegionNotQuiescent { outstanding: 1 });
        assert!(refusal.indicts_subject());
        assert!(!region.is_closed());
        assert_eq!(obligations.outstanding(), 1);
        assert_eq!(obligations.outstanding_ids(), vec!["secret-lease/7"]);

        // Paired permitted case: settle it and the same close proceeds.
        obligations.settled("secret-lease/7", Settlement::Transferred);
        let report = region.close(&obligations).expect("now quiescent");
        assert!(region.is_closed());
        assert_eq!(
            report.settlements(),
            &[(Settlement::Aborted, 1), (Settlement::Transferred, 1)][..]
        );
    }

    #[test]
    fn closing_with_a_running_task_is_refused() {
        let obligations = ObligationOracle::new();
        let mut region = QuiescenceOracle::new();
        region.task_started();
        region.task_started();
        region.task_finished();

        assert_eq!(region.active(), 1);
        let refusal = region
            .close(&obligations)
            .expect_err("a task is still running");
        assert_eq!(refusal, LabRefusal::RegionNotQuiescent { outstanding: 1 });

        // Paired permitted case: finish it and close succeeds.
        region.task_finished();
        let report = region.close(&obligations).expect("quiescent");
        assert_eq!(report.peak_tasks(), 2);
    }

    #[test]
    fn settling_an_obligation_twice_is_recorded_not_ignored() {
        let mut obligations = ObligationOracle::new();
        obligations.opened("outbox/1");
        obligations.settled("outbox/1", Settlement::Committed);
        // The second settlement has no open obligation to close.
        obligations.settled("outbox/1", Settlement::Committed);

        assert_eq!(obligations.outstanding(), 0);
        assert_eq!(
            obligations.double_settlements(),
            &["outbox/1".to_owned()][..]
        );
        assert!(!obligations.is_clean());

        // A double settlement blocks close even though nothing is outstanding,
        // because the count balancing to zero is exactly how a leak hides.
        let mut region = QuiescenceOracle::new();
        assert!(region.close(&obligations).is_err());
    }

    #[test]
    fn the_same_id_can_be_opened_more_than_once() {
        let mut obligations = ObligationOracle::new();
        obligations.opened("charge");
        obligations.opened("charge");
        assert_eq!(obligations.outstanding(), 2);

        obligations.settled("charge", Settlement::Committed);
        assert_eq!(obligations.outstanding(), 1);
        assert!(!obligations.is_clean());

        obligations.settled("charge", Settlement::Committed);
        assert_eq!(obligations.outstanding(), 0);
        assert!(obligations.is_clean());
        assert!(
            obligations.double_settlements().is_empty(),
            "no obligation was settled twice, got {:?}",
            obligations.double_settlements()
        );
    }

    #[test]
    fn settlement_codes_are_distinct_and_stable() {
        let codes = [
            Settlement::Committed.code(),
            Settlement::Aborted.code(),
            Settlement::Transferred.code(),
        ];
        let mut sorted = codes.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 3);
        assert_eq!(Settlement::Committed.code(), "committed");
    }

    #[test]
    fn an_empty_run_is_trivially_quiescent() {
        let obligations = ObligationOracle::new();
        let mut region = QuiescenceOracle::new();
        let report = region.close(&obligations).expect("nothing happened");
        assert_eq!(report.peak_tasks(), 0);
        assert_eq!(report.canonical_line(), "fgit-lab-oracle-v1|peak_tasks=0");
    }
}
