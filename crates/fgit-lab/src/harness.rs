//! The laboratory itself.
//!
//! A [`Lab`] owns the run's determinism inputs — clock, entropy, schedule,
//! failpoints, hazards — and the trace they produce. Executing the same
//! [`LabConfig`] twice yields byte-identical trace bytes; that is checked by
//! [`Lab::verify_replay`] rather than asserted.
//!
//! # Ambient sources are masked, not merely discouraged
//!
//! [`LabConfig::capability_profile`] narrows the node-root capability envelope
//! by removing the runtime `TIME` and `RANDOM` bits. A subsystem handed a lab
//! context therefore cannot reach the runtime clock or runtime entropy at all;
//! it must take the lab's [`VirtualClock`] and [`SeededEntropy`]. That is the
//! difference between a rule and an enforcement, and it is why a lab run's
//! determinism does not depend on everyone remembering the rule.

use asupersync::cx::cap::{CapMask, CapSet, CapSetRuntimeMask};
use fgit_runtime::grant::{AuthoritySet, CapabilityProfile, Ownership};
use fgit_runtime::{BudgetClass, NodeRuntime, ProfileIdentity, RuntimeProfile};

use crate::hazard::HazardScript;
use crate::journal::{LogicalTrace, TraceEvent};
use crate::plan::{LabSchedule, StepId};
use crate::probe::{CoverageReport, FailpointId, FailpointRegistry};
use crate::refuse::LabRefusal;
use crate::rng::SeededEntropy;
use crate::tick::{LabTime, VirtualClock};
use crate::verdict::{ObligationOracle, OracleReport, QuiescenceOracle};

/// The capability row a lab context runs under: spawn and I/O, but never the
/// runtime's clock or entropy.
///
/// `CapSet<SPAWN, TIME, RANDOM, IO, REMOTE>` — `TIME` and `RANDOM` are `false`,
/// which makes reaching for them a compile error in any code generic over the
/// capability row, and masks them at runtime for code that is not.
pub type LabCaps = CapSet<true, false, false, true, false>;

/// A class of evidence, and whether the lab can honestly replay it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReplayClass {
    /// Logical step interleaving.
    LogicalInterleaving,
    /// Cancellation phase ordering.
    CancellationOrdering,
    /// Budget and capability propagation.
    BudgetPropagation,
    /// Storage, packet, and object-store fault composition.
    FaultComposition,
    /// Obligation settlement and region quiescence.
    ObligationSettlement,
    /// Real worker threads parking and unparking.
    NativeWorkerParking,
    /// Real files, sockets, and OS I/O.
    NativeIo,
    /// Blocking-pool thread joins.
    NativeBlockingPool,
    /// Signal delivery.
    NativeSignals,
    /// Child-process spawning and reaping.
    NativeProcessReaping,
    /// Wall-clock timing behaviour.
    WallClockTiming,
}

/// Every class, for exhaustive checks.
const ALL_CLASSES: [ReplayClass; 11] = [
    ReplayClass::LogicalInterleaving,
    ReplayClass::CancellationOrdering,
    ReplayClass::BudgetPropagation,
    ReplayClass::FaultComposition,
    ReplayClass::ObligationSettlement,
    ReplayClass::NativeWorkerParking,
    ReplayClass::NativeIo,
    ReplayClass::NativeBlockingPool,
    ReplayClass::NativeSignals,
    ReplayClass::NativeProcessReaping,
    ReplayClass::WallClockTiming,
];

impl ReplayClass {
    /// Stable machine code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::LogicalInterleaving => "logical_interleaving",
            Self::CancellationOrdering => "cancellation_ordering",
            Self::BudgetPropagation => "budget_propagation",
            Self::FaultComposition => "fault_composition",
            Self::ObligationSettlement => "obligation_settlement",
            Self::NativeWorkerParking => "native_worker_parking",
            Self::NativeIo => "native_io",
            Self::NativeBlockingPool => "native_blocking_pool",
            Self::NativeSignals => "native_signals",
            Self::NativeProcessReaping => "native_process_reaping",
            Self::WallClockTiming => "wall_clock_timing",
        }
    }

    /// Whether the lab's model actually covers this class.
    ///
    /// The native classes are `false` and must stay `false`: they are owned by
    /// FG-011b and the native crash campaigns, and a lab run says nothing
    /// about them.
    #[must_use]
    pub const fn is_lab_replayable(self) -> bool {
        matches!(
            self,
            Self::LogicalInterleaving
                | Self::CancellationOrdering
                | Self::BudgetPropagation
                | Self::FaultComposition
                | Self::ObligationSettlement
        )
    }

    /// Every class.
    #[must_use]
    pub const fn all() -> [Self; 11] {
        ALL_CLASSES
    }
}

/// Everything that determines a run.
///
/// Two configs that compare equal produce identical traces. Anything that
/// could change a run and is not in here is a determinism bug.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabConfig {
    seed: u64,
    profile: RuntimeProfile,
    schedule: LabSchedule,
    hazards: HazardScript,
}

impl LabConfig {
    /// Assemble a run configuration.
    ///
    /// The profile is forced to the deterministic class: a lab run on a
    /// parking, multi-worker profile would not be replayable, and silently
    /// accepting one would produce traces that diverge for reasons the trace
    /// cannot show.
    #[must_use]
    pub fn new(seed: u64, schedule: LabSchedule, hazards: HazardScript) -> Self {
        Self {
            seed,
            profile: RuntimeProfile::deterministic(),
            schedule,
            hazards,
        }
    }

    /// The run seed.
    #[must_use]
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// The runtime profile.
    #[must_use]
    pub const fn profile(&self) -> &RuntimeProfile {
        &self.profile
    }

    /// The schedule.
    #[must_use]
    pub const fn schedule(&self) -> &LabSchedule {
        &self.schedule
    }

    /// The fault configuration.
    #[must_use]
    pub const fn hazards(&self) -> &HazardScript {
        &self.hazards
    }

    /// The runtime profile identity, which is part of evidence identity.
    #[must_use]
    pub fn profile_identity(&self) -> ProfileIdentity {
        self.profile.identity()
    }

    /// The capability envelope a lab context runs under.
    ///
    /// Node-root capability narrowed by removing runtime `TIME` and `RANDOM`.
    /// Narrowing can only ever drop capabilities, so this cannot widen.
    ///
    /// # Errors
    ///
    /// [`fgit_runtime::RuntimeRefusal`] if the narrowing is somehow rejected,
    /// which would mean the runtime's capability lattice changed underneath
    /// this crate.
    pub fn capability_profile(&self) -> Result<CapabilityProfile, fgit_runtime::RuntimeRefusal> {
        CapabilityProfile::node_root().narrow(
            <LabCaps as CapSetRuntimeMask>::MASK,
            AuthoritySet::all(),
            Ownership::Owned,
        )
    }

    /// Build the runtime this configuration describes.
    ///
    /// The lab does not fabricate a context: a run that wants a real `Cx`
    /// takes one from this runtime through `fgit-runtime`'s production
    /// factory, which is the only admitted way to mint one.
    ///
    /// # Errors
    ///
    /// [`fgit_runtime::RuntimeRefusal`] if the profile is inadmissible or the
    /// runtime cannot start.
    pub fn build_runtime(&self) -> Result<NodeRuntime, fgit_runtime::RuntimeRefusal> {
        self.profile.clone().build()
    }

    /// A canonical, stable, single-line rendering of the whole configuration.
    ///
    /// This is the reproduction recipe: source revision plus this line is
    /// enough for someone else to reproduce the run.
    #[must_use]
    pub fn canonical_line(&self) -> String {
        format!(
            "fgit-lab-config-v1|seed={}|profile={}|schedule={}|hazards={}",
            self.seed,
            self.profile_identity().canonical_descriptor(),
            self.schedule.canonical_line(),
            self.hazards.canonical_line()
        )
    }
}

/// A finished run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabRun {
    trace: LogicalTrace,
    coverage: CoverageReport,
    oracle: Option<OracleReport>,
    steps: usize,
    draws: u64,
    finished_at: LabTime,
}

impl LabRun {
    /// The run's trace.
    #[must_use]
    pub const fn trace(&self) -> &LogicalTrace {
        &self.trace
    }

    /// Failpoint coverage for the run.
    #[must_use]
    pub const fn coverage(&self) -> &CoverageReport {
        &self.coverage
    }

    /// The oracle report, when the region closed quiescent.
    #[must_use]
    pub const fn oracle(&self) -> Option<&OracleReport> {
        self.oracle.as_ref()
    }

    /// Steps executed.
    #[must_use]
    pub const fn steps(&self) -> usize {
        self.steps
    }

    /// Entropy draws consumed.
    #[must_use]
    pub const fn draws(&self) -> u64 {
        self.draws
    }

    /// Logical time at the end of the run.
    #[must_use]
    pub const fn finished_at(&self) -> LabTime {
        self.finished_at
    }
}

/// The deterministic laboratory.
pub struct Lab {
    config: LabConfig,
    clock: VirtualClock,
    entropy: SeededEntropy,
    failpoints: FailpointRegistry,
    trace: LogicalTrace,
    obligations: ObligationOracle,
    region: QuiescenceOracle,
    steps: usize,
    cancellation_phases: usize,
}

impl core::fmt::Debug for Lab {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Lab")
            .field("seed", &self.config.seed)
            .field("now", &self.clock.now())
            .field("steps", &self.steps)
            .field("events", &self.trace.len())
            .finish_non_exhaustive()
    }
}

impl Lab {
    /// Start a run.
    ///
    /// The opening trace event records the profile identity and seed, so a
    /// trace produced under a different profile can never silently compare
    /// equal to one produced under this profile.
    #[must_use]
    pub fn start(config: LabConfig) -> Self {
        let mut trace = LogicalTrace::new();
        trace.record(TraceEvent::RunStarted {
            profile: config.profile_identity().canonical_descriptor(),
            seed: config.seed,
        });
        let entropy = SeededEntropy::from_seed(config.seed);
        Self {
            config,
            clock: VirtualClock::new(),
            entropy,
            failpoints: FailpointRegistry::new(),
            trace,
            obligations: ObligationOracle::new(),
            region: QuiescenceOracle::new(),
            steps: 0,
            cancellation_phases: 0,
        }
    }

    /// The configuration this run is executing.
    #[must_use]
    pub const fn config(&self) -> &LabConfig {
        &self.config
    }

    /// The current logical instant.
    #[must_use]
    pub const fn now(&self) -> LabTime {
        self.clock.now()
    }

    /// The lab's entropy source. The only randomness a run may use.
    pub const fn entropy(&mut self) -> &mut SeededEntropy {
        &mut self.entropy
    }

    /// The failpoint registry.
    pub const fn failpoints(&mut self) -> &mut FailpointRegistry {
        &mut self.failpoints
    }

    /// The obligation oracle.
    pub const fn obligations(&mut self) -> &mut ObligationOracle {
        &mut self.obligations
    }

    /// The region quiescence oracle.
    pub const fn region(&mut self) -> &mut QuiescenceOracle {
        &mut self.region
    }

    /// The trace recorded so far.
    #[must_use]
    pub const fn trace(&self) -> &LogicalTrace {
        &self.trace
    }

    /// Fold a sub-run's caller-visible trace into this one.
    ///
    /// Used when a component runs its own driver and produces its own trace —
    /// [`AuthorityCampaign`](crate::store::AuthorityCampaign) is the case that
    /// exists today. The events are appended in order, so the composed trace
    /// stays a single ordered record rather than becoming a set of parallel
    /// logs a reader would have to interleave by hand.
    ///
    /// Only pass a trace that already excludes ground truth; this does not
    /// filter, because the component that produced the events is the one that
    /// knows which of them a caller could actually observe.
    pub fn absorb_trace(&mut self, other: &LogicalTrace) {
        for event in other.events() {
            self.trace.record(event.clone());
        }
    }

    /// Advance logical time, recording it.
    pub fn advance(&mut self, ticks: u64) -> LabTime {
        let now = self.clock.advance(ticks);
        self.trace
            .record(TraceEvent::ClockAdvanced { to: now, ticks });
        now
    }

    /// Take the next scheduled step, recording it.
    ///
    /// # Errors
    ///
    /// [`LabRefusal::ScheduleExhausted`] when the schedule is finished.
    pub fn step(&mut self) -> Result<StepId, LabRefusal> {
        let participant = self
            .config
            .schedule
            .order()
            .get(self.steps)
            .cloned()
            .ok_or_else(|| LabRefusal::ScheduleExhausted {
                declared: self.config.schedule.len(),
            })?;
        self.trace.record(TraceEvent::Stepped {
            at: self.clock.now(),
            participant: participant.clone(),
            position: self.steps,
        });
        self.steps += 1;
        Ok(participant)
    }

    /// Declare a failpoint.
    ///
    /// # Errors
    ///
    /// [`LabRefusal::FailpointRedeclared`] for a duplicate name.
    pub fn declare_failpoint(
        &mut self,
        id: FailpointId,
        description: impl Into<String>,
    ) -> Result<(), LabRefusal> {
        self.failpoints.declare(id, description)
    }

    /// Reach a failpoint, recording it and reporting whether it fires.
    ///
    /// # Errors
    ///
    /// [`LabRefusal::FailpointUndeclared`] for an unknown name.
    pub fn reach_failpoint(&mut self, id: &FailpointId) -> Result<bool, LabRefusal> {
        let fired = self.failpoints.should_fire(id)?;
        self.trace.record(TraceEvent::FailpointReached {
            at: self.clock.now(),
            point: id.clone(),
            fired,
        });
        Ok(fired)
    }

    /// Record the *declared* context for a work class.
    ///
    /// Reads the class's declared limits directly rather than resolving them
    /// into an absolute budget: a budget's poll quota does not depend on the
    /// clock, so resolving one at a fabricated instant to read that one field
    /// would put a fake time into the derivation for no gain. When a run has a
    /// live context, prefer
    /// [`record_minted_context`](Self::record_minted_context), which records
    /// what the request actually carried.
    pub fn record_context(&mut self, class: BudgetClass) {
        let limits = self.config.profile.budgets().limits_for(class);
        self.trace.record(TraceEvent::ContextDeclared {
            at: self.clock.now(),
            class: class.code(),
            poll_quota: limits.poll_quota,
        });
    }

    /// Record a context that was actually minted by the runtime.
    ///
    /// Both recorded facts come from the value, not from a constant beside it:
    /// the budget is read off the live [`Cx`], and the capability mask is the
    /// mask of that context's own capability row `C`, which is part of its
    /// type. Pass a context obtained from
    /// [`NodeRuntime::request_cx_narrowed`](fgit_runtime::NodeRuntime::request_cx_narrowed)
    /// and the recorded row is the row it actually carries.
    ///
    /// An earlier version of this method stamped a fixed `LabCaps` mask
    /// regardless of the context handed in, which made the trace's `caps` field
    /// a fabrication whenever the context was not in fact narrowed. The type
    /// parameter is what stops that from being expressible.
    pub fn record_minted_context<C>(&mut self, cx: &asupersync::cx::Cx<C>, class: BudgetClass)
    where
        C: CapSetRuntimeMask,
    {
        self.trace.record(TraceEvent::ContextMinted {
            at: self.clock.now(),
            class: class.code(),
            capability_mask: C::MASK.bits(),
            poll_quota: cx.budget().poll_quota,
        });
    }

    /// Record entry into a cancellation phase, in the fixed order.
    ///
    /// Cancellation is request → drain → finalize, and the order is the
    /// protocol rather than a convention: draining before requesting
    /// cancellation admits work that is about to be cancelled, and finalizing
    /// before draining strands in-flight effects. So this *enforces* the
    /// sequence instead of recording whatever it is handed — a trace that
    /// merely replays the order its caller happened to use proves nothing
    /// about the order the system requires.
    ///
    /// # Errors
    ///
    /// [`LabRefusal::CancellationPhaseOutOfOrder`] naming the expected phase.
    pub fn record_cancellation(&mut self, phase: &'static str) -> Result<(), LabRefusal> {
        let expected = CANCELLATION_PHASES
            .get(self.cancellation_phases)
            .copied()
            .unwrap_or("none");
        if expected != phase {
            return Err(LabRefusal::CancellationPhaseOutOfOrder {
                expected,
                actual: phase,
            });
        }
        self.cancellation_phases += 1;
        self.trace.record(TraceEvent::CancellationPhase {
            at: self.clock.now(),
            phase,
        });
        Ok(())
    }

    /// Record an injected fault.
    pub fn record_fault(&mut self, fault: impl Into<String>) {
        self.trace.record(TraceEvent::FaultInjected {
            at: self.clock.now(),
            fault: fault.into(),
        });
    }

    /// Record an observed outcome arm.
    pub fn record_outcome(&mut self, participant: &StepId, outcome: &'static str) {
        self.trace.record(TraceEvent::OutcomeObserved {
            at: self.clock.now(),
            participant: participant.clone(),
            outcome,
        });
    }

    /// Whether the lab can honestly certify a class as replayable.
    ///
    /// # Errors
    ///
    /// [`LabRefusal::UnavailableClassNotReplayable`] for every native or
    /// wall-clock class. This is the evidence boundary as executable code: the
    /// harness refuses to label an unavailable class replayable.
    pub const fn classify(class: ReplayClass) -> Result<ReplayClass, LabRefusal> {
        if class.is_lab_replayable() {
            Ok(class)
        } else {
            Err(LabRefusal::UnavailableClassNotReplayable {
                class: class.code(),
            })
        }
    }

    /// Finish the run, closing the region and requiring quiescence.
    ///
    /// # Errors
    ///
    /// [`LabRefusal::RegionNotQuiescent`] if obligations are outstanding.
    pub fn finish(mut self) -> Result<LabRun, LabRefusal> {
        let report = self.region.close(&self.obligations)?;
        self.trace.record(TraceEvent::RegionClosed {
            at: self.clock.now(),
            outstanding: self.obligations.outstanding(),
        });
        self.trace.record(TraceEvent::RunFinished {
            at: self.clock.now(),
            steps: self.steps,
            draws: self.entropy.draws(),
        });
        Ok(LabRun {
            trace: self.trace,
            coverage: self.failpoints.coverage(),
            oracle: Some(report),
            steps: self.steps,
            draws: self.entropy.draws(),
            finished_at: self.clock.now(),
        })
    }

    /// Finish without requiring quiescence, for a run that is *studying* a
    /// leak rather than asserting its absence.
    ///
    /// The region-closed event still records the true outstanding count, so a
    /// trace produced this way cannot be mistaken for a clean one.
    #[must_use]
    pub fn finish_reporting_leaks(mut self) -> LabRun {
        let outstanding = self.obligations.outstanding();
        self.trace.record(TraceEvent::RegionClosed {
            at: self.clock.now(),
            outstanding,
        });
        self.trace.record(TraceEvent::RunFinished {
            at: self.clock.now(),
            steps: self.steps,
            draws: self.entropy.draws(),
        });
        LabRun {
            trace: self.trace,
            coverage: self.failpoints.coverage(),
            oracle: None,
            steps: self.steps,
            draws: self.entropy.draws(),
            finished_at: self.clock.now(),
        }
    }

    /// Run `body` twice under the same config and require identical traces.
    ///
    /// This is the acceptance property as an executable check: identical
    /// source, profile, seed, schedule, and input must yield byte-identical
    /// logical traces. A campaign calls this on its own scenario rather than
    /// trusting that determinism held.
    ///
    /// # Errors
    ///
    /// [`LabRefusal::ScheduleNondeterministic`] naming the seed and the first
    /// differing event index.
    pub fn verify_replay<F>(config: &LabConfig, mut body: F) -> Result<LabRun, LabRefusal>
    where
        F: FnMut(&mut Self) -> Result<(), LabRefusal>,
    {
        let first = {
            let mut lab = Self::start(config.clone());
            body(&mut lab)?;
            lab.finish_reporting_leaks()
        };
        let second = {
            let mut lab = Self::start(config.clone());
            body(&mut lab)?;
            lab.finish_reporting_leaks()
        };

        if let Some(mismatch) = second.trace.first_divergence(&first.trace) {
            return Err(LabRefusal::ScheduleNondeterministic {
                seed: config.seed,
                event_index: mismatch.event_index,
            });
        }
        Ok(first)
    }
}

/// The cancellation phases, in the order the runtime profile fixes.
pub const CANCELLATION_PHASES: [&str; 3] = ["request", "drain", "finalize"];

/// The runtime capability mask a lab context carries.
#[must_use]
pub const fn lab_capability_mask() -> CapMask {
    <LabCaps as CapSetRuntimeMask>::MASK
}

#[cfg(test)]
mod tests {
    use asupersync::cx::cap::CapSetRuntimeMask;

    use super::*;
    use crate::verdict::Settlement;

    fn participants() -> Vec<StepId> {
        vec![StepId::new("writer"), StepId::new("reader")]
    }

    fn config(seed: u64) -> LabConfig {
        LabConfig::new(
            seed,
            LabSchedule::round_robin(participants(), 2).expect("valid"),
            HazardScript::seeded(seed, 16, 2, 2),
        )
    }

    fn scenario(lab: &mut Lab) -> Result<(), LabRefusal> {
        lab.declare_failpoint(
            FailpointId::new("authority.cas.after_effect"),
            "endpoint dies after the CAS applied",
        )?;
        lab.record_context(BudgetClass::Request);
        while !lab.trace().is_empty() && lab.steps < lab.config().schedule().len() {
            let participant = lab.step()?;
            lab.advance(2);
            lab.region().task_started();
            lab.obligations().opened("outbox/1");
            let fired = lab.reach_failpoint(&FailpointId::new("authority.cas.after_effect"))?;
            lab.record_outcome(&participant, if fired { "cancelled" } else { "success" });
            lab.obligations().settled("outbox/1", Settlement::Committed);
            lab.region().task_finished();
        }
        for phase in CANCELLATION_PHASES {
            lab.record_cancellation(phase)?;
        }
        Ok(())
    }

    #[test]
    fn identical_inputs_yield_byte_identical_traces() {
        // The headline acceptance property.
        let config = config(4242);
        let first = {
            let mut lab = Lab::start(config.clone());
            scenario(&mut lab).expect("scenario runs");
            lab.finish().expect("quiescent")
        };
        let second = {
            let mut lab = Lab::start(config);
            scenario(&mut lab).expect("scenario runs");
            lab.finish().expect("quiescent")
        };

        assert_eq!(
            first.trace().canonical_bytes(),
            second.trace().canonical_bytes()
        );
        assert_eq!(first.trace().fingerprint(), second.trace().fingerprint());
        assert_eq!(first.steps(), second.steps());
        assert_eq!(first.draws(), second.draws());
        assert_eq!(first.finished_at(), second.finished_at());
    }

    #[test]
    fn verify_replay_accepts_a_deterministic_scenario() {
        let config = config(11);
        let run = Lab::verify_replay(&config, scenario).expect("the scenario is deterministic");
        assert!(run.trace().len() > 4);
    }

    #[test]
    fn verify_replay_catches_a_nondeterministic_scenario() {
        // Planted negative: a scenario whose trace depends on something the
        // config does not pin. A counter outside the lab stands in for any
        // ambient source a subject might reach for.
        use std::cell::Cell;
        thread_local! {
            static COUNTER: Cell<u64> = const { Cell::new(0) };
        }

        let config = config(5);
        let refusal = Lab::verify_replay(&config, |lab| {
            let drift = COUNTER.with(|counter| {
                let value = counter.get();
                counter.set(value + 1);
                value
            });
            lab.advance(drift);
            Ok(())
        })
        .expect_err("a run that depends on outside state is not replayable");

        match refusal {
            LabRefusal::ScheduleNondeterministic { seed, event_index } => {
                assert_eq!(seed, 5);
                // Event 0 is RunStarted, identical in both; the drift shows at 1.
                assert_eq!(event_index, 1);
            }
            other => panic!("expected nondeterminism, got {other:?}"),
        }
        assert!(refusal.indicts_subject());
    }

    #[test]
    fn a_different_seed_produces_a_different_trace() {
        let run = |seed| {
            let mut lab = Lab::start(config(seed));
            scenario(&mut lab).expect("runs");
            lab.finish().expect("quiescent").trace().canonical_bytes()
        };
        // The hazard script differs by seed, and the config line is in the
        // opening event, so seeds are distinguishable in the trace itself.
        assert_ne!(run(1), run(2));
    }

    #[test]
    fn the_lab_capability_row_masks_runtime_time_and_randomness() {
        let mask = lab_capability_mask();
        let spawn = <CapSet<true, false, false, false, false> as CapSetRuntimeMask>::MASK;
        let time = <CapSet<false, true, false, false, false> as CapSetRuntimeMask>::MASK;
        let random = <CapSet<false, false, true, false, false> as CapSetRuntimeMask>::MASK;
        let io = <CapSet<false, false, false, true, false> as CapSetRuntimeMask>::MASK;

        assert!(mask.contains(spawn), "the lab still spawns work");
        assert!(mask.contains(io), "the lab still performs logical I/O");
        // The two ambient sources the lab owns are removed outright.
        assert!(!mask.contains(time), "runtime TIME must be masked");
        assert!(!mask.contains(random), "runtime RANDOM must be masked");
    }

    #[test]
    fn the_lab_capability_profile_is_a_narrowing_of_node_root() {
        let profile = config(1)
            .capability_profile()
            .expect("narrowing node root can never widen");
        assert_eq!(profile.runtime_mask(), lab_capability_mask());
        assert_eq!(profile.ownership(), Ownership::Owned);
        // Narrowing is monotone: the lab mask is contained in node root's.
        assert!(CapMask::all().contains(profile.runtime_mask()));
    }

    #[test]
    fn native_classes_are_refused_as_replayable() {
        // The evidence boundary, enforced rather than documented.
        for class in [
            ReplayClass::NativeWorkerParking,
            ReplayClass::NativeIo,
            ReplayClass::NativeBlockingPool,
            ReplayClass::NativeSignals,
            ReplayClass::NativeProcessReaping,
            ReplayClass::WallClockTiming,
        ] {
            let refusal =
                Lab::classify(class).expect_err("the lab must not certify a native class");
            assert_eq!(
                refusal,
                LabRefusal::UnavailableClassNotReplayable {
                    class: class.code()
                }
            );
            assert!(!class.is_lab_replayable());
        }
    }

    #[test]
    fn logical_classes_are_accepted_as_replayable() {
        // The paired permitted twin: what the lab genuinely does cover.
        for class in [
            ReplayClass::LogicalInterleaving,
            ReplayClass::CancellationOrdering,
            ReplayClass::BudgetPropagation,
            ReplayClass::FaultComposition,
            ReplayClass::ObligationSettlement,
        ] {
            assert_eq!(Lab::classify(class).expect("lab-replayable"), class);
            assert!(class.is_lab_replayable());
        }
    }

    #[test]
    fn every_declared_class_is_decided_one_way_or_the_other() {
        // No class may be silently unclassified: each is either covered or
        // explicitly refused.
        let mut replayable = 0;
        let mut refused = 0;
        for class in ReplayClass::all() {
            match Lab::classify(class) {
                Ok(_) => replayable += 1,
                Err(_) => refused += 1,
            }
        }
        assert_eq!(replayable, 5);
        assert_eq!(refused, 6);
        assert_eq!(replayable + refused, ReplayClass::all().len());
    }

    #[test]
    fn a_declared_context_records_no_capability_mask() {
        // `record_context` reports the profile's DECLARED limits. Nothing was
        // minted, so there is no context whose row could be reported, and
        // stamping one would describe a context that does not exist. This is
        // the audit finding: a mask beside a value it does not come from is a
        // fabricated field.
        let mut lab = Lab::start(config(3));
        lab.record_context(BudgetClass::Request);
        lab.record_context(BudgetClass::Parser);

        let text = String::from_utf8(lab.trace().canonical_bytes()).expect("utf-8");
        assert!(text.contains("context_declared"));
        assert!(text.contains("class=request"));
        assert!(text.contains("class=parser"));
        assert!(
            !text.contains("caps="),
            "a declared context must not carry a capability mask: {text}"
        );
        // Finite budget, present in the trace rather than assumed.
        assert!(!text.contains("poll_quota=4294967295"));
    }

    #[test]
    fn a_minted_context_records_the_row_it_actually_carries() {
        // The paired positive: a context genuinely narrowed through
        // `request_cx_narrowed` records ITS row, read from the context's type
        // rather than from a constant standing beside it.
        use std::time::Duration;

        let config = config(3);
        let node = config.build_runtime().expect("builds");
        let narrowed = node.request_cx_narrowed::<LabCaps>(BudgetClass::Request);

        let mut lab = Lab::start(config);
        lab.record_minted_context(narrowed.as_ref(), BudgetClass::Request);

        let text = String::from_utf8(lab.trace().canonical_bytes()).expect("utf-8");
        assert!(text.contains(&format!("caps={:#06b}", lab_capability_mask().bits())));
        assert!(!text.contains("poll_quota=4294967295"));

        // And the row really is narrower than node root, so the recorded value
        // is a fact about the context rather than a restatement of the default.
        assert!(CapMask::all().contains(lab_capability_mask()));
        assert_ne!(lab_capability_mask(), CapMask::all());

        drop(narrowed);
        assert!(node.join_root(Duration::from_secs(5)));
    }

    #[test]
    fn a_real_runtime_owned_context_appears_in_the_trace() {
        // The acceptance line asks for a runtime-owned Cx in traces, not a
        // computed stand-in. This mints one through fgit-runtime's production
        // factory and records the budget it actually carries.
        use std::time::Duration;

        let config = config(31);
        let node = config
            .build_runtime()
            .expect("the deterministic profile builds");
        let cx = node.request_cx(BudgetClass::Request);
        let live_quota = cx.budget().poll_quota;

        let mut lab = Lab::start(config);
        lab.record_minted_context(&cx, BudgetClass::Request);

        let text = String::from_utf8(lab.trace().canonical_bytes()).expect("utf-8");
        assert!(text.contains(&format!("poll_quota={live_quota}")));
        assert!(text.contains("class=request"));
        // A real request context is bounded, which is what makes it safe to
        // hand to a subject under test.
        assert!(live_quota < u32::MAX);
        assert!(cx.budget().deadline.is_some());

        drop(cx);
        assert!(node.join_root(Duration::from_secs(5)));
    }

    #[test]
    fn the_recorded_budget_matches_the_profile_for_every_class() {
        use std::time::Duration;

        let config = config(32);
        let node = config.build_runtime().expect("builds");
        for class in BudgetClass::finite_classes() {
            let cx = node.request_cx(class);
            let mut lab = Lab::start(config.clone());
            lab.record_minted_context(&cx, class);
            let text = String::from_utf8(lab.trace().canonical_bytes()).expect("utf-8");
            assert!(
                text.contains(&format!("class={}", class.code())),
                "class {} missing from trace",
                class.code()
            );
            assert!(!text.contains("poll_quota=4294967295"));
            drop(cx);
        }
        assert!(node.join_root(Duration::from_secs(5)));
    }

    #[test]
    fn the_cancellation_phase_order_is_enforced_not_merely_replayed() {
        // The audit finding this answers: the old version of this test wrote
        // the phases in order and then asserted they were in order, which is a
        // tautology — it would have passed against a lab that recorded whatever
        // it was handed. The property worth asserting is that the lab REFUSES
        // an order the protocol does not allow.
        let mut lab = Lab::start(config(3));

        // Independent expectation, written out rather than taken from the
        // constant under test.
        assert_eq!(CANCELLATION_PHASES, ["request", "drain", "finalize"]);

        // Skipping drain is refused, naming what was expected.
        lab.record_cancellation("request")
            .expect("request is first");
        let refusal = lab
            .record_cancellation("finalize")
            .expect_err("finalize cannot precede drain");
        assert_eq!(
            refusal,
            LabRefusal::CancellationPhaseOutOfOrder {
                expected: "drain",
                actual: "finalize",
            }
        );
        assert!(refusal.indicts_subject());

        // Starting out of order is refused too.
        let mut fresh = Lab::start(config(3));
        assert_eq!(
            fresh
                .record_cancellation("drain")
                .expect_err("drain cannot be first"),
            LabRefusal::CancellationPhaseOutOfOrder {
                expected: "request",
                actual: "drain",
            }
        );

        // Paired permitted case: the correct order proceeds and reaches the
        // trace in that order.
        let mut ok = Lab::start(config(3));
        for phase in CANCELLATION_PHASES {
            ok.record_cancellation(phase).expect("in order");
        }
        let text = String::from_utf8(ok.trace().canonical_bytes()).expect("utf-8");
        let at = |p: &str| text.find(&format!("phase={p}")).expect("phase recorded");
        assert!(at("request") < at("drain"));
        assert!(at("drain") < at("finalize"));

        // And a fourth phase has nowhere to go.
        assert!(ok.record_cancellation("request").is_err());
    }

    #[test]
    fn finishing_with_an_outstanding_obligation_is_refused() {
        let mut lab = Lab::start(config(9));
        lab.obligations().opened("secret-lease/1");

        let refusal = lab
            .finish()
            .expect_err("a leaked obligation must not close clean");
        assert_eq!(refusal, LabRefusal::RegionNotQuiescent { outstanding: 1 });
    }

    #[test]
    fn a_leak_study_run_records_the_true_outstanding_count() {
        // The paired permitted case: studying a leak is allowed, but the trace
        // says so and no oracle report is produced.
        let mut lab = Lab::start(config(9));
        lab.obligations().opened("secret-lease/1");
        let run = lab.finish_reporting_leaks();

        assert!(run.oracle().is_none());
        let text = String::from_utf8(run.trace().canonical_bytes()).expect("utf-8");
        assert!(text.contains("region_closed\tt0\toutstanding=1"));
    }

    #[test]
    fn stepping_past_the_schedule_is_refused() {
        let mut lab = Lab::start(config(1));
        for _ in 0..lab.config().schedule().len() {
            lab.step().expect("in range");
        }
        let refusal = lab.step().expect_err("the schedule is exhausted");
        assert_eq!(refusal, LabRefusal::ScheduleExhausted { declared: 4 });
    }

    #[test]
    fn the_config_line_is_the_whole_reproduction_recipe() {
        let line = config(777).canonical_line();
        assert!(line.starts_with("fgit-lab-config-v1|seed=777"));
        assert!(line.contains("class=deterministic"));
        assert!(line.contains("fgit-lab-schedule-v1"));
        assert!(line.contains("fgit-lab-hazards-v1"));
        // Stable across renderings.
        assert_eq!(line, config(777).canonical_line());
        assert_ne!(line, config(778).canonical_line());
    }

    #[test]
    fn a_lab_run_always_uses_the_deterministic_profile() {
        // A parking multi-worker profile would not be replayable, so the
        // config forces the pinned one rather than trusting the caller.
        let identity = config(1).profile_identity();
        assert_eq!(identity.worker_threads, 1);
        assert!(!identity.enable_parking);
        assert!(!identity.host_derived_parallelism);
    }
}
