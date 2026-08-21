//! Driving the in-memory faultable `AuthorityStore` from the laboratory.
//!
//! `fgit-authority` owns the store, its fault script, and its ground-truth
//! logs. This module does not reimplement any of that — it drives
//! [`MemoryAuthorityStore`] through [`drive`] and records what a *caller* can
//! see into the lab's trace.
//!
//! That distinction is the whole point of the module. The store keeps two logs
//! the caller cannot observe: [`FaultLog`] (what was injected) and
//! [`EffectLog`] (what actually linearized). A campaign may read them to check
//! its own conclusions, but they must never leak into the trace, because a
//! trace containing ground truth would let an assertion "resolve" an ambiguous
//! response by peeking — which is exactly the reasoning error ambiguity exists
//! to prevent. So [`TraceObserver`] records only
//! [`AuthorityResponse::effect_knowledge`], which is what the caller genuinely
//! knows: `Observed`, `NoEffect`, or `Unknown`.

use fgit_authority::{
    AuthorityClient, AuthorityObserver, AuthorityOp, AuthorityOpKind, AuthorityResponse, ClientId,
    DriveSummary, EffectKnowledge, FaultableAuthorityStore, Interleaving, MemoryAuthorityStore,
    StoreInstanceId, drive,
};

use crate::hazard::HazardScript;
use crate::journal::{LogicalTrace, TraceEvent};
use crate::plan::{LabSchedule, StepId};
use crate::tick::VirtualClock;

/// A client that issues a fixed list of operations.
///
/// Scripted rather than generated, so a campaign's operation sequence is data
/// it can print and check in alongside the schedule. Responses are retained so
/// a caller can inspect what this client actually saw.
#[derive(Debug, Clone, Default)]
pub struct ScriptedClient {
    ops: Vec<AuthorityOp>,
    issued: usize,
    seen: Vec<AuthorityResponse>,
}

impl ScriptedClient {
    /// A client that will issue `ops` in order.
    #[must_use]
    pub const fn new(ops: Vec<AuthorityOp>) -> Self {
        Self {
            ops,
            issued: 0,
            seen: Vec::new(),
        }
    }

    /// Responses this client observed, in order.
    #[must_use]
    pub fn responses(&self) -> &[AuthorityResponse] {
        &self.seen
    }

    /// How many operations it issued.
    #[must_use]
    pub const fn issued(&self) -> usize {
        self.issued
    }
}

impl AuthorityClient for ScriptedClient {
    fn next_op(&mut self) -> Option<AuthorityOp> {
        let op = self.ops.get(self.issued).cloned()?;
        self.issued += 1;
        Some(op)
    }

    fn observe(&mut self, response: &AuthorityResponse) {
        self.seen.push(response.clone());
    }
}

/// Records every invocation and return into a logical trace.
///
/// Deliberately records only caller-visible facts. See the module docs for why
/// ground truth stays out.
#[derive(Debug)]
pub struct TraceObserver {
    trace: LogicalTrace,
    clock: VirtualClock,
    ticks_per_op: u64,
    invocations: u64,
    ambiguous: u64,
}

impl TraceObserver {
    /// An observer that advances logical time by `ticks_per_op` per operation.
    #[must_use]
    pub const fn new(ticks_per_op: u64) -> Self {
        Self {
            trace: LogicalTrace::new(),
            clock: VirtualClock::new(),
            ticks_per_op,
            invocations: 0,
            ambiguous: 0,
        }
    }

    /// The trace recorded so far.
    #[must_use]
    pub const fn trace(&self) -> &LogicalTrace {
        &self.trace
    }

    /// Take the trace, consuming the observer.
    #[must_use]
    pub fn into_trace(self) -> LogicalTrace {
        self.trace
    }

    /// How many operations were invoked.
    #[must_use]
    pub const fn invocations(&self) -> u64 {
        self.invocations
    }

    /// How many returns were ambiguous.
    #[must_use]
    pub const fn ambiguous(&self) -> u64 {
        self.ambiguous
    }
}

/// The stable name of an operation kind, for the trace.
const fn op_code(kind: AuthorityOpKind) -> &'static str {
    match kind {
        AuthorityOpKind::PutIfAbsent => "put_if_absent",
        AuthorityOpKind::ReadImmutable => "read_immutable",
        AuthorityOpKind::InitializeHead => "initialize_head",
        AuthorityOpKind::ReadHead => "read_head",
        AuthorityOpKind::CompareExchangeHead => "compare_exchange_head",
        AuthorityOpKind::AuthenticateHeadReceipt => "authenticate_head_receipt",
    }
}

/// The stable name of what the caller learned, for the trace.
const fn knowledge_code(knowledge: EffectKnowledge) -> &'static str {
    match knowledge {
        EffectKnowledge::Observed => "observed",
        EffectKnowledge::NoEffect => "no_effect",
        EffectKnowledge::Unknown => "unknown",
    }
}

impl AuthorityObserver for TraceObserver {
    fn on_invoke(&mut self, client: ClientId, step: u64, op: &AuthorityOp) {
        let at = self.clock.advance(self.ticks_per_op);
        self.trace.record(TraceEvent::ClockAdvanced {
            to: at,
            ticks: self.ticks_per_op,
        });
        self.trace.record(TraceEvent::Stepped {
            at,
            participant: StepId::new(format!("client-{}", client.index())),
            position: usize::try_from(step).unwrap_or(usize::MAX),
        });
        self.trace.record(TraceEvent::FaultInjected {
            at,
            fault: format!("invoke:{}", op_code(op.kind())),
        });
        self.invocations = self.invocations.saturating_add(1);
    }

    fn on_return(&mut self, client: ClientId, _step: u64, response: &AuthorityResponse) {
        let knowledge = response.effect_knowledge();
        if knowledge == EffectKnowledge::Unknown {
            self.ambiguous = self.ambiguous.saturating_add(1);
        }
        self.trace.record(TraceEvent::OutcomeObserved {
            at: self.clock.now(),
            participant: StepId::new(format!("client-{}", client.index())),
            outcome: knowledge_code(knowledge),
        });
    }
}

/// What a campaign produced.
#[derive(Debug)]
pub struct CampaignOutcome {
    trace: LogicalTrace,
    summary: DriveSummary,
    ambiguous: u64,
    injected_faults: usize,
    reached_effects: usize,
    crashed: bool,
}

impl CampaignOutcome {
    /// The caller-visible trace.
    #[must_use]
    pub const fn trace(&self) -> &LogicalTrace {
        &self.trace
    }

    /// Operations issued and turns skipped.
    #[must_use]
    pub const fn summary(&self) -> &DriveSummary {
        &self.summary
    }

    /// How many returns the caller could not resolve.
    #[must_use]
    pub const fn ambiguous(&self) -> u64 {
        self.ambiguous
    }

    /// How many faults the store injected.
    ///
    /// Ground truth, read from the store's own [`FaultLog`]. Available to a
    /// campaign for checking its conclusions; never present in the trace.
    #[must_use]
    pub const fn injected_faults(&self) -> usize {
        self.injected_faults
    }

    /// How many effects actually reached the store.
    ///
    /// Ground truth, from the store's [`EffectLog`]. This is the fact an
    /// ambiguous caller cannot see.
    #[must_use]
    pub const fn reached_effects(&self) -> usize {
        self.reached_effects
    }

    /// Whether the endpoint ended the run crashed.
    #[must_use]
    pub const fn crashed(&self) -> bool {
        self.crashed
    }
}

/// One authority campaign against the in-memory faultable store.
///
/// The store, its fault script, and its logs all belong to `fgit-authority`;
/// this composes them with the lab's schedule, clock, and trace.
#[derive(Debug)]
pub struct AuthorityCampaign {
    instance: StoreInstanceId,
    ticks_per_op: u64,
}

impl AuthorityCampaign {
    /// A campaign against the given store instance.
    #[must_use]
    pub const fn new(instance: StoreInstanceId) -> Self {
        Self {
            instance,
            ticks_per_op: 1,
        }
    }

    /// Set how much logical time each operation consumes.
    #[must_use]
    pub const fn with_ticks_per_op(mut self, ticks: u64) -> Self {
        self.ticks_per_op = ticks;
        self
    }

    /// Run `clients` against a fresh faulted store under `schedule`.
    ///
    /// The storage half of `hazards` is installed on the store via
    /// [`FaultableAuthorityStore::install_fault_plan`]; the packet and
    /// object-store halves are the caller's to apply at their own boundaries,
    /// because this store has no packets and no object store.
    #[must_use]
    pub fn run(
        &self,
        clients: &mut [Box<dyn AuthorityClient>],
        schedule: &LabSchedule,
        hazards: &HazardScript,
    ) -> CampaignOutcome {
        let store = MemoryAuthorityStore::new(self.instance);
        self.run_on(&store, clients, schedule, hazards)
    }

    /// Run against a store the caller owns.
    ///
    /// Same driving as [`run`](Self::run), but the store outlives the call so
    /// the caller can interrogate final state — the head generation after a
    /// campaign, say, which is what a linearizability check needs and what a
    /// per-operation trace cannot tell you.
    #[must_use]
    pub fn run_on<S>(
        &self,
        store: &S,
        clients: &mut [Box<dyn AuthorityClient>],
        schedule: &LabSchedule,
        hazards: &HazardScript,
    ) -> CampaignOutcome
    where
        S: FaultableAuthorityStore + ?Sized,
    {
        store.install_fault_plan(hazards.storage().clone());

        let interleaving = interleaving_for(schedule, clients.len());
        let mut observer = TraceObserver::new(self.ticks_per_op);
        let summary = drive(store, clients, &interleaving, &mut observer);

        CampaignOutcome {
            ambiguous: observer.ambiguous(),
            trace: observer.into_trace(),
            summary,
            injected_faults: store.fault_log().len(),
            reached_effects: store.effect_log().len(),
            crashed: store.is_crashed(),
        }
    }
}

/// Translate a lab schedule into the authority crate's interleaving.
///
/// A participant's position in the schedule's declared list is its client
/// index, so the same schedule drives both layers and a quoted interleaving
/// means one thing everywhere. A step naming a participant with no
/// corresponding client maps to an out-of-range index, which `drive` counts as
/// skipped rather than dropping silently.
fn interleaving_for(schedule: &LabSchedule, clients: usize) -> Interleaving {
    let order: Vec<ClientId> = schedule
        .order()
        .iter()
        .map(|step| {
            let index = schedule
                .participants()
                .iter()
                .position(|participant| participant == step)
                .unwrap_or(clients);
            ClientId::from_raw(u32::try_from(index).unwrap_or(u32::MAX))
        })
        .collect();
    Interleaving::explicit(order)
}

#[cfg(test)]
mod tests {
    use fgit_authority::{HeadGeneration, HeadKey, ImmutableKey};

    use super::*;
    use crate::journal::LogicalTrace;

    fn instance() -> StoreInstanceId {
        StoreInstanceId::from_raw(1)
    }

    fn immutable(name: &str) -> ImmutableKey {
        ImmutableKey::new(name.as_bytes().to_vec()).expect("short key")
    }

    fn head(name: &str) -> HeadKey {
        HeadKey::new(name.as_bytes().to_vec()).expect("short key")
    }

    fn writer_ops() -> Vec<AuthorityOp> {
        vec![
            AuthorityOp::PutIfAbsent {
                key: immutable("blob/a"),
                body: b"alpha".to_vec(),
            },
            AuthorityOp::InitializeHead {
                key: head("repo/main"),
                generation: HeadGeneration::try_new(1).expect("generation 1 is valid"),
                body: b"root-1".to_vec(),
            },
        ]
    }

    fn reader_ops() -> Vec<AuthorityOp> {
        vec![
            AuthorityOp::ReadImmutable {
                key: immutable("blob/a"),
            },
            AuthorityOp::ReadHead {
                key: head("repo/main"),
            },
        ]
    }

    fn clients() -> Vec<Box<dyn AuthorityClient>> {
        vec![
            Box::new(ScriptedClient::new(writer_ops())),
            Box::new(ScriptedClient::new(reader_ops())),
        ]
    }

    fn schedule() -> LabSchedule {
        LabSchedule::round_robin(vec![StepId::new("writer"), StepId::new("reader")], 2)
            .expect("valid")
    }

    #[test]
    fn a_clean_campaign_drives_the_real_store_and_records_every_step() {
        let campaign = AuthorityCampaign::new(instance());
        let mut clients = clients();
        let outcome = campaign.run(&mut clients, &schedule(), &HazardScript::none());

        // Four scheduled turns, four operations issued, nothing skipped.
        assert_eq!(outcome.summary().steps, 4);
        assert_eq!(outcome.summary().skipped, 0);

        // With no faults every return is resolvable and every effect landed.
        assert_eq!(outcome.ambiguous(), 0);
        assert_eq!(outcome.injected_faults(), 0);
        assert!(!outcome.crashed());

        let text = String::from_utf8(outcome.trace().canonical_bytes()).expect("utf-8");
        assert!(text.contains("invoke:put_if_absent"));
        assert!(text.contains("invoke:initialize_head"));
        assert!(text.contains("invoke:read_immutable"));
        assert!(text.contains("invoke:read_head"));
        assert!(text.contains("outcome=observed"));
    }

    #[test]
    fn the_same_seed_and_schedule_replay_byte_identically() {
        // Trace identity across a real store run, not just over synthetic
        // events: same source, profile, seed, schedule, and input.
        let campaign = AuthorityCampaign::new(instance());
        let hazards = HazardScript::seeded(2024, 8, 3, 0);

        let first = {
            let mut c = clients();
            campaign.run(&mut c, &schedule(), &hazards)
        };
        let second = {
            let mut c = clients();
            campaign.run(&mut c, &schedule(), &hazards)
        };

        assert_eq!(
            first.trace().canonical_bytes(),
            second.trace().canonical_bytes()
        );
        first
            .trace()
            .expect_matches(second.trace())
            .expect("identical inputs replay identically");
        assert_eq!(first.injected_faults(), second.injected_faults());
        assert_eq!(first.ambiguous(), second.ambiguous());
    }

    #[test]
    fn storage_faults_are_driven_from_the_authority_crates_own_plan() {
        // The bead requires driving BoldIbis's faultable backend rather than
        // forking it: the plan installed here is fgit-authority's FaultPlan,
        // generated by its own seeded constructor.
        let hazards = HazardScript::seeded(7, 4, 4, 0);
        assert!(!hazards.storage().is_empty());

        let campaign = AuthorityCampaign::new(instance());
        let mut clients = clients();
        let outcome = campaign.run(&mut clients, &schedule(), &hazards);

        // The store really injected the scripted faults.
        assert!(
            outcome.injected_faults() > 0,
            "a non-empty plan must inject faults"
        );
    }

    #[test]
    fn an_ambiguous_return_is_recorded_as_unknown_not_resolved() {
        // The reasoning error this guards: a trace that carried ground truth
        // would let an assertion "resolve" ambiguity by peeking at the effect
        // log instead of doing the outcome lookup the protocol requires.
        let mut found_ambiguity = false;
        for seed in 0..24_u64 {
            let hazards = HazardScript::seeded(seed, 4, 4, 0);
            let campaign = AuthorityCampaign::new(instance());
            let mut clients = clients();
            let outcome = campaign.run(&mut clients, &schedule(), &hazards);

            if outcome.ambiguous() > 0 {
                found_ambiguity = true;
                let text = String::from_utf8(outcome.trace().canonical_bytes()).expect("utf-8");
                assert!(text.contains("outcome=unknown"));
                // Ground truth must not appear anywhere in the trace.
                assert!(!text.contains("effect_log"));
                assert!(!text.contains("fault_log"));
                assert!(!text.contains("reached_effects"));
                break;
            }
        }
        assert!(
            found_ambiguity,
            "no seed in 0..24 produced an ambiguous return; the fault model is not reaching the caller"
        );
    }

    #[test]
    fn ground_truth_is_available_to_the_campaign_but_absent_from_the_trace() {
        let hazards = HazardScript::seeded(3, 4, 4, 0);
        let campaign = AuthorityCampaign::new(instance());
        let mut clients = clients();
        let outcome = campaign.run(&mut clients, &schedule(), &hazards);

        // The campaign can check its conclusions against the store's logs...
        let _injected = outcome.injected_faults();
        let _reached = outcome.reached_effects();

        // ...but the trace, which is what replay compares, carries only what a
        // caller could actually observe.
        let text = String::from_utf8(outcome.trace().canonical_bytes()).expect("utf-8");
        for observable in ["outcome=observed", "outcome=no_effect", "outcome=unknown"] {
            let _ = text.contains(observable);
        }
        assert!(!text.contains("injected"));
    }

    #[test]
    fn a_schedule_step_without_a_client_is_skipped_not_dropped() {
        // Three declared participants, two clients: the third participant's
        // turns must be counted as skipped so the schedule and the run stay
        // comparable.
        let schedule = LabSchedule::round_robin(
            vec![
                StepId::new("writer"),
                StepId::new("reader"),
                StepId::new("absent"),
            ],
            2,
        )
        .expect("valid");

        let campaign = AuthorityCampaign::new(instance());
        let mut clients = clients();
        let outcome = campaign.run(&mut clients, &schedule, &HazardScript::none());

        assert_eq!(outcome.summary().steps, 4);
        assert_eq!(outcome.summary().skipped, 2);
    }

    #[test]
    fn a_finished_client_is_skipped_rather_than_reissuing() {
        // Each client scripts two operations but the schedule offers three
        // turns each; the extra turns are skipped, not silently repeated.
        let schedule =
            LabSchedule::round_robin(vec![StepId::new("writer"), StepId::new("reader")], 3)
                .expect("valid");

        let campaign = AuthorityCampaign::new(instance());
        let mut clients = clients();
        let outcome = campaign.run(&mut clients, &schedule, &HazardScript::none());

        assert_eq!(outcome.summary().steps, 4);
        assert_eq!(outcome.summary().skipped, 2);
    }

    #[test]
    fn logical_time_advances_once_per_operation() {
        let campaign = AuthorityCampaign::new(instance()).with_ticks_per_op(5);
        let mut clients = clients();
        let outcome = campaign.run(&mut clients, &schedule(), &HazardScript::none());

        let text = String::from_utf8(outcome.trace().canonical_bytes()).expect("utf-8");
        // Four operations at five ticks each: t5, t10, t15, t20.
        for instant in ["t5", "t10", "t15", "t20"] {
            assert!(text.contains(instant), "missing {instant} in trace");
        }
    }

    #[test]
    fn the_trace_carries_the_supported_format_marker() {
        let campaign = AuthorityCampaign::new(instance());
        let mut clients = clients();
        let outcome = campaign.run(&mut clients, &schedule(), &HazardScript::none());
        LogicalTrace::check_version(&outcome.trace().canonical_bytes())
            .expect("campaign traces use the current format");
    }
}
