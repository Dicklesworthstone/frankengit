//! Named runtime profile inputs, evidence-safe profile identity, and the
//! production context factory.
//!
//! The integration profile requires that worker count, queue bounds,
//! blocking-pool limits, stack size, parking, scheduler/cohort policy, and
//! admission mode be *named profile inputs* rather than incidental defaults,
//! and that host-derived parallelism be an explicit opt-in that never enters
//! replay identity by accident. [`RuntimeProfile`] is that named set.
//!
//! It also requires that production contexts come from the owning runtime.
//! [`NodeRuntime::request_cx`] and [`NodeRuntime::try_request_cx`] delegate to
//! [`Runtime::request_cx_with_budget`] and
//! [`RuntimeHandle::try_request_cx_with_budget`]; no test-only or detached
//! constructor appears anywhere in this crate's production sources.

use std::time::Duration;

use asupersync::cx::Cx;
use asupersync::runtime::config::{
    BlockingPoolConfig, RuntimeConfig, SchedulerPlacementMode, SpawnAdmissionMode,
};
use asupersync::runtime::{Runtime, RuntimeHandle};
use asupersync::Budget;

use crate::grant::CapabilityProfile;
use crate::meter::{BudgetClass, BudgetPolicy};
use crate::obligations::LeakPolicy;
use crate::refuse::RuntimeRefusal;

/// The exact Asupersync release this profile is built against.
///
/// `no_dependency_drift` in `tests/` asserts this matches the version declared
/// in `Cargo.toml`, so the identity a node reports cannot silently disagree
/// with the version it actually linked.
pub const ASUPERSYNC_VERSION: &str = "0.4.9";

/// The exact Asupersync feature set this profile enables.
///
/// Empty: the crate is declared with `default-features = false` and selects no
/// features. This is the smallest closure that supplies the runtime, context,
/// budget, outcome, supervision, and obligation surfaces this crate uses.
pub const ASUPERSYNC_FEATURES: &[&str] = &[];

/// What a runtime profile is for, which decides what policy it may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProfileClass {
    /// A serving node. May use a controlled recovering leak policy.
    Production,
    /// A verification or release lane. Must fail fast on obligation leaks.
    Verification,
    /// A deterministic replay profile: pinned workers, parking disabled, fixed
    /// poll budget. Must also fail fast.
    Deterministic,
}

impl ProfileClass {
    /// Stable machine code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Verification => "verification",
            Self::Deterministic => "deterministic",
        }
    }

    /// Whether this class must use the fail-fast obligation-leak policy.
    #[must_use]
    pub const fn requires_fail_fast_leaks(self) -> bool {
        matches!(self, Self::Verification | Self::Deterministic)
    }

    /// Whether this class must pin its scheduler inputs for replay.
    #[must_use]
    pub const fn requires_pinned_scheduler(self) -> bool {
        matches!(self, Self::Deterministic)
    }
}

/// The named runtime inputs for a FrankenGit node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeProfile {
    class: ProfileClass,
    worker_threads: usize,
    host_derived_parallelism: bool,
    spawn_admission: SpawnAdmissionMode,
    scheduler_placement: SchedulerPlacementMode,
    thread_stack_size: usize,
    thread_name_prefix: String,
    global_queue_limit: usize,
    blocking_min_threads: usize,
    blocking_max_threads: usize,
    enable_parking: bool,
    poll_budget: u32,
    leak_policy: LeakPolicy,
    budgets: BudgetPolicy,
}

impl RuntimeProfile {
    /// A serving-node profile with explicit worker count.
    ///
    /// Worker count is explicit because host-derived parallelism must be an
    /// opt-in: see [`with_host_derived_parallelism`](Self::with_host_derived_parallelism).
    #[must_use]
    pub fn production(worker_threads: usize) -> Self {
        Self {
            class: ProfileClass::Production,
            worker_threads: worker_threads.max(1),
            host_derived_parallelism: false,
            spawn_admission: SpawnAdmissionMode::Direct,
            scheduler_placement: SchedulerPlacementMode::LocalityFirst,
            thread_stack_size: 2 * 1024 * 1024,
            thread_name_prefix: "fgit-worker".to_owned(),
            global_queue_limit: 8_192,
            blocking_min_threads: 1,
            blocking_max_threads: 8,
            enable_parking: true,
            poll_budget: 128,
            leak_policy: LeakPolicy::fail_fast(),
            budgets: BudgetPolicy::finite_defaults(),
        }
    }

    /// A verification/release-lane profile: fail-fast leaks, modest fan-out.
    #[must_use]
    pub fn verification() -> Self {
        Self {
            class: ProfileClass::Verification,
            ..Self::production(2)
        }
    }

    /// A deterministic replay profile.
    ///
    /// One worker, parking disabled, and a fixed poll budget, so a replay
    /// under this profile sees one schedule. These values are part of replay
    /// identity and appear in [`ProfileIdentity`].
    #[must_use]
    pub fn deterministic() -> Self {
        Self {
            class: ProfileClass::Deterministic,
            worker_threads: 1,
            enable_parking: false,
            poll_budget: 32,
            scheduler_placement: SchedulerPlacementMode::LocalityFirst,
            spawn_admission: SpawnAdmissionMode::Direct,
            thread_name_prefix: "fgit-det".to_owned(),
            ..Self::production(1)
        }
    }

    /// Opt in to host-derived worker parallelism.
    ///
    /// Recorded in the identity so a replay can tell that the worker count was
    /// taken from the host rather than pinned by the profile. Refused for
    /// classes that must pin their scheduler.
    ///
    /// # Errors
    ///
    /// [`RuntimeRefusal::TopologyInvalid`] is not used here; instead a
    /// deterministic profile refuses via
    /// [`RuntimeRefusal::CapabilityWidening`]-free explicit validation in
    /// [`build`](Self::build). This setter records intent only.
    #[must_use]
    pub fn with_host_derived_parallelism(mut self, workers: usize) -> Self {
        self.host_derived_parallelism = true;
        self.worker_threads = workers.max(1);
        self
    }

    /// Set the obligation-leak policy.
    #[must_use]
    pub fn with_leak_policy(mut self, leak_policy: LeakPolicy) -> Self {
        self.leak_policy = leak_policy;
        self
    }

    /// Set the budget policy.
    #[must_use]
    pub const fn with_budgets(mut self, budgets: BudgetPolicy) -> Self {
        self.budgets = budgets;
        self
    }

    /// Set the worker count explicitly.
    #[must_use]
    pub const fn with_worker_threads(mut self, workers: usize) -> Self {
        self.worker_threads = if workers == 0 { 1 } else { workers };
        self.host_derived_parallelism = false;
        self
    }

    /// Set the global run-queue bound.
    #[must_use]
    pub const fn with_global_queue_limit(mut self, limit: usize) -> Self {
        self.global_queue_limit = limit;
        self
    }

    /// Set the blocking-pool bounds.
    #[must_use]
    pub const fn with_blocking_threads(mut self, min: usize, max: usize) -> Self {
        self.blocking_min_threads = min;
        self.blocking_max_threads = if max < min { min } else { max };
        self
    }

    /// Set the spawn admission mode.
    #[must_use]
    pub const fn with_spawn_admission(mut self, mode: SpawnAdmissionMode) -> Self {
        self.spawn_admission = mode;
        self
    }

    /// Set the scheduler placement mode.
    #[must_use]
    pub const fn with_scheduler_placement(mut self, mode: SchedulerPlacementMode) -> Self {
        self.scheduler_placement = mode;
        self
    }

    /// The profile class.
    #[must_use]
    pub const fn class(&self) -> ProfileClass {
        self.class
    }

    /// The budget policy.
    #[must_use]
    pub const fn budgets(&self) -> BudgetPolicy {
        self.budgets
    }

    /// The obligation-leak policy.
    #[must_use]
    pub const fn leak_policy(&self) -> &LeakPolicy {
        &self.leak_policy
    }

    /// Validate this profile against its class rules.
    ///
    /// # Errors
    ///
    /// - [`RuntimeRefusal::UnboundedServiceBudget`] when any finite class
    ///   carries an unbounded budget.
    /// - [`RuntimeRefusal::LeakPolicyInsufficient`] when a class that must fail
    ///   fast was given a recovering policy.
    pub fn validate(&self) -> Result<(), RuntimeRefusal> {
        self.budgets.verify_finite()?;
        if self.class.requires_fail_fast_leaks() && !self.leak_policy.is_fail_fast() {
            return Err(RuntimeRefusal::LeakPolicyInsufficient {
                policy: "recovering",
            });
        }
        if self.class.requires_pinned_scheduler()
            && (self.host_derived_parallelism || self.worker_threads != 1 || self.enable_parking)
        {
            return Err(RuntimeRefusal::LeakPolicyInsufficient {
                policy: "unpinned_deterministic_profile",
            });
        }
        Ok(())
    }

    /// The evidence-safe identity of this profile.
    #[must_use]
    pub fn identity(&self) -> ProfileIdentity {
        ProfileIdentity {
            class: self.class,
            asupersync_version: ASUPERSYNC_VERSION,
            asupersync_features: ASUPERSYNC_FEATURES,
            target_arch: std::env::consts::ARCH,
            target_os: std::env::consts::OS,
            worker_threads: self.worker_threads,
            host_derived_parallelism: self.host_derived_parallelism,
            spawn_admission: admission_code(self.spawn_admission),
            scheduler_placement: placement_code(self.scheduler_placement),
            thread_stack_size: self.thread_stack_size,
            global_queue_limit: self.global_queue_limit,
            blocking_min_threads: self.blocking_min_threads,
            blocking_max_threads: self.blocking_max_threads,
            enable_parking: self.enable_parking,
            poll_budget: self.poll_budget,
            leak_policy: self.leak_policy.code(),
            leak_escalation_threshold: self
                .leak_policy
                .escalation()
                .map(|escalation| escalation.threshold),
            budget_defaults: BudgetClass::finite_classes()
                .map(|class| (class.code(), self.budgets.budget_for(class))),
            unbounded_root: self.budgets.has_unbounded_root(),
        }
    }

    /// Translate this profile into an Asupersync runtime configuration.
    fn to_config(&self) -> RuntimeConfig {
        let mut config = RuntimeConfig::default();
        config.worker_threads = self.worker_threads;
        config.spawn_admission = self.spawn_admission;
        config.scheduler_placement_mode = self.scheduler_placement;
        config.thread_stack_size = self.thread_stack_size;
        config.thread_name_prefix.clone_from(&self.thread_name_prefix);
        config.global_queue_limit = self.global_queue_limit;
        config.enable_parking = self.enable_parking;
        config.poll_budget = self.poll_budget;
        config.blocking = BlockingPoolConfig {
            min_threads: self.blocking_min_threads,
            max_threads: self.blocking_max_threads,
            ..config.blocking
        };
        config.blocking.normalize();
        config.obligation_leak_response = self.leak_policy.response();
        config.leak_escalation = self.leak_policy.escalation();
        config
    }

    /// Build the node runtime.
    ///
    /// # Errors
    ///
    /// Whatever [`validate`](Self::validate) refuses, plus
    /// [`RuntimeRefusal::RuntimeUnavailable`] when the runtime cannot start.
    pub fn build(self) -> Result<NodeRuntime, RuntimeRefusal> {
        self.validate()?;
        let runtime = Runtime::with_config(self.to_config())
            .map_err(|_| RuntimeRefusal::RuntimeUnavailable)?;
        Ok(NodeRuntime {
            runtime,
            profile: self,
            root_capabilities: CapabilityProfile::node_root(),
        })
    }
}

const fn admission_code(mode: SpawnAdmissionMode) -> &'static str {
    match mode {
        SpawnAdmissionMode::Direct => "direct",
        SpawnAdmissionMode::Mailbox => "mailbox",
    }
}

const fn placement_code(mode: SchedulerPlacementMode) -> &'static str {
    match mode {
        SchedulerPlacementMode::LocalityFirst => "locality_first",
        SchedulerPlacementMode::LatencyFirst => "latency_first",
        SchedulerPlacementMode::ThroughputFirst => "throughput_first",
    }
}

/// The evidence-safe fingerprint of a runtime profile.
///
/// Everything a replay needs to know about how the node was configured, and
/// nothing else: there are no handles, no secrets, and no host identifiers
/// beyond the target triple components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileIdentity {
    /// Profile class.
    pub class: ProfileClass,
    /// Exact Asupersync version linked.
    pub asupersync_version: &'static str,
    /// Exact Asupersync features enabled.
    pub asupersync_features: &'static [&'static str],
    /// Target architecture.
    pub target_arch: &'static str,
    /// Target operating system.
    pub target_os: &'static str,
    /// Worker thread count.
    pub worker_threads: usize,
    /// Whether the worker count came from the host rather than the profile.
    pub host_derived_parallelism: bool,
    /// Spawn admission mode.
    pub spawn_admission: &'static str,
    /// Scheduler placement mode.
    pub scheduler_placement: &'static str,
    /// Worker thread stack size.
    pub thread_stack_size: usize,
    /// Global run-queue bound.
    pub global_queue_limit: usize,
    /// Blocking-pool minimum threads.
    pub blocking_min_threads: usize,
    /// Blocking-pool maximum threads.
    pub blocking_max_threads: usize,
    /// Whether worker parking is enabled.
    pub enable_parking: bool,
    /// Per-poll budget.
    pub poll_budget: u32,
    /// Obligation-leak policy code.
    pub leak_policy: &'static str,
    /// Leak escalation threshold, when the policy escalates.
    pub leak_escalation_threshold: Option<u64>,
    /// Default budget per finite work class.
    pub budget_defaults: [(&'static str, Budget); 6],
    /// Whether the node root is unbounded.
    pub unbounded_root: bool,
}

impl ProfileIdentity {
    /// A canonical, stable, single-line descriptor.
    ///
    /// This is a canonical *descriptor*, not a cryptographic digest: it is
    /// deterministic and comparable, and it is what a replay record should
    /// carry, but it makes no collision-resistance claim.
    #[must_use]
    pub fn canonical_descriptor(&self) -> String {
        let mut out = String::new();
        out.push_str("fgit-runtime-profile-v1");
        out.push_str(&format!("|class={}", self.class.code()));
        out.push_str(&format!("|asupersync={}", self.asupersync_version));
        out.push_str(&format!(
            "|features={}",
            if self.asupersync_features.is_empty() {
                "none".to_owned()
            } else {
                self.asupersync_features.join(",")
            }
        ));
        out.push_str(&format!("|target={}-{}", self.target_arch, self.target_os));
        out.push_str(&format!("|workers={}", self.worker_threads));
        out.push_str(&format!("|host_parallelism={}", self.host_derived_parallelism));
        out.push_str(&format!("|admission={}", self.spawn_admission));
        out.push_str(&format!("|placement={}", self.scheduler_placement));
        out.push_str(&format!("|stack={}", self.thread_stack_size));
        out.push_str(&format!("|queue={}", self.global_queue_limit));
        out.push_str(&format!(
            "|blocking={}..{}",
            self.blocking_min_threads, self.blocking_max_threads
        ));
        out.push_str(&format!("|parking={}", self.enable_parking));
        out.push_str(&format!("|poll={}", self.poll_budget));
        out.push_str(&format!("|leak={}", self.leak_policy));
        out.push_str(&format!(
            "|leak_escalation={}",
            self.leak_escalation_threshold
                .map_or_else(|| "none".to_owned(), |threshold| threshold.to_string())
        ));
        out.push_str(&format!("|unbounded_root={}", self.unbounded_root));
        for (class, budget) in &self.budget_defaults {
            out.push_str(&format!(
                "|budget.{}={}:{}:{}:{}",
                class,
                budget
                    .deadline
                    .map_or_else(|| "none".to_owned(), |time| format!("{time:?}")),
                budget.poll_quota,
                budget
                    .cost_quota
                    .map_or_else(|| "none".to_owned(), |quota| quota.to_string()),
                budget.priority
            ));
        }
        out
    }
}

/// A running FrankenGit node runtime.
///
/// Owns the Asupersync [`Runtime`] and is the only production source of
/// request contexts in this crate.
pub struct NodeRuntime {
    runtime: Runtime,
    profile: RuntimeProfile,
    root_capabilities: CapabilityProfile,
}

impl core::fmt::Debug for NodeRuntime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The runtime itself is not `Debug`, and printing scheduler internals
        // would not be evidence-safe anyway. The profile identity is.
        f.debug_struct("NodeRuntime")
            .field("profile_class", &self.profile.class)
            .field("identity", &self.identity().canonical_descriptor())
            .finish_non_exhaustive()
    }
}

impl NodeRuntime {
    /// The profile this runtime was built from.
    #[must_use]
    pub const fn profile(&self) -> &RuntimeProfile {
        &self.profile
    }

    /// The node-root capability envelope.
    #[must_use]
    pub const fn root_capabilities(&self) -> CapabilityProfile {
        self.root_capabilities
    }

    /// A handle for minting contexts away from the owning thread.
    #[must_use]
    pub fn handle(&self) -> RuntimeHandle {
        self.runtime.handle()
    }

    /// Mint a production request context for a work class.
    ///
    /// The budget is the class default met against the node root, so a context
    /// can never carry more budget than the root granted.
    #[must_use]
    pub fn request_cx(&self, class: BudgetClass) -> Cx {
        self.runtime.request_cx_with_budget(self.budget_for(class))
    }

    /// Mint a production request context, reporting runtime teardown instead of
    /// panicking.
    ///
    /// # Errors
    ///
    /// [`RuntimeRefusal::RuntimeUnavailable`] when the runtime is gone.
    pub fn try_request_cx(&self, class: BudgetClass) -> Result<Cx, RuntimeRefusal> {
        self.runtime
            .handle()
            .try_request_cx_with_budget(self.budget_for(class))
            .map_err(|_| RuntimeRefusal::RuntimeUnavailable)
    }

    /// The effective budget for a work class beneath the node root.
    #[must_use]
    pub fn budget_for(&self, class: BudgetClass) -> Budget {
        let root = self.profile.budgets.budget_for(BudgetClass::NodeRoot);
        if class == BudgetClass::NodeRoot {
            root
        } else {
            self.profile.budgets.derive(root, class)
        }
    }

    /// Run a future to completion on the calling thread.
    pub fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.runtime.block_on(future)
    }

    /// The profile identity, for evidence.
    #[must_use]
    pub fn identity(&self) -> ProfileIdentity {
        self.profile.identity()
    }

    /// Join the node root to quiescence within the shutdown-cleanup budget.
    ///
    /// Returns `true` when quiescence was reached. This is the final
    /// [`ShutdownPhase::JoinRoot`](crate::topology::ShutdownPhase::JoinRoot)
    /// step; the phases before it are the caller's sequence to run, because
    /// this crate does not own sessions, database workers, or the evidence
    /// sink.
    #[must_use]
    pub fn join_root(self, timeout: Duration) -> bool {
        self.runtime.shutdown_timeout(timeout)
    }
}

#[cfg(test)]
mod tests {
    use asupersync::runtime::config::ObligationLeakResponse;
    use asupersync::types::id::Time;

    use super::*;
    use crate::obligations::{LeakControls, RecoverySinks};

    fn recovering() -> LeakPolicy {
        LeakPolicy::recovering(
            LeakControls::new(
                Budget::new()
                    .with_deadline(Time::from_secs(5))
                    .with_poll_quota(1_000)
                    .with_cost_quota(1_000),
                8,
            )
            .expect("bounded"),
            RecoverySinks::new("fgit.evidence.leak", "fgit.health.degraded").expect("named"),
        )
        .expect("controlled recovery")
    }

    #[test]
    fn verification_profile_requires_fail_fast_leak_handling() {
        let refusal = RuntimeProfile::verification()
            .with_leak_policy(recovering())
            .validate()
            .expect_err("a verification lane may not recover from leaks");
        assert_eq!(
            refusal,
            RuntimeRefusal::LeakPolicyInsufficient {
                policy: "recovering"
            }
        );

        // Paired permitted case: the same lane with fail-fast leaks.
        RuntimeProfile::verification()
            .validate()
            .expect("fail-fast verification profile is admissible");
    }

    #[test]
    fn deterministic_profile_requires_fail_fast_leak_handling() {
        assert!(ProfileClass::Deterministic.requires_fail_fast_leaks());
        let refusal = RuntimeProfile::deterministic()
            .with_leak_policy(recovering())
            .validate()
            .expect_err("a replay profile may not recover from leaks");
        assert!(matches!(
            refusal,
            RuntimeRefusal::LeakPolicyInsufficient { .. }
        ));
    }

    #[test]
    fn production_profile_may_use_controlled_recovery() {
        // The permitted twin of the two refusals above.
        let profile = RuntimeProfile::production(2).with_leak_policy(recovering());
        profile
            .validate()
            .expect("a serving node may use controlled recovery");
        assert_eq!(
            profile.leak_policy().response(),
            ObligationLeakResponse::Recover
        );
        assert_eq!(
            profile.leak_policy().escalation().map(|e| e.threshold),
            Some(8)
        );
    }

    #[test]
    fn deterministic_profile_pins_its_scheduler_inputs() {
        let profile = RuntimeProfile::deterministic();
        profile.validate().expect("pinned by construction");

        let identity = profile.identity();
        assert_eq!(identity.worker_threads, 1);
        assert!(!identity.enable_parking);
        assert!(!identity.host_derived_parallelism);

        // Planted negative: host-derived parallelism breaks replay identity.
        let refusal = RuntimeProfile::deterministic()
            .with_host_derived_parallelism(16)
            .validate()
            .expect_err("a replay profile may not take its worker count from the host");
        assert!(matches!(
            refusal,
            RuntimeRefusal::LeakPolicyInsufficient { .. }
        ));
    }

    #[test]
    fn host_derived_parallelism_is_recorded_in_identity() {
        let pinned = RuntimeProfile::production(4).identity();
        assert!(!pinned.host_derived_parallelism);
        assert_eq!(pinned.worker_threads, 4);

        // Paired permitted case: production may opt in, and it is recorded.
        let derived = RuntimeProfile::production(4)
            .with_host_derived_parallelism(9)
            .identity();
        assert!(derived.host_derived_parallelism);
        assert_eq!(derived.worker_threads, 9);
        assert_ne!(
            pinned.canonical_descriptor(),
            derived.canonical_descriptor(),
            "host-derived parallelism must change replay identity"
        );
    }

    #[test]
    fn profile_identity_carries_every_required_field() {
        let identity = RuntimeProfile::production(3).identity();
        let descriptor = identity.canonical_descriptor();

        for required in [
            "class=",
            "asupersync=0.4.9",
            "features=",
            "target=",
            "workers=3",
            "host_parallelism=",
            "admission=",
            "placement=",
            "stack=",
            "queue=",
            "blocking=",
            "parking=",
            "poll=",
            "leak=",
            "leak_escalation=",
            "unbounded_root=",
        ] {
            assert!(
                descriptor.contains(required),
                "identity descriptor is missing `{required}`: {descriptor}"
            );
        }

        // Every finite budget class appears in the identity.
        for class in BudgetClass::finite_classes() {
            assert!(
                descriptor.contains(&format!("|budget.{}=", class.code())),
                "identity descriptor is missing budget class `{}`",
                class.code()
            );
        }
    }

    #[test]
    fn profile_identity_is_deterministic() {
        let first = RuntimeProfile::production(3).identity().canonical_descriptor();
        for _ in 0..8 {
            assert_eq!(
                RuntimeProfile::production(3).identity().canonical_descriptor(),
                first
            );
        }
    }

    #[test]
    fn distinct_profiles_have_distinct_identities() {
        let descriptors = [
            RuntimeProfile::production(2).identity().canonical_descriptor(),
            RuntimeProfile::production(4).identity().canonical_descriptor(),
            RuntimeProfile::verification().identity().canonical_descriptor(),
            RuntimeProfile::deterministic().identity().canonical_descriptor(),
        ];
        let mut unique = descriptors.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), descriptors.len());
    }

    #[test]
    fn identity_records_the_exact_linked_version_and_feature_set() {
        let identity = RuntimeProfile::production(1).identity();
        assert_eq!(identity.asupersync_version, ASUPERSYNC_VERSION);
        assert_eq!(identity.asupersync_features, ASUPERSYNC_FEATURES);
        assert!(
            identity.asupersync_features.is_empty(),
            "this profile selects no Asupersync features"
        );
        assert!(identity.canonical_descriptor().contains("features=none"));
    }

    #[test]
    fn an_unbounded_service_budget_never_reaches_a_runtime() {
        let mut budgets = BudgetPolicy::finite_defaults();
        budgets = budgets
            .with_class_budget(BudgetClass::NodeRoot, Budget::INFINITE)
            .expect("the root may be unbounded");

        // Root unbounded is fine...
        RuntimeProfile::production(1)
            .with_budgets(budgets)
            .validate()
            .expect("an unbounded root is a named policy");

        // ...but a finite class never is. `with_class_budget` refuses first,
        // so construct the defect the only other way it could arise.
        let refusal = BudgetPolicy::finite_defaults()
            .with_class_budget(BudgetClass::Transfer, Budget::INFINITE)
            .expect_err("an unbounded transfer budget is refused at the policy");
        assert_eq!(
            refusal,
            RuntimeRefusal::UnboundedServiceBudget { class: "transfer" }
        );
    }

    #[test]
    fn config_translation_carries_the_named_inputs() {
        let profile = RuntimeProfile::production(6)
            .with_global_queue_limit(4_096)
            .with_blocking_threads(2, 5)
            .with_spawn_admission(SpawnAdmissionMode::Mailbox)
            .with_scheduler_placement(SchedulerPlacementMode::ThroughputFirst);

        let config = profile.to_config();
        assert_eq!(config.worker_threads, 6);
        assert_eq!(config.global_queue_limit, 4_096);
        assert_eq!(config.blocking.min_threads, 2);
        assert_eq!(config.blocking.max_threads, 5);
        assert_eq!(config.spawn_admission, SpawnAdmissionMode::Mailbox);
        assert_eq!(
            config.scheduler_placement_mode,
            SchedulerPlacementMode::ThroughputFirst
        );
        assert_eq!(
            config.obligation_leak_response,
            ObligationLeakResponse::Panic
        );
        assert_eq!(config.leak_escalation, None);
    }

    #[test]
    fn recovering_policy_reaches_the_runtime_config_with_escalation() {
        let config = RuntimeProfile::production(2)
            .with_leak_policy(recovering())
            .to_config();
        assert_eq!(
            config.obligation_leak_response,
            ObligationLeakResponse::Recover
        );
        let escalation = config.leak_escalation.expect("recovery escalates");
        assert_eq!(escalation.threshold, 8);
        assert_eq!(escalation.escalate_to, ObligationLeakResponse::Panic);
    }

    #[test]
    fn blocking_bounds_are_normalized_rather_than_inverted() {
        let profile = RuntimeProfile::production(1).with_blocking_threads(4, 2);
        assert_eq!(profile.blocking_min_threads, 4);
        assert_eq!(profile.blocking_max_threads, 4);
    }

    #[test]
    fn worker_count_is_never_zero() {
        assert_eq!(RuntimeProfile::production(0).identity().worker_threads, 1);
        assert_eq!(
            RuntimeProfile::production(4)
                .with_worker_threads(0)
                .identity()
                .worker_threads,
            1
        );
    }

    #[test]
    fn production_contexts_come_from_the_owning_runtime() {
        let node = RuntimeProfile::deterministic()
            .build()
            .expect("the deterministic profile builds");

        // Both production factories work and honour the class budget.
        let request_cx = node.request_cx(BudgetClass::Request);
        assert!(request_cx.budget().poll_quota <= node.budget_for(BudgetClass::Request).poll_quota);

        let parser_cx = node
            .try_request_cx(BudgetClass::Parser)
            .expect("the runtime is alive");
        assert!(parser_cx.budget().deadline.is_some());

        assert!(node.join_root(Duration::from_secs(5)));
    }

    #[test]
    fn every_class_context_is_bounded_beneath_the_root() {
        let node = RuntimeProfile::deterministic()
            .build()
            .expect("builds");
        let root = node.budget_for(BudgetClass::NodeRoot);

        for class in BudgetClass::finite_classes() {
            let budget = node.budget_for(class);
            assert!(
                !crate::meter::is_unbounded(budget),
                "class `{}` must be bounded",
                class.code()
            );
            assert!(budget.poll_quota <= root.poll_quota);
            assert!(budget.deadline <= root.deadline);
        }

        assert!(node.join_root(Duration::from_secs(5)));
    }
}
