//! Deterministic worker-budget calculation: the one shared batch-parallelism
//! policy.
//!
//! Six subsystems run batches — render, index, graph, pack, repair, and CI.
//! Left alone each picks its own worker count, and the folklore choice is
//! "one worker per core", which knows nothing about how much memory a job
//! holds. The result is a fleet that fits the CPU and exhausts the machine.
//!
//! This module is the single mechanism they share. [`plan`] is a pure function
//! of declared inputs, so the same inputs give the same fleet on every machine,
//! in every process, on every replay.
//!
//! # Why determinism is correctness here, not tuning
//!
//! A batch's output must not depend on how many workers ran it. If it does,
//! the same batch replayed on a smaller machine produces a different answer,
//! and every receipt over that batch becomes unreproducible. So this module
//! owns two things that are usually kept apart: the count, and the ordering
//! contract that makes the count unobservable in the output.
//!
//! [`BatchPlan`] assigns jobs to workers, and [`merge_in_job_order`] reassembles
//! results in job order regardless of which worker finished first. Concatenating
//! per-worker outputs — the obvious implementation — is exactly the bug: it
//! yields a different order for each worker count. `tests/worker_budget_determinism.rs`
//! asserts that the naive order really does diverge before asserting that this
//! one does not, so the determinism test cannot pass vacuously.
//!
//! # No floating point
//!
//! Every computation here is integer arithmetic with explicit rounding. Floats
//! are not used anywhere in the formula, deliberately: a determinism contract
//! that rests on float rounding agreeing across targets is a contract resting
//! on something this crate does not control. Multiplications are checked, and
//! an overflow is a typed refusal rather than a wrap.
//!
//! # Non-claims
//!
//! `per_job_rss_bytes` is an *estimate the caller declares*, not a measurement
//! this module takes. Nothing here observes real memory, enforces a limit, or
//! prevents a job from exceeding its estimate. The guarantee is arithmetic: the
//! returned fleet's aggregate estimate fits the declared budget. A job that
//! outgrows its estimate is a job-level failure and needs the runtime's
//! obligation machinery, not this calculator.

use core::fmt;

use crate::algebra::Grade;

/// How much of the CPU cap a batch may claim.
///
/// The mode is the caller's declaration of what else the machine is doing, and
/// it is a policy input rather than a measurement: nothing here inspects load.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WorkerMode {
    /// A human is waiting on something else; leave half the cap free.
    Interactive,
    /// The batch is the machine's purpose; claim the whole cap.
    Batch,
    /// Opportunistic work that must yield to everything else.
    Background,
}

impl WorkerMode {
    /// Percentage of the CPU cap this mode may claim.
    #[must_use]
    pub const fn cpu_share_percent(self) -> u32 {
        match self {
            Self::Interactive => 50,
            Self::Batch => 100,
            Self::Background => 25,
        }
    }
}

impl fmt::Display for WorkerMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::Interactive => "interactive",
            Self::Batch => "batch",
            Self::Background => "background",
        };
        f.write_str(name)
    }
}

/// How much the caller trusts its own per-job memory estimate.
///
/// Headroom is applied to the estimate, not to the budget: a wide-variance job
/// is treated as bigger, which is what makes the memory bound hold when the
/// estimate is soft.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VarianceClass {
    /// The estimate is a measured ceiling; take it at face value.
    Tight,
    /// The estimate is typical; allow a quarter more.
    Moderate,
    /// The estimate is a guess; allow double.
    Wide,
    /// The estimate has a heavy upper tail; reserve four times it.
    ///
    /// This is deliberately distinct from [`Self::Wide`]: a caller that
    /// declares skewed work must not silently receive the smaller two-times
    /// headroom merely because another consumer does not need four times it.
    Extreme,
}

impl VarianceClass {
    /// Percentage the per-job estimate is inflated by before planning.
    #[must_use]
    pub const fn headroom_percent(self) -> u32 {
        match self {
            Self::Tight => 100,
            Self::Moderate => 125,
            Self::Wide => 200,
            Self::Extreme => 400,
        }
    }
}

impl fmt::Display for VarianceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::Tight => "tight",
            Self::Moderate => "moderate",
            Self::Wide => "wide",
            Self::Extreme => "extreme",
        };
        f.write_str(name)
    }
}

/// The declared inputs the worker count is a pure function of.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WorkerBudgetInputs {
    /// Maximum processors this batch may use. Not the machine's core count:
    /// the cap the deployment declares.
    pub cpu_cap: u32,
    /// Total resident bytes the batch may hold across all workers.
    pub memory_budget_bytes: u64,
    /// Caller's estimate of resident bytes held by one in-flight job.
    pub per_job_rss_bytes: u64,
    /// What else the machine is doing.
    pub mode: WorkerMode,
    /// How much the caller trusts `per_job_rss_bytes`.
    pub variance: VarianceClass,
}

/// Why a fleet could not be planned.
///
/// Every variant carries the numbers that produced it, because a refusal a
/// caller cannot act on is barely better than a panic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WorkerBudgetRefusal {
    /// A cap of zero processors admits no fleet at all.
    ZeroCpuCap,
    /// A job estimated to hold nothing gives the memory bound no denominator.
    ///
    /// This is refused rather than defaulted, because the plausible default —
    /// "unbounded workers" — is the exact failure this module exists to stop.
    ZeroPerJobEstimate,
    /// The budget cannot hold even one job at its inflated estimate.
    ///
    /// Returning one worker anyway would break the memory bound, and returning
    /// zero workers would be a fleet that cannot make progress. Both are worse
    /// than saying so.
    BudgetBelowOneJob {
        /// Bytes the caller declared.
        budget_bytes: u64,
        /// Bytes one job needs after headroom.
        required_bytes: u64,
    },
    /// Applying headroom to the estimate overflowed `u64`.
    EstimateOverflow {
        /// The declared per-job estimate.
        per_job_rss_bytes: u64,
        /// The headroom percentage being applied.
        headroom_percent: u32,
    },
}

impl fmt::Display for WorkerBudgetRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::ZeroCpuCap => {
                f.write_str("a cpu cap of zero admits no workers; declare at least one processor")
            }
            Self::ZeroPerJobEstimate => f.write_str(
                "a per-job estimate of zero bytes leaves the memory bound undefined; \
                 declare what one job holds",
            ),
            Self::BudgetBelowOneJob {
                budget_bytes,
                required_bytes,
            } => write!(
                f,
                "a memory budget of {budget_bytes} bytes cannot hold one job needing \
                 {required_bytes} bytes after headroom; no fleet fits"
            ),
            Self::EstimateOverflow {
                per_job_rss_bytes,
                headroom_percent,
            } => write!(
                f,
                "inflating {per_job_rss_bytes} bytes by {headroom_percent}% overflows; \
                 the calculator refuses rather than wrapping"
            ),
        }
    }
}

impl std::error::Error for WorkerBudgetRefusal {}

/// Which input bound the fleet size.
///
/// Recorded because "why is this batch running four workers on a 64-core box"
/// is the first question anyone asks, and the answer should not require
/// rederiving the formula.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BindingConstraint {
    /// The CPU cap and mode were the limit.
    Cpu,
    /// The memory budget and per-job estimate were the limit.
    Memory,
    /// Both limits landed on the same count.
    Both,
    /// The batch is smaller than either limit allows.
    ///
    /// Planning more workers than there are jobs is not wrong so much as
    /// meaningless: the surplus workers are handed no work. Reporting it as a
    /// distinct binding keeps "your budget is tight" separate from "your batch
    /// is small", which are different things to act on.
    BatchSize,
}

impl fmt::Display for BindingConstraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::Cpu => "cpu",
            Self::Memory => "memory",
            Self::Both => "cpu and memory",
            Self::BatchSize => "batch size",
        };
        f.write_str(name)
    }
}

/// A planned fleet, with the arithmetic that justifies it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[must_use]
pub struct WorkerBudget {
    workers: u32,
    effective_per_job_bytes: u64,
    memory_reserved_bytes: u64,
    binding: BindingConstraint,
}

impl WorkerBudget {
    /// Number of workers the batch may run concurrently. Always at least one.
    #[must_use]
    pub const fn workers(&self) -> u32 {
        self.workers
    }

    /// Per-job estimate after variance headroom.
    #[must_use]
    pub const fn effective_per_job_bytes(&self) -> u64 {
        self.effective_per_job_bytes
    }

    /// Aggregate resident bytes this fleet is permitted to hold.
    ///
    /// Never exceeds the declared budget; that is the property
    /// `memory_bound_holds_across_the_parameter_space` checks.
    #[must_use]
    pub const fn memory_reserved_bytes(&self) -> u64 {
        self.memory_reserved_bytes
    }

    /// Which input limited the fleet.
    #[must_use]
    pub const fn binding(&self) -> BindingConstraint {
        self.binding
    }

    /// The grades this fleet spends, for charging against a region's budget.
    ///
    /// Slots are [`Grade::FailureDomainSlots`] because a worker *is* a
    /// concurrent slot in one failure domain, which is the grade the algebra
    /// already has for it. No new grade is introduced: the grade list is closed
    /// and adding one is a protocol change.
    #[must_use]
    pub fn charge(&self) -> [(Grade, u64); 2] {
        [
            (Grade::MemoryBytes, self.memory_reserved_bytes),
            (Grade::FailureDomainSlots, u64::from(self.workers)),
        ]
    }
}

/// Multiply `value` by `percent/100`, rounding up, refusing on overflow.
///
/// Rounding up is what keeps the memory bound conservative: a job is never
/// planned as smaller than its estimate.
fn inflate(value: u64, percent: u32) -> Option<u64> {
    let scaled = value.checked_mul(u64::from(percent))?;
    // Ceiling division: the remainder always costs a whole byte.
    Some(scaled.div_ceil(100))
}

/// Plan a fleet from declared inputs.
///
/// The formula, in order:
///
/// 1. `effective = ceil(per_job_rss_bytes * variance.headroom_percent / 100)`
/// 2. `memory_workers = memory_budget_bytes / effective` (floor)
/// 3. `cpu_workers = max(1, cpu_cap * mode.cpu_share_percent / 100)` (floor)
/// 4. `workers = min(cpu_workers, memory_workers)`
///
/// Step 3 floors then lifts to one, so a background batch on a two-core cap
/// gets one worker rather than none. Step 2 does not: a budget that cannot
/// hold one job is [`WorkerBudgetRefusal::BudgetBelowOneJob`], because lifting
/// it to one would break the bound this function exists to enforce.
///
/// # Errors
///
/// Returns [`WorkerBudgetRefusal`] when the inputs admit no fleet: a zero CPU
/// cap, a zero per-job estimate, a budget below one job, or an estimate whose
/// headroom overflows.
pub fn plan(inputs: WorkerBudgetInputs) -> Result<WorkerBudget, WorkerBudgetRefusal> {
    if inputs.cpu_cap == 0 {
        return Err(WorkerBudgetRefusal::ZeroCpuCap);
    }
    if inputs.per_job_rss_bytes == 0 {
        return Err(WorkerBudgetRefusal::ZeroPerJobEstimate);
    }

    let headroom_percent = inputs.variance.headroom_percent();
    let effective_per_job_bytes = inflate(inputs.per_job_rss_bytes, headroom_percent).ok_or(
        WorkerBudgetRefusal::EstimateOverflow {
            per_job_rss_bytes: inputs.per_job_rss_bytes,
            headroom_percent,
        },
    )?;

    let memory_workers = inputs.memory_budget_bytes / effective_per_job_bytes;
    if memory_workers == 0 {
        return Err(WorkerBudgetRefusal::BudgetBelowOneJob {
            budget_bytes: inputs.memory_budget_bytes,
            required_bytes: effective_per_job_bytes,
        });
    }

    // The cap is a u32 and the share is at most 100, so this cannot overflow
    // u64; the count is then narrowed back only after clamping.
    let cpu_scaled = u64::from(inputs.cpu_cap) * u64::from(inputs.mode.cpu_share_percent()) / 100;
    let cpu_workers = cpu_scaled.max(1);

    let workers_u64 = cpu_workers.min(memory_workers);
    let binding = if cpu_workers == memory_workers {
        BindingConstraint::Both
    } else if workers_u64 == cpu_workers {
        BindingConstraint::Cpu
    } else {
        BindingConstraint::Memory
    };

    // `workers_u64 <= cpu_workers <= cpu_cap`, which is a u32, so this
    // conversion cannot truncate. It is written as a saturating narrow rather
    // than a cast so that a future change to the formula cannot silently wrap.
    let workers = u32::try_from(workers_u64).unwrap_or(u32::MAX);

    // Cannot overflow: workers <= memory_budget / effective, so the product is
    // at most memory_budget.
    let memory_reserved_bytes = workers_u64 * effective_per_job_bytes;

    Ok(WorkerBudget {
        workers,
        effective_per_job_bytes,
        memory_reserved_bytes,
        binding,
    })
}

/// Plan a fleet for a batch of known size.
///
/// Identical to [`plan`], then capped so the fleet is never larger than the
/// batch it serves. A calculator that answers "sixty-four workers" for a
/// three-job batch is not merely inefficient: it is reporting a bound that has
/// nothing to do with the work, and callers size thread pools and reservations
/// from that number.
///
/// The cap never raises the count and never relaxes the memory bound, so every
/// guarantee [`plan`] makes still holds here. An empty batch still yields one
/// worker: a fleet must be able to make progress if the batch later grows, and
/// zero is not a fleet.
///
/// # Errors
///
/// Returns the same [`WorkerBudgetRefusal`] cases as [`plan`]; capping by batch
/// size introduces no new refusal.
pub fn plan_for_batch(
    inputs: WorkerBudgetInputs,
    job_count: usize,
) -> Result<WorkerBudget, WorkerBudgetRefusal> {
    let uncapped = plan(inputs)?;

    let cap = u32::try_from(job_count).unwrap_or(u32::MAX).max(1);
    if cap >= uncapped.workers {
        return Ok(uncapped);
    }

    Ok(WorkerBudget {
        workers: cap,
        effective_per_job_bytes: uncapped.effective_per_job_bytes,
        // Recomputed, never carried over: a smaller fleet reserves less. Keeping
        // the uncapped reservation would over-report memory this batch will
        // never hold, which is the same class of error as under-reporting it.
        memory_reserved_bytes: u64::from(cap) * uncapped.effective_per_job_bytes,
        binding: BindingConstraint::BatchSize,
    })
}

/// A deterministic assignment of jobs to workers.
///
/// The assignment is round-robin by job index. What matters is not which
/// worker gets which job — it is that the mapping is a pure function of
/// `(job_count, workers)` and that the *output* order does not depend on it at
/// all. See [`merge_in_job_order`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[must_use]
pub struct BatchPlan {
    job_count: usize,
    workers: u32,
}

impl BatchPlan {
    /// Build a plan for `job_count` jobs across `budget.workers()` workers.
    ///
    /// No `#[must_use]` here: `BatchPlan` already carries it at the type level,
    /// so repeating it on the constructor adds nothing.
    pub const fn new(job_count: usize, budget: &WorkerBudget) -> Self {
        Self {
            job_count,
            workers: budget.workers,
        }
    }

    /// Number of jobs in the batch.
    #[must_use]
    pub const fn job_count(&self) -> usize {
        self.job_count
    }

    /// Number of workers the batch runs on.
    #[must_use]
    pub const fn workers(&self) -> u32 {
        self.workers
    }

    /// Which worker owns `job_index`, or `None` if the index is out of range.
    #[must_use]
    pub fn owner_of(&self, job_index: usize) -> Option<u32> {
        if job_index >= self.job_count {
            return None;
        }
        let workers = usize::try_from(self.workers).unwrap_or(usize::MAX);
        u32::try_from(job_index % workers).ok()
    }

    /// The job indices assigned to `worker`, in ascending order.
    #[must_use]
    pub fn jobs_for(&self, worker: u32) -> Vec<usize> {
        if worker >= self.workers {
            return Vec::new();
        }
        let start = usize::try_from(worker).unwrap_or(usize::MAX);
        let stride = usize::try_from(self.workers).unwrap_or(usize::MAX);
        (start..self.job_count).step_by(stride).collect()
    }
}

/// Why a batch's results could not be reassembled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BatchMergeRefusal {
    /// No worker reported a result for this job index.
    ///
    /// A dropped job is silent corruption if the merge just returns a shorter
    /// vector, so it is a refusal instead.
    MissingJob {
        /// The index nobody reported.
        index: usize,
    },
    /// Two results claimed the same job index.
    DuplicateJob {
        /// The index reported more than once.
        index: usize,
    },
    /// A result claimed an index outside the batch.
    IndexOutOfRange {
        /// The claimed index.
        index: usize,
        /// Number of jobs in the batch.
        job_count: usize,
    },
}

impl fmt::Display for BatchMergeRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::MissingJob { index } => write!(
                f,
                "no worker reported job {index}; the batch is incomplete and the merge \
                 refuses rather than returning a short result"
            ),
            Self::DuplicateJob { index } => {
                write!(f, "job {index} was reported more than once")
            }
            Self::IndexOutOfRange { index, job_count } => {
                write!(f, "job {index} is outside a batch of {job_count} jobs")
            }
        }
    }
}

impl std::error::Error for BatchMergeRefusal {}

/// Reassemble per-worker results into job order.
///
/// `completed` is what the workers actually produced: one bucket per worker,
/// each holding `(job_index, result)` pairs in whatever order that worker
/// finished them. The output is ordered by job index, so it is identical for
/// every worker count and every completion order.
///
/// This is the function the determinism contract rests on. The obvious
/// alternative — concatenating the buckets — produces a different order for
/// each worker count, which is why the test suite asserts that the naive order
/// diverges before asserting that this one does not.
///
/// # Errors
///
/// Returns [`BatchMergeRefusal`] if any job is missing, duplicated, or out of
/// range. A batch that lost a job is not silently shortened.
pub fn merge_in_job_order<T>(
    job_count: usize,
    completed: Vec<Vec<(usize, T)>>,
) -> Result<Vec<T>, BatchMergeRefusal> {
    let mut slots: Vec<Option<T>> = Vec::with_capacity(job_count);
    slots.resize_with(job_count, || None);

    for bucket in completed {
        for (index, value) in bucket {
            let slot = slots
                .get_mut(index)
                .ok_or(BatchMergeRefusal::IndexOutOfRange { index, job_count })?;
            if slot.is_some() {
                return Err(BatchMergeRefusal::DuplicateJob { index });
            }
            *slot = Some(value);
        }
    }

    let mut ordered = Vec::with_capacity(job_count);
    for (index, slot) in slots.into_iter().enumerate() {
        ordered.push(slot.ok_or(BatchMergeRefusal::MissingJob { index })?);
    }
    Ok(ordered)
}

#[cfg(test)]
mod tests {
    use super::{
        BindingConstraint, VarianceClass, WorkerBudgetInputs, WorkerBudgetRefusal, WorkerMode, plan,
    };

    fn inputs(cpu_cap: u32, budget: u64, per_job: u64) -> WorkerBudgetInputs {
        WorkerBudgetInputs {
            cpu_cap,
            memory_budget_bytes: budget,
            per_job_rss_bytes: per_job,
            mode: WorkerMode::Batch,
            variance: VarianceClass::Tight,
        }
    }

    #[test]
    fn a_zero_cpu_cap_is_refused_rather_than_defaulted() {
        assert_eq!(
            plan(inputs(0, 1024, 16)),
            Err(WorkerBudgetRefusal::ZeroCpuCap)
        );
    }

    #[test]
    fn a_zero_per_job_estimate_is_refused_because_it_has_no_denominator() {
        assert_eq!(
            plan(inputs(8, 1024, 0)),
            Err(WorkerBudgetRefusal::ZeroPerJobEstimate)
        );
    }

    #[test]
    fn a_budget_below_one_job_refuses_instead_of_rounding_up_to_one() {
        // Rounding up to one worker here is the tempting bug: it would return a
        // fleet whose aggregate estimate exceeds the declared budget.
        assert_eq!(
            plan(inputs(8, 100, 101)),
            Err(WorkerBudgetRefusal::BudgetBelowOneJob {
                budget_bytes: 100,
                required_bytes: 101,
            })
        );
    }

    #[test]
    fn headroom_overflow_refuses_rather_than_wrapping() {
        let over = WorkerBudgetInputs {
            variance: VarianceClass::Wide,
            ..inputs(8, u64::MAX, u64::MAX / 2 + 1)
        };
        assert_eq!(
            plan(over),
            Err(WorkerBudgetRefusal::EstimateOverflow {
                per_job_rss_bytes: u64::MAX / 2 + 1,
                headroom_percent: 200,
            })
        );
    }

    #[test]
    fn extreme_variance_reserves_four_times_the_declared_estimate() {
        let extreme = plan(WorkerBudgetInputs {
            variance: VarianceClass::Extreme,
            ..inputs(64, 8 * 1024, 1024)
        })
        .expect("four-times headroom still fits two jobs");

        assert_eq!(extreme.effective_per_job_bytes(), 4 * 1024);
        assert_eq!(extreme.workers(), 2);
        assert!(extreme.memory_reserved_bytes() <= 8 * 1024);
    }

    #[test]
    fn cpu_binds_when_memory_is_plentiful() {
        let budget = plan(inputs(4, 1 << 30, 1024)).expect("a generous budget must plan");
        assert_eq!(budget.workers(), 4);
        assert_eq!(budget.binding(), BindingConstraint::Cpu);
    }

    #[test]
    fn memory_binds_when_the_budget_is_tight() {
        // 64 cores of cap, but only room for three jobs.
        let budget = plan(inputs(64, 3 * 1024, 1024)).expect("three jobs must fit");
        assert_eq!(budget.workers(), 3);
        assert_eq!(budget.binding(), BindingConstraint::Memory);
        assert_eq!(budget.memory_reserved_bytes(), 3 * 1024);
    }

    #[test]
    fn variance_headroom_shrinks_the_fleet_rather_than_the_budget() {
        let tight = plan(inputs(64, 8 * 1024, 1024)).expect("tight must plan");
        let wide = plan(WorkerBudgetInputs {
            variance: VarianceClass::Wide,
            ..inputs(64, 8 * 1024, 1024)
        })
        .expect("wide must plan");

        assert_eq!(tight.workers(), 8);
        assert_eq!(
            wide.workers(),
            4,
            "doubling the estimate must halve the fleet"
        );
        assert!(
            wide.memory_reserved_bytes() <= 8 * 1024,
            "headroom must not push the reservation past the budget"
        );
    }

    #[test]
    fn mode_scales_the_cpu_claim_but_never_below_one_worker() {
        let background = plan(WorkerBudgetInputs {
            mode: WorkerMode::Background,
            ..inputs(2, 1 << 30, 1024)
        })
        .expect("a two-core background batch must still plan");
        // 2 * 25% = 0 by floor; the formula lifts it to one rather than
        // returning a fleet that cannot make progress.
        assert_eq!(background.workers(), 1);
    }
}
