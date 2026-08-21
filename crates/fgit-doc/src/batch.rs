//! Deterministic batch rendering with complete per-input receipts.
//!
//! Two properties matter here and both are structural rather than incidental:
//!
//! - the **worker count is a pure function of the declared workload** — core
//!   cap, memory budget, per-job estimate, render mode, size variance, and the
//!   number of inputs — not of what the machine happens to be doing;
//! - the **output order follows the input order** and the outcome of every
//!   input is independent of the shard it landed in, so changing the worker
//!   count can never change the receipt.
//!
//! Non-claim: this slice executes shards sequentially in the calling thread.
//! It takes no runtime dependency and makes no concurrency claim. The plan is
//! the contract a concurrent executor must satisfy, and the determinism tests
//! pin exactly that contract: the same inputs rendered under materially
//! different plans produce byte-identical receipts.

use crate::limits::{Refusal, RefusalKind, as_u64, offset_u32, usize_of};
use crate::parse::parse_with;
use crate::profile::ParseProfile;
use crate::render::{RenderProfile, Rendered, render};

/// How much the sizes of the declared inputs vary.
///
/// Variance is a memory-headroom input, not a scheduling hint: a skewed batch
/// has a much larger peak job than its mean job, so the same memory budget
/// safely supports fewer concurrent workers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VarianceClass {
    /// Inputs are close to the same size.
    Uniform,
    /// Inputs differ by a small factor.
    Mixed,
    /// A few inputs dominate the batch.
    Skewed,
}

impl VarianceClass {
    /// Headroom multiplier applied to the per-job memory estimate.
    #[must_use]
    pub const fn headroom(self) -> u64 {
        match self {
            Self::Uniform => 1,
            Self::Mixed => 2,
            Self::Skewed => 4,
        }
    }

    /// Stable machine-readable tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Uniform => "uniform",
            Self::Mixed => "mixed",
            Self::Skewed => "skewed",
        }
    }
}

/// The declared shape of a batch, from which the worker count is derived.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkloadProfile {
    /// Maximum cores the host permits this batch to use.
    pub cpu_cap: u32,
    /// Total memory the host permits this batch to use, in bytes.
    pub memory_budget_bytes: u64,
    /// Host estimate of one job's peak resident bytes.
    pub per_job_bytes: u64,
    /// How much the input sizes vary.
    pub variance: VarianceClass,
}

impl WorkloadProfile {
    /// A single-worker workload, useful for tests and for embedded hosts.
    pub const SERIAL: Self = Self {
        cpu_cap: 1,
        memory_budget_bytes: 64 * 1024 * 1024,
        per_job_bytes: 4 * 1024 * 1024,
        variance: VarianceClass::Uniform,
    };
}

/// Ceiling on concurrent workers for one render mode.
///
/// Heavier surfaces hold more intermediate state per job, so they cap lower.
const fn mode_cap(surface: RenderProfile) -> u32 {
    match surface {
        RenderProfile::PlainText | RenderProfile::CompactMachine => 64,
        RenderProfile::HtmlSafe => 48,
        RenderProfile::ApiJson => 32,
    }
}

/// Derives the worker count from the declared workload.
///
/// The count is `min(cpu_cap, memory_workers, mode_cap, input_count)` clamped
/// to at least one, where `memory_workers` is the memory budget divided by the
/// per-job estimate scaled by the variance headroom. A zero core cap or a zero
/// per-job estimate is a refusal, not a guess.
pub fn worker_count(
    workload: WorkloadProfile,
    surface: RenderProfile,
    input_count: u32,
) -> Result<u32, Refusal> {
    if workload.cpu_cap == 0 || workload.per_job_bytes == 0 {
        return Err(Refusal::precondition(RefusalKind::WorkloadUnusable));
    }
    if input_count == 0 {
        return Ok(1);
    }
    let scaled = workload
        .per_job_bytes
        .saturating_mul(workload.variance.headroom());
    let memory_workers = u32::try_from(workload.memory_budget_bytes / scaled.max(1)).unwrap_or(u32::MAX);
    let workers = workload
        .cpu_cap
        .min(memory_workers)
        .min(mode_cap(surface))
        .min(input_count)
        .max(1);
    Ok(workers)
}

/// A deterministic assignment of inputs to workers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchPlan {
    workers: u32,
    assignment: Vec<u32>,
}

impl BatchPlan {
    /// Derives the plan for a declared workload and input count.
    ///
    /// A uniform batch is split into contiguous blocks, which keeps each
    /// worker's inputs adjacent. A mixed or skewed batch is dealt round-robin,
    /// which spreads the large inputs across workers instead of stacking them
    /// on one. Both assignments are pure functions of the declaration.
    pub fn derive(
        workload: WorkloadProfile,
        surface: RenderProfile,
        input_count: u32,
    ) -> Result<Self, Refusal> {
        let workers = worker_count(workload, surface, input_count)?;
        let total = usize_of(input_count);
        let mut assignment = Vec::with_capacity(total);
        if workload.variance == VarianceClass::Uniform {
            let per_worker = total.div_ceil(usize_of(workers)).max(1);
            for index in 0..total {
                let worker = u32::try_from(index / per_worker).unwrap_or(0);
                assignment.push(worker.min(workers.saturating_sub(1)));
            }
        } else {
            for index in 0..total {
                assignment.push(offset_u32(index) % workers);
            }
        }
        Ok(Self {
            workers,
            assignment,
        })
    }

    /// How many workers the plan declares.
    #[must_use]
    pub const fn workers(&self) -> u32 {
        self.workers
    }

    /// The worker each input is assigned to, in input order.
    #[must_use]
    pub fn assignment(&self) -> &[u32] {
        &self.assignment
    }

    /// The input indices each worker owns, in input order within each shard.
    #[must_use]
    pub fn shards(&self) -> Vec<Vec<u32>> {
        let mut shards = vec![Vec::new(); usize_of(self.workers)];
        for (index, worker) in self.assignment.iter().enumerate() {
            if let Some(shard) = shards.get_mut(usize_of(*worker)) {
                shard.push(offset_u32(index));
            }
        }
        shards
    }
}

/// Why the host declared an input as not to be rendered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SkipReason {
    /// The input is unchanged since the previous batch.
    Unchanged,
    /// The host excluded the input by policy.
    ExcludedByHost,
}

impl SkipReason {
    /// Stable machine-readable tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::ExcludedByHost => "excluded_by_host",
        }
    }
}

/// One declared batch input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchInput<'src> {
    /// The source text to parse and render.
    pub source: &'src str,
    /// Set when the host has already decided not to render this input.
    pub skip: Option<SkipReason>,
}

impl<'src> BatchInput<'src> {
    /// Declares an input to be rendered.
    #[must_use]
    pub const fn render(source: &'src str) -> Self {
        Self { source, skip: None }
    }

    /// Declares an input the host has excluded, with its reason.
    #[must_use]
    pub const fn skipped(source: &'src str, reason: SkipReason) -> Self {
        Self {
            source,
            skip: Some(reason),
        }
    }
}

/// The terminal outcome of one input. Every input receives exactly one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputOutcome {
    /// The input parsed and rendered.
    Rendered(Rendered),
    /// The input hit a ceiling or a precondition and was refused.
    Refused(Refusal),
    /// The host declared the input as not to be rendered.
    Skipped(SkipReason),
}

impl InputOutcome {
    /// Stable machine-readable tag.
    #[must_use]
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::Rendered(_) => "rendered",
            Self::Refused(_) => "refused",
            Self::Skipped(_) => "skipped",
        }
    }
}

/// The complete receipt for one batch: the plan and one outcome per input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchReceipt {
    plan: BatchPlan,
    outcomes: Vec<InputOutcome>,
}

impl BatchReceipt {
    /// The plan the batch was executed under.
    #[must_use]
    pub const fn plan(&self) -> &BatchPlan {
        &self.plan
    }

    /// One outcome per input, in input order.
    #[must_use]
    pub fn outcomes(&self) -> &[InputOutcome] {
        &self.outcomes
    }

    /// How many inputs rendered.
    #[must_use]
    pub fn rendered_count(&self) -> usize {
        self.count(|outcome| matches!(outcome, InputOutcome::Rendered(_)))
    }

    /// How many inputs were refused.
    #[must_use]
    pub fn refused_count(&self) -> usize {
        self.count(|outcome| matches!(outcome, InputOutcome::Refused(_)))
    }

    /// How many inputs were skipped.
    #[must_use]
    pub fn skipped_count(&self) -> usize {
        self.count(|outcome| matches!(outcome, InputOutcome::Skipped(_)))
    }

    fn count(&self, predicate: impl Fn(&InputOutcome) -> bool) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| predicate(outcome))
            .count()
    }
}

/// Renders a batch, accounting for every declared input exactly once.
///
/// Inputs are visited shard by shard, in worker order, but each outcome is
/// stored at its own input index, so the receipt order is the input order
/// whatever the plan was.
pub fn render_batch(
    inputs: &[BatchInput<'_>],
    profile: ParseProfile,
    surface: RenderProfile,
    workload: WorkloadProfile,
) -> Result<BatchReceipt, Refusal> {
    let count = inputs.len();
    if count > usize_of(profile.limits.max_batch_inputs) {
        return Err(Refusal::exceeded(
            RefusalKind::TooManyBatchInputs,
            u64::from(profile.limits.max_batch_inputs),
            as_u64(count),
        ));
    }
    let plan = BatchPlan::derive(workload, surface, offset_u32(count))?;
    let mut outcomes: Vec<Option<InputOutcome>> = vec![None; count];
    for shard in plan.shards() {
        for index in shard {
            let position = usize_of(index);
            let Some(input) = inputs.get(position) else {
                continue;
            };
            let outcome = match input.skip {
                Some(reason) => InputOutcome::Skipped(reason),
                None => render_one(input.source, profile, surface),
            };
            if let Some(slot) = outcomes.get_mut(position) {
                *slot = Some(outcome);
            }
        }
    }
    let outcomes = outcomes
        .into_iter()
        .map(|slot| {
            slot.unwrap_or(InputOutcome::Refused(Refusal::precondition(
                RefusalKind::WorkloadUnusable,
            )))
        })
        .collect::<Vec<_>>();
    Ok(BatchReceipt { plan, outcomes })
}

fn render_one(source: &str, profile: ParseProfile, surface: RenderProfile) -> InputOutcome {
    match parse_with(source, profile) {
        Err(refusal) => InputOutcome::Refused(refusal),
        Ok(parsed) => match render(parsed.document(), surface, profile.limits) {
            Err(refusal) => InputOutcome::Refused(refusal),
            Ok(rendered) => InputOutcome::Rendered(rendered),
        },
    }
}
