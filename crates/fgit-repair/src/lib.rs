#![forbid(unsafe_code)]
//! Bounded, authority-fed scrubbing for the `microsegment_v1` durable class.
//!
//! A scrub walk does not list storage and does not treat an object read as a
//! repair decision. Its input is an authenticated, canonically ordered batch
//! of manifest-bound repair work. A missing or corrupt placement becomes a
//! [`HealthRecord::Suspect`] first; only then does the worker use the existing
//! `fgit-raptorq` repair path, which quarantines decoded bytes, verifies the
//! original commitments, revalidates current authority, and publishes through
//! its placement authority.
//!
//! `DurabilityHealthLedger` is an append-only persistence boundary, while
//! [`DurabilityHealth`] is a replayable derived view. The latter is deliberately
//! not a second durability authority or a mutable replacement for the
//! authenticated manifest/retention basis.

use core::fmt;
use std::error::Error;
use std::num::NonZeroU16;

use asupersync::security::SecurityContext;
use asupersync::{Cx, Outcome};
use fgit_object_fabric::SegmentLimits;
use fgit_object_fabric::fabric::SegmentManifest;
use fgit_raptorq::{
    MicrosegmentRaptorProfile, MicrosegmentScope, RaptorRefusal, RepairPlacementAuthority,
    RepairPlan, ScopedSymbol, repair_microsegment,
};
use fgit_resource::{BudgetGrant, Grade, ObligationLedger, ResourceError, ResourceVector};
use fgit_types::{RepositoryAuthorityHeadId, SegmentManifestId};

/// Canonical recovery-drill evidence bound to the existing S5 export attestation.
pub mod recovery_report;

/// Incarnation-bound repository deletion disclosure states.
pub mod repository_deletion;

/// Authenticated root-mark-grace-revalidate GC over immutable object fabric.
pub mod gc;

/// The sole durable class this first repair slice can scrub.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DurableClass {
    /// `DUR-016`, the `microsegment_v1` `RaptorQ` profile.
    MicrosegmentV1,
}

impl DurableClass {
    /// Registry durable-class identifier.
    #[must_use]
    pub const fn registry_id(self) -> &'static str {
        match self {
            Self::MicrosegmentV1 => fgit_raptorq::DURABLE_CLASS,
        }
    }
}

/// Whether a profile verifies every eligible placement or a deterministic sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScrubMode {
    /// Verify every target in an authenticated batch.
    Full,
    /// Verify `numerator / denominator` of targets using the manifest identity.
    Sample {
        /// Number of buckets admitted by the sample.
        numerator: u16,
        /// Total stable buckets.
        denominator: NonZeroU16,
    },
}

impl ScrubMode {
    /// Creates a non-vacuous deterministic sample ratio.
    pub fn sample(numerator: u16, denominator: u16) -> Result<Self, ScrubRefusal> {
        let denominator =
            NonZeroU16::new(denominator).ok_or(ScrubRefusal::ZeroSampleDenominator)?;
        if numerator == 0 || numerator > denominator.get() {
            return Err(ScrubRefusal::InvalidSampleRatio {
                numerator,
                denominator: denominator.get(),
            });
        }
        Ok(Self::Sample {
            numerator,
            denominator,
        })
    }

    /// Determines membership entirely from the immutable manifest identity.
    #[must_use]
    pub fn selects(self, target: SegmentManifestId) -> bool {
        match self {
            Self::Full => true,
            Self::Sample {
                numerator,
                denominator,
            } => {
                let bytes = target.as_internal_object_id().digest().as_bytes();
                let high = bytes.first().copied().unwrap_or(0);
                let low = bytes.get(1).copied().unwrap_or(0);
                let bucket = u16::from_be_bytes([high, low]) % denominator.get();
                bucket < numerator
            }
        }
    }
}

/// Static bounds for one background scrub walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScrubProfile {
    mode: ScrubMode,
    max_targets: u16,
    max_target_bytes: u64,
    foreground_floor: ResourceVector,
    worker_budget: ResourceVector,
    repair_budget: ResourceVector,
}

impl ScrubProfile {
    /// Creates a profile after checking the bounds that must hold before work starts.
    pub fn new(
        mode: ScrubMode,
        max_targets: u16,
        max_target_bytes: u64,
        foreground_floor: ResourceVector,
        worker_budget: ResourceVector,
        repair_budget: ResourceVector,
    ) -> Result<Self, ScrubRefusal> {
        if max_targets == 0 {
            return Err(ScrubRefusal::ZeroTargetLimit);
        }
        let profile_limit =
            u64::try_from(MicrosegmentRaptorProfile::MAX_SOURCE_BYTES).unwrap_or(u64::MAX);
        if max_target_bytes == 0 || max_target_bytes > profile_limit {
            return Err(ScrubRefusal::TargetBytesOutOfProfile {
                offered: max_target_bytes,
                maximum: profile_limit,
            });
        }
        for grade in [Grade::Bytes, Grade::CpuMicros] {
            if repair_budget.get(grade) == 0 {
                return Err(ScrubRefusal::RepairBudgetMissingGrade { grade });
            }
        }
        if let Some(error) = worker_budget.first_deficit(&repair_budget) {
            return Err(ScrubRefusal::WorkerBudgetCannotFundRepair(error));
        }
        Ok(Self {
            mode,
            max_targets,
            max_target_bytes,
            foreground_floor,
            worker_budget,
            repair_budget,
        })
    }

    /// Whether this profile samples or verifies every authenticated target.
    #[must_use]
    pub const fn mode(&self) -> ScrubMode {
        self.mode
    }

    /// Maximum targets accepted from one source page.
    #[must_use]
    pub const fn max_targets(&self) -> u16 {
        self.max_targets
    }

    /// Maximum bytes in one `microsegment_v1` source.
    #[must_use]
    pub const fn max_target_bytes(&self) -> u64 {
        self.max_target_bytes
    }

    /// Budget left available for foreground work before a scrub starts.
    #[must_use]
    pub const fn foreground_floor(&self) -> ResourceVector {
        self.foreground_floor
    }

    /// Total budget one scrub walk can acquire.
    #[must_use]
    pub const fn worker_budget(&self) -> ResourceVector {
        self.worker_budget
    }

    /// Budget carved out for one repair permit.
    #[must_use]
    pub const fn repair_budget(&self) -> ResourceVector {
        self.repair_budget
    }
}

/// One manifest-bound source/symbol set from an authenticated scrub basis.
#[derive(Clone, Debug)]
pub struct AuthenticatedScrubTarget {
    identity: SegmentManifestId,
    expected: MicrosegmentScope,
    manifest: SegmentManifest,
    authority_basis: RepositoryAuthorityHeadId,
    symbols: Vec<ScopedSymbol>,
}

impl AuthenticatedScrubTarget {
    /// Binds repair material to exactly one manifest and authority basis.
    pub fn new(
        expected: MicrosegmentScope,
        manifest: SegmentManifest,
        authority_basis: RepositoryAuthorityHeadId,
        symbols: Vec<ScopedSymbol>,
    ) -> Result<Self, ScrubRefusal> {
        let identity = manifest
            .identity()
            .map_err(|_| ScrubRefusal::ManifestIdentityUnavailable)?;
        if manifest.namespace() != expected.namespace()
            || manifest.segment_digest() != expected.segment_digest()
        {
            return Err(ScrubRefusal::ManifestScopeMismatch);
        }
        Ok(Self {
            identity,
            expected,
            manifest,
            authority_basis,
            symbols,
        })
    }

    /// Authenticated immutable manifest identity used for order and sampling.
    #[must_use]
    pub const fn identity(&self) -> SegmentManifestId {
        self.identity
    }

    /// Exact authority basis against which the source read this target.
    #[must_use]
    pub const fn authority_basis(&self) -> RepositoryAuthorityHeadId {
        self.authority_basis
    }

    /// Exact protected source length.
    #[must_use]
    pub const fn source_len(&self) -> u64 {
        self.expected.source_len()
    }

    const fn repair_plan(&self) -> RepairPlan<'_> {
        RepairPlan {
            expected: &self.expected,
            manifest: &self.manifest,
            authority_basis: self.authority_basis,
        }
    }
}

/// A canonically ordered source page obtained from one authenticated authority basis.
#[derive(Clone, Debug)]
pub struct AuthenticatedScrubBatch {
    authority_basis: RepositoryAuthorityHeadId,
    schedule_sequence: u64,
    remaining_targets: u32,
    targets: Vec<AuthenticatedScrubTarget>,
}

impl AuthenticatedScrubBatch {
    /// Validates basis agreement and strict manifest-identity ordering.
    pub fn new(
        authority_basis: RepositoryAuthorityHeadId,
        schedule_sequence: u64,
        remaining_targets: u32,
        targets: Vec<AuthenticatedScrubTarget>,
    ) -> Result<Self, ScrubRefusal> {
        let mut previous = None;
        for target in &targets {
            if target.authority_basis() != authority_basis {
                return Err(ScrubRefusal::BatchAuthorityMismatch);
            }
            if let Some(previous_identity) = previous {
                if target.identity() == previous_identity {
                    return Err(ScrubRefusal::DuplicateTarget);
                }
                if target.identity() < previous_identity {
                    return Err(ScrubRefusal::NonCanonicalTargetOrder);
                }
            }
            previous = Some(target.identity());
        }
        Ok(Self {
            authority_basis,
            schedule_sequence,
            remaining_targets,
            targets,
        })
    }

    /// Authority root used to read every target in this page.
    #[must_use]
    pub const fn authority_basis(&self) -> RepositoryAuthorityHeadId {
        self.authority_basis
    }

    /// Logical scheduling sequence; this is not an ambient clock.
    #[must_use]
    pub const fn schedule_sequence(&self) -> u64 {
        self.schedule_sequence
    }

    /// Eligible targets still pending after this page.
    #[must_use]
    pub const fn remaining_targets(&self) -> u32 {
        self.remaining_targets
    }

    /// Ordered repair targets from the authenticated basis.
    #[must_use]
    pub fn targets(&self) -> &[AuthenticatedScrubTarget] {
        &self.targets
    }
}

/// What a bounded placement verification observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScrubObservation {
    /// A placement passed the profile's verification closure.
    Verified,
    /// The authoritative manifest named a placement that was not present.
    Missing,
    /// A placement was present but failed the profile's verification closure.
    Corrupt,
}

/// The authority-fed source and repair-publication boundary for one scrub class.
///
/// Implementations enumerate only manifest identities reachable from an
/// authenticated retention/placement basis. They must not substitute a bucket,
/// directory, or cache listing for that basis.
pub trait AuthenticatedScrubSource: RepairPlacementAuthority {
    /// Loads at most `limit` canonically ordered targets after `after`.
    fn load_batch(
        &self,
        after: Option<SegmentManifestId>,
        limit: u16,
    ) -> Result<AuthenticatedScrubBatch, ScrubRefusal>;

    /// Performs the profile's bounded placement verification for one target.
    fn probe(&self, target: &AuthenticatedScrubTarget) -> Result<ScrubObservation, ScrubRefusal>;
}

/// Append-only health evidence from a scrub or destructive drill.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HealthRecord {
    /// A placement verification reached a concrete outcome.
    TargetChecked {
        /// Protected durable class.
        class: DurableClass,
        /// Logical schedule sequence.
        sequence: u64,
        /// Manifest that was checked.
        target: SegmentManifestId,
        /// Observed placement state.
        observation: ScrubObservation,
    },
    /// A non-healthy placement entered repair detection.
    Suspect {
        /// Protected durable class.
        class: DurableClass,
        /// Logical schedule sequence.
        sequence: u64,
        /// Manifest sent to the repair state machine's Detect stage.
        target: SegmentManifestId,
        /// The trigger retained with the repair evidence.
        observation: ScrubObservation,
    },
    /// The repair attempt's terminal outcome.
    Repair {
        /// Protected durable class.
        class: DurableClass,
        /// Logical schedule sequence.
        sequence: u64,
        /// Repaired or refused manifest.
        target: SegmentManifestId,
        /// Outcome after decode, verification, authority revalidation, and publication.
        outcome: RepairOutcome,
    },
    /// A bounded walk completed and named the remaining authenticated backlog.
    WalkCompleted {
        /// Protected durable class.
        class: DurableClass,
        /// Logical schedule sequence.
        sequence: u64,
        /// Targets actually selected and checked.
        checked_targets: u32,
        /// Targets skipped by deterministic sampling.
        skipped_targets: u32,
        /// Eligible targets still pending after the page.
        remaining_targets: u32,
    },
    /// A destructive recovery drill completed for this class.
    DestructiveDrillCompleted {
        /// Protected durable class.
        class: DurableClass,
        /// Logical schedule sequence of the drill evidence.
        sequence: u64,
    },
}

impl HealthRecord {
    /// Logical sequence used to order this evidence on replay.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        match self {
            Self::TargetChecked { sequence, .. }
            | Self::Suspect { sequence, .. }
            | Self::Repair { sequence, .. }
            | Self::WalkCompleted { sequence, .. }
            | Self::DestructiveDrillCompleted { sequence, .. } => *sequence,
        }
    }
}

/// Terminal result of the `RaptorQ` repair state machine after a scrub trigger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RepairOutcome {
    /// Verified bytes were published under the revalidated authority basis.
    Published,
    /// The worker retained the suspect but lacked another complete repair budget.
    DeferredForBudget,
    /// The existing `RaptorQ` repair machinery refused the candidate or publication.
    Refused(RaptorRefusal),
}

/// Persistence boundary for health evidence.
///
/// A production implementation appends these records to its declared durable
/// evidence/operations stream. This trait intentionally provides no in-memory
/// production implementation: a local collection is suitable only as a test
/// observer and cannot stand in for a durability ledger.
pub trait DurabilityHealthLedger {
    /// Appends one immutable health record or refuses without claiming it landed.
    fn append(&self, record: HealthRecord) -> Result<(), ScrubRefusal>;
}

/// Replayable derived durability-health view, never an authority source.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DurabilityHealth {
    last_record_sequence: Option<u64>,
    last_scrub_sequence: Option<u64>,
    last_destructive_drill_sequence: Option<u64>,
    checked_targets: u64,
    suspect_targets: u64,
    repairs_published: u64,
    repairs_refused: u64,
    repairs_deferred: u64,
    last_walk_checked_targets: Option<u32>,
    last_walk_skipped_targets: Option<u32>,
    remaining_targets: u32,
}

impl DurabilityHealth {
    /// Replays a contiguous nondecreasing evidence stream.
    pub fn replay(records: &[HealthRecord]) -> Result<Self, ScrubRefusal> {
        let mut health = Self::default();
        for record in records {
            health.apply(record)?;
        }
        Ok(health)
    }

    /// Applies one appended record to this derived view.
    pub const fn apply(&mut self, record: &HealthRecord) -> Result<(), ScrubRefusal> {
        if let Some(previous) = self.last_record_sequence
            && record.sequence() < previous
        {
            return Err(ScrubRefusal::NonMonotoneHealthSequence {
                previous,
                observed: record.sequence(),
            });
        }
        self.last_record_sequence = Some(record.sequence());
        match record {
            HealthRecord::TargetChecked { .. } => self.checked_targets += 1,
            HealthRecord::Suspect { .. } => self.suspect_targets += 1,
            HealthRecord::Repair { outcome, .. } => match outcome {
                RepairOutcome::Published => self.repairs_published += 1,
                RepairOutcome::DeferredForBudget => self.repairs_deferred += 1,
                RepairOutcome::Refused(_) => self.repairs_refused += 1,
            },
            HealthRecord::WalkCompleted {
                sequence,
                checked_targets,
                skipped_targets,
                remaining_targets,
                ..
            } => {
                self.last_scrub_sequence = Some(*sequence);
                self.last_walk_checked_targets = Some(*checked_targets);
                self.last_walk_skipped_targets = Some(*skipped_targets);
                self.remaining_targets = *remaining_targets;
            }
            HealthRecord::DestructiveDrillCompleted { sequence, .. } => {
                self.last_destructive_drill_sequence = Some(*sequence);
            }
        }
        Ok(())
    }

    /// Current metrics derived exclusively from appended records.
    #[must_use]
    pub const fn metrics(&self) -> DurabilityHealthMetrics {
        DurabilityHealthMetrics {
            last_scrub_sequence: self.last_scrub_sequence,
            last_destructive_drill_sequence: self.last_destructive_drill_sequence,
            checked_targets: self.checked_targets,
            suspect_targets: self.suspect_targets,
            repairs_published: self.repairs_published,
            repairs_refused: self.repairs_refused,
            repairs_deferred: self.repairs_deferred,
            last_walk_checked_targets: self.last_walk_checked_targets,
            last_walk_skipped_targets: self.last_walk_skipped_targets,
            remaining_targets: self.remaining_targets,
        }
    }

    /// Computes typed alarms at a caller-supplied logical sequence.
    #[must_use]
    pub fn alarms(&self, now_sequence: u64, thresholds: HealthThresholds) -> Vec<HealthAlarm> {
        let mut alarms = Vec::new();
        let scrub_lag = self
            .last_scrub_sequence
            .map_or(u64::MAX, |last| now_sequence.saturating_sub(last));
        if scrub_lag > thresholds.maximum_scrub_lag {
            alarms.push(HealthAlarm::ScrubLagExceeded {
                observed: scrub_lag,
                maximum: thresholds.maximum_scrub_lag,
            });
        }
        let coverage = self.metrics().coverage_per_mille();
        if coverage < thresholds.minimum_coverage_per_mille {
            alarms.push(HealthAlarm::CoverageBelowMinimum {
                observed: coverage,
                minimum: thresholds.minimum_coverage_per_mille,
            });
        }
        let drill_age = self
            .last_destructive_drill_sequence
            .map(|last| now_sequence.saturating_sub(last));
        if drill_age.is_none_or(|age| age > thresholds.maximum_drill_age) {
            alarms.push(HealthAlarm::DestructiveDrillOverdue {
                last_drill: self.last_destructive_drill_sequence,
                current_sequence: now_sequence,
                maximum_age: thresholds.maximum_drill_age,
            });
        }
        alarms
    }
}

/// Metrics derived from health records, with no local listing authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurabilityHealthMetrics {
    /// Latest completed scrub logical sequence.
    pub last_scrub_sequence: Option<u64>,
    /// Latest successful destructive drill logical sequence.
    pub last_destructive_drill_sequence: Option<u64>,
    /// Total target probes observed in the replayed evidence.
    pub checked_targets: u64,
    /// Total detected missing/corrupt targets.
    pub suspect_targets: u64,
    /// Repairs published after current-authority revalidation.
    pub repairs_published: u64,
    /// Repair refusals retained as health evidence.
    pub repairs_refused: u64,
    /// Repairs deferred because no full permit budget remained.
    pub repairs_deferred: u64,
    /// Checked targets in the most recently completed authenticated walk.
    pub last_walk_checked_targets: Option<u32>,
    /// Targets the most recent completed walk skipped under its deterministic sample policy.
    pub last_walk_skipped_targets: Option<u32>,
    /// Pending authenticated targets named by the latest completed walk.
    pub remaining_targets: u32,
}

impl DurabilityHealthMetrics {
    /// The latest-walk coverage ratio, rounded down in thousandths.
    #[must_use]
    pub fn coverage_per_mille(&self) -> u16 {
        self.last_walk_checked_targets.map_or(0, |checked_targets| {
            coverage_per_mille(
                u64::from(checked_targets),
                u64::from(self.last_walk_skipped_targets.unwrap_or(0)),
                u64::from(self.remaining_targets),
            )
        })
    }
}

/// Thresholds over replayed logical schedule evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HealthThresholds {
    maximum_scrub_lag: u64,
    minimum_coverage_per_mille: u16,
    maximum_drill_age: u64,
}

impl HealthThresholds {
    /// Builds bounded thresholds without interpreting wall-clock time.
    pub const fn new(
        maximum_scrub_lag: u64,
        minimum_coverage_per_mille: u16,
        maximum_drill_age: u64,
    ) -> Result<Self, ScrubRefusal> {
        if minimum_coverage_per_mille > 1_000 {
            return Err(ScrubRefusal::CoverageThresholdOutOfRange(
                minimum_coverage_per_mille,
            ));
        }
        Ok(Self {
            maximum_scrub_lag,
            minimum_coverage_per_mille,
            maximum_drill_age,
        })
    }
}

/// Health condition that must be surfaced rather than silently retried away.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HealthAlarm {
    /// The latest complete walk is too far behind the caller's logical schedule.
    ScrubLagExceeded {
        /// Observed logical lag.
        observed: u64,
        /// Permitted logical lag.
        maximum: u64,
    },
    /// The latest walk covered too little of its authenticated backlog.
    CoverageBelowMinimum {
        /// Observed coverage in thousandths.
        observed: u16,
        /// Required coverage in thousandths.
        minimum: u16,
    },
    /// No destructive drill has completed inside the permitted schedule window.
    DestructiveDrillOverdue {
        /// Last completed drill, if any.
        last_drill: Option<u64>,
        /// Sequence at which this alarm was evaluated.
        current_sequence: u64,
        /// Largest permitted age in logical sequence units.
        maximum_age: u64,
    },
}

/// Result of one completed scrub page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScrubReport {
    /// Authority basis shared by every target on this page.
    pub authority_basis: RepositoryAuthorityHeadId,
    /// Logical schedule sequence of the page.
    pub schedule_sequence: u64,
    /// Selected targets whose placement was checked.
    pub checked_targets: u32,
    /// Authenticated targets skipped by deterministic sampling.
    pub skipped_targets: u32,
    /// Missing/corrupt targets emitted to the repair machine.
    pub suspect_targets: u32,
    /// Repairs whose placement publication completed.
    pub repairs_published: u32,
    /// Repairs retained as typed refusals.
    pub repairs_refused: u32,
    /// Repairs held for a later page because no complete permit budget remained.
    pub repairs_deferred: u32,
    /// Remaining targets reported by the authenticated source.
    pub remaining_targets: u32,
    /// Last processed manifest identity for the next deterministic page.
    pub resume_after: Option<SegmentManifestId>,
}

/// Bounded scrub worker for one registered durable class.
#[derive(Clone, Debug)]
pub struct ScrubWorker {
    profile: ScrubProfile,
    segment_limits: SegmentLimits,
}

impl ScrubWorker {
    /// Constructs a worker whose source-byte ceiling is already profile-checked.
    #[must_use]
    pub const fn new(profile: ScrubProfile, segment_limits: SegmentLimits) -> Self {
        Self {
            profile,
            segment_limits,
        }
    }

    /// Executes one bounded, cancellable scrub page.
    ///
    /// Cancellation is observed before the source read and before each target.
    /// One `microsegment_v1` repair is bounded to the registered 8 KiB profile;
    /// the existing `RaptorQ` repair path owns the decode/verify/publish interval.
    pub fn walk<Caps>(
        &self,
        cx: &Cx<Caps>,
        source: &impl AuthenticatedScrubSource,
        ledger: &ObligationLedger,
        health: &impl DurabilityHealthLedger,
        security: &SecurityContext,
        after: Option<SegmentManifestId>,
    ) -> Outcome<ScrubReport, ScrubRefusal> {
        if let Some(outcome) = checkpoint(cx) {
            return outcome;
        }
        let mut worker_budget = match self.acquire_budget(ledger) {
            Ok(budget) => budget,
            Err(refusal) => return Outcome::Err(refusal),
        };
        let batch = match source.load_batch(after, self.profile.max_targets()) {
            Ok(batch) => batch,
            Err(refusal) => {
                let _released = worker_budget.release();
                return Outcome::Err(refusal);
            }
        };
        if batch.targets().len() > usize::from(self.profile.max_targets()) {
            let _released = worker_budget.release();
            return Outcome::Err(ScrubRefusal::BatchTooLarge {
                offered: batch.targets().len(),
                maximum: self.profile.max_targets(),
            });
        }

        let mut checked_targets = 0_u32;
        let mut skipped_targets = 0_u32;
        let mut suspect_targets = 0_u32;
        let mut repairs_published = 0_u32;
        let mut repairs_refused = 0_u32;
        let mut repairs_deferred = 0_u32;
        let mut resume_after = after;

        for target in batch.targets() {
            if let Some(outcome) = checkpoint(cx) {
                let _released = worker_budget.release();
                return outcome;
            }
            resume_after = Some(target.identity());
            if target.source_len() > self.profile.max_target_bytes() {
                let _released = worker_budget.release();
                return Outcome::Err(ScrubRefusal::TargetBytesOutOfProfile {
                    offered: target.source_len(),
                    maximum: self.profile.max_target_bytes(),
                });
            }
            if !self.profile.mode().selects(target.identity()) {
                skipped_targets = skipped_targets.saturating_add(1);
                continue;
            }
            let observation = match source.probe(target) {
                Ok(observation) => observation,
                Err(refusal) => {
                    let _released = worker_budget.release();
                    return Outcome::Err(refusal);
                }
            };
            checked_targets = checked_targets.saturating_add(1);
            if let Err(refusal) = health.append(HealthRecord::TargetChecked {
                class: DurableClass::MicrosegmentV1,
                sequence: batch.schedule_sequence(),
                target: target.identity(),
                observation,
            }) {
                let _released = worker_budget.release();
                return Outcome::Err(refusal);
            }
            if observation == ScrubObservation::Verified {
                continue;
            }

            suspect_targets = suspect_targets.saturating_add(1);
            if let Err(refusal) = health.append(HealthRecord::Suspect {
                class: DurableClass::MicrosegmentV1,
                sequence: batch.schedule_sequence(),
                target: target.identity(),
                observation,
            }) {
                let _released = worker_budget.release();
                return Outcome::Err(refusal);
            }
            let repair_budget = match worker_budget.split_off(&self.profile.repair_budget()) {
                Ok(budget) => budget,
                Err(_) => {
                    repairs_deferred = repairs_deferred.saturating_add(1);
                    if let Err(refusal) = health.append(HealthRecord::Repair {
                        class: DurableClass::MicrosegmentV1,
                        sequence: batch.schedule_sequence(),
                        target: target.identity(),
                        outcome: RepairOutcome::DeferredForBudget,
                    }) {
                        let _released = worker_budget.release();
                        return Outcome::Err(refusal);
                    }
                    continue;
                }
            };
            match repair_microsegment(
                target.repair_plan(),
                &target.symbols,
                &self.segment_limits,
                security,
                ledger,
                repair_budget,
                source,
            ) {
                Ok(_) => {
                    repairs_published = repairs_published.saturating_add(1);
                    if let Err(refusal) = health.append(HealthRecord::Repair {
                        class: DurableClass::MicrosegmentV1,
                        sequence: batch.schedule_sequence(),
                        target: target.identity(),
                        outcome: RepairOutcome::Published,
                    }) {
                        let _released = worker_budget.release();
                        return Outcome::Err(refusal);
                    }
                }
                Err(refusal) => {
                    repairs_refused = repairs_refused.saturating_add(1);
                    if let Err(health_refusal) = health.append(HealthRecord::Repair {
                        class: DurableClass::MicrosegmentV1,
                        sequence: batch.schedule_sequence(),
                        target: target.identity(),
                        outcome: RepairOutcome::Refused(refusal),
                    }) {
                        let _released = worker_budget.release();
                        return Outcome::Err(health_refusal);
                    }
                }
            }
        }

        if let Err(refusal) = health.append(HealthRecord::WalkCompleted {
            class: DurableClass::MicrosegmentV1,
            sequence: batch.schedule_sequence(),
            checked_targets,
            skipped_targets,
            remaining_targets: batch.remaining_targets(),
        }) {
            let _released = worker_budget.release();
            return Outcome::Err(refusal);
        }
        let _released = worker_budget.release();
        Outcome::Ok(ScrubReport {
            authority_basis: batch.authority_basis(),
            schedule_sequence: batch.schedule_sequence(),
            checked_targets,
            skipped_targets,
            suspect_targets,
            repairs_published,
            repairs_refused,
            repairs_deferred,
            remaining_targets: batch.remaining_targets(),
            resume_after,
        })
    }

    fn acquire_budget(&self, ledger: &ObligationLedger) -> Result<BudgetGrant, ScrubRefusal> {
        let required = self
            .profile
            .foreground_floor()
            .combine(&self.profile.worker_budget())
            .map_err(ScrubRefusal::Resource)?;
        if let Some(ResourceError::Conservation {
            grade,
            available,
            requested,
        }) = ledger.snapshot().available().first_deficit(&required)
        {
            return Err(ScrubRefusal::ForegroundFloorWouldBeViolated {
                grade,
                available,
                required: requested,
            });
        }
        ledger
            .grant(self.profile.worker_budget())
            .map_err(ScrubRefusal::Resource)
    }
}

/// Records a completed destructive drill through the same append-only ledger boundary.
pub fn record_destructive_drill(
    ledger: &impl DurabilityHealthLedger,
    sequence: u64,
) -> Result<(), ScrubRefusal> {
    ledger.append(HealthRecord::DestructiveDrillCompleted {
        class: DurableClass::MicrosegmentV1,
        sequence,
    })
}

/// Typed refusal from profile admission, authenticated inventory, or health persistence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScrubRefusal {
    /// A page with zero capacity cannot make progress.
    ZeroTargetLimit,
    /// A sample denominator of zero has no stable buckets.
    ZeroSampleDenominator,
    /// A sample ratio was empty or exceeded its denominator.
    InvalidSampleRatio {
        /// Requested bucket count.
        numerator: u16,
        /// Available bucket count.
        denominator: u16,
    },
    /// Target-size bound was zero or exceeded the registered `RaptorQ` profile.
    TargetBytesOutOfProfile {
        /// Requested or observed size.
        offered: u64,
        /// Registered profile maximum.
        maximum: u64,
    },
    /// A repair permit would lack a required resource grade.
    RepairBudgetMissingGrade {
        /// Required grade that was zero.
        grade: Grade,
    },
    /// The worker budget could not carve one complete repair permit.
    WorkerBudgetCannotFundRepair(ResourceError),
    /// The authenticated manifest could not reproduce its typed identity.
    ManifestIdentityUnavailable,
    /// A manifest and protected `RaptorQ` scope disagreed.
    ManifestScopeMismatch,
    /// A batch mixed targets from distinct authority bases.
    BatchAuthorityMismatch,
    /// A batch repeated one manifest identity.
    DuplicateTarget,
    /// A batch was not sorted by immutable manifest identity.
    NonCanonicalTargetOrder,
    /// The authenticated source returned more targets than the pre-admitted bound.
    BatchTooLarge {
        /// Target count returned by the source.
        offered: usize,
        /// Maximum accepted count.
        maximum: u16,
    },
    /// Starting the scrub would consume budget reserved for foreground work.
    ForegroundFloorWouldBeViolated {
        /// First resource grade that would cross the floor.
        grade: Grade,
        /// Currently available amount.
        available: u64,
        /// Amount required by floor plus walk.
        required: u64,
    },
    /// The health ledger refused one record; the worker never claims that record landed.
    HealthLedgerAppendFailed,
    /// Health records were supplied out of their logical sequence order.
    NonMonotoneHealthSequence {
        /// Previous observed sequence.
        previous: u64,
        /// Later record's invalid older sequence.
        observed: u64,
    },
    /// Coverage threshold was outside zero through one thousand per mille.
    CoverageThresholdOutOfRange(u16),
    /// A runtime checkpoint rejected without an attached cancellation reason.
    RuntimeCheckpointRejected,
    /// A `RaptorQ` repair refusal was retained in the health evidence.
    Raptor(Box<RaptorRefusal>),
    /// Resource algebra refused a pre-work or budget operation.
    Resource(ResourceError),
}

impl fmt::Display for ScrubRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroTargetLimit => formatter.write_str("scrub target limit must be non-zero"),
            Self::ZeroSampleDenominator => {
                formatter.write_str("scrub sample denominator must be non-zero")
            }
            Self::InvalidSampleRatio {
                numerator,
                denominator,
            } => write!(
                formatter,
                "sample ratio {numerator}/{denominator} is invalid"
            ),
            Self::TargetBytesOutOfProfile { offered, maximum } => write!(
                formatter,
                "scrub target has {offered} bytes; registered profile permits at most {maximum}"
            ),
            Self::RepairBudgetMissingGrade { grade } => {
                write!(
                    formatter,
                    "repair permit budget omitted required grade {grade}"
                )
            }
            Self::WorkerBudgetCannotFundRepair(error) | Self::Resource(error) => {
                fmt::Display::fmt(error, formatter)
            }
            Self::ManifestIdentityUnavailable => {
                formatter.write_str("scrub target manifest identity is unavailable")
            }
            Self::ManifestScopeMismatch => {
                formatter.write_str("scrub target manifest does not match protected RaptorQ scope")
            }
            Self::BatchAuthorityMismatch => {
                formatter.write_str("scrub batch mixes authenticated authority bases")
            }
            Self::DuplicateTarget => formatter.write_str("scrub batch repeats a manifest target"),
            Self::NonCanonicalTargetOrder => {
                formatter.write_str("scrub batch is not in canonical manifest-identity order")
            }
            Self::BatchTooLarge { offered, maximum } => write!(
                formatter,
                "scrub source returned {offered} targets; walk bound is {maximum}"
            ),
            Self::ForegroundFloorWouldBeViolated {
                grade,
                available,
                required,
            } => write!(
                formatter,
                "scrub would leave foreground grade {grade} below its floor: {available} available, {required} required"
            ),
            Self::HealthLedgerAppendFailed => {
                formatter.write_str("durability health ledger rejected a scrub record")
            }
            Self::NonMonotoneHealthSequence { previous, observed } => write!(
                formatter,
                "health record sequence {observed} follows later sequence {previous}"
            ),
            Self::CoverageThresholdOutOfRange(value) => write!(
                formatter,
                "coverage threshold {value} exceeds one thousand per mille"
            ),
            Self::RuntimeCheckpointRejected => {
                formatter.write_str("runtime checkpoint rejected without a cancellation reason")
            }
            Self::Raptor(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl Error for ScrubRefusal {}

fn coverage_per_mille(checked_targets: u64, skipped_targets: u64, remaining_targets: u64) -> u16 {
    let total =
        u128::from(checked_targets) + u128::from(skipped_targets) + u128::from(remaining_targets);
    if total == 0 {
        return 1_000;
    }
    let coverage = (u128::from(checked_targets) * 1_000) / total;
    u16::try_from(coverage).expect("coverage is mathematically bounded by one thousand")
}

fn checkpoint<T, Caps>(cx: &Cx<Caps>) -> Option<Outcome<T, ScrubRefusal>> {
    if cx.checkpoint().is_ok() {
        return None;
    }
    // A failed checkpoint without a reason is reachable through the upstream
    // test-only `set_cancel_requested(true)` hook. FrankenGit has no call
    // sites for that hook, so ordinary production cancellation reaches the
    // `Cancelled` branch; retain this typed refusal if that discipline changes.
    cx.cancel_reason().map_or_else(
        || Some(Outcome::Err(ScrubRefusal::RuntimeCheckpointRejected)),
        |reason| Some(Outcome::Cancelled(reason)),
    )
}
