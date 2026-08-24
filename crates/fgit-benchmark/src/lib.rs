#![forbid(unsafe_code)]
//! Reproducible benchmark evidence, not a dashboard.
//!
//! The crate owns the minimum final abstraction every optimization bead needs
//! before it can make a performance claim: one artifact contains a complete
//! environment and workload identity, a baseline/candidate/A-A experiment,
//! raw observations and tails, the economic metric families, a correctness
//! oracle result for every observation, and replay/rollback instructions.
//! It deliberately does not decide that an optimization is acceptable.  It
//! produces the bounded benchmark evidence which the optimization admission
//! review consumes.
//!
//! A workload cannot opt out of the oracle. [`BenchmarkRunner`] invokes it
//! once for every measured execution, including both baseline control passes;
//! a failed or missing oracle yields a typed refusal and no claimable artifact.
//! The second baseline pass is the A/A control. A candidate delta smaller than
//! or equal to that control's p95 noise is recorded as negative evidence, not
//! a speedup.

use std::{
    collections::BTreeMap,
    fmt::{self, Write as _},
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::Instant,
};

use fgit_crypto::sha256_digest;

pub mod authority;
pub mod transport;

/// Pinned schema name for a benchmark evidence artifact.
pub const ARTIFACT_SCHEMA: &str = "frankengit.benchmark.evidence.v1";
/// Pinned schema version for [`ARTIFACT_SCHEMA`].
pub const ARTIFACT_SCHEMA_VERSION: u16 = 1;
/// A tail needs several observations; fewer are not admissible evidence.
pub const MIN_SAMPLES_PER_VARIANT: usize = 3;

/// A typed reason a benchmark record was not produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BenchmarkRefusal {
    /// A required plan field was absent.
    MissingRequiredField(&'static str),
    /// The configured sample count cannot provide a tail.
    InsufficientSamples { configured: usize, minimum: usize },
    /// The workload declined to run.
    WorkloadFailed { variant: Variant, detail: String },
    /// The correctness oracle did not certify an observed result.
    OracleFailed {
        variant: Variant,
        sample: usize,
        detail: String,
    },
    /// A metric family supplied an invalid denominator or contradictory value.
    InvalidMetric { field: &'static str, detail: String },
    /// An artifact sink could not be written.
    Io {
        operation: &'static str,
        detail: String,
    },
}

impl fmt::Display for BenchmarkRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRequiredField(field) => {
                write!(formatter, "missing required field: {field}")
            }
            Self::InsufficientSamples {
                configured,
                minimum,
            } => write!(
                formatter,
                "insufficient samples per variant: configured {configured}, minimum {minimum}"
            ),
            Self::WorkloadFailed { variant, detail } => {
                write!(formatter, "{} workload failed: {detail}", variant.as_str())
            }
            Self::OracleFailed {
                variant,
                sample,
                detail,
            } => write!(
                formatter,
                "{} correctness oracle failed for sample {sample}: {detail}",
                variant.as_str()
            ),
            Self::InvalidMetric { field, detail } => {
                write!(formatter, "invalid metric {field}: {detail}")
            }
            Self::Io { operation, detail } => write!(formatter, "{operation}: {detail}"),
        }
    }
}

impl std::error::Error for BenchmarkRefusal {}

fn io_refusal(operation: &'static str, error: io::Error) -> BenchmarkRefusal {
    BenchmarkRefusal::Io {
        operation,
        detail: error.to_string(),
    }
}

/// Which required execution produced a measurement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Variant {
    /// The pre-optimization implementation.
    Baseline,
    /// The proposed implementation.
    Candidate,
    /// The second baseline pass used to expose A/A noise.
    AaControl,
}

impl Variant {
    /// Stable serialization label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Candidate => "candidate",
            Self::AaControl => "aa_control",
        }
    }
}

/// Source, lockfile, toolchain, host, target, and profile identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentFingerprint {
    /// Exact source revision or immutable source-tree identity.
    pub source_revision: String,
    /// Clean/dirty tree state or a stronger tree digest supplied by the runner.
    pub source_tree: String,
    /// SHA-256 digest of the exact `Cargo.lock` bytes.
    pub cargo_lock_sha256: String,
    /// Dated toolchain identity.
    pub toolchain: String,
    /// Operating-system identity.
    pub operating_system: String,
    /// CPU model or a host-provided, explicit unavailable marker.
    pub cpu: String,
    /// Build target triple.
    pub target: String,
    /// Build profile.
    pub build_profile: String,
}

impl EnvironmentFingerprint {
    /// Reads stable local inputs without shelling out to an external tool.
    ///
    /// `source_revision` and `source_tree` are explicit because a benchmark
    /// harness must not invoke Git as an ambient, unpinned source of truth.
    pub fn from_workspace(
        workspace_root: &Path,
        source_revision: impl Into<String>,
        source_tree: impl Into<String>,
        cpu: impl Into<String>,
        target: impl Into<String>,
        build_profile: impl Into<String>,
    ) -> Result<Self, BenchmarkRefusal> {
        let lock = fs::read(workspace_root.join("Cargo.lock"))
            .map_err(|error| io_refusal("read Cargo.lock", error))?;
        let toolchain = fs::read_to_string(workspace_root.join("rust-toolchain.toml"))
            .map_err(|error| io_refusal("read rust-toolchain.toml", error))?;

        Ok(Self {
            source_revision: source_revision.into(),
            source_tree: source_tree.into(),
            cargo_lock_sha256: hex(&sha256_digest(&lock)),
            toolchain,
            operating_system: format!("{}-{}", std::env::consts::OS, std::env::consts::FAMILY),
            cpu: cpu.into(),
            target: target.into(),
            build_profile: build_profile.into(),
        })
    }

    fn validate(&self) -> Result<(), BenchmarkRefusal> {
        require_nonempty("fingerprint.source_revision", &self.source_revision)?;
        require_nonempty("fingerprint.source_tree", &self.source_tree)?;
        require_nonempty("fingerprint.cargo_lock_sha256", &self.cargo_lock_sha256)?;
        require_nonempty("fingerprint.toolchain", &self.toolchain)?;
        require_nonempty("fingerprint.operating_system", &self.operating_system)?;
        require_nonempty("fingerprint.cpu", &self.cpu)?;
        require_nonempty("fingerprint.target", &self.target)?;
        require_nonempty("fingerprint.build_profile", &self.build_profile)
    }
}

/// The workload and state a result applies to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkloadDescriptor {
    /// Pinned dataset identity and generation command.
    pub dataset: String,
    /// Exact workload operation and parameters.
    pub workload: String,
    /// Whether the run began cold, warm, or in another named state.
    pub thermal_state: String,
    /// Cache state and preparation protocol.
    pub cache_state: String,
    /// Commands which prepared or ran the workload, in execution order.
    pub commands: Vec<String>,
    /// Only these environment names and values may enter the artifact.
    pub environment_allowlist: BTreeMap<String, String>,
}

impl WorkloadDescriptor {
    fn validate(&self) -> Result<(), BenchmarkRefusal> {
        require_nonempty("workload.dataset", &self.dataset)?;
        require_nonempty("workload.workload", &self.workload)?;
        require_nonempty("workload.thermal_state", &self.thermal_state)?;
        require_nonempty("workload.cache_state", &self.cache_state)?;
        if self.commands.is_empty() {
            return Err(BenchmarkRefusal::MissingRequiredField("workload.commands"));
        }
        Ok(())
    }
}

/// Required admission evidence which a benchmark must carry, never infer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OptimizationAdmission {
    /// Observable ordering/tie-break/FP/RNG/codec equivalence obligation.
    pub equivalence_obligation: String,
    /// The correctness oracle that receives every workload result.
    pub oracle_name: String,
    /// Exact command capable of reproducing the experiment.
    pub replay_command: String,
    /// Artifact or command that reverts the candidate safely.
    pub rollback_artifact: String,
    /// Claimed mechanism hypothesis, retained even on a negative result.
    pub hypothesis: String,
}

impl OptimizationAdmission {
    fn validate(&self) -> Result<(), BenchmarkRefusal> {
        require_nonempty(
            "admission.equivalence_obligation",
            &self.equivalence_obligation,
        )?;
        require_nonempty("admission.oracle_name", &self.oracle_name)?;
        require_nonempty("admission.replay_command", &self.replay_command)?;
        require_nonempty("admission.rollback_artifact", &self.rollback_artifact)?;
        require_nonempty("admission.hypothesis", &self.hypothesis)
    }
}

/// All inputs that identify one benchmark experiment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BenchmarkPlan {
    /// Immutable execution context.
    pub fingerprint: EnvironmentFingerprint,
    /// Dataset, workload, and hot/cold state.
    pub workload: WorkloadDescriptor,
    /// Behavior and replay obligations.
    pub admission: OptimizationAdmission,
    /// Raw samples captured for each baseline/candidate/A-A phase.
    pub samples_per_variant: usize,
}

impl BenchmarkPlan {
    /// Validates all constitutional evidence fields before any workload runs.
    pub fn validate(&self) -> Result<(), BenchmarkRefusal> {
        self.fingerprint.validate()?;
        self.workload.validate()?;
        self.admission.validate()?;
        if self.samples_per_variant < MIN_SAMPLES_PER_VARIANT {
            return Err(BenchmarkRefusal::InsufficientSamples {
                configured: self.samples_per_variant,
                minimum: MIN_SAMPLES_PER_VARIANT,
            });
        }
        Ok(())
    }
}

/// Storage classes needed to compute storage amplification without hiding a
/// class in one aggregate number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct StorageClasses {
    /// Canonical object bytes.
    pub canonical_bytes: u64,
    /// Repair material bytes.
    pub repair_bytes: u64,
    /// Replica bytes.
    pub replica_bytes: u64,
    /// Retained derived bytes.
    pub retained_derived_bytes: u64,
    /// Logical reachable Git bytes, the only amplification denominator.
    pub logical_reachable_git_bytes: u64,
}

impl StorageClasses {
    /// Saturating physical bytes held across every reported class.
    #[must_use]
    pub const fn retained_bytes(self) -> u64 {
        self.canonical_bytes
            .saturating_add(self.repair_bytes)
            .saturating_add(self.replica_bytes)
            .saturating_add(self.retained_derived_bytes)
    }

    /// Storage amplification in parts per million, avoiding a floating-point
    /// value that would make artifacts target-dependent.
    pub fn amplification_parts_per_million(self) -> Result<u64, BenchmarkRefusal> {
        if self.logical_reachable_git_bytes == 0 {
            return Err(BenchmarkRefusal::InvalidMetric {
                field: "storage.logical_reachable_git_bytes",
                detail: "must be nonzero for storage amplification".to_owned(),
            });
        }
        Ok(self
            .retained_bytes()
            .saturating_mul(1_000_000)
            .checked_div(self.logical_reachable_git_bytes)
            .unwrap_or(u64::MAX))
    }
}

/// Per-observation system and economic metrics supplied by an instrumented
/// workload. Latency is owned by the runner and set after the workload returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct SystemMetrics {
    /// End-to-end elapsed wall time, filled by [`BenchmarkRunner`].
    pub latency_ns: u64,
    /// CPU time attributed by the workload's pinned metric probe.
    pub cpu_ns: u64,
    /// Peak memory attributed to the workload.
    pub memory_bytes: u64,
    /// Immutable-object requests issued.
    pub object_requests: u64,
    /// Logical bytes requested from object storage.
    pub object_request_bytes: u64,
    /// Egress bytes.
    pub egress_bytes: u64,
    /// Authority decisions committed per compare-and-exchange attempt.
    pub decisions: u64,
    /// Authority compare-and-exchange attempts.
    pub cas_attempts: u64,
    /// Storage classes used for amplification.
    pub storage: StorageClasses,
}

impl SystemMetrics {
    fn validate(self) -> Result<(), BenchmarkRefusal> {
        self.storage.amplification_parts_per_million()?;
        if self.cas_attempts == 0 {
            return Err(BenchmarkRefusal::InvalidMetric {
                field: "cas_attempts",
                detail: "must be nonzero to report decisions-per-CAS".to_owned(),
            });
        }
        Ok(())
    }

    /// Decisions per CAS in parts per million.
    #[must_use]
    pub fn decisions_per_cas_parts_per_million(self) -> u64 {
        self.decisions
            .saturating_mul(1_000_000)
            .checked_div(self.cas_attempts)
            .unwrap_or(u64::MAX)
    }
}

/// One successful correctness-oracle observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleReceipt {
    /// Stable oracle identifier or result digest.
    pub receipt: String,
}

impl OracleReceipt {
    fn validate(&self) -> Result<(), BenchmarkRefusal> {
        require_nonempty("oracle.receipt", &self.receipt)
    }
}

/// An instrumented benchmark subject.
///
/// `measure` is called once per trial. The runner measures elapsed time around
/// it, then unconditionally calls `verify` on that exact output before it
/// admits the sample. A subject therefore cannot selectively disable
/// correctness while the candidate is measured.
pub trait BenchmarkWorkload {
    /// The opaque result checked by the oracle.
    type Output;

    /// Runs one operation and returns the metric families other than latency.
    fn measure(&mut self) -> Result<(Self::Output, SystemMetrics), String>;
    /// Verifies the exact output that was measured.
    fn verify(&mut self, output: &Self::Output) -> Result<OracleReceipt, String>;
}

/// One raw sample in a benchmark evidence artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawSample {
    /// Baseline, candidate, or A/A control phase.
    pub variant: Variant,
    /// Zero-based sample index within that phase.
    pub sample_index: usize,
    /// All latency, resource, and economic metrics.
    pub metrics: SystemMetrics,
    /// The mandatory concurrent correctness receipt.
    pub oracle: OracleReceipt,
}

/// Exact tail summary calculated from raw values with a deterministic
/// nearest-rank rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TailSummary {
    /// Arithmetic mean in nanoseconds.
    pub mean_ns: u64,
    /// Median in nanoseconds (upper middle for an even count).
    pub p50_ns: u64,
    /// Nearest-rank p95 in nanoseconds.
    pub p95_ns: u64,
    /// Nearest-rank p99 in nanoseconds.
    pub p99_ns: u64,
}

impl TailSummary {
    fn from_samples(samples: &[RawSample]) -> Self {
        let mut latencies: Vec<u64> = samples
            .iter()
            .map(|sample| sample.metrics.latency_ns)
            .collect();
        latencies.sort_unstable();
        let count = u64::try_from(latencies.len()).unwrap_or(u64::MAX);
        let sum = latencies.iter().copied().fold(0_u64, u64::saturating_add);
        Self {
            mean_ns: sum.checked_div(count).unwrap_or(0),
            p50_ns: percentile_nearest_rank(&latencies, 50),
            p95_ns: percentile_nearest_rank(&latencies, 95),
            p99_ns: percentile_nearest_rank(&latencies, 99),
        }
    }
}

/// The observed A/A control noise floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AaControl {
    /// Absolute p95 difference between the first and second baseline passes.
    pub p95_noise_ns: u64,
    /// Absolute p99 difference between the first and second baseline passes.
    pub p99_noise_ns: u64,
}

/// Aggregated result for all required experiment phases.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BenchmarkArtifact {
    /// Pinned artifact schema.
    pub schema: &'static str,
    /// Pinned schema version.
    pub schema_version: u16,
    /// Inputs and admission obligations.
    pub plan: BenchmarkPlan,
    /// Raw baseline observations.
    pub baseline: Vec<RawSample>,
    /// Raw candidate observations.
    pub candidate: Vec<RawSample>,
    /// Raw second-baseline observations used for A/A.
    pub aa_control: Vec<RawSample>,
    /// Baseline tail summary.
    pub baseline_tails: TailSummary,
    /// Candidate tail summary.
    pub candidate_tails: TailSummary,
    /// A/A control tail summary.
    pub aa_control_tails: TailSummary,
    /// A/A noise floor used to decide whether an A/B delta is admissible.
    pub aa_noise: AaControl,
}

impl BenchmarkArtifact {
    /// Whether the candidate p95 beats baseline by more than the observed A/A
    /// p95 noise. This is an admissibility prerequisite, not a performance
    /// claim and not an optimization approval.
    #[must_use]
    pub const fn speedup_is_admissible(&self) -> bool {
        self.baseline_tails.p95_ns
            > self
                .candidate_tails
                .p95_ns
                .saturating_add(self.aa_noise.p95_noise_ns)
    }

    /// Writes one deterministic NDJSON artifact, its replay/rollback recipe,
    /// and an append-only negative-evidence record when the hypothesis did not
    /// clear the A/A noise floor.
    pub fn write_to(&self, directory: &Path) -> Result<WrittenArtifacts, BenchmarkRefusal> {
        fs::create_dir_all(directory)
            .map_err(|error| io_refusal("create artifact directory", error))?;
        let evidence_path = directory.join("benchmark.ndjson");
        let replay_path = directory.join("replay-and-rollback.txt");
        write_file(&evidence_path, &self.to_ndjson())?;
        write_file(
            &replay_path,
            &format!(
                "replay={}\nrollback={}\n",
                self.plan.admission.replay_command, self.plan.admission.rollback_artifact
            ),
        )?;

        let negative_evidence_path = if self.speedup_is_admissible() {
            None
        } else {
            let path = directory.join("negative-evidence.ndjson");
            self.append_negative_evidence(&path)?;
            Some(path)
        };

        Ok(WrittenArtifacts {
            evidence_path,
            replay_path,
            negative_evidence_path,
        })
    }

    /// Deterministic NDJSON representation. Raw samples precede one terminal
    /// summary so a truncated artifact cannot be mistaken for an intact claim.
    #[must_use]
    pub fn to_ndjson(&self) -> String {
        let mut output = String::new();
        writeln!(
            output,
            "{{\"schema\":\"{ARTIFACT_SCHEMA}\",\"schema_version\":{ARTIFACT_SCHEMA_VERSION},\"kind\":\"begin\",\"fingerprint\":{},\"workload\":{},\"admission\":{}}}",
            fingerprint_json(&self.plan.fingerprint),
            workload_json(&self.plan.workload),
            admission_json(&self.plan.admission),
        )
        .expect("writing into a String cannot fail");
        for sample in self
            .baseline
            .iter()
            .chain(&self.candidate)
            .chain(&self.aa_control)
        {
            output.push_str(&raw_sample_json(sample));
            output.push('\n');
        }
        writeln!(
            output,
            "{{\"schema\":\"{ARTIFACT_SCHEMA}\",\"schema_version\":{ARTIFACT_SCHEMA_VERSION},\"kind\":\"terminal\",\"baseline_tails\":{},\"candidate_tails\":{},\"aa_control_tails\":{},\"aa_noise\":{{\"p95_noise_ns\":{},\"p99_noise_ns\":{}}},\"speedup_admissible\":{}}}",
            tails_json(self.baseline_tails),
            tails_json(self.candidate_tails),
            tails_json(self.aa_control_tails),
            self.aa_noise.p95_noise_ns,
            self.aa_noise.p99_noise_ns,
            self.speedup_is_admissible(),
        )
        .expect("writing into a String cannot fail");
        output
    }

    fn append_negative_evidence(&self, path: &Path) -> Result<(), BenchmarkRefusal> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|error| io_refusal("open negative-evidence ledger", error))?;
        writeln!(
            file,
            "{{\"schema\":\"frankengit.benchmark.negative-evidence.v1\",\"kind\":\"disproven_speedup\",\"hypothesis\":\"{}\",\"reason\":\"candidate_p95_did_not_beat_baseline_beyond_aa_noise\",\"baseline_p95_ns\":{},\"candidate_p95_ns\":{},\"aa_p95_noise_ns\":{},\"replay\":\"{}\",\"rollback\":\"{}\"}}",
            json_escape(&self.plan.admission.hypothesis),
            self.baseline_tails.p95_ns,
            self.candidate_tails.p95_ns,
            self.aa_noise.p95_noise_ns,
            json_escape(&self.plan.admission.replay_command),
            json_escape(&self.plan.admission.rollback_artifact),
        )
        .map_err(|error| io_refusal("append negative-evidence ledger", error))
    }
}

/// Paths emitted by [`BenchmarkArtifact::write_to`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrittenArtifacts {
    /// The immutable benchmark NDJSON artifact.
    pub evidence_path: PathBuf,
    /// The reproduction and rollback commands.
    pub replay_path: PathBuf,
    /// Present exactly when the candidate did not clear A/A noise.
    pub negative_evidence_path: Option<PathBuf>,
}

/// Runs baseline, candidate, and second baseline (A/A) phases under a single
/// validated evidence plan.
#[derive(Clone, Debug)]
pub struct BenchmarkRunner {
    plan: BenchmarkPlan,
}

impl BenchmarkRunner {
    /// Refuses an incomplete evidence plan before any subject runs.
    pub fn new(plan: BenchmarkPlan) -> Result<Self, BenchmarkRefusal> {
        plan.validate()?;
        Ok(Self { plan })
    }

    /// Captures the complete baseline/candidate/A-A experiment.
    pub fn run<B, C>(
        &self,
        baseline: &mut B,
        candidate: &mut C,
    ) -> Result<BenchmarkArtifact, BenchmarkRefusal>
    where
        B: BenchmarkWorkload,
        C: BenchmarkWorkload,
    {
        let baseline_samples = self.run_variant(Variant::Baseline, baseline)?;
        let candidate_samples = self.run_variant(Variant::Candidate, candidate)?;
        let aa_samples = self.run_variant(Variant::AaControl, baseline)?;
        let baseline_tails = TailSummary::from_samples(&baseline_samples);
        let candidate_tails = TailSummary::from_samples(&candidate_samples);
        let aa_control_tails = TailSummary::from_samples(&aa_samples);
        let aa_noise = AaControl {
            p95_noise_ns: baseline_tails.p95_ns.abs_diff(aa_control_tails.p95_ns),
            p99_noise_ns: baseline_tails.p99_ns.abs_diff(aa_control_tails.p99_ns),
        };

        Ok(BenchmarkArtifact {
            schema: ARTIFACT_SCHEMA,
            schema_version: ARTIFACT_SCHEMA_VERSION,
            plan: self.plan.clone(),
            baseline: baseline_samples,
            candidate: candidate_samples,
            aa_control: aa_samples,
            baseline_tails,
            candidate_tails,
            aa_control_tails,
            aa_noise,
        })
    }

    fn run_variant<W>(
        &self,
        variant: Variant,
        workload: &mut W,
    ) -> Result<Vec<RawSample>, BenchmarkRefusal>
    where
        W: BenchmarkWorkload,
    {
        let mut samples = Vec::with_capacity(self.plan.samples_per_variant);
        for sample_index in 0..self.plan.samples_per_variant {
            let started = Instant::now();
            let (output, mut metrics) = workload
                .measure()
                .map_err(|detail| BenchmarkRefusal::WorkloadFailed { variant, detail })?;
            metrics.validate()?;
            let oracle =
                workload
                    .verify(&output)
                    .map_err(|detail| BenchmarkRefusal::OracleFailed {
                        variant,
                        sample: sample_index,
                        detail,
                    })?;
            oracle.validate()?;
            // Verification is part of the system under test. Stopping the
            // clock before this call would make a candidate that disables or
            // defers verification look faster than the verified baseline.
            metrics.latency_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
            samples.push(RawSample {
                variant,
                sample_index,
                metrics,
                oracle,
            });
        }
        Ok(samples)
    }
}

fn require_nonempty(field: &'static str, value: &str) -> Result<(), BenchmarkRefusal> {
    if value.trim().is_empty() {
        Err(BenchmarkRefusal::MissingRequiredField(field))
    } else {
        Ok(())
    }
}

fn percentile_nearest_rank(values: &[u64], percentile: u8) -> u64 {
    let count = values.len();
    if count == 0 {
        return 0;
    }
    let rank = usize::from(percentile)
        .saturating_mul(count)
        .saturating_add(99)
        .checked_div(100)
        .unwrap_or(count)
        .clamp(1, count);
    values[rank - 1]
}

fn write_file(path: &Path, content: &str) -> Result<(), BenchmarkRefusal> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| io_refusal("create immutable artifact", error))?;
    file.write_all(content.as_bytes())
        .map_err(|error| io_refusal("write artifact", error))
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            control if control.is_control() => {
                use fmt::Write as _;
                let _ = write!(escaped, "\\u{:04x}", u32::from(control));
            }
            character => escaped.push(character),
        }
    }
    escaped
}

fn fingerprint_json(fingerprint: &EnvironmentFingerprint) -> String {
    format!(
        "{{\"source_revision\":\"{}\",\"source_tree\":\"{}\",\"cargo_lock_sha256\":\"{}\",\"toolchain\":\"{}\",\"operating_system\":\"{}\",\"cpu\":\"{}\",\"target\":\"{}\",\"build_profile\":\"{}\"}}",
        json_escape(&fingerprint.source_revision),
        json_escape(&fingerprint.source_tree),
        json_escape(&fingerprint.cargo_lock_sha256),
        json_escape(&fingerprint.toolchain),
        json_escape(&fingerprint.operating_system),
        json_escape(&fingerprint.cpu),
        json_escape(&fingerprint.target),
        json_escape(&fingerprint.build_profile),
    )
}

fn workload_json(workload: &WorkloadDescriptor) -> String {
    let commands = workload
        .commands
        .iter()
        .map(|command| format!("\"{}\"", json_escape(command)))
        .collect::<Vec<_>>()
        .join(",");
    let environment = workload
        .environment_allowlist
        .iter()
        .map(|(key, value)| format!("\"{}\":\"{}\"", json_escape(key), json_escape(value)))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"dataset\":\"{}\",\"workload\":\"{}\",\"thermal_state\":\"{}\",\"cache_state\":\"{}\",\"commands\":[{}],\"environment_allowlist\":{{{}}}}}",
        json_escape(&workload.dataset),
        json_escape(&workload.workload),
        json_escape(&workload.thermal_state),
        json_escape(&workload.cache_state),
        commands,
        environment,
    )
}

fn admission_json(admission: &OptimizationAdmission) -> String {
    format!(
        "{{\"equivalence_obligation\":\"{}\",\"oracle_name\":\"{}\",\"replay_command\":\"{}\",\"rollback_artifact\":\"{}\",\"hypothesis\":\"{}\"}}",
        json_escape(&admission.equivalence_obligation),
        json_escape(&admission.oracle_name),
        json_escape(&admission.replay_command),
        json_escape(&admission.rollback_artifact),
        json_escape(&admission.hypothesis),
    )
}

fn raw_sample_json(sample: &RawSample) -> String {
    let metrics = sample.metrics;
    let storage = metrics.storage;
    format!(
        "{{\"schema\":\"{ARTIFACT_SCHEMA}\",\"schema_version\":{ARTIFACT_SCHEMA_VERSION},\"kind\":\"sample\",\"variant\":\"{}\",\"sample_index\":{},\"metrics\":{{\"latency_ns\":{},\"cpu_ns\":{},\"memory_bytes\":{},\"object_requests\":{},\"object_request_bytes\":{},\"egress_bytes\":{},\"decisions\":{},\"cas_attempts\":{},\"decisions_per_cas_ppm\":{},\"storage\":{{\"canonical_bytes\":{},\"repair_bytes\":{},\"replica_bytes\":{},\"retained_derived_bytes\":{},\"logical_reachable_git_bytes\":{},\"amplification_ppm\":{}}}}},\"oracle\":\"{}\"}}",
        sample.variant.as_str(),
        sample.sample_index,
        metrics.latency_ns,
        metrics.cpu_ns,
        metrics.memory_bytes,
        metrics.object_requests,
        metrics.object_request_bytes,
        metrics.egress_bytes,
        metrics.decisions,
        metrics.cas_attempts,
        metrics.decisions_per_cas_parts_per_million(),
        storage.canonical_bytes,
        storage.repair_bytes,
        storage.replica_bytes,
        storage.retained_derived_bytes,
        storage.logical_reachable_git_bytes,
        storage.amplification_parts_per_million().unwrap_or(0),
        json_escape(&sample.oracle.receipt),
    )
}

fn tails_json(tails: TailSummary) -> String {
    format!(
        "{{\"mean_ns\":{},\"p50_ns\":{},\"p95_ns\":{},\"p99_ns\":{}}}",
        tails.mean_ns, tails.p50_ns, tails.p95_ns, tails.p99_ns
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct KnownCost {
        input: u32,
        padding: u32,
        oracle_calls: usize,
        fail_oracle: bool,
    }

    impl KnownCost {
        fn new(input: u32, padding: u32) -> Self {
            Self {
                input,
                padding,
                oracle_calls: 0,
                fail_oracle: false,
            }
        }
    }

    impl BenchmarkWorkload for KnownCost {
        type Output = u64;

        fn measure(&mut self) -> Result<(Self::Output, SystemMetrics), String> {
            let mut accumulator = 0_u64;
            for value in 0..self.input {
                accumulator = accumulator.wrapping_add(u64::from(value).wrapping_mul(3));
            }
            let mut padding = 0_u64;
            for value in 0..self.padding {
                padding = padding.wrapping_add(u64::from(value).wrapping_mul(7));
            }
            std::hint::black_box(padding);
            Ok((
                accumulator,
                SystemMetrics {
                    cpu_ns: u64::from(self.input).saturating_add(u64::from(self.padding)),
                    memory_bytes: 64,
                    object_requests: 2,
                    object_request_bytes: 128,
                    egress_bytes: 16,
                    decisions: 4,
                    cas_attempts: 2,
                    storage: StorageClasses {
                        canonical_bytes: 100,
                        repair_bytes: 10,
                        replica_bytes: 100,
                        retained_derived_bytes: 5,
                        logical_reachable_git_bytes: 100,
                    },
                    ..SystemMetrics::default()
                },
            ))
        }

        fn verify(&mut self, output: &Self::Output) -> Result<OracleReceipt, String> {
            self.oracle_calls = self.oracle_calls.saturating_add(1);
            if self.fail_oracle {
                return Err("known failing oracle".to_owned());
            }
            Ok(OracleReceipt {
                receipt: format!("sum-{output}"),
            })
        }
    }

    fn plan() -> BenchmarkPlan {
        BenchmarkPlan {
            fingerprint: EnvironmentFingerprint {
                source_revision: "test-revision".to_owned(),
                source_tree: "clean".to_owned(),
                cargo_lock_sha256: "00".repeat(32),
                toolchain: "nightly-2026-08-20".to_owned(),
                operating_system: "test-os".to_owned(),
                cpu: "test-cpu".to_owned(),
                target: "test-target".to_owned(),
                build_profile: "test".to_owned(),
            },
            workload: WorkloadDescriptor {
                dataset: "known-cost-v1".to_owned(),
                workload: "accumulate".to_owned(),
                thermal_state: "warm".to_owned(),
                cache_state: "primed".to_owned(),
                commands: vec!["fgit-benchmark self-test".to_owned()],
                environment_allowlist: BTreeMap::from([(
                    "RUST_LOG".to_owned(),
                    "error".to_owned(),
                )]),
            },
            admission: OptimizationAdmission {
                equivalence_obligation: "sum output is identical".to_owned(),
                oracle_name: "known-cost exact sum".to_owned(),
                replay_command: "fgit-benchmark self-test --out <dir>".to_owned(),
                rollback_artifact: "remove candidate implementation".to_owned(),
                hypothesis: "fewer arithmetic operations lower elapsed latency".to_owned(),
            },
            samples_per_variant: MIN_SAMPLES_PER_VARIANT,
        }
    }

    #[test]
    fn known_cost_self_test_captures_every_required_phase_and_oracle() {
        let runner = BenchmarkRunner::new(plan()).expect("complete plan");
        let mut baseline = KnownCost::new(3_000, 0);
        let mut candidate = KnownCost::new(3_000, 10);
        let artifact = runner
            .run(&mut baseline, &mut candidate)
            .expect("valid evidence");

        assert_eq!(artifact.schema, ARTIFACT_SCHEMA);
        assert_eq!(artifact.baseline.len(), MIN_SAMPLES_PER_VARIANT);
        assert_eq!(artifact.candidate.len(), MIN_SAMPLES_PER_VARIANT);
        assert_eq!(artifact.aa_control.len(), MIN_SAMPLES_PER_VARIANT);
        assert_eq!(baseline.oracle_calls, MIN_SAMPLES_PER_VARIANT * 2);
        assert_eq!(candidate.oracle_calls, MIN_SAMPLES_PER_VARIANT);
        assert!(artifact.to_ndjson().contains("\"kind\":\"terminal\""));
        assert!(artifact.to_ndjson().contains("\"aa_noise\""));
        assert!(artifact.to_ndjson().contains("\"decisions_per_cas_ppm\""));
    }

    #[test]
    fn an_oracle_failure_refuses_the_exact_variant_and_sample() {
        let runner = BenchmarkRunner::new(plan()).expect("complete plan");
        let mut baseline = KnownCost::new(10, 0);
        let mut candidate = KnownCost::new(10, 0);
        candidate.fail_oracle = true;

        assert_eq!(
            runner.run(&mut baseline, &mut candidate),
            Err(BenchmarkRefusal::OracleFailed {
                variant: Variant::Candidate,
                sample: 0,
                detail: "known failing oracle".to_owned(),
            })
        );
    }

    #[test]
    fn incomplete_admission_evidence_is_refused_before_workload_execution() {
        let mut incomplete = plan();
        incomplete.admission.rollback_artifact.clear();
        let refusal = BenchmarkRunner::new(incomplete).expect_err("incomplete admission refused");
        assert_eq!(
            refusal,
            BenchmarkRefusal::MissingRequiredField("admission.rollback_artifact")
        );
    }

    #[test]
    fn a_non_speedup_writes_the_append_only_negative_evidence_ledger() {
        let runner = BenchmarkRunner::new(plan()).expect("complete plan");
        let mut baseline = KnownCost::new(1_000, 0);
        let mut candidate = KnownCost::new(1_000, 1_000_000);
        let artifact = runner
            .run(&mut baseline, &mut candidate)
            .expect("valid evidence");
        let root = std::env::temp_dir().join(format!("fgit-benchmark-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        let written = artifact.write_to(&root).expect("write artifacts");
        assert!(written.evidence_path.is_file());
        assert!(written.replay_path.is_file());
        let ledger = written
            .negative_evidence_path
            .expect("identical known-cost candidate must not claim a speedup");
        assert!(
            fs::read_to_string(ledger)
                .expect("read ledger")
                .contains("disproven_speedup")
        );
        fs::remove_dir_all(root).expect("remove test artifacts");
    }

    #[test]
    fn an_existing_primary_artifact_is_refused_instead_of_overwritten() {
        let runner = BenchmarkRunner::new(plan()).expect("complete plan");
        let mut baseline = KnownCost::new(100, 0);
        let mut candidate = KnownCost::new(100, 10_000);
        let artifact = runner
            .run(&mut baseline, &mut candidate)
            .expect("valid evidence");
        let root =
            std::env::temp_dir().join(format!("fgit-benchmark-overwrite-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        artifact.write_to(&root).expect("first write succeeds");
        assert!(matches!(
            artifact.write_to(&root),
            Err(BenchmarkRefusal::Io {
                operation: "create immutable artifact",
                ..
            })
        ));
        fs::remove_dir_all(root).expect("remove test artifacts");
    }
}
