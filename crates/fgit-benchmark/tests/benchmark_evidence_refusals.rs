#![forbid(unsafe_code)]
//! The evidence harness's refusals and its one admissibility boundary
//! (`frankengit-1ky6`).
//!
//! **This crate had no `tests/` directory.** Its only coverage was an inline
//! `cfg(test)` module of five tests. Measured per variant across the whole
//! tree — `tests/`, `src`, `scripts/e2e`, `registries/*.tsv`:
//!
//! ```text
//! OracleFailed          in-src-only, one case
//! MissingRequiredField  in-src-only, ONE of nineteen field labels
//! Io                    in-src-only, one of six operations
//! InsufficientSamples   named by nothing, anywhere
//! WorkloadFailed        named by nothing, anywhere
//! InvalidMetric         named by nothing, anywhere
//! ```
//!
//! The e2e suite `scripts/e2e/suites/benchmark/benchmark_harness.sh` runs the
//! *binary* and asserts happy-path artifact contents. It probes no refusal.
//!
//! # The line this file exists for
//!
//! §7 requires a baseline/candidate/A-A control and a recorded negative
//! result; §10 forbids calling a benchmark an invariant. One expression
//! decides which side of that line a run lands on:
//!
//! ```text
//! speedup_is_admissible -> baseline.p95 > candidate.p95 + aa_noise.p95
//! ```
//!
//! The comparison is **strict**, so a candidate whose entire improvement is
//! *exactly* the observed A/A noise floor is not a speedup and must be written
//! as negative evidence. Nothing tested it in either direction. Loosening that
//! `>` to `>=` publishes noise as a speedup — RH-2 proof-class inflation,
//! mechanised.
//!
//! # Measured, not predicted
//!
//! Two mutations, each `cargo check`ed before any test ran because
//! `fgit-benchmark` is a `default-members` crate and a broken `src` here is
//! every pane's compiler:
//!
//! ```text
//! A: speedup_is_admissible, strict ">" weakened to ">="
//!    (an improvement equal to the noise floor becomes a speedup)
//!      inline cfg(test) module    5 passed  0 failed   BLIND
//!      this file                 20 passed  3 failed   caught it
//!
//! B: require_nonempty drops trim()
//!    (a field holding only spaces counts as evidence)
//!      inline cfg(test) module    5 passed  0 failed   BLIND
//!      this file                 22 passed  1 failed   caught it
//! ```
//!
//! Mutation A is caught only by accepted/refused *boundary* cases. The
//! permitted twin `one_nanosecond_past_the_noise_floor_is_admissible` stays
//! green under it, correctly: a delta past the floor is admissible either way.
//! That is the loosened/tightened asymmetry again, from the refused side.
//! Mutation B is caught by exactly one probe, the only test for that axis.
//!
//! Both were re-measured after the lint drain restructured the fixture, since
//! the earlier numbers described a file that no longer existed.
//!
//! The boundary is pinned by constructing the artifact directly rather than by
//! timing a workload: every field is `pub`, and a wall-clock-derived p95 could
//! not put a delta *exactly* on the floor twice in a row.
//!
//! # Non-claims
//!
//! This is refusal and boundary coverage for the evidence harness. It does not
//! verify that any `FrankenGit` optimization is real, and it does not make this
//! crate's output an invariant — §10 still governs whatever consumes the
//! artifact. Nothing here modifies `crates/fgit-benchmark/src/**`.

use std::{collections::BTreeMap, fs, path::PathBuf};

use fgit_benchmark::{
    ARTIFACT_SCHEMA, ARTIFACT_SCHEMA_VERSION, AaControl, BenchmarkArtifact, BenchmarkPlan,
    BenchmarkRefusal, BenchmarkRunner, BenchmarkWorkload, EnvironmentFingerprint,
    MIN_SAMPLES_PER_VARIANT, OptimizationAdmission, OracleReceipt, RawSample, StorageClasses,
    SystemMetrics, TailSummary, Variant, WorkloadDescriptor,
};

// ---------------------------------------------------------------------------
// Fixtures: one conforming plan and one conforming workload, so that every
// refusal below is a ONE-FIELD departure from an accepted run and is therefore
// attributable to the field it names.
// ---------------------------------------------------------------------------

fn conforming_fingerprint() -> EnvironmentFingerprint {
    EnvironmentFingerprint {
        source_revision: "1ky6-test-revision".to_owned(),
        source_tree: "clean".to_owned(),
        cargo_lock_sha256: "00".repeat(32),
        toolchain: "nightly-2026-08-20".to_owned(),
        operating_system: "test-os".to_owned(),
        cpu: "test-cpu".to_owned(),
        target: "test-target".to_owned(),
        build_profile: "test".to_owned(),
    }
}

fn conforming_workload_descriptor() -> WorkloadDescriptor {
    WorkloadDescriptor {
        dataset: "fixed-cost-v1".to_owned(),
        workload: "accumulate".to_owned(),
        thermal_state: "warm".to_owned(),
        cache_state: "primed".to_owned(),
        commands: vec!["fgit-benchmark self-test".to_owned()],
        environment_allowlist: BTreeMap::from([("RUST_LOG".to_owned(), "error".to_owned())]),
    }
}

fn conforming_admission() -> OptimizationAdmission {
    OptimizationAdmission {
        equivalence_obligation: "sum output is identical".to_owned(),
        oracle_name: "fixed-cost exact sum".to_owned(),
        replay_command: "fgit-benchmark self-test --out <dir>".to_owned(),
        rollback_artifact: "remove candidate implementation".to_owned(),
        hypothesis: "fewer arithmetic operations lower elapsed latency".to_owned(),
    }
}

fn conforming_plan() -> BenchmarkPlan {
    BenchmarkPlan {
        fingerprint: conforming_fingerprint(),
        workload: conforming_workload_descriptor(),
        admission: conforming_admission(),
        samples_per_variant: MIN_SAMPLES_PER_VARIANT,
    }
}

fn conforming_metrics() -> SystemMetrics {
    SystemMetrics {
        cpu_ns: 10,
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
    }
}

/// One fault a probe workload can be armed with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    /// `measure` declines on exactly this zero-based call index.
    DeclineMeasureOnCall(usize),
    /// The oracle rejects every output.
    FailOracle,
    /// The oracle returns a receipt that names nothing.
    EmptyReceipt,
    /// Report an amplification denominator of zero.
    ZeroDenominator,
    /// Report zero compare-and-exchange attempts.
    ZeroCasAttempts,
}

/// A workload whose faults are an explicit set, so a probe cannot refuse for a
/// reason it did not arm and every refusal below is attributable to one switch.
/// Only `metric_validation_precedes_the_correctness_oracle` arms two, and it
/// does so precisely to establish which of the two reports.
#[derive(Debug, Default)]
struct ProbeWorkload {
    /// Zero-based count of `measure` calls made so far on THIS object.
    calls: usize,
    /// Exactly the faults this probe is armed with.
    faults: &'static [Fault],
}

impl ProbeWorkload {
    const fn armed_with(faults: &'static [Fault]) -> Self {
        Self { calls: 0, faults }
    }

    fn is_armed(&self, fault: Fault) -> bool {
        self.faults.contains(&fault)
    }
}

impl BenchmarkWorkload for ProbeWorkload {
    type Output = u64;

    fn measure(&mut self) -> Result<(Self::Output, SystemMetrics), String> {
        let call = self.calls;
        self.calls = self.calls.saturating_add(1);
        if self.is_armed(Fault::DeclineMeasureOnCall(call)) {
            return Err(format!("probe declined on call {call}"));
        }
        let mut metrics = conforming_metrics();
        if self.is_armed(Fault::ZeroDenominator) {
            metrics.storage.logical_reachable_git_bytes = 0;
        }
        if self.is_armed(Fault::ZeroCasAttempts) {
            metrics.cas_attempts = 0;
        }
        Ok((u64::try_from(call).unwrap_or(u64::MAX), metrics))
    }

    fn verify(&mut self, output: &Self::Output) -> Result<OracleReceipt, String> {
        if self.is_armed(Fault::FailOracle) {
            return Err("probe oracle rejected the output".to_owned());
        }
        Ok(OracleReceipt {
            receipt: if self.is_armed(Fault::EmptyReceipt) {
                String::new()
            } else {
                format!("sum-{output}")
            },
        })
    }
}

fn scratch_directory(tag: &str) -> PathBuf {
    let root =
        std::env::temp_dir().join(format!("fgit-benchmark-1ky6-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    root
}

// ---------------------------------------------------------------------------
// The permitted directions, built first
// ---------------------------------------------------------------------------

/// The fixture itself is admissible, so every refusal below is attributable to
/// the single field that test changes.
#[test]
fn a_complete_plan_is_admitted() {
    conforming_plan()
        .validate()
        .expect("the conforming fixture must be a complete evidence plan");
    BenchmarkRunner::new(conforming_plan()).expect("a complete plan builds a runner");
}

/// **The exact boundary of the tail floor.** The guard reads `<`, so a plan
/// configured at exactly the minimum is admitted.
#[test]
fn exactly_the_minimum_sample_count_is_admitted() {
    let mut plan = conforming_plan();
    plan.samples_per_variant = MIN_SAMPLES_PER_VARIANT;
    plan.validate()
        .expect("exactly the minimum sample count is admissible evidence");
}

/// A conforming experiment produces every phase, and the A/A control re-runs
/// the *baseline* object — which is what makes the variant discrimination in
/// `a_baseline_that_declines_only_on_its_second_pass_reports_the_aa_control`
/// meaningful rather than incidental.
#[test]
fn a_conforming_experiment_produces_all_three_phases() {
    let runner = BenchmarkRunner::new(conforming_plan()).expect("complete plan");
    let mut baseline = ProbeWorkload::default();
    let mut candidate = ProbeWorkload::default();
    let artifact = runner
        .run(&mut baseline, &mut candidate)
        .expect("a conforming experiment yields an artifact");

    assert_eq!(artifact.schema, ARTIFACT_SCHEMA);
    assert_eq!(artifact.schema_version, ARTIFACT_SCHEMA_VERSION);
    assert_eq!(artifact.baseline.len(), MIN_SAMPLES_PER_VARIANT);
    assert_eq!(artifact.candidate.len(), MIN_SAMPLES_PER_VARIANT);
    assert_eq!(artifact.aa_control.len(), MIN_SAMPLES_PER_VARIANT);
    assert_eq!(
        baseline.calls,
        MIN_SAMPLES_PER_VARIANT * 2,
        "the A/A control must re-run the baseline object, not a fresh one"
    );
    assert_eq!(candidate.calls, MIN_SAMPLES_PER_VARIANT);
}

// ---------------------------------------------------------------------------
// InsufficientSamples — named by nothing before this file
// ---------------------------------------------------------------------------

/// Fewer samples than the tail floor cannot describe a tail.
///
/// Paired with `exactly_the_minimum_sample_count_is_admitted`: together they
/// pin the guard at its exact inclusive boundary rather than somewhere below.
#[test]
fn fewer_samples_than_the_tail_floor_are_refused() {
    for configured in 0..MIN_SAMPLES_PER_VARIANT {
        let mut plan = conforming_plan();
        plan.samples_per_variant = configured;
        assert_eq!(
            plan.validate(),
            Err(BenchmarkRefusal::InsufficientSamples {
                configured,
                minimum: MIN_SAMPLES_PER_VARIANT,
            }),
            "the refusal must report BOTH what was configured and the floor it missed"
        );
    }
}

// ---------------------------------------------------------------------------
// WorkloadFailed — named by nothing before this file
// ---------------------------------------------------------------------------

#[test]
fn a_baseline_that_declines_to_run_names_the_baseline_variant() {
    let runner = BenchmarkRunner::new(conforming_plan()).expect("complete plan");
    let mut baseline = ProbeWorkload::armed_with(&[Fault::DeclineMeasureOnCall(0)]);
    let mut candidate = ProbeWorkload::default();

    assert_eq!(
        runner.run(&mut baseline, &mut candidate),
        Err(BenchmarkRefusal::WorkloadFailed {
            variant: Variant::Baseline,
            detail: "probe declined on call 0".to_owned(),
        })
    );
    assert_eq!(
        candidate.calls, 0,
        "a failed baseline must not go on to measure the candidate"
    );
}

#[test]
fn a_candidate_that_declines_to_run_names_the_candidate_variant() {
    let runner = BenchmarkRunner::new(conforming_plan()).expect("complete plan");
    let mut baseline = ProbeWorkload::default();
    let mut candidate = ProbeWorkload::armed_with(&[Fault::DeclineMeasureOnCall(0)]);

    assert_eq!(
        runner.run(&mut baseline, &mut candidate),
        Err(BenchmarkRefusal::WorkloadFailed {
            variant: Variant::Candidate,
            detail: "probe declined on call 0".to_owned(),
        })
    );
}

/// **The A/A control is a different phase of the same object.**
///
/// `run` calls `run_variant(Baseline, baseline)` and later
/// `run_variant(AaControl, baseline)` — the *same* workload twice. A baseline
/// that declines only on its second pass must therefore report
/// `Variant::AaControl`, not `Variant::Baseline`.
///
/// That distinction is the entire point of an A/A control: it separates "the
/// baseline is broken" from "the baseline is not reproducible", and a
/// `variant` field wired to the object rather than the phase would report the
/// first while the run actually failed the second. Paired with the
/// `Baseline`-on-call-0 test above, so the field is shown to track the phase
/// and not merely to be present.
#[test]
fn a_baseline_that_declines_only_on_its_second_pass_reports_the_aa_control() {
    let runner = BenchmarkRunner::new(conforming_plan()).expect("complete plan");
    // Calls 0..MIN are the baseline pass; the next call begins the A/A pass.
    let mut baseline =
        ProbeWorkload::armed_with(&[Fault::DeclineMeasureOnCall(MIN_SAMPLES_PER_VARIANT)]);
    let mut candidate = ProbeWorkload::default();

    assert_eq!(
        runner.run(&mut baseline, &mut candidate),
        Err(BenchmarkRefusal::WorkloadFailed {
            variant: Variant::AaControl,
            detail: format!("probe declined on call {MIN_SAMPLES_PER_VARIANT}"),
        })
    );
    assert_eq!(
        candidate.calls, MIN_SAMPLES_PER_VARIANT,
        "the candidate phase completes before the A/A pass begins"
    );
}

// ---------------------------------------------------------------------------
// InvalidMetric — named by nothing before this file. TWO sites, and they are
// not reachable the same way.
// ---------------------------------------------------------------------------

/// Reachable directly: `amplification_parts_per_million` is public.
#[test]
fn a_zero_amplification_denominator_is_refused_by_name() {
    let storage = StorageClasses {
        canonical_bytes: 100,
        logical_reachable_git_bytes: 0,
        ..StorageClasses::default()
    };
    assert_eq!(
        storage.amplification_parts_per_million(),
        Err(BenchmarkRefusal::InvalidMetric {
            field: "storage.logical_reachable_git_bytes",
            detail: "must be nonzero for storage amplification".to_owned(),
        }),
        "an amplification ratio with no denominator is not a metric"
    );
}

/// The permitted twin, and it checks the quantity rather than only the `Ok`:
/// a guard that refused zero but computed the ratio the wrong way round would
/// pass a bare `is_ok`.
#[test]
fn a_nonzero_denominator_yields_the_amplification_figure() {
    let storage = StorageClasses {
        canonical_bytes: 150,
        repair_bytes: 25,
        replica_bytes: 0,
        retained_derived_bytes: 25,
        logical_reachable_git_bytes: 100,
    };
    assert_eq!(storage.retained_bytes(), 200);
    assert_eq!(
        storage.amplification_parts_per_million(),
        Ok(2_000_000),
        "200 physical bytes over 100 logical bytes is 2x, in parts per million"
    );
}

/// Reachable ONLY through the runner: `SystemMetrics::validate` is private, so
/// no external caller can drive this site directly.
#[test]
fn zero_cas_attempts_is_refused_through_the_runner() {
    let runner = BenchmarkRunner::new(conforming_plan()).expect("complete plan");
    let mut baseline = ProbeWorkload::armed_with(&[Fault::ZeroCasAttempts]);
    let mut candidate = ProbeWorkload::default();

    assert_eq!(
        runner.run(&mut baseline, &mut candidate),
        Err(BenchmarkRefusal::InvalidMetric {
            field: "cas_attempts",
            detail: "must be nonzero to report decisions-per-CAS".to_owned(),
        }),
        "decisions-per-CAS with no CAS attempts has no denominator"
    );
}

// ---------------------------------------------------------------------------
// MissingRequiredField — nineteen labels, one of which was covered
// ---------------------------------------------------------------------------

/// Every required *string* field, each blanked individually while the other
/// sixteen stay valid.
///
/// Blanking all seventeen at once would pass against an implementation that
/// checked only the first, which is why this is a table and not one case.
#[test]
fn every_required_string_field_is_named_when_it_is_blank() {
    for (label, set) in required_string_fields() {
        let mut plan = conforming_plan();
        set(&mut plan, "");
        assert_eq!(
            plan.validate(),
            Err(BenchmarkRefusal::MissingRequiredField(label)),
            "blanking {label} must be refused by that exact name"
        );
    }
}

/// **The `trim` axis.** `require_nonempty` refuses on `trim().is_empty()`, so a
/// field holding only spaces and tabs is as absent as one holding nothing —
/// a run whose `source_revision` is `"   "` identifies no source tree.
///
/// Nothing covered this axis; a guard simplified to `value.is_empty()` would
/// keep every other test in this file green.
#[test]
fn whitespace_only_values_are_refused_exactly_like_empty_ones() {
    for (label, set) in required_string_fields() {
        let mut plan = conforming_plan();
        set(&mut plan, " \t \n ");
        assert_eq!(
            plan.validate(),
            Err(BenchmarkRefusal::MissingRequiredField(label)),
            "a whitespace-only {label} names nothing and must refuse"
        );
    }
}

/// The eighteenth label, and a **different shape** of the same refusal: an
/// empty `Vec`, not a trimmed-empty `String`, so it is guarded by its own
/// branch rather than by `require_nonempty`.
#[test]
fn an_empty_command_list_is_the_same_refusal_in_a_different_shape() {
    let mut plan = conforming_plan();
    plan.workload.commands.clear();
    assert_eq!(
        plan.validate(),
        Err(BenchmarkRefusal::MissingRequiredField("workload.commands")),
        "evidence that names no command cannot be replayed"
    );
}

/// The nineteenth label, reachable only through the runner: the oracle receipt
/// is supplied by the workload at measurement time, not by the plan.
#[test]
fn an_empty_oracle_receipt_is_refused_through_the_runner() {
    let runner = BenchmarkRunner::new(conforming_plan()).expect("complete plan");
    let mut baseline = ProbeWorkload::armed_with(&[Fault::EmptyReceipt]);
    let mut candidate = ProbeWorkload::default();

    assert_eq!(
        runner.run(&mut baseline, &mut candidate),
        Err(BenchmarkRefusal::MissingRequiredField("oracle.receipt")),
        "an oracle that certifies nothing has not certified the sample"
    );
}

/// A required string field's stable label, and a setter that writes a value
/// into exactly that field.
type StringFieldCase = (&'static str, fn(&mut BenchmarkPlan, &str));

/// The seventeen `require_nonempty` fields and a setter for each.
///
/// Returned as data rather than written out per test so the empty case and the
/// whitespace case cannot drift apart.
fn required_string_fields() -> Vec<StringFieldCase> {
    vec![
        ("fingerprint.source_revision", |plan, value| {
            value.clone_into(&mut plan.fingerprint.source_revision);
        }),
        ("fingerprint.source_tree", |plan, value| {
            value.clone_into(&mut plan.fingerprint.source_tree);
        }),
        ("fingerprint.cargo_lock_sha256", |plan, value| {
            value.clone_into(&mut plan.fingerprint.cargo_lock_sha256);
        }),
        ("fingerprint.toolchain", |plan, value| {
            value.clone_into(&mut plan.fingerprint.toolchain);
        }),
        ("fingerprint.operating_system", |plan, value| {
            value.clone_into(&mut plan.fingerprint.operating_system);
        }),
        ("fingerprint.cpu", |plan, value| {
            value.clone_into(&mut plan.fingerprint.cpu);
        }),
        ("fingerprint.target", |plan, value| {
            value.clone_into(&mut plan.fingerprint.target);
        }),
        ("fingerprint.build_profile", |plan, value| {
            value.clone_into(&mut plan.fingerprint.build_profile);
        }),
        ("workload.dataset", |plan, value| {
            value.clone_into(&mut plan.workload.dataset);
        }),
        ("workload.workload", |plan, value| {
            value.clone_into(&mut plan.workload.workload);
        }),
        ("workload.thermal_state", |plan, value| {
            value.clone_into(&mut plan.workload.thermal_state);
        }),
        ("workload.cache_state", |plan, value| {
            value.clone_into(&mut plan.workload.cache_state);
        }),
        ("admission.equivalence_obligation", |plan, value| {
            value.clone_into(&mut plan.admission.equivalence_obligation);
        }),
        ("admission.oracle_name", |plan, value| {
            value.clone_into(&mut plan.admission.oracle_name);
        }),
        ("admission.replay_command", |plan, value| {
            value.clone_into(&mut plan.admission.replay_command);
        }),
        ("admission.rollback_artifact", |plan, value| {
            value.clone_into(&mut plan.admission.rollback_artifact);
        }),
        ("admission.hypothesis", |plan, value| {
            value.clone_into(&mut plan.admission.hypothesis);
        }),
    ]
}

// ---------------------------------------------------------------------------
// Ordering: wrong twice, at two different points in the pipeline
// ---------------------------------------------------------------------------

/// A plan bad in two places reports the earlier stage.
///
/// `BenchmarkPlan::validate` runs fingerprint, then workload, then admission,
/// then the sample floor. A probe that armed only one fault could not tell an
/// ordered chain from an arbitrary one.
#[test]
fn plan_validation_reports_the_fingerprint_before_the_sample_floor() {
    let mut plan = conforming_plan();
    plan.fingerprint.source_revision.clear();
    plan.admission.hypothesis.clear();
    plan.samples_per_variant = 0;

    assert_eq!(
        plan.validate(),
        Err(BenchmarkRefusal::MissingRequiredField(
            "fingerprint.source_revision"
        )),
        "the first stage of the chain owns the refusal"
    );

    // ...and with the fingerprint repaired, the NEXT stage in the chain
    // reports, not the sample floor. Two points, so the order is pinned rather
    // than one adjacency.
    let mut later = conforming_plan();
    later.admission.hypothesis.clear();
    later.samples_per_variant = 0;
    assert_eq!(
        later.validate(),
        Err(BenchmarkRefusal::MissingRequiredField(
            "admission.hypothesis"
        )),
        "the admission stage precedes the sample floor"
    );
}

/// The oracle fault **alone** refuses, naming the variant and the sample.
///
/// This exists to keep the two-fault ordering probe below honest: if
/// `Fault::FailOracle` ever stopped arming, that probe would still report
/// `InvalidMetric` and still pass — vacuously, having stopped testing the
/// ordering it is named for. A refusal that fires on its own is what makes the
/// combined probe evidence about precedence rather than about one fault.
#[test]
fn an_oracle_that_rejects_its_output_is_refused_on_its_own() {
    let runner = BenchmarkRunner::new(conforming_plan()).expect("complete plan");
    let mut baseline = ProbeWorkload::armed_with(&[Fault::FailOracle]);
    let mut candidate = ProbeWorkload::default();

    assert_eq!(
        runner.run(&mut baseline, &mut candidate),
        Err(BenchmarkRefusal::OracleFailed {
            variant: Variant::Baseline,
            sample: 0,
            detail: "probe oracle rejected the output".to_owned(),
        })
    );
}

/// Metrics are validated before the oracle runs.
///
/// A sample that both reports an impossible metric and fails its oracle must
/// report `InvalidMetric`: the measurement was never admissible, so there was
/// nothing for the oracle to certify.
#[test]
fn metric_validation_precedes_the_correctness_oracle() {
    let runner = BenchmarkRunner::new(conforming_plan()).expect("complete plan");
    let mut baseline = ProbeWorkload::armed_with(&[Fault::ZeroDenominator, Fault::FailOracle]);
    let mut candidate = ProbeWorkload::default();

    assert_eq!(
        runner.run(&mut baseline, &mut candidate),
        Err(BenchmarkRefusal::InvalidMetric {
            field: "storage.logical_reachable_git_bytes",
            detail: "must be nonzero for storage amplification".to_owned(),
        }),
        "an inadmissible measurement is refused before the oracle is consulted"
    );
}

// ---------------------------------------------------------------------------
// The admissibility boundary: speedup or negative evidence
// ---------------------------------------------------------------------------

const fn tails(p95_ns: u64) -> TailSummary {
    TailSummary {
        mean_ns: p95_ns,
        p50_ns: p95_ns,
        p95_ns,
        p99_ns: p95_ns,
    }
}

fn sample(variant: Variant, latency_ns: u64) -> RawSample {
    RawSample {
        variant,
        sample_index: 0,
        metrics: SystemMetrics {
            latency_ns,
            ..conforming_metrics()
        },
        oracle: OracleReceipt {
            receipt: "sum-0".to_owned(),
        },
    }
}

/// Builds an artifact with exact tails, so the boundary can be hit on the
/// nanosecond. A timing-derived p95 could not land exactly on the floor.
fn artifact_with(baseline_p95: u64, candidate_p95: u64, aa_noise_p95: u64) -> BenchmarkArtifact {
    let aa_p95 = baseline_p95.saturating_add(aa_noise_p95);
    BenchmarkArtifact {
        schema: ARTIFACT_SCHEMA,
        schema_version: ARTIFACT_SCHEMA_VERSION,
        plan: conforming_plan(),
        baseline: vec![sample(Variant::Baseline, baseline_p95)],
        candidate: vec![sample(Variant::Candidate, candidate_p95)],
        aa_control: vec![sample(Variant::AaControl, aa_p95)],
        baseline_tails: tails(baseline_p95),
        candidate_tails: tails(candidate_p95),
        aa_control_tails: tails(aa_p95),
        aa_noise: AaControl {
            p95_noise_ns: aa_noise_p95,
            p99_noise_ns: aa_noise_p95,
        },
    }
}

/// **The boundary itself.** An improvement of exactly the A/A noise floor is
/// not a speedup.
///
/// baseline 1000, candidate 900, noise 100: the candidate is faster by exactly
/// what the baseline differed from itself. `>` refuses it; `>=` would admit it.
#[test]
fn a_delta_of_exactly_the_aa_noise_floor_is_not_admissible() {
    let artifact = artifact_with(1_000, 900, 100);
    assert!(
        !artifact.speedup_is_admissible(),
        "an improvement equal to the run-to-run noise is not evidence of a speedup"
    );
}

/// One nanosecond past the floor is admissible — the permitted twin, so this
/// is a boundary and not a blanket refusal.
#[test]
fn one_nanosecond_past_the_noise_floor_is_admissible() {
    let artifact = artifact_with(1_000, 899, 100);
    assert!(
        artifact.speedup_is_admissible(),
        "a delta strictly larger than the A/A noise clears the floor"
    );
}

/// A candidate that is slower is plainly inadmissible, and a delta far past
/// the floor is plainly admissible — the two easy cases, so the pair above is
/// shown to be the boundary of a real order rather than a lucky constant.
#[test]
fn the_admissibility_order_holds_away_from_the_boundary_too() {
    assert!(!artifact_with(1_000, 1_200, 100).speedup_is_admissible());
    assert!(!artifact_with(1_000, 1_000, 0).speedup_is_admissible());
    assert!(artifact_with(1_000, 100, 100).speedup_is_admissible());
    assert!(
        artifact_with(1_000, 999, 0).speedup_is_admissible(),
        "with no observed noise, any strict improvement clears the floor"
    );
}

/// **What the boundary decides.** At the floor the run is written as negative
/// evidence; one nanosecond past it, no negative-evidence file is produced.
///
/// The ledger line is checked for the exact three numbers, not merely for the
/// file's existence: a record that said "disproven" without saying which
/// figures disproved it could not be audited against a re-run.
#[test]
fn the_noise_floor_decides_whether_negative_evidence_is_written() {
    let at_floor = scratch_directory("at-floor");
    let written = artifact_with(1_000, 900, 100)
        .write_to(&at_floor)
        .expect("write artifacts");
    assert!(written.evidence_path.is_file());
    assert!(written.replay_path.is_file());
    let ledger = written
        .negative_evidence_path
        .expect("a delta at the noise floor must be recorded as negative evidence");
    let recorded = fs::read_to_string(&ledger).expect("read the ledger");
    assert!(recorded.contains("disproven_speedup"));
    assert!(
        recorded.contains("\"baseline_p95_ns\":1000")
            && recorded.contains("\"candidate_p95_ns\":900")
            && recorded.contains("\"aa_p95_noise_ns\":100"),
        "the ledger must record the figures that disproved the hypothesis, got: {recorded}"
    );
    fs::remove_dir_all(&at_floor).expect("remove test artifacts");

    let past_floor = scratch_directory("past-floor");
    let cleared = artifact_with(1_000, 899, 100)
        .write_to(&past_floor)
        .expect("write artifacts");
    assert_eq!(
        cleared.negative_evidence_path, None,
        "a delta that clears the noise floor writes no negative-evidence record"
    );
    fs::remove_dir_all(&past_floor).expect("remove test artifacts");
}

// ---------------------------------------------------------------------------
// Io — operations other than the one already covered
// ---------------------------------------------------------------------------

/// The fingerprint reads pinned local inputs rather than shelling out to Git,
/// so a missing `Cargo.lock` is its own named operation.
#[test]
fn a_missing_cargo_lock_is_reported_as_its_own_operation() {
    let root = scratch_directory("no-lock");
    fs::create_dir_all(&root).expect("create scratch root");

    let error = EnvironmentFingerprint::from_workspace(
        &root, "revision", "clean", "cpu", "target", "profile",
    )
    .expect_err("a workspace without a lock file cannot be fingerprinted");
    match error {
        BenchmarkRefusal::Io { operation, detail } => {
            assert_eq!(operation, "read Cargo.lock");
            assert!(
                !detail.is_empty(),
                "the refusal must carry the underlying io error"
            );
        }
        other => panic!("expected an Io refusal, got {other:?}"),
    }
    fs::remove_dir_all(&root).expect("remove scratch root");
}

/// A *distinct* operation, and it also shows the two reads are ordered: with
/// the lock file present, the toolchain read is the one that reports.
#[test]
fn a_missing_toolchain_file_is_reported_as_a_distinct_operation() {
    let root = scratch_directory("no-toolchain");
    fs::create_dir_all(&root).expect("create scratch root");
    fs::write(root.join("Cargo.lock"), b"# pinned\n").expect("write lock file");

    let error = EnvironmentFingerprint::from_workspace(
        &root, "revision", "clean", "cpu", "target", "profile",
    )
    .expect_err("a workspace without a pinned toolchain cannot be fingerprinted");
    match error {
        BenchmarkRefusal::Io { operation, detail } => {
            assert_eq!(
                operation, "read rust-toolchain.toml",
                "the two reads are separate operations and the lock file is read first"
            );
            assert_ne!(detail, "");
        }
        other => panic!("expected an Io refusal, got {other:?}"),
    }
    fs::remove_dir_all(&root).expect("remove scratch root");
}
