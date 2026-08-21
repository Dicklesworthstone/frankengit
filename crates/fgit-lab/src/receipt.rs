//! The versioned coverage receipt: what a lab run actually proved.
//!
//! A run that reports "all properties held" tells you nothing on its own. Held
//! over what space, under which bounds, on which build, with which failpoints
//! reached, and could anyone reproduce it? A receipt is the record that turns a
//! verdict into evidence, and this module's job is to make the *limits* of a
//! run as hard to omit as its successes.
//!
//! # Three things this receipt refuses to let a caller do
//!
//! **Credit lab evidence for a native requirement.** Parked workers, real
//! sockets, blocking-pool joins, signals, and process reaping are not
//! observable in a deterministic model. [`CoverageReceipt::credit_for`] fails
//! closed on those classes with
//! [`LabRefusal::DeterministicEvidenceForNativeClass`] rather than quietly
//! counting a model run as an OS-level result. That is proof-class inflation,
//! and it is the single easiest way for a green board to mean nothing.
//!
//! **Pass while incomplete.** A run whose external artifacts are missing is not
//! a run that passed with a caveat; it is a run that cannot be fully replayed.
//! Missing artifacts *lower* [`ReplayCompleteness`] rather than being recorded
//! as a footnote next to a pass.
//!
//! **Replay onto the wrong build.** A seed reproduces a failure only against
//! the source, toolchain, and runtime profile that produced it.
//! [`CoverageReceipt::check_build`] refuses a mismatched build with
//! [`LabRefusal::ReplayDrift`] instead of reporting the original signature
//! against code that never ran it.
//!
//! # Format
//!
//! One NDJSON object per line, versioned by [`RECEIPT_VERSION`]. Field order is
//! fixed and every collection is emitted in sorted order, so two runs that
//! reached the same state produce byte-identical receipts and a diff is
//! meaningful.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::harness::ReplayClass;
use crate::journal::TraceFingerprint;
use crate::probe::CoverageReport;
use crate::refuse::LabRefusal;

/// The receipt format marker.
///
/// A consumer that does not understand this exact string must refuse the
/// receipt rather than parse it optimistically.
pub const RECEIPT_VERSION: &str = "fgit-lab-receipt-v1";

/// Identity of the build a run was produced by.
///
/// Every field is load-bearing for replay: change any one of them and the same
/// seed may take a different path. They are compared as a unit by
/// [`CoverageReceipt::check_build`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildIdentity {
    /// Digest of the source tree the run was built from.
    pub source_digest: String,
    /// Exact toolchain, not a floating channel name.
    pub toolchain: String,
    /// The runtime profile descriptor, from `fgit_runtime::ProfileIdentity`.
    pub runtime_profile: String,
}

impl BuildIdentity {
    /// Build an identity from its three parts.
    #[must_use]
    pub fn new(
        source_digest: impl Into<String>,
        toolchain: impl Into<String>,
        runtime_profile: impl Into<String>,
    ) -> Self {
        Self {
            source_digest: source_digest.into(),
            toolchain: toolchain.into(),
            runtime_profile: runtime_profile.into(),
        }
    }
}

/// An artifact a replay needs, and whether this run actually has it.
///
/// Modelled as an enum rather than an `Option<String>` so that "we know this is
/// missing" is a distinct, recorded state instead of an absence that reads the
/// same as "we never looked".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalArtifact {
    /// Present, with its content digest.
    Present {
        /// Artifact name.
        name: String,
        /// Content digest.
        digest: String,
    },
    /// Declared as required, but not captured by this run.
    Missing {
        /// Artifact name.
        name: String,
        /// Why it is absent, so a reader need not guess.
        reason: String,
    },
}

impl ExternalArtifact {
    /// The artifact's name.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Present { name, .. } | Self::Missing { name, .. } => name,
        }
    }

    /// Whether the artifact was captured.
    #[must_use]
    pub const fn is_present(&self) -> bool {
        matches!(self, Self::Present { .. })
    }
}

/// How completely this run can be replayed.
///
/// Deliberately not a boolean. "Replayable" and "replayable except for the two
/// artifacts nobody captured" are different claims, and collapsing them is how
/// an incomplete run comes to read as a passing one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayCompleteness {
    /// Everything a replay needs is recorded.
    Complete,
    /// The run is replayable, but named artifacts are absent.
    ///
    /// This is **not** a pass with a note attached; it is a lower completeness
    /// class, and a gate that requires `Complete` must reject it.
    Degraded {
        /// Names of the missing artifacts, sorted.
        missing: Vec<String>,
    },
}

impl ReplayCompleteness {
    /// Stable machine code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Degraded { .. } => "degraded",
        }
    }

    /// Whether this class satisfies a gate that demands full replayability.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// The exploration bounds a run declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeclaredBounds {
    /// Ceiling on complete executions.
    pub max_executions: usize,
    /// Ceiling on transitions.
    pub max_transitions: u64,
}

/// What a lab run proved, and what it did not.
#[derive(Debug, Clone)]
pub struct CoverageReceipt {
    build: BuildIdentity,
    seed: u64,
    schedule_identity: String,
    trace_fingerprint: TraceFingerprint,
    classes_explored: usize,
    classes_remaining: Option<usize>,
    bounds: DeclaredBounds,
    exhausted: bool,
    failpoints_exercised: Vec<(String, u64)>,
    failpoints_unexercised: Vec<String>,
    capability_mask: u32,
    budgets: BTreeMap<String, String>,
    regions_open: usize,
    obligations_outstanding: usize,
    covered_classes: Vec<ReplayClass>,
    artifacts: Vec<ExternalArtifact>,
    native_cross_reference: Option<String>,
}

impl CoverageReceipt {
    /// Start a receipt for a run of `build` at `seed`.
    #[must_use]
    pub fn new(build: BuildIdentity, seed: u64, bounds: DeclaredBounds) -> Self {
        Self {
            build,
            seed,
            schedule_identity: String::new(),
            trace_fingerprint: TraceFingerprint::of(&[]),
            classes_explored: 0,
            classes_remaining: None,
            bounds,
            exhausted: false,
            failpoints_exercised: Vec::new(),
            failpoints_unexercised: Vec::new(),
            capability_mask: 0,
            budgets: BTreeMap::new(),
            regions_open: 0,
            obligations_outstanding: 0,
            covered_classes: Vec::new(),
            artifacts: Vec::new(),
            native_cross_reference: None,
        }
    }

    /// Record the schedule and trace identity this run is about.
    #[must_use]
    pub fn with_identity(
        mut self,
        schedule_identity: impl Into<String>,
        trace_fingerprint: TraceFingerprint,
    ) -> Self {
        self.schedule_identity = schedule_identity.into();
        self.trace_fingerprint = trace_fingerprint;
        self
    }

    /// Record how much of the equivalence-class space was walked.
    ///
    /// `exhausted` is what separates "the space holds the property" from "the
    /// part we reached holds it", so it is a required argument rather than
    /// something inferred from `remaining == Some(0)`.
    ///
    /// `remaining` is `None` when the number genuinely is not known — which is
    /// the normal case after a violation, because exploration stops at the
    /// first failure and never counts the rest of the space. Recording `0`
    /// there would read as "nothing left to explore", which is the opposite of
    /// the truth, so the unknown is carried as an unknown and rendered `null`.
    #[must_use]
    pub const fn with_exploration(
        mut self,
        explored: usize,
        remaining: Option<usize>,
        exhausted: bool,
    ) -> Self {
        self.classes_explored = explored;
        self.classes_remaining = remaining;
        self.exhausted = exhausted;
        self
    }

    /// Record failpoint coverage.
    #[must_use]
    pub fn with_failpoints(mut self, coverage: &CoverageReport) -> Self {
        self.failpoints_exercised = coverage
            .exercised()
            .iter()
            .map(|(id, hits)| (id.as_str().to_owned(), *hits))
            .collect();
        self.failpoints_exercised.sort();
        self.failpoints_unexercised = coverage
            .unexercised()
            .iter()
            .map(|id| id.as_str().to_owned())
            .collect();
        self.failpoints_unexercised.sort();
        self
    }

    /// Record the capability mask contexts were minted under.
    #[must_use]
    pub const fn with_capabilities(mut self, mask: u32) -> Self {
        self.capability_mask = mask;
        self
    }

    /// Record one budget class and its resolved limit.
    #[must_use]
    pub fn with_budget(mut self, class: impl Into<String>, limit: impl Into<String>) -> Self {
        self.budgets.insert(class.into(), limit.into());
        self
    }

    /// Record the region and obligation state at the end of the run.
    #[must_use]
    pub const fn with_settlement(mut self, regions_open: usize, outstanding: usize) -> Self {
        self.regions_open = regions_open;
        self.obligations_outstanding = outstanding;
        self
    }

    /// Declare a replay class this run carries evidence for.
    ///
    /// Declaring a class does not by itself credit it: [`credit_for`] still
    /// refuses native classes.
    ///
    /// [`credit_for`]: Self::credit_for
    #[must_use]
    pub fn covering(mut self, class: ReplayClass) -> Self {
        if !self.covered_classes.contains(&class) {
            self.covered_classes.push(class);
            self.covered_classes.sort_by_key(|class| class.code());
        }
        self
    }

    /// Record an artifact, present or missing.
    #[must_use]
    pub fn with_artifact(mut self, artifact: ExternalArtifact) -> Self {
        self.artifacts.push(artifact);
        self.artifacts
            .sort_by(|left, right| left.name().cmp(right.name()));
        self
    }

    /// Point at the native evidence that covers what this run cannot.
    ///
    /// This is a link, not a substitute: it exists so a reader can find the
    /// native result, and it never raises this receipt's own class.
    #[must_use]
    pub fn with_native_cross_reference(mut self, reference: impl Into<String>) -> Self {
        self.native_cross_reference = Some(reference.into());
        self
    }

    /// The build this receipt describes.
    #[must_use]
    pub const fn build(&self) -> &BuildIdentity {
        &self.build
    }

    /// The seed the run used.
    #[must_use]
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// Whether the declared space was fully walked.
    #[must_use]
    pub const fn is_exhaustive(&self) -> bool {
        self.exhausted
    }

    /// Classes this receipt claims evidence for.
    #[must_use]
    pub fn covered_classes(&self) -> &[ReplayClass] {
        &self.covered_classes
    }

    /// How completely this run can be replayed.
    ///
    /// Derived from the artifacts rather than set by the caller, so a run
    /// cannot declare itself complete while missing what a replay needs.
    #[must_use]
    pub fn completeness(&self) -> ReplayCompleteness {
        let mut missing: Vec<String> = self
            .artifacts
            .iter()
            .filter(|artifact| !artifact.is_present())
            .map(|artifact| artifact.name().to_owned())
            .collect();
        if missing.is_empty() {
            ReplayCompleteness::Complete
        } else {
            missing.sort();
            ReplayCompleteness::Degraded { missing }
        }
    }

    /// Whether this receipt may be credited as evidence for `class`.
    ///
    /// # Errors
    ///
    /// - [`LabRefusal::DeterministicEvidenceForNativeClass`] when `class` is one
    ///   only real execution can establish. A cross-reference to native evidence
    ///   does not change this: the native run is the evidence, and it has its
    ///   own receipt.
    /// - [`LabRefusal::UnavailableClassNotReplayable`] when the receipt does not
    ///   claim the class at all.
    pub fn credit_for(&self, class: ReplayClass) -> Result<(), LabRefusal> {
        if !class.is_lab_replayable() {
            return Err(LabRefusal::DeterministicEvidenceForNativeClass {
                class: class.code(),
            });
        }
        if !self.covered_classes.contains(&class) {
            return Err(LabRefusal::UnavailableClassNotReplayable {
                class: class.code(),
            });
        }
        Ok(())
    }

    /// Whether `current` is the build this receipt was produced by.
    ///
    /// # Errors
    ///
    /// [`LabRefusal::ReplayDrift`] naming the first field that disagrees.
    /// Fields are checked in a fixed order so the reported drift is stable.
    pub fn check_build(&self, current: &BuildIdentity) -> Result<(), LabRefusal> {
        let checks: [(&'static str, &String, &String); 3] = [
            (
                "source_digest",
                &self.build.source_digest,
                &current.source_digest,
            ),
            ("toolchain", &self.build.toolchain, &current.toolchain),
            (
                "runtime_profile",
                &self.build.runtime_profile,
                &current.runtime_profile,
            ),
        ];
        for (field, recorded, observed) in checks {
            if recorded != observed {
                return Err(LabRefusal::ReplayDrift {
                    field,
                    recorded: recorded.clone(),
                    observed: observed.clone(),
                });
            }
        }
        Ok(())
    }

    /// The receipt as one canonical NDJSON line.
    #[must_use]
    pub fn to_ndjson(&self) -> String {
        let completeness = self.completeness();
        let missing = match &completeness {
            ReplayCompleteness::Complete => String::new(),
            ReplayCompleteness::Degraded { missing } => missing.join(","),
        };
        let exercised: Vec<String> = self
            .failpoints_exercised
            .iter()
            .map(|(name, hits)| format!("{}:{hits}", escape(name)))
            .collect();
        let classes: Vec<String> = self
            .covered_classes
            .iter()
            .map(|class| format!("\"{}\"", class.code()))
            .collect();
        let budgets: Vec<String> = self
            .budgets
            .iter()
            .map(|(class, limit)| format!("\"{}\":\"{}\"", escape(class), escape(limit)))
            .collect();
        let artifacts: Vec<String> = self
            .artifacts
            .iter()
            .map(|artifact| match artifact {
                ExternalArtifact::Present { name, digest } => format!(
                    "{{\"name\":\"{}\",\"present\":true,\"digest\":\"{}\"}}",
                    escape(name),
                    escape(digest)
                ),
                ExternalArtifact::Missing { name, reason } => format!(
                    "{{\"name\":\"{}\",\"present\":false,\"reason\":\"{}\"}}",
                    escape(name),
                    escape(reason)
                ),
            })
            .collect();

        format!(
            concat!(
                "{{\"version\":\"{}\",\"record\":\"lab_coverage_receipt\"",
                ",\"source_digest\":\"{}\",\"toolchain\":\"{}\",\"runtime_profile\":\"{}\"",
                ",\"seed\":{},\"schedule_identity\":\"{}\",\"trace_fingerprint\":\"{}\"",
                ",\"classes_explored\":{},\"classes_remaining\":{},\"exhaustive\":{}",
                ",\"max_executions\":{},\"max_transitions\":{}",
                ",\"failpoints_declared\":{},\"failpoints_exercised\":[{}]",
                ",\"failpoints_unexercised\":[{}]",
                ",\"capability_mask\":{},\"budgets\":{{{}}}",
                ",\"regions_open\":{},\"obligations_outstanding\":{}",
                ",\"replay_classes\":[{}],\"artifacts\":[{}]",
                ",\"replay_completeness\":\"{}\",\"missing_artifacts\":\"{}\"",
                ",\"native_cross_reference\":\"{}\"}}"
            ),
            RECEIPT_VERSION,
            escape(&self.build.source_digest),
            escape(&self.build.toolchain),
            escape(&self.build.runtime_profile),
            self.seed,
            escape(&self.schedule_identity),
            self.trace_fingerprint,
            self.classes_explored,
            self.classes_remaining
                .map_or_else(|| "null".to_owned(), |count| count.to_string()),
            self.exhausted,
            self.bounds.max_executions,
            self.bounds.max_transitions,
            self.failpoints_exercised.len() + self.failpoints_unexercised.len(),
            exercised
                .iter()
                .map(|entry| format!("\"{entry}\""))
                .collect::<Vec<_>>()
                .join(","),
            self.failpoints_unexercised
                .iter()
                .map(|name| format!("\"{}\"", escape(name)))
                .collect::<Vec<_>>()
                .join(","),
            self.capability_mask,
            budgets.join(","),
            self.regions_open,
            self.obligations_outstanding,
            classes.join(","),
            artifacts.join(","),
            completeness.code(),
            escape(&missing),
            escape(self.native_cross_reference.as_deref().unwrap_or("")),
        )
    }
}

/// Escape the characters JSON string bodies may not carry literally.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if control < ' ' => {
                let _ = write!(out, "\\u{:04x}", control as u32);
            }
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::{FailpointId, FailpointRegistry};

    fn build() -> BuildIdentity {
        BuildIdentity::new(
            "sha256:0f1e2d3c",
            "nightly-2026-08-19-x86_64-unknown-linux-gnu",
            "fgit-runtime-profile-v1 class=deterministic asupersync=0.4.9",
        )
    }

    fn bounds() -> DeclaredBounds {
        DeclaredBounds {
            max_executions: 512,
            max_transitions: 100_000,
        }
    }

    fn receipt() -> CoverageReceipt {
        CoverageReceipt::new(build(), 42, bounds())
            .with_identity("schedule-7f3a", TraceFingerprint::of(b"trace"))
            .with_exploration(4, Some(0), true)
            .covering(ReplayClass::LogicalInterleaving)
    }

    #[test]
    fn a_receipt_names_its_version_and_every_required_field() {
        let line = receipt().to_ndjson();
        for field in [
            "\"version\":\"fgit-lab-receipt-v1\"",
            "\"record\":\"lab_coverage_receipt\"",
            "\"source_digest\":",
            "\"toolchain\":",
            "\"runtime_profile\":",
            "\"seed\":42",
            "\"schedule_identity\":",
            "\"trace_fingerprint\":",
            "\"classes_explored\":4",
            "\"classes_remaining\":0",
            "\"exhaustive\":true",
            "\"max_executions\":512",
            "\"max_transitions\":100000",
            "\"failpoints_declared\":",
            "\"capability_mask\":",
            "\"budgets\":",
            "\"regions_open\":",
            "\"obligations_outstanding\":",
            "\"replay_classes\":",
            "\"artifacts\":",
            "\"replay_completeness\":",
            "\"native_cross_reference\":",
        ] {
            assert!(
                line.contains(field),
                "the receipt must state {field}, got: {line}"
            );
        }
    }

    #[test]
    fn a_receipt_with_every_artifact_present_is_complete() {
        let complete = receipt().with_artifact(ExternalArtifact::Present {
            name: "trace.ndjson".to_owned(),
            digest: "sha256:aabb".to_owned(),
        });
        assert_eq!(complete.completeness(), ReplayCompleteness::Complete);
        assert!(complete.completeness().is_complete());
        assert!(
            complete
                .to_ndjson()
                .contains("\"replay_completeness\":\"complete\"")
        );
    }

    #[test]
    fn a_missing_artifact_lowers_completeness_rather_than_passing() {
        // The acceptance line: absence degrades the class, it does not become a
        // footnote beside a pass.
        let degraded = receipt()
            .with_artifact(ExternalArtifact::Present {
                name: "trace.ndjson".to_owned(),
                digest: "sha256:aabb".to_owned(),
            })
            .with_artifact(ExternalArtifact::Missing {
                name: "worker-stderr.log".to_owned(),
                reason: "not captured by the deterministic lane".to_owned(),
            });

        assert!(!degraded.completeness().is_complete());
        assert_eq!(
            degraded.completeness(),
            ReplayCompleteness::Degraded {
                missing: vec!["worker-stderr.log".to_owned()]
            }
        );
        let line = degraded.to_ndjson();
        assert!(line.contains("\"replay_completeness\":\"degraded\""));
        assert!(line.contains("\"missing_artifacts\":\"worker-stderr.log\""));
        assert!(
            line.contains("\"present\":false"),
            "the missing artifact must be named in the receipt, not merely counted"
        );
    }

    #[test]
    fn deterministic_evidence_cannot_be_credited_for_a_native_class() {
        // The strongest rule in this module. Every native class must refuse,
        // even when the receipt has been told it covers them.
        for class in ReplayClass::all() {
            if class.is_lab_replayable() {
                continue;
            }
            let claiming = receipt().covering(class);
            let refusal = claiming
                .credit_for(class)
                .expect_err("a native class must not be credited from lab evidence");
            assert_eq!(
                refusal.code(),
                "lab.evidence.deterministic_for_native_class",
                "wrong refusal for {}",
                class.code()
            );
        }
    }

    #[test]
    fn a_native_cross_reference_does_not_upgrade_the_class() {
        // Linking native evidence is allowed; being credited for it is not.
        let linked = receipt()
            .covering(ReplayClass::NativeIo)
            .with_native_cross_reference("frankengit-fg011b native lane, run 12");

        assert!(linked.credit_for(ReplayClass::NativeIo).is_err());
        assert!(
            linked
                .to_ndjson()
                .contains("\"native_cross_reference\":\"frankengit-fg011b native lane, run 12\""),
            "the cross-reference must still be recorded so a reader can find it"
        );
    }

    #[test]
    fn a_lab_class_the_receipt_does_not_claim_is_refused() {
        let refusal = receipt()
            .credit_for(ReplayClass::ObligationSettlement)
            .expect_err("an unclaimed class must not be credited");
        assert_eq!(refusal.code(), "lab.boundary.not_replayable");
    }

    #[test]
    fn a_claimed_lab_class_is_credited() {
        // The paired permitted case for the two refusals above.
        assert!(
            receipt()
                .credit_for(ReplayClass::LogicalInterleaving)
                .is_ok()
        );
    }

    #[test]
    fn replaying_against_a_different_build_is_refused_as_drift() {
        let recorded = receipt();

        for (field, drifted) in [
            (
                "source_digest",
                BuildIdentity::new(
                    "sha256:different",
                    build().toolchain,
                    build().runtime_profile,
                ),
            ),
            (
                "toolchain",
                BuildIdentity::new(
                    build().source_digest,
                    "nightly-2026-01-01",
                    build().runtime_profile,
                ),
            ),
            (
                "runtime_profile",
                BuildIdentity::new(build().source_digest, build().toolchain, "class=production"),
            ),
        ] {
            let refusal = recorded
                .check_build(&drifted)
                .expect_err("a changed build must be refused");
            assert_eq!(refusal.code(), "lab.replay.drift");
            assert!(
                format!("{refusal:?}").contains(field),
                "the refusal must name the field that drifted, expected {field}"
            );
        }
    }

    #[test]
    fn replaying_against_the_same_build_is_accepted() {
        assert!(receipt().check_build(&build()).is_ok());
    }

    #[test]
    fn failpoint_coverage_is_recorded_with_both_sides() {
        // Exercised and unexercised both matter: a receipt that listed only
        // what was reached would make a run that touched one failpoint out of
        // twenty look the same as one that touched all twenty.
        let mut registry = FailpointRegistry::new();
        let write_fail = FailpointId::new("store.write.fail");
        let read_stall = FailpointId::new("store.read.stall");
        registry
            .declare(write_fail.clone(), "the object store refuses a write")
            .expect("declares");
        registry
            .declare(read_stall, "the object store stalls a read")
            .expect("declares");
        registry.arm(&write_fail).expect("arms");
        registry.should_fire(&write_fail).expect("fires");

        let with_coverage = receipt().with_failpoints(&registry.coverage());
        let line = with_coverage.to_ndjson();

        assert!(line.contains("\"failpoints_declared\":2"));
        assert!(line.contains("\"store.write.fail:1\""));
        assert!(line.contains("\"failpoints_unexercised\":[\"store.read.stall\"]"));
    }

    #[test]
    fn an_unknown_remainder_is_rendered_null_rather_than_zero() {
        // After a violation, exploration stops and never counts the rest of the
        // space. Zero would read as "nothing left"; null says "not known".
        let after_violation =
            CoverageReceipt::new(build(), 42, bounds()).with_exploration(2, None, false);
        let line = after_violation.to_ndjson();

        assert!(
            line.contains("\"classes_remaining\":null"),
            "an unknown remainder must render as null, got {line}"
        );
        assert!(!line.contains("\"classes_remaining\":0"));
        assert!(line.contains("\"exhaustive\":false"));
    }

    #[test]
    fn a_non_exhaustive_run_says_so() {
        // Bounded exploration that stopped early must never read as complete
        // coverage of the space.
        let bounded =
            CoverageReceipt::new(build(), 7, bounds()).with_exploration(3, Some(11), false);
        let line = bounded.to_ndjson();
        assert!(line.contains("\"exhaustive\":false"));
        assert!(line.contains("\"classes_remaining\":11"));
        assert!(!bounded.is_exhaustive());
    }

    #[test]
    fn the_receipt_is_byte_stable_across_construction_order() {
        let forward = receipt()
            .with_budget("request", "poll=1000")
            .with_budget("database", "poll=5000")
            .with_artifact(ExternalArtifact::Present {
                name: "a.log".to_owned(),
                digest: "sha256:1".to_owned(),
            })
            .with_artifact(ExternalArtifact::Present {
                name: "b.log".to_owned(),
                digest: "sha256:2".to_owned(),
            });
        let reverse = receipt()
            .with_budget("database", "poll=5000")
            .with_budget("request", "poll=1000")
            .with_artifact(ExternalArtifact::Present {
                name: "b.log".to_owned(),
                digest: "sha256:2".to_owned(),
            })
            .with_artifact(ExternalArtifact::Present {
                name: "a.log".to_owned(),
                digest: "sha256:1".to_owned(),
            });

        assert_eq!(forward.to_ndjson(), reverse.to_ndjson());
    }

    #[test]
    fn quotes_and_control_characters_cannot_break_the_line() {
        // A receipt is NDJSON: one record per line. An artifact name carrying a
        // newline or a quote must not be able to forge a second record.
        let hostile = receipt().with_artifact(ExternalArtifact::Missing {
            name: "evil\"name".to_owned(),
            reason: "line\nbreak\tand \\backslash".to_owned(),
        });
        let line = hostile.to_ndjson();

        assert_eq!(line.lines().count(), 1, "a receipt must stay one line");
        assert!(line.contains("evil\\\"name"));
        assert!(line.contains("line\\nbreak\\tand \\\\backslash"));
    }
}
