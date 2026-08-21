//! Crashpacks: everything needed to reproduce one failure, in one place.
//!
//! When exploration finds a violation, the useful output is not "a property
//! failed". It is the exact inputs, the trace, the reduced counterexample, the
//! signature to expect on replay, and a command someone can paste. A crashpack
//! is that bundle, and it is deliberately self-describing: a reader who has
//! never seen this crate should be able to run one command and watch the same
//! failure happen.
//!
//! # What the fingerprints in here are, and are not
//!
//! [`ArtifactFingerprint`] values are FNV-1a over the canonical bytes — 64 bits,
//! **not** a cryptographic digest. They detect accidental drift: an edited
//! trace, a regenerated schedule, a crashpack that no longer matches the run it
//! claims. They do **not** resist an adversary who wants to substitute content
//! while preserving the fingerprint, and nothing here should be read as
//! tamper-evidence.
//!
//! Real content commitments are SHA-256 over the written files, computed by the
//! e2e harness (`fge_digest_file`) when the crashpack is persisted, and carried
//! in the [`CoverageReceipt`](crate::receipt::CoverageReceipt) as artifact
//! digests. The split is deliberate: this crate has no cryptographic
//! dependency, and inventing one to make a field look stronger than it is would
//! be worse than naming the limit.
//!
//! # Replay is checked, not asserted
//!
//! [`Crashpack::confirm_replay`] compares the signature a replay actually
//! produced against the one the pack expects, and refuses a mismatch. A replay
//! that reproduces *a* failure rather than *the* failure is a different bug,
//! and reporting it as a successful reproduction would hide both.

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;

use crate::journal::LogicalTrace;
use crate::minimize::{CausalSignature, Reduction};
use crate::receipt::{BuildIdentity, CoverageReceipt};
use crate::refuse::LabRefusal;

/// The crashpack format marker.
pub const CRASHPACK_VERSION: &str = "fgit-lab-crashpack-v1";

/// A non-cryptographic fingerprint over canonical bytes.
///
/// See the module documentation: this detects drift, not tampering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArtifactFingerprint(u64);

impl ArtifactFingerprint {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    /// Fingerprint some bytes.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        let mut hash = Self::OFFSET;
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(Self::PRIME);
        }
        Self(hash)
    }
}

impl fmt::Display for ArtifactFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fnv1a64:{:016x}", self.0)
    }
}

/// The exact inputs a replay needs.
///
/// Kept as a distinct type so that "the inputs" is one thing a caller either
/// supplies completely or not at all, rather than several fields that can each
/// be forgotten independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayInputs {
    /// The seed the run was driven with.
    pub seed: u64,
    /// The schedule identity that produced the failure.
    pub schedule_identity: String,
    /// The property that was being checked.
    pub property: String,
}

/// One reproducible failure, bundled.
#[derive(Debug, Clone)]
pub struct Crashpack {
    inputs: ReplayInputs,
    build: BuildIdentity,
    signature: CausalSignature,
    reduction: Reduction,
    trace: LogicalTrace,
    replay_command: String,
    fingerprints: BTreeMap<String, ArtifactFingerprint>,
}

impl Crashpack {
    /// Bundle a failure.
    ///
    /// The fingerprints of the trace and the reduced counterexample are
    /// computed here rather than accepted from the caller, so a pack cannot
    /// carry a fingerprint that does not match its own contents.
    #[must_use]
    pub fn new(
        inputs: ReplayInputs,
        build: BuildIdentity,
        signature: CausalSignature,
        reduction: Reduction,
        trace: LogicalTrace,
        replay_command: impl Into<String>,
    ) -> Self {
        let mut fingerprints = BTreeMap::new();
        fingerprints.insert(
            "trace".to_owned(),
            ArtifactFingerprint::of(&trace.canonical_bytes()),
        );
        fingerprints.insert(
            "minimized".to_owned(),
            ArtifactFingerprint::of(canonical_sequence(&reduction).as_bytes()),
        );
        fingerprints.insert(
            "signature".to_owned(),
            ArtifactFingerprint::of(signature.canonical().as_bytes()),
        );

        Self {
            inputs,
            build,
            signature,
            reduction,
            trace,
            replay_command: replay_command.into(),
            fingerprints,
        }
    }

    /// The inputs a replay needs.
    #[must_use]
    pub const fn inputs(&self) -> &ReplayInputs {
        &self.inputs
    }

    /// The signature a correct replay must reproduce.
    #[must_use]
    pub const fn expected_signature(&self) -> &CausalSignature {
        &self.signature
    }

    /// The reduction that produced the minimized counterexample.
    #[must_use]
    pub const fn reduction(&self) -> &Reduction {
        &self.reduction
    }

    /// The trace of the failing run.
    #[must_use]
    pub const fn trace(&self) -> &LogicalTrace {
        &self.trace
    }

    /// The one command that reproduces this failure.
    #[must_use]
    pub fn replay_command(&self) -> &str {
        &self.replay_command
    }

    /// Fingerprints of this pack's own contents.
    #[must_use]
    pub const fn fingerprints(&self) -> &BTreeMap<String, ArtifactFingerprint> {
        &self.fingerprints
    }

    /// Whether this pack describes the build in front of us.
    ///
    /// # Errors
    ///
    /// [`LabRefusal::ReplayDrift`] naming the field that disagrees. Delegates to
    /// the receipt's own check so a pack and a receipt cannot disagree about
    /// what counts as the same build.
    pub fn check_build(&self, receipt: &CoverageReceipt) -> Result<(), LabRefusal> {
        receipt.check_build(&self.build)
    }

    /// Whether a replay reproduced *this* failure.
    ///
    /// # Errors
    ///
    /// [`LabRefusal::CausalSignatureMismatch`] when the replay failed for a
    /// different reason. Reproducing some other violation is not a successful
    /// replay, and is arguably worse than reproducing nothing, because it looks
    /// like success.
    pub fn confirm_replay(&self, observed: &CausalSignature) -> Result<(), LabRefusal> {
        if observed == &self.signature {
            Ok(())
        } else {
            Err(LabRefusal::CausalSignatureMismatch {
                expected: self.signature.canonical(),
                observed: observed.canonical(),
            })
        }
    }

    /// The pack as NDJSON: a header line, then one line per reduction step.
    ///
    /// Multi-line by design. The header is what a gate reads; the steps are
    /// what a human reads when they want to know why the minimizer kept what it
    /// kept.
    #[must_use]
    pub fn to_ndjson(&self) -> String {
        let mut lines = Vec::new();

        let fingerprints: Vec<String> = self
            .fingerprints
            .iter()
            .map(|(name, print)| format!("\"{name}\":\"{print}\""))
            .collect();

        lines.push(format!(
            concat!(
                "{{\"version\":\"{}\",\"record\":\"lab_crashpack\"",
                ",\"seed\":{},\"schedule_identity\":\"{}\",\"property\":\"{}\"",
                ",\"source_digest\":\"{}\",\"toolchain\":\"{}\",\"runtime_profile\":\"{}\"",
                ",\"expected_signature\":\"{}\"",
                ",\"original_events\":{},\"minimized_events\":{},\"removed\":{}",
                ",\"reduction_passes\":{},\"reduction_rejected\":{}",
                ",\"fingerprints\":{{{}}},\"replay_command\":\"{}\"}}"
            ),
            CRASHPACK_VERSION,
            self.inputs.seed,
            escape(&self.inputs.schedule_identity),
            escape(&self.inputs.property),
            escape(&self.build.source_digest),
            escape(&self.build.toolchain),
            escape(&self.build.runtime_profile),
            escape(&self.signature.canonical()),
            self.reduction.original().len(),
            self.reduction.minimized().len(),
            self.reduction.removed_count(),
            self.reduction.passes(),
            self.reduction.rejected(),
            fingerprints.join(","),
            escape(&self.replay_command),
        ));

        for step in self.reduction.steps() {
            lines.push(format!(
                concat!(
                    "{{\"version\":\"{}\",\"record\":\"lab_reduction_step\"",
                    ",\"pass\":{},\"index\":{},\"length_before\":{}",
                    ",\"accepted\":{},\"rejection\":\"{}\"}}"
                ),
                CRASHPACK_VERSION,
                step.pass,
                step.index,
                step.length_before,
                step.accepted,
                step.rejection.map_or("", |reason| reason.code()),
            ));
        }

        lines.join("\n")
    }
}

/// A stable rendering of the minimized sequence, for fingerprinting.
fn canonical_sequence(reduction: &Reduction) -> String {
    reduction
        .minimized()
        .iter()
        .map(|event| {
            format!(
                "{}:{}:{}",
                event.actor,
                event.event.code(),
                event.event.key().unwrap_or("-")
            )
        })
        .collect::<Vec<_>>()
        .join(",")
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
    use crate::commute::{ConflictRelation, OwnedEvent, ProtocolEvent};
    use crate::minimize::minimize;
    use crate::plan::StepId;
    use crate::receipt::{CoverageReceipt, DeclaredBounds};

    fn body_write(who: &str, key: &str) -> OwnedEvent {
        OwnedEvent::new(
            StepId::new(who),
            ProtocolEvent::BodyWrite {
                key: key.to_owned(),
            },
        )
    }

    fn read_body(who: &str, key: &str) -> OwnedEvent {
        OwnedEvent::new(
            StepId::new(who),
            ProtocolEvent::ReadBody {
                key: key.to_owned(),
            },
        )
    }

    fn build() -> BuildIdentity {
        BuildIdentity::new("sha256:0f1e", "nightly-2026-08-19", "class=deterministic")
    }

    fn cause_present(candidate: &[OwnedEvent]) -> bool {
        let write_at = candidate
            .iter()
            .position(|event| *event == body_write("w1", "a"));
        let read_at = candidate
            .iter()
            .position(|event| *event == read_body("r2", "a"));
        matches!((write_at, read_at), (Some(w), Some(r)) if w < r)
    }

    fn pack() -> Crashpack {
        let sequence = vec![
            read_body("c1", "padding"),
            body_write("w1", "a"),
            body_write("w2", "padding-two"),
            read_body("r2", "a"),
        ];
        let reduction = minimize(
            "linearizable",
            &sequence,
            ConflictRelation,
            &mut cause_present,
        );
        let signature = reduction.signature().clone();

        Crashpack::new(
            ReplayInputs {
                seed: 42,
                schedule_identity: "schedule-7f3a".to_owned(),
                property: "linearizable".to_owned(),
            },
            build(),
            signature,
            reduction,
            LogicalTrace::new(),
            "cargo test -p fgit-lab --test dpor_authority -- --exact \
             the_counterexample_schedule_replays_the_violation",
        )
    }

    #[test]
    fn a_crashpack_carries_every_part_a_reproduction_needs() {
        let line = pack().to_ndjson();
        let header = line.lines().next().expect("a header line");

        for field in [
            "\"version\":\"fgit-lab-crashpack-v1\"",
            "\"record\":\"lab_crashpack\"",
            "\"seed\":42",
            "\"schedule_identity\":\"schedule-7f3a\"",
            "\"property\":\"linearizable\"",
            "\"source_digest\":",
            "\"toolchain\":",
            "\"runtime_profile\":",
            "\"expected_signature\":",
            "\"original_events\":",
            "\"minimized_events\":",
            "\"fingerprints\":",
            "\"replay_command\":",
        ] {
            assert!(header.contains(field), "the header must state {field}");
        }
    }

    #[test]
    fn the_replay_command_is_present_and_runnable_looking() {
        let pack = pack();
        assert!(
            pack.replay_command().starts_with("cargo test"),
            "a crashpack must carry one command, got {:?}",
            pack.replay_command()
        );
    }

    #[test]
    fn a_replay_that_reproduces_the_same_cause_is_confirmed() {
        let pack = pack();
        let observed = pack.expected_signature().clone();
        assert!(pack.confirm_replay(&observed).is_ok());
    }

    #[test]
    fn a_replay_that_fails_for_a_different_reason_is_refused() {
        // The paired forbidden case: reproducing *a* failure is not
        // reproducing *the* failure.
        let pack = pack();
        let different = CausalSignature::of(
            "linearizable",
            &[read_body("r1", "a"), read_body("r2", "a")],
            ConflictRelation,
        );

        let refusal = pack
            .confirm_replay(&different)
            .expect_err("a different causal signature must be refused");
        assert_eq!(refusal.code(), "lab.replay.causal_signature_mismatch");
    }

    #[test]
    fn a_crashpack_from_another_build_is_refused_as_drift() {
        let pack = pack();
        let elsewhere = CoverageReceipt::new(
            BuildIdentity::new(
                "sha256:different",
                "nightly-2026-08-19",
                "class=deterministic",
            ),
            42,
            DeclaredBounds {
                max_executions: 8,
                max_transitions: 100,
            },
        );

        let refusal = pack
            .check_build(&elsewhere)
            .expect_err("a crashpack must not replay onto a different build");
        assert_eq!(refusal.code(), "lab.replay.drift");
    }

    #[test]
    fn a_crashpack_matching_its_build_is_accepted() {
        let pack = pack();
        let same = CoverageReceipt::new(
            build(),
            42,
            DeclaredBounds {
                max_executions: 8,
                max_transitions: 100,
            },
        );
        assert!(pack.check_build(&same).is_ok());
    }

    #[test]
    fn the_reduction_log_is_emitted_line_per_step() {
        let pack = pack();
        let ndjson = pack.to_ndjson();
        let step_lines = ndjson
            .lines()
            .filter(|line| line.contains("\"record\":\"lab_reduction_step\""))
            .count();

        assert_eq!(
            step_lines,
            pack.reduction().steps().len(),
            "every removal tried must appear in the pack"
        );
        assert!(
            ndjson.contains("\"accepted\":true"),
            "the log must show which removals were kept"
        );
        assert!(
            ndjson.contains("\"rejection\":\"no_longer_fails\""),
            "the log must show why a removal was refused"
        );
    }

    #[test]
    fn fingerprints_are_computed_from_the_contents_not_supplied() {
        // A pack cannot claim a fingerprint that does not match what it holds,
        // because the caller never provides one.
        let pack = pack();
        let prints = pack.fingerprints();

        assert!(prints.contains_key("trace"));
        assert!(prints.contains_key("minimized"));
        assert!(prints.contains_key("signature"));
        assert_eq!(
            prints["signature"],
            ArtifactFingerprint::of(pack.expected_signature().canonical().as_bytes())
        );
    }

    #[test]
    fn a_fingerprint_names_its_algorithm_so_it_cannot_read_as_a_digest() {
        // The module is explicit that these are not cryptographic commitments;
        // the rendering has to say so too, or a reader will assume sha256.
        let rendered = ArtifactFingerprint::of(b"anything").to_string();
        assert!(
            rendered.starts_with("fnv1a64:"),
            "a fingerprint must name its algorithm, got {rendered}"
        );
    }

    #[test]
    fn changing_one_event_changes_the_minimized_fingerprint() {
        let first = pack();
        let other_sequence = vec![body_write("w1", "b"), read_body("r2", "b")];
        let other_reduction = minimize(
            "linearizable",
            &other_sequence,
            ConflictRelation,
            &mut |candidate: &[OwnedEvent]| candidate.len() == 2,
        );
        let second = Crashpack::new(
            first.inputs().clone(),
            build(),
            other_reduction.signature().clone(),
            other_reduction,
            LogicalTrace::new(),
            "cargo test",
        );

        assert_ne!(
            first.fingerprints()["minimized"],
            second.fingerprints()["minimized"],
            "different counterexamples must not share a fingerprint"
        );
    }
}
