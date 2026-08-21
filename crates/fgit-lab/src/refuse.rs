//! The laboratory's refusal vocabulary.
//!
//! Every way the lab declines to produce or to certify a result is one variant
//! with one stable machine code, mirroring the convention in
//! [`fgit_runtime::RuntimeRefusal`]. The codes are namespaced under `lab.` so
//! a campaign report can carry refusals from both layers without collision.

use core::fmt;

/// Every typed refusal the laboratory can raise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabRefusal {
    /// A replay produced different trace bytes than the recorded run.
    ///
    /// This is the headline failure: the lab's whole value is that it cannot
    /// happen for a well-behaved subject.
    ReplayDiverged {
        /// Zero-based index of the first differing trace event.
        event_index: usize,
        /// What the recorded run emitted.
        expected: String,
        /// What the replay emitted.
        actual: String,
    },
    /// Two runs with identical inputs produced different traces, so the
    /// subject or the harness is nondeterministic.
    ScheduleNondeterministic {
        /// The seed both runs used.
        seed: u64,
        /// Where they first differed.
        event_index: usize,
    },
    /// A campaign declared failpoints it never exercised, and claimed
    /// completeness anyway.
    FailpointsUnexercised {
        /// The declared-but-untouched failpoint names, sorted.
        unexercised: Vec<String>,
    },
    /// A failpoint was armed or hit without being declared first.
    FailpointUndeclared {
        /// The offending name.
        name: String,
    },
    /// The same failpoint name was declared twice.
    FailpointRedeclared {
        /// The offending name.
        name: String,
    },
    /// Something read a clock or an entropy source the lab does not own.
    ///
    /// The lab masks the runtime `TIME` and `RANDOM` capabilities, so this
    /// reports a subject that reached around the capability system rather than
    /// through it.
    AmbientSourceUsed {
        /// Which ambient source: `time` or `random`.
        source: &'static str,
    },
    /// A step tried to move logical time backwards.
    ClockRegressed {
        /// The current logical time.
        now: u64,
        /// The time the step asked for.
        requested: u64,
    },
    /// The schedule was exhausted but the campaign asked for another step.
    ScheduleExhausted {
        /// How many steps the schedule declared.
        declared: usize,
    },
    /// A schedule step named a participant the schedule never declared.
    UnknownParticipant {
        /// The offending participant name.
        name: String,
    },
    /// The harness was asked to certify a class it cannot replay.
    ///
    /// Native worker parking, OS threads, real sockets, blocking-pool joins,
    /// signals, and process reaping are not lab-replayable, and the lab
    /// refuses to say otherwise.
    UnavailableClassNotReplayable {
        /// The class that was requested.
        class: &'static str,
    },
    /// A region closed while obligations were still outstanding.
    RegionNotQuiescent {
        /// How many obligations were still outstanding.
        outstanding: usize,
    },
    /// A trace was decoded from an unknown or unsupported format version.
    TraceVersionUnsupported {
        /// The marker that was found.
        found: String,
    },
    /// A cancellation phase was recorded out of the fixed order.
    CancellationPhaseOutOfOrder {
        /// The phase the sequence expected next.
        expected: &'static str,
        /// The phase that was recorded.
        actual: &'static str,
    },
    /// A stress count was offered where a coverage claim was required.
    StressIsNotCoverage {
        /// How many runs were offered as the claim.
        runs: u64,
    },
    /// A receipt was replayed against a build it does not describe.
    ///
    /// The seed and schedule can only reproduce a failure on the source,
    /// toolchain, and runtime profile that produced it. Replaying against a
    /// different build and reporting the original signature would be a
    /// fabricated result, so the drift is refused instead.
    ReplayDrift {
        /// Which identity field disagreed.
        field: &'static str,
        /// What the receipt recorded.
        recorded: String,
        /// What the current build reports.
        observed: String,
    },
    /// A replay reproduced a failure, but not the one the crashpack is about.
    ///
    /// Reproducing some other violation is not a successful replay; it looks
    /// like success while hiding two bugs at once.
    CausalSignatureMismatch {
        /// The signature the crashpack expects.
        expected: String,
        /// The signature the replay actually produced.
        observed: String,
    },
    /// Close evidence was folded against a different region's observations.
    ///
    /// A verdict built from one region's ledger and another's lab observations
    /// describes neither. This is the same class of error as a stale read or a
    /// benchmark attributed to the wrong crate: a real measurement bound to
    /// the wrong subject.
    RegionEvidenceMismatch {
        /// The region the observer watched.
        expected: u64,
        /// The region the close evidence describes.
        observed: u64,
    },
    /// A deterministic receipt was offered as evidence for a native class.
    ///
    /// Lab evidence is evidence about the model, not about parked workers, OS
    /// I/O, signals, or process reaping. Crediting it for a native requirement
    /// is proof-class inflation, so it fails closed.
    DeterministicEvidenceForNativeClass {
        /// The native class that was claimed.
        class: &'static str,
    },
}

impl LabRefusal {
    /// Stable machine code for evidence and campaign reports.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ReplayDiverged { .. } => "lab.replay.diverged",
            Self::ScheduleNondeterministic { .. } => "lab.schedule.nondeterministic",
            Self::FailpointsUnexercised { .. } => "lab.failpoint.unexercised",
            Self::FailpointUndeclared { .. } => "lab.failpoint.undeclared",
            Self::FailpointRedeclared { .. } => "lab.failpoint.redeclared",
            Self::AmbientSourceUsed { .. } => "lab.ambient.source_used",
            Self::ClockRegressed { .. } => "lab.clock.regressed",
            Self::ScheduleExhausted { .. } => "lab.schedule.exhausted",
            Self::UnknownParticipant { .. } => "lab.schedule.unknown_participant",
            Self::UnavailableClassNotReplayable { .. } => "lab.boundary.not_replayable",
            Self::RegionNotQuiescent { .. } => "lab.region.not_quiescent",
            Self::TraceVersionUnsupported { .. } => "lab.trace.version_unsupported",
            Self::CancellationPhaseOutOfOrder { .. } => "lab.cancellation.out_of_order",
            Self::StressIsNotCoverage { .. } => "lab.coverage.stress_is_not_coverage",
            Self::ReplayDrift { .. } => "lab.replay.drift",
            Self::CausalSignatureMismatch { .. } => "lab.replay.causal_signature_mismatch",
            Self::RegionEvidenceMismatch { .. } => "lab.region.evidence_mismatch",
            Self::DeterministicEvidenceForNativeClass { .. } => {
                "lab.evidence.deterministic_for_native_class"
            }
        }
    }

    /// Whether this refusal indicates the *subject* misbehaved, as opposed to
    /// the campaign being configured wrongly.
    ///
    /// A diverged replay or a nondeterministic schedule is a finding about the
    /// code under test. An undeclared failpoint or an exhausted schedule is a
    /// mistake in the campaign itself. Reporting them the same way would let a
    /// harness bug masquerade as a discovery.
    #[must_use]
    pub const fn indicts_subject(&self) -> bool {
        matches!(
            self,
            Self::ReplayDiverged { .. }
                | Self::ScheduleNondeterministic { .. }
                | Self::AmbientSourceUsed { .. }
                | Self::ClockRegressed { .. }
                | Self::RegionNotQuiescent { .. }
                | Self::CancellationPhaseOutOfOrder { .. }
        )
    }
}

impl fmt::Display for LabRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReplayDiverged {
                event_index,
                expected,
                actual,
            } => write!(
                f,
                "replay diverged at event {event_index}: recorded `{expected}`, replayed `{actual}`"
            ),
            Self::ScheduleNondeterministic { seed, event_index } => write!(
                f,
                "two runs at seed {seed} diverged at event {event_index}; the subject or harness is nondeterministic"
            ),
            Self::FailpointsUnexercised { unexercised } => write!(
                f,
                "campaign claimed completeness with {} declared failpoint(s) never exercised: {}",
                unexercised.len(),
                unexercised.join(", ")
            ),
            Self::FailpointUndeclared { name } => {
                write!(f, "failpoint `{name}` was used without being declared")
            }
            Self::FailpointRedeclared { name } => {
                write!(f, "failpoint `{name}` was declared twice")
            }
            Self::AmbientSourceUsed { source } => write!(
                f,
                "ambient `{source}` was used; the lab owns time and entropy and masks both capabilities"
            ),
            Self::ClockRegressed { now, requested } => write!(
                f,
                "logical time cannot regress: now {now}, requested {requested}"
            ),
            Self::ScheduleExhausted { declared } => {
                write!(f, "schedule exhausted after {declared} declared step(s)")
            }
            Self::UnknownParticipant { name } => {
                write!(f, "schedule step names undeclared participant `{name}`")
            }
            Self::UnavailableClassNotReplayable { class } => write!(
                f,
                "class `{class}` is not lab-replayable; it is native evidence owned by FG-011b"
            ),
            Self::RegionNotQuiescent { outstanding } => write!(
                f,
                "region closed with {outstanding} outstanding obligation(s); closure requires quiescence or a typed containment failure"
            ),
            Self::TraceVersionUnsupported { found } => {
                write!(f, "unsupported trace format marker `{found}`")
            }
            Self::CancellationPhaseOutOfOrder { expected, actual } => write!(
                f,
                "cancellation phase `{actual}` recorded out of order; the protocol expects `{expected}` next"
            ),
            Self::StressIsNotCoverage { runs } => write!(
                f,
                "{runs} run(s) is a stress count, not a coverage claim; report exercised failpoints instead"
            ),
            Self::ReplayDrift {
                field,
                recorded,
                observed,
            } => write!(
                f,
                "replay drift on `{field}`: receipt recorded `{recorded}`, this build reports \
                 `{observed}`"
            ),
            Self::CausalSignatureMismatch { expected, observed } => write!(
                f,
                "replay reproduced a different failure: expected `{expected}`, observed \
                 `{observed}`"
            ),
            Self::RegionEvidenceMismatch { expected, observed } => write!(
                f,
                "region-close evidence mismatch: observer watched region {expected}, evidence \
                 describes region {observed}"
            ),
            Self::DeterministicEvidenceForNativeClass { class } => write!(
                f,
                "deterministic lab evidence cannot be credited for the native class `{class}`"
            ),
        }
    }
}

impl std::error::Error for LabRefusal {}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_variant() -> Vec<LabRefusal> {
        vec![
            LabRefusal::ReplayDiverged {
                event_index: 3,
                expected: "a".to_owned(),
                actual: "b".to_owned(),
            },
            LabRefusal::ScheduleNondeterministic {
                seed: 7,
                event_index: 1,
            },
            LabRefusal::FailpointsUnexercised {
                unexercised: vec!["p".to_owned()],
            },
            LabRefusal::FailpointUndeclared {
                name: "p".to_owned(),
            },
            LabRefusal::FailpointRedeclared {
                name: "p".to_owned(),
            },
            LabRefusal::AmbientSourceUsed { source: "time" },
            LabRefusal::ClockRegressed {
                now: 5,
                requested: 4,
            },
            LabRefusal::ScheduleExhausted { declared: 2 },
            LabRefusal::UnknownParticipant {
                name: "x".to_owned(),
            },
            LabRefusal::UnavailableClassNotReplayable {
                class: "native_worker_parking",
            },
            LabRefusal::RegionNotQuiescent { outstanding: 1 },
            LabRefusal::TraceVersionUnsupported {
                found: "nope".to_owned(),
            },
            LabRefusal::CancellationPhaseOutOfOrder {
                expected: "drain",
                actual: "finalize",
            },
            LabRefusal::StressIsNotCoverage { runs: 10_000 },
        ]
    }

    #[test]
    fn refusal_codes_are_unique_and_namespaced() {
        let refusals = every_variant();
        let mut codes: Vec<&str> = refusals.iter().map(LabRefusal::code).collect();
        let total = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), total, "lab refusal codes must be unique");
        for code in &codes {
            assert!(
                code.starts_with("lab."),
                "refusal code `{code}` must be namespaced under `lab.`"
            );
        }
    }

    #[test]
    fn subject_findings_are_separated_from_campaign_mistakes() {
        // A diverged replay is a finding about the code under test.
        assert!(
            LabRefusal::ReplayDiverged {
                event_index: 0,
                expected: String::new(),
                actual: String::new(),
            }
            .indicts_subject()
        );
        assert!(
            LabRefusal::ScheduleNondeterministic {
                seed: 1,
                event_index: 0
            }
            .indicts_subject()
        );
        assert!(LabRefusal::AmbientSourceUsed { source: "random" }.indicts_subject());

        // A misconfigured campaign is not a discovery about the subject.
        assert!(
            !LabRefusal::FailpointUndeclared {
                name: "p".to_owned()
            }
            .indicts_subject()
        );
        assert!(!LabRefusal::ScheduleExhausted { declared: 1 }.indicts_subject());
        assert!(
            !LabRefusal::UnavailableClassNotReplayable {
                class: "native_signals"
            }
            .indicts_subject()
        );
        assert!(!LabRefusal::StressIsNotCoverage { runs: 1 }.indicts_subject());
    }

    #[test]
    fn every_refusal_renders_a_message_naming_its_subject() {
        for refusal in every_variant() {
            let rendered = refusal.to_string();
            assert!(
                !rendered.is_empty(),
                "{} must render a message",
                refusal.code()
            );
            // The message must be more than the code echoed back.
            assert!(rendered.len() > 10, "{rendered}");
        }
    }
}
