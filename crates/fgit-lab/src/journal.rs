//! The canonical logical trace, and replay comparison.
//!
//! A trace is the run's observable record: ordered events, each rendered in a
//! canonical single-line form. Trace identity is defined by *bytes*, not by a
//! digest — comparing bytes is exact, needs no hash, and when two runs differ
//! it can point at the first differing event and print both sides, which is
//! the diagnostic a campaign actually needs.
//!
//! [`TraceFingerprint`] exists for cheap logging and indexing only. It is a
//! 64-bit FNV-1a checksum, **not** a cryptographic digest, and nothing in the
//! lab decides equality by comparing fingerprints.

use crate::plan::StepId;
use crate::probe::FailpointId;
use crate::refuse::LabRefusal;
use crate::tick::LabTime;

/// The trace format marker. Bumping it is a format change.
pub const TRACE_VERSION: &str = "fgit-lab-trace-v1";

/// One observable event in a run.
///
/// Events carry logical time and the participant, so the trace records *when*
/// and *who* alongside *what*. Everything here is deterministic data; nothing
/// derives from a host clock, an address, or an iteration order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceEvent {
    /// A run began under a named profile and seed.
    RunStarted {
        /// The runtime profile identity descriptor.
        profile: String,
        /// The run seed.
        seed: u64,
    },
    /// A participant took a scheduled step.
    Stepped {
        /// Logical time at the step.
        at: LabTime,
        /// Who stepped.
        participant: StepId,
        /// Zero-based schedule position.
        position: usize,
    },
    /// Logical time advanced.
    ClockAdvanced {
        /// The new instant.
        to: LabTime,
        /// How many ticks were consumed.
        ticks: u64,
    },
    /// A failpoint was reached.
    FailpointReached {
        /// Logical time.
        at: LabTime,
        /// Which point.
        point: FailpointId,
        /// Whether it fired.
        fired: bool,
    },
    /// A fault was injected.
    FaultInjected {
        /// Logical time.
        at: LabTime,
        /// A stable description of the fault.
        fault: String,
    },
    /// A request context was minted for a work class.
    ContextMinted {
        /// Logical time.
        at: LabTime,
        /// The budget class.
        class: &'static str,
        /// The runtime capability mask bits.
        capability_mask: u8,
        /// The poll quota granted.
        poll_quota: u32,
    },
    /// A cancellation phase was entered.
    CancellationPhase {
        /// Logical time.
        at: LabTime,
        /// `request`, `drain`, or `finalize`.
        phase: &'static str,
    },
    /// An operation produced one of the four outcome arms.
    OutcomeObserved {
        /// Logical time.
        at: LabTime,
        /// Who produced it.
        participant: StepId,
        /// The outcome class code.
        outcome: &'static str,
    },
    /// A region reached quiescence, or failed to.
    RegionClosed {
        /// Logical time.
        at: LabTime,
        /// Outstanding obligations at close.
        outstanding: usize,
    },
    /// The run ended.
    RunFinished {
        /// Logical time at the end.
        at: LabTime,
        /// Steps taken.
        steps: usize,
        /// Entropy draws consumed.
        draws: u64,
    },
}

impl TraceEvent {
    /// The canonical single-line rendering of this event.
    ///
    /// Field order is fixed and every field is present, so two runs that
    /// differ anywhere differ in these bytes.
    #[must_use]
    pub fn canonical_line(&self) -> String {
        match self {
            Self::RunStarted { profile, seed } => {
                format!("run_started\tseed={seed}\tprofile={profile}")
            }
            Self::Stepped {
                at,
                participant,
                position,
            } => format!("stepped\t{at}\tparticipant={participant}\tposition={position}"),
            Self::ClockAdvanced { to, ticks } => {
                format!("clock_advanced\t{to}\tticks={ticks}")
            }
            Self::FailpointReached { at, point, fired } => {
                format!("failpoint\t{at}\tpoint={point}\tfired={fired}")
            }
            Self::FaultInjected { at, fault } => format!("fault\t{at}\tfault={fault}"),
            Self::ContextMinted {
                at,
                class,
                capability_mask,
                poll_quota,
            } => format!(
                "context\t{at}\tclass={class}\tcaps={capability_mask:#06b}\tpoll_quota={poll_quota}"
            ),
            Self::CancellationPhase { at, phase } => {
                format!("cancellation\t{at}\tphase={phase}")
            }
            Self::OutcomeObserved {
                at,
                participant,
                outcome,
            } => format!("outcome\t{at}\tparticipant={participant}\toutcome={outcome}"),
            Self::RegionClosed { at, outstanding } => {
                format!("region_closed\t{at}\toutstanding={outstanding}")
            }
            Self::RunFinished { at, steps, draws } => {
                format!("run_finished\t{at}\tsteps={steps}\tdraws={draws}")
            }
        }
    }
}

/// The ordered record of a run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogicalTrace {
    events: Vec<TraceEvent>,
}

impl LogicalTrace {
    /// An empty trace.
    #[must_use]
    pub const fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Append an event.
    pub fn record(&mut self, event: TraceEvent) {
        self.events.push(event);
    }

    /// The recorded events.
    #[must_use]
    pub fn events(&self) -> &[TraceEvent] {
        &self.events
    }

    /// How many events were recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether nothing was recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// The canonical serialization: version marker, then one line per event.
    ///
    /// This is the artifact trace identity is defined over.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = String::from(TRACE_VERSION);
        out.push('\n');
        for event in &self.events {
            out.push_str(&event.canonical_line());
            out.push('\n');
        }
        out.into_bytes()
    }

    /// A cheap non-cryptographic fingerprint, for logging and indexing.
    #[must_use]
    pub fn fingerprint(&self) -> TraceFingerprint {
        TraceFingerprint::of(&self.canonical_bytes())
    }

    /// Parse the header of a serialized trace, refusing an unknown version.
    ///
    /// # Errors
    ///
    /// [`LabRefusal::TraceVersionUnsupported`] when the marker is not
    /// [`TRACE_VERSION`]. A trace whose format is not understood must not be
    /// compared against a current one and silently "match".
    pub fn check_version(bytes: &[u8]) -> Result<(), LabRefusal> {
        let text = String::from_utf8_lossy(bytes);
        let marker = text.lines().next().unwrap_or_default();
        if marker == TRACE_VERSION {
            Ok(())
        } else {
            Err(LabRefusal::TraceVersionUnsupported {
                found: marker.to_owned(),
            })
        }
    }

    /// Compare this trace against a recorded one.
    ///
    /// # Errors
    ///
    /// [`LabRefusal::ReplayDiverged`] naming the first differing event and
    /// printing both sides. A trailing or missing event counts as a
    /// divergence at that index, so a truncated replay is caught too.
    pub fn expect_matches(&self, recorded: &Self) -> Result<(), LabRefusal> {
        if let Some(mismatch) = self.first_divergence(recorded) {
            return Err(LabRefusal::ReplayDiverged {
                event_index: mismatch.event_index,
                expected: mismatch.expected,
                actual: mismatch.actual,
            });
        }
        Ok(())
    }

    /// Where two traces first differ, if they do.
    #[must_use]
    pub fn first_divergence(&self, recorded: &Self) -> Option<ReplayMismatch> {
        let limit = self.events.len().max(recorded.events.len());
        for index in 0..limit {
            let actual = self.events.get(index).map(TraceEvent::canonical_line);
            let expected = recorded.events.get(index).map(TraceEvent::canonical_line);
            if actual != expected {
                return Some(ReplayMismatch {
                    event_index: index,
                    expected: expected.unwrap_or_else(|| "<end of trace>".to_owned()),
                    actual: actual.unwrap_or_else(|| "<end of trace>".to_owned()),
                });
            }
        }
        None
    }
}

/// Where a replay diverged from its recording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayMismatch {
    /// Zero-based index of the first differing event.
    pub event_index: usize,
    /// What the recorded run emitted there.
    pub expected: String,
    /// What the replay emitted there.
    pub actual: String,
}

impl core::fmt::Display for ReplayMismatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "event {}: expected `{}`, got `{}`",
            self.event_index, self.expected, self.actual
        )
    }
}

/// A 64-bit FNV-1a checksum over canonical trace bytes.
///
/// **Not a cryptographic digest.** It is here so a campaign can label and
/// index runs cheaply. Equality decisions in this crate compare canonical
/// bytes, never fingerprints, because a checksum collision must never be able
/// to turn a diverged replay into a pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TraceFingerprint(u64);

impl TraceFingerprint {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    /// Checksum some bytes.
    #[must_use]
    pub const fn of(bytes: &[u8]) -> Self {
        let mut hash = Self::OFFSET;
        let mut index = 0;
        while index < bytes.len() {
            hash ^= bytes[index] as u64;
            hash = hash.wrapping_mul(Self::PRIME);
            index += 1;
        }
        Self(hash)
    }

    /// The raw value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

impl core::fmt::Display for TraceFingerprint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> LogicalTrace {
        let mut trace = LogicalTrace::new();
        trace.record(TraceEvent::RunStarted {
            profile: "fgit-runtime-profile-v1|class=deterministic".to_owned(),
            seed: 42,
        });
        trace.record(TraceEvent::Stepped {
            at: LabTime::ZERO,
            participant: StepId::new("writer-a"),
            position: 0,
        });
        trace.record(TraceEvent::ClockAdvanced {
            to: LabTime::from_ticks(3),
            ticks: 3,
        });
        trace.record(TraceEvent::FailpointReached {
            at: LabTime::from_ticks(3),
            point: FailpointId::new("authority.cas.after_effect"),
            fired: true,
        });
        trace.record(TraceEvent::OutcomeObserved {
            at: LabTime::from_ticks(3),
            participant: StepId::new("writer-a"),
            outcome: "cancelled",
        });
        trace.record(TraceEvent::RunFinished {
            at: LabTime::from_ticks(3),
            steps: 1,
            draws: 2,
        });
        trace
    }

    #[test]
    fn a_trace_serializes_canonically_and_stably() {
        let trace = sample();
        let first = trace.canonical_bytes();
        for _ in 0..8 {
            assert_eq!(trace.canonical_bytes(), first);
        }
        let text = String::from_utf8(first).expect("utf-8");
        assert!(text.starts_with("fgit-lab-trace-v1\n"));
        assert!(text.contains("\nstepped\tt0\tparticipant=writer-a\tposition=0\n"));
        assert!(text.contains("\nfailpoint\tt3\tpoint=authority.cas.after_effect\tfired=true\n"));
        assert!(text.ends_with("run_finished\tt3\tsteps=1\tdraws=2\n"));
    }

    #[test]
    fn identical_runs_produce_byte_identical_traces() {
        // The headline acceptance property, at the trace layer.
        assert_eq!(sample().canonical_bytes(), sample().canonical_bytes());
        sample()
            .expect_matches(&sample())
            .expect("identical traces match");
        assert_eq!(sample().fingerprint(), sample().fingerprint());
    }

    #[test]
    fn a_divergence_names_the_index_and_prints_both_sides() {
        let recorded = sample();
        let mut replay = sample();
        replay.events[2] = TraceEvent::ClockAdvanced {
            to: LabTime::from_ticks(4),
            ticks: 4,
        };

        let refusal = replay
            .expect_matches(&recorded)
            .expect_err("a changed event must be caught");
        match refusal {
            LabRefusal::ReplayDiverged {
                event_index,
                expected,
                actual,
            } => {
                assert_eq!(event_index, 2);
                assert_eq!(expected, "clock_advanced\tt3\tticks=3");
                assert_eq!(actual, "clock_advanced\tt4\tticks=4");
            }
            other => panic!("expected a divergence, got {other:?}"),
        }
    }

    #[test]
    fn a_truncated_replay_is_a_divergence_not_a_prefix_match() {
        let recorded = sample();
        let mut replay = sample();
        replay.events.truncate(3);

        let mismatch = replay
            .first_divergence(&recorded)
            .expect("a short replay diverges");
        assert_eq!(mismatch.event_index, 3);
        assert_eq!(mismatch.actual, "<end of trace>");
        assert!(mismatch.expected.starts_with("failpoint"));
        assert!(mismatch.to_string().contains("event 3"));
    }

    #[test]
    fn an_extra_event_is_a_divergence() {
        let recorded = sample();
        let mut replay = sample();
        replay.record(TraceEvent::RegionClosed {
            at: LabTime::from_ticks(3),
            outstanding: 0,
        });

        let mismatch = replay
            .first_divergence(&recorded)
            .expect("a longer replay diverges");
        assert_eq!(mismatch.event_index, recorded.len());
        assert_eq!(mismatch.expected, "<end of trace>");
    }

    #[test]
    fn every_event_variant_renders_a_distinct_canonical_line() {
        let events = vec![
            TraceEvent::RunStarted {
                profile: "p".to_owned(),
                seed: 1,
            },
            TraceEvent::Stepped {
                at: LabTime::ZERO,
                participant: StepId::new("a"),
                position: 0,
            },
            TraceEvent::ClockAdvanced {
                to: LabTime::ZERO,
                ticks: 0,
            },
            TraceEvent::FailpointReached {
                at: LabTime::ZERO,
                point: FailpointId::new("p"),
                fired: false,
            },
            TraceEvent::FaultInjected {
                at: LabTime::ZERO,
                fault: "lose_request".to_owned(),
            },
            TraceEvent::ContextMinted {
                at: LabTime::ZERO,
                class: "request",
                capability_mask: 0b0000_1010,
                poll_quota: 7,
            },
            TraceEvent::CancellationPhase {
                at: LabTime::ZERO,
                phase: "drain",
            },
            TraceEvent::OutcomeObserved {
                at: LabTime::ZERO,
                participant: StepId::new("a"),
                outcome: "success",
            },
            TraceEvent::RegionClosed {
                at: LabTime::ZERO,
                outstanding: 0,
            },
            TraceEvent::RunFinished {
                at: LabTime::ZERO,
                steps: 0,
                draws: 0,
            },
        ];

        let mut lines: Vec<String> = events.iter().map(TraceEvent::canonical_line).collect();
        let total = lines.len();
        lines.sort();
        lines.dedup();
        assert_eq!(lines.len(), total, "event renderings must be distinguishable");
    }

    #[test]
    fn the_context_event_records_the_capability_mask_and_budget() {
        let line = TraceEvent::ContextMinted {
            at: LabTime::from_ticks(2),
            class: "parser",
            capability_mask: 0b0000_1010,
            poll_quota: 50_000,
        }
        .canonical_line();
        // The acceptance line: capability masks and finite budgets are present
        // in traces, not merely applied somewhere off-record.
        assert_eq!(line, "context\tt2\tclass=parser\tcaps=0b1010\tpoll_quota=50000");
    }

    #[test]
    fn an_unknown_trace_version_is_refused() {
        let refusal = LogicalTrace::check_version(b"some-other-format-v9\nstepped\n")
            .expect_err("an unknown format must not be compared");
        assert_eq!(
            refusal,
            LabRefusal::TraceVersionUnsupported {
                found: "some-other-format-v9".to_owned()
            }
        );

        // Paired permitted case: the current marker checks out.
        LogicalTrace::check_version(&sample().canonical_bytes())
            .expect("the current version is supported");
    }

    #[test]
    fn the_fingerprint_is_deterministic_and_input_sensitive() {
        assert_eq!(TraceFingerprint::of(b"abc"), TraceFingerprint::of(b"abc"));
        assert_ne!(TraceFingerprint::of(b"abc"), TraceFingerprint::of(b"abd"));
        assert_ne!(TraceFingerprint::of(b"ab"), TraceFingerprint::of(b"ba"));
        assert_eq!(format!("{}", TraceFingerprint::of(b"")).len(), 16);
    }

    #[test]
    fn equality_is_decided_by_bytes_not_by_fingerprint() {
        // Guard against someone "optimising" expect_matches into a
        // fingerprint comparison: a checksum collision must never be able to
        // pass a diverged replay.
        let recorded = sample();
        let mut replay = sample();
        replay.events[1] = TraceEvent::Stepped {
            at: LabTime::ZERO,
            participant: StepId::new("writer-b"),
            position: 0,
        };
        assert!(replay.expect_matches(&recorded).is_err());
        assert_ne!(replay.canonical_bytes(), recorded.canonical_bytes());
    }
}
