#![forbid(unsafe_code)]
//! FrankenGit's deterministic protocol laboratory.
//!
//! The lab exists so a protocol campaign can be *replayed*. Everything a run
//! depends on is an explicit input — the seed, the schedule, the profile
//! identity, the fault plan, the starting state — and everything a run
//! observes is written into one canonical [`journal::LogicalTrace`]. Re-run
//! with the same inputs and you get byte-identical trace bytes, or the lab
//! tells you exactly where they diverged.
//!
//! That property only holds if nothing ambient leaks in, so the lab does not
//! merely ask nicely:
//!
//! - time comes from [`tick::VirtualClock`], which advances only when a step
//!   advances it;
//! - entropy comes from [`rng::SeededEntropy`], which is
//!   [`SplitMix64`](fgit_authority::SplitMix64) under a recorded seed;
//! - the lab's request contexts are minted through [`fgit_runtime`] with the
//!   runtime `TIME` and `RANDOM` capability bits **masked off**, so a
//!   subsystem that reaches for the runtime clock or runtime entropy cannot
//!   compile against a lab context rather than failing mysteriously at replay
//!   time.
//!
//! # Evidence boundary
//!
//! **The lab proves logical interleavings under its own model. It proves
//! nothing about native behaviour.**
//!
//! In scope: logical step order, cancellation phase ordering, budget and
//! capability propagation, failpoint coverage, storage/packet/object-store
//! fault composition, region quiescence and obligation settlement as recorded
//! by the lab's own oracles, and trace identity across replays.
//!
//! Explicitly **not** in scope, and never to be described as proved here:
//! actual worker parking, OS thread scheduling, real files or sockets,
//! blocking-pool joins, signal delivery, child-process reaping, media loss,
//! or wall-clock timing. Those are native classes owned by FG-011b and the
//! downstream native crash campaigns. **Neither class substitutes for the
//! other**: a green lab run is not evidence about a parked worker, and a
//! green native run is not evidence about an unexplored interleaving.
//!
//! The lab enforces that boundary rather than documenting it — see
//! [`harness::Lab::classify`] and [`refuse::LabRefusal::UnavailableClassNotReplayable`],
//! which refuse to label an external or native class replayable.
//!
//! # What the lab is not
//!
//! Running many random schedules is not coverage. The lab reports which
//! *declared* failpoints a campaign actually exercised
//! ([`probe::CoverageReport`]) and refuses a campaign that claims completeness
//! while leaving declared points untouched. A stress count is never accepted
//! as a coverage claim.

pub mod harness;
pub mod hazard;
pub mod journal;
pub mod plan;
pub mod probe;
pub mod refuse;
pub mod rng;
pub mod tick;
pub mod verdict;

pub use harness::{Lab, LabConfig, LabRun, ReplayClass};
pub use hazard::{ObjectStoreFault, PacketFault};
pub use journal::{LogicalTrace, ReplayMismatch, TraceEvent, TraceFingerprint};
pub use plan::{LabSchedule, StepCursor, StepId};
pub use probe::{CoverageReport, FailpointId, FailpointRegistry};
pub use refuse::LabRefusal;
pub use rng::SeededEntropy;
pub use tick::{LabTime, VirtualClock};
pub use verdict::{ObligationOracle, OracleReport, QuiescenceOracle};
