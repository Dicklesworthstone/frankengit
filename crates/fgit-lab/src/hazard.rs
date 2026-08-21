//! Packet and object-store fault models, and how faults compose.
//!
//! Storage faults are **not** modelled here. `fgit-authority` already owns a
//! faultable `AuthorityStore` with a scripted [`FaultPlan`], and the lab drives
//! that rather than forking it — two fault models over the same store would
//! drift, and the campaign that matters most (crash at the CAS boundary) is
//! exactly where the drift would land.
//!
//! What this module adds is the two classes `fgit-authority` does not cover:
//! packet-level transport faults and object-store faults. Together with the
//! storage plan they form a [`HazardScript`], which is the one place a run's
//! whole fault configuration lives so it can be quoted and replayed.

use fgit_authority::{FaultPlan, OpIndex};
use fgit_runtime::Exhaustion;

use crate::rng::SeededEntropy;

/// A transport-level fault against a framed protocol stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PacketFault {
    /// The frame is cut short mid-payload.
    Truncate {
        /// Bytes delivered before the cut.
        after_bytes: u32,
    },
    /// The frame is delivered twice.
    Duplicate,
    /// The frame is dropped entirely.
    Drop,
    /// Delivery is held back by some number of frames.
    Reorder {
        /// How many later frames overtake this one.
        by_frames: u16,
    },
    /// A byte in the payload is corrupted.
    Corrupt {
        /// Offset of the corrupted byte.
        at_byte: u32,
    },
    /// The peer closes the stream without the expected terminator.
    PrematureClose,
}

impl PacketFault {
    /// Stable machine code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Truncate { .. } => "packet.truncate",
            Self::Duplicate => "packet.duplicate",
            Self::Drop => "packet.drop",
            Self::Reorder { .. } => "packet.reorder",
            Self::Corrupt { .. } => "packet.corrupt",
            Self::PrematureClose => "packet.premature_close",
        }
    }

    /// Whether the receiver can still observe a well-formed frame.
    ///
    /// A duplicate or a reorder delivers intact bytes; the rest do not. The
    /// distinction matters because only the intact classes exercise
    /// idempotency, while the others exercise parser bounds.
    #[must_use]
    pub const fn delivers_intact_bytes(self) -> bool {
        matches!(self, Self::Duplicate | Self::Reorder { .. })
    }

    /// A canonical rendering for the trace.
    #[must_use]
    pub fn canonical(self) -> String {
        match self {
            Self::Truncate { after_bytes } => format!("packet.truncate:{after_bytes}"),
            Self::Duplicate => "packet.duplicate".to_owned(),
            Self::Drop => "packet.drop".to_owned(),
            Self::Reorder { by_frames } => format!("packet.reorder:{by_frames}"),
            Self::Corrupt { at_byte } => format!("packet.corrupt:{at_byte}"),
            Self::PrematureClose => "packet.premature_close".to_owned(),
        }
    }
}

/// A fault against an object-store read or write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObjectStoreFault {
    /// The write is reported as failed after the bytes landed.
    WriteAmbiguous,
    /// A read returns bytes that do not match their commitment.
    ReadCorrupt {
        /// Offset of the mismatching byte.
        at_byte: u32,
    },
    /// A read finds nothing where a completed write should be.
    ReadMissing,
    /// The store rejects the request for exceeding a declared bound.
    LimitExceeded,
    /// The store is temporarily refusing and the caller may retry.
    Throttled,
    /// A read observes an older generation than the one just written.
    StaleGeneration {
        /// How many generations behind.
        behind: u32,
    },
}

impl ObjectStoreFault {
    /// Stable machine code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::WriteAmbiguous => "object.write_ambiguous",
            Self::ReadCorrupt { .. } => "object.read_corrupt",
            Self::ReadMissing => "object.read_missing",
            Self::LimitExceeded => "object.limit_exceeded",
            Self::Throttled => "object.throttled",
            Self::StaleGeneration { .. } => "object.stale_generation",
        }
    }

    /// Whether the caller may retry the identical request.
    ///
    /// Only throttling is transient. An ambiguous write must be *resolved*,
    /// not retried blindly, and corruption or a stale generation is a
    /// correctness signal rather than a hint to try again.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::Throttled)
    }

    /// Whether the fault leaves the caller unable to conclude anything about
    /// the effect.
    #[must_use]
    pub const fn is_ambiguous(self) -> bool {
        matches!(self, Self::WriteAmbiguous)
    }

    /// A canonical rendering for the trace.
    #[must_use]
    pub fn canonical(self) -> String {
        match self {
            Self::ReadCorrupt { at_byte } => format!("object.read_corrupt:{at_byte}"),
            Self::StaleGeneration { behind } => format!("object.stale_generation:{behind}"),
            other => other.code().to_owned(),
        }
    }
}

/// A fault against a work unit's own execution, rather than against a
/// resource it talks to.
///
/// The bead requires storage, packet, **budget**, **cancellation**, **panic**,
/// and obligation faults to compose. The first two are resource-facing and
/// live above; these three are execution-facing, and they are modelled
/// separately because they arrive through a different channel: the runtime
/// imposes them on the task, rather than a peer returning them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExecutionFault {
    /// A budget dimension is driven to empty.
    BudgetExhausted {
        /// Which dimension runs out.
        dimension: Exhaustion,
    },
    /// Cancellation is requested during a named phase.
    ///
    /// The phase matters: cancelling during `finalize` is the case that can
    /// strand an obligation, and it is not the same experiment as cancelling
    /// during `request`.
    Cancelled {
        /// `request`, `drain`, or `finalize`.
        phase: CancelPhase,
    },
    /// The work unit panics and the panic is contained.
    PanicContained,
}

/// The cancellation phase a fault targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CancelPhase {
    /// Cancellation requested before draining begins.
    Request,
    /// Cancellation lands while in-flight work is draining.
    Drain,
    /// Cancellation lands during finalization, where obligations settle.
    Finalize,
}

impl CancelPhase {
    /// Stable machine code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Drain => "drain",
            Self::Finalize => "finalize",
        }
    }

    /// The phases in their fixed order.
    #[must_use]
    pub const fn sequence() -> [Self; 3] {
        [Self::Request, Self::Drain, Self::Finalize]
    }

    /// Whether a fault in this phase can strand an obligation.
    ///
    /// Only `Finalize` can: before it, obligations have not begun settling, so
    /// cancelling loses no responsibility that was not already unclaimed.
    #[must_use]
    pub const fn can_strand_an_obligation(self) -> bool {
        matches!(self, Self::Finalize)
    }
}

impl ExecutionFault {
    /// Stable machine code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::BudgetExhausted { .. } => "exec.budget_exhausted",
            Self::Cancelled { .. } => "exec.cancelled",
            Self::PanicContained => "exec.panic_contained",
        }
    }

    /// Which `Outcome` arm a caller should see.
    ///
    /// Budget exhaustion and cancellation both surface as cancellation; a
    /// contained panic surfaces as the panic arm. Collapsing either into the
    /// domain-error arm is the failure this mapping exists to prevent.
    #[must_use]
    pub const fn expected_outcome(self) -> &'static str {
        match self {
            Self::BudgetExhausted { .. } | Self::Cancelled { .. } => "cancelled",
            Self::PanicContained => "panicked",
        }
    }

    /// A canonical rendering for the trace.
    #[must_use]
    pub fn canonical(self) -> String {
        match self {
            Self::BudgetExhausted { dimension } => {
                format!("exec.budget_exhausted:{}", dimension.code())
            }
            Self::Cancelled { phase } => format!("exec.cancelled:{}", phase.code()),
            Self::PanicContained => "exec.panic_contained".to_owned(),
        }
    }
}

/// One scheduled fault, at one logical operation index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduledHazard {
    /// A packet fault.
    Packet {
        /// Operation index at which it fires.
        at: OpIndex,
        /// The fault.
        fault: PacketFault,
    },
    /// An object-store fault.
    ObjectStore {
        /// Operation index at which it fires.
        at: OpIndex,
        /// The fault.
        fault: ObjectStoreFault,
    },
    /// An execution fault against the work unit itself.
    Execution {
        /// Operation index at which it fires.
        at: OpIndex,
        /// The fault.
        fault: ExecutionFault,
    },
}

impl ScheduledHazard {
    /// The operation index at which this fires.
    #[must_use]
    pub const fn at(self) -> OpIndex {
        match self {
            Self::Packet { at, .. } | Self::ObjectStore { at, .. } | Self::Execution { at, .. } => {
                at
            }
        }
    }

    /// A canonical rendering for the trace.
    #[must_use]
    pub fn canonical(self) -> String {
        match self {
            Self::Packet { at, fault } => format!("{}@{}", fault.canonical(), at.raw()),
            Self::ObjectStore { at, fault } => format!("{}@{}", fault.canonical(), at.raw()),
            Self::Execution { at, fault } => format!("{}@{}", fault.canonical(), at.raw()),
        }
    }
}

/// A run's complete fault configuration.
///
/// Storage faults are delegated to `fgit-authority`'s [`FaultPlan`]; packet and
/// object-store faults are held here. Keeping all three in one value is what
/// lets a campaign say "this exact configuration" and mean it.
#[derive(Debug, Clone, PartialEq)]
pub struct HazardScript {
    storage: FaultPlan,
    hazards: Vec<ScheduledHazard>,
    seed: Option<u64>,
}

impl HazardScript {
    /// A script with no faults at all.
    ///
    /// The control condition. A campaign that cannot pass with no faults has
    /// not yet learned anything about faults.
    #[must_use]
    pub fn none() -> Self {
        Self {
            storage: FaultPlan::none(),
            hazards: Vec::new(),
            seed: None,
        }
    }

    /// A script with an explicit storage plan and hazard list.
    ///
    /// Hazards are sorted by operation index so the script reads in the order
    /// it fires, and so two scripts built from the same set compare equal
    /// regardless of construction order.
    #[must_use]
    pub fn explicit(storage: FaultPlan, mut hazards: Vec<ScheduledHazard>) -> Self {
        hazards.sort_by_key(|hazard| hazard.at().raw());
        Self {
            storage,
            hazards,
            seed: None,
        }
    }

    /// A seeded script over a span of operations.
    ///
    /// The storage plan comes from `fgit-authority`'s own seeded generator, so
    /// storage faults stay that crate's business; only the packet and
    /// object-store choices are made here, from a forked sub-stream so adding
    /// hazards cannot perturb the storage plan.
    #[must_use]
    pub fn seeded(seed: u64, span: u64, storage_count: usize, hazard_count: usize) -> Self {
        let storage = FaultPlan::seeded(seed, span, storage_count);
        let mut entropy = SeededEntropy::from_seed(seed).fork("hazard");
        let mut hazards = Vec::with_capacity(hazard_count);
        for _ in 0..hazard_count {
            let at = OpIndex::from_raw(entropy.next_below(span.max(1)));
            let hazard = if entropy.chance_percent(50) {
                ScheduledHazard::Packet {
                    at,
                    fault: match entropy.next_below(6) {
                        0 => PacketFault::Truncate {
                            after_bytes: u32::try_from(entropy.next_below(4096)).unwrap_or(0),
                        },
                        1 => PacketFault::Duplicate,
                        2 => PacketFault::Drop,
                        3 => PacketFault::Reorder {
                            by_frames: u16::try_from(entropy.next_below(8)).unwrap_or(0),
                        },
                        4 => PacketFault::Corrupt {
                            at_byte: u32::try_from(entropy.next_below(4096)).unwrap_or(0),
                        },
                        _ => PacketFault::PrematureClose,
                    },
                }
            } else {
                ScheduledHazard::ObjectStore {
                    at,
                    fault: match entropy.next_below(6) {
                        0 => ObjectStoreFault::WriteAmbiguous,
                        1 => ObjectStoreFault::ReadCorrupt {
                            at_byte: u32::try_from(entropy.next_below(4096)).unwrap_or(0),
                        },
                        2 => ObjectStoreFault::ReadMissing,
                        3 => ObjectStoreFault::LimitExceeded,
                        4 => ObjectStoreFault::Throttled,
                        _ => ObjectStoreFault::StaleGeneration {
                            behind: u32::try_from(entropy.next_below(4)).unwrap_or(1),
                        },
                    },
                }
            };
            hazards.push(hazard);
        }
        hazards.sort_by_key(|hazard| hazard.at().raw());
        Self {
            storage,
            hazards,
            seed: Some(seed),
        }
    }

    /// The storage fault plan, to install on a faultable store.
    #[must_use]
    pub fn storage(&self) -> &FaultPlan {
        &self.storage
    }

    /// The packet and object-store hazards, in firing order.
    #[must_use]
    pub fn hazards(&self) -> &[ScheduledHazard] {
        &self.hazards
    }

    /// The seed, when generated.
    #[must_use]
    pub const fn seed(&self) -> Option<u64> {
        self.seed
    }

    /// Whether this script injects nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.storage.is_empty() && self.hazards.is_empty()
    }

    /// Every hazard scheduled at a given operation index.
    #[must_use]
    pub fn at(&self, index: OpIndex) -> Vec<ScheduledHazard> {
        self.hazards
            .iter()
            .filter(|hazard| hazard.at() == index)
            .copied()
            .collect()
    }

    /// A canonical, stable, single-line rendering.
    #[must_use]
    pub fn canonical_line(&self) -> String {
        let mut parts = vec![
            "fgit-lab-hazards-v1".to_owned(),
            format!(
                "seed={}",
                self.seed
                    .map_or_else(|| "none".to_owned(), |seed| seed.to_string())
            ),
            format!("storage={}", self.storage.directives().len()),
            format!("hazards={}", self.hazards.len()),
        ];
        for hazard in &self.hazards {
            parts.push(hazard.canonical());
        }
        parts.join("|")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_empty_script_is_the_control_condition() {
        let script = HazardScript::none();
        assert!(script.is_empty());
        assert!(script.hazards().is_empty());
        assert!(script.storage().is_empty());
        assert_eq!(script.seed(), None);
        assert_eq!(
            script.canonical_line(),
            "fgit-lab-hazards-v1|seed=none|storage=0|hazards=0"
        );
    }

    #[test]
    fn a_seeded_script_is_reproducible_and_seed_sensitive() {
        let first = HazardScript::seeded(1234, 64, 3, 5);
        let second = HazardScript::seeded(1234, 64, 3, 5);
        assert_eq!(first, second);
        assert_eq!(first.canonical_line(), second.canonical_line());
        assert_eq!(first.seed(), Some(1234));

        let other = HazardScript::seeded(1235, 64, 3, 5);
        assert_ne!(first.canonical_line(), other.canonical_line());
    }

    #[test]
    fn seeded_hazards_stay_inside_the_declared_span() {
        let script = HazardScript::seeded(9, 32, 4, 40);
        assert_eq!(script.hazards().len(), 40);
        for hazard in script.hazards() {
            assert!(hazard.at().raw() < 32, "hazard escaped the span");
        }
    }

    #[test]
    fn hazards_are_sorted_so_a_script_reads_as_it_runs() {
        let script = HazardScript::explicit(
            FaultPlan::none(),
            vec![
                ScheduledHazard::Packet {
                    at: OpIndex::from_raw(9),
                    fault: PacketFault::Drop,
                },
                ScheduledHazard::ObjectStore {
                    at: OpIndex::from_raw(2),
                    fault: ObjectStoreFault::Throttled,
                },
                ScheduledHazard::Packet {
                    at: OpIndex::from_raw(5),
                    fault: PacketFault::Duplicate,
                },
            ],
        );
        let positions: Vec<u64> = script.hazards().iter().map(|h| h.at().raw()).collect();
        assert_eq!(positions, vec![2, 5, 9]);

        // Construction order does not change the script.
        let reordered = HazardScript::explicit(
            FaultPlan::none(),
            vec![
                ScheduledHazard::Packet {
                    at: OpIndex::from_raw(5),
                    fault: PacketFault::Duplicate,
                },
                ScheduledHazard::Packet {
                    at: OpIndex::from_raw(9),
                    fault: PacketFault::Drop,
                },
                ScheduledHazard::ObjectStore {
                    at: OpIndex::from_raw(2),
                    fault: ObjectStoreFault::Throttled,
                },
            ],
        );
        assert_eq!(script.canonical_line(), reordered.canonical_line());
    }

    #[test]
    fn hazards_can_be_selected_by_operation_index() {
        let script = HazardScript::explicit(
            FaultPlan::none(),
            vec![
                ScheduledHazard::Packet {
                    at: OpIndex::from_raw(4),
                    fault: PacketFault::Drop,
                },
                ScheduledHazard::ObjectStore {
                    at: OpIndex::from_raw(4),
                    fault: ObjectStoreFault::WriteAmbiguous,
                },
                ScheduledHazard::Packet {
                    at: OpIndex::from_raw(7),
                    fault: PacketFault::Duplicate,
                },
            ],
        );
        // Faults compose: two classes can fire at the same operation.
        assert_eq!(script.at(OpIndex::from_raw(4)).len(), 2);
        assert_eq!(script.at(OpIndex::from_raw(7)).len(), 1);
        assert!(script.at(OpIndex::from_raw(5)).is_empty());
    }

    #[test]
    fn storage_faults_are_delegated_not_reimplemented() {
        // The lab composes fgit-authority's plan rather than modelling storage
        // faults itself; two models over one store would drift.
        let script = HazardScript::seeded(77, 20, 4, 2);
        assert_eq!(script.storage().seed(), Some(77));
        assert!(!script.storage().is_empty());
        assert!(script.canonical_line().contains("|storage="));
    }

    #[test]
    fn adding_hazards_does_not_perturb_the_storage_plan() {
        // Hazards draw from a forked sub-stream, so the storage script for a
        // seed is stable however many hazards a campaign asks for.
        let few = HazardScript::seeded(5, 40, 3, 1);
        let many = HazardScript::seeded(5, 40, 3, 25);
        assert_eq!(few.storage(), many.storage());
        assert_ne!(few.hazards().len(), many.hazards().len());
    }

    #[test]
    fn packet_fault_classes_separate_intact_delivery_from_malformed() {
        assert!(PacketFault::Duplicate.delivers_intact_bytes());
        assert!(PacketFault::Reorder { by_frames: 2 }.delivers_intact_bytes());
        // These exercise parser bounds, not idempotency.
        assert!(!PacketFault::Drop.delivers_intact_bytes());
        assert!(!PacketFault::Truncate { after_bytes: 8 }.delivers_intact_bytes());
        assert!(!PacketFault::Corrupt { at_byte: 3 }.delivers_intact_bytes());
        assert!(!PacketFault::PrematureClose.delivers_intact_bytes());
    }

    #[test]
    fn only_throttling_is_retryable_and_only_a_lost_write_is_ambiguous() {
        assert!(ObjectStoreFault::Throttled.is_retryable());
        for fault in [
            ObjectStoreFault::WriteAmbiguous,
            ObjectStoreFault::ReadCorrupt { at_byte: 0 },
            ObjectStoreFault::ReadMissing,
            ObjectStoreFault::LimitExceeded,
            ObjectStoreFault::StaleGeneration { behind: 1 },
        ] {
            assert!(
                !fault.is_retryable(),
                "{} must not be retryable",
                fault.code()
            );
        }

        assert!(ObjectStoreFault::WriteAmbiguous.is_ambiguous());
        assert!(!ObjectStoreFault::Throttled.is_ambiguous());
        assert!(!ObjectStoreFault::ReadMissing.is_ambiguous());
    }

    #[test]
    fn fault_codes_are_unique_within_each_class() {
        let packet = [
            PacketFault::Truncate { after_bytes: 0 }.code(),
            PacketFault::Duplicate.code(),
            PacketFault::Drop.code(),
            PacketFault::Reorder { by_frames: 0 }.code(),
            PacketFault::Corrupt { at_byte: 0 }.code(),
            PacketFault::PrematureClose.code(),
        ];
        let mut sorted = packet.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), packet.len());

        let object = [
            ObjectStoreFault::WriteAmbiguous.code(),
            ObjectStoreFault::ReadCorrupt { at_byte: 0 }.code(),
            ObjectStoreFault::ReadMissing.code(),
            ObjectStoreFault::LimitExceeded.code(),
            ObjectStoreFault::Throttled.code(),
            ObjectStoreFault::StaleGeneration { behind: 0 }.code(),
        ];
        let mut sorted = object.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), object.len());
    }

    #[test]
    fn execution_faults_map_to_the_right_outcome_arm() {
        // Budget exhaustion and cancellation are both cancellation; a
        // contained panic is its own arm. Neither may become a domain error.
        for dimension in [
            Exhaustion::Deadline,
            Exhaustion::PollQuota,
            Exhaustion::CostQuota,
        ] {
            let fault = ExecutionFault::BudgetExhausted { dimension };
            assert_eq!(fault.expected_outcome(), "cancelled");
            assert_ne!(fault.expected_outcome(), "refusal");
        }
        for phase in CancelPhase::sequence() {
            assert_eq!(
                ExecutionFault::Cancelled { phase }.expected_outcome(),
                "cancelled"
            );
        }
        assert_eq!(
            ExecutionFault::PanicContained.expected_outcome(),
            "panicked"
        );
        assert_ne!(
            ExecutionFault::PanicContained.expected_outcome(),
            ExecutionFault::Cancelled {
                phase: CancelPhase::Drain
            }
            .expected_outcome()
        );
    }

    #[test]
    fn only_finalize_cancellation_can_strand_an_obligation() {
        assert!(CancelPhase::Finalize.can_strand_an_obligation());
        // Paired permitted cases: the earlier phases cannot.
        assert!(!CancelPhase::Request.can_strand_an_obligation());
        assert!(!CancelPhase::Drain.can_strand_an_obligation());
    }

    #[test]
    fn all_six_fault_classes_compose_at_one_operation_index() {
        // The acceptance line: storage, packet, budget, cancellation, panic,
        // and obligation faults compose. Storage is the FaultPlan; obligation
        // is the oracle; the other four are scheduled hazards, and they can
        // all land on the same operation.
        let at = OpIndex::from_raw(3);
        let script = HazardScript::explicit(
            FaultPlan::seeded(1, 8, 2),
            vec![
                ScheduledHazard::Packet {
                    at,
                    fault: PacketFault::Truncate { after_bytes: 12 },
                },
                ScheduledHazard::ObjectStore {
                    at,
                    fault: ObjectStoreFault::WriteAmbiguous,
                },
                ScheduledHazard::Execution {
                    at,
                    fault: ExecutionFault::BudgetExhausted {
                        dimension: Exhaustion::Deadline,
                    },
                },
                ScheduledHazard::Execution {
                    at,
                    fault: ExecutionFault::Cancelled {
                        phase: CancelPhase::Finalize,
                    },
                },
                ScheduledHazard::Execution {
                    at,
                    fault: ExecutionFault::PanicContained,
                },
            ],
        );

        assert_eq!(script.at(at).len(), 5);
        assert!(!script.storage().is_empty());

        let line = script.canonical_line();
        for expected in [
            "packet.truncate:12@3",
            "object.write_ambiguous@3",
            "exec.budget_exhausted:deadline@3",
            "exec.cancelled:finalize@3",
            "exec.panic_contained@3",
        ] {
            assert!(line.contains(expected), "missing {expected} in {line}");
        }
    }

    #[test]
    fn execution_fault_codes_are_unique() {
        let codes = [
            ExecutionFault::BudgetExhausted {
                dimension: Exhaustion::Deadline,
            }
            .code(),
            ExecutionFault::Cancelled {
                phase: CancelPhase::Request,
            }
            .code(),
            ExecutionFault::PanicContained.code(),
        ];
        let mut sorted = codes.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len());
    }

    #[test]
    fn canonical_renderings_carry_the_parameters() {
        assert_eq!(
            PacketFault::Truncate { after_bytes: 96 }.canonical(),
            "packet.truncate:96"
        );
        assert_eq!(
            ObjectStoreFault::StaleGeneration { behind: 3 }.canonical(),
            "object.stale_generation:3"
        );
        assert_eq!(
            ScheduledHazard::Packet {
                at: OpIndex::from_raw(12),
                fault: PacketFault::Drop
            }
            .canonical(),
            "packet.drop@12"
        );
    }
}
