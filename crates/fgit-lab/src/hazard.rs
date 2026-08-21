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
}

impl ScheduledHazard {
    /// The operation index at which this fires.
    #[must_use]
    pub const fn at(self) -> OpIndex {
        match self {
            Self::Packet { at, .. } | Self::ObjectStore { at, .. } => at,
        }
    }

    /// A canonical rendering for the trace.
    #[must_use]
    pub fn canonical(self) -> String {
        match self {
            Self::Packet { at, fault } => format!("{}@{}", fault.canonical(), at.raw()),
            Self::ObjectStore { at, fault } => format!("{}@{}", fault.canonical(), at.raw()),
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
        let mut out = String::from("fgit-lab-hazards-v1");
        out.push_str(&format!(
            "|seed={}",
            self.seed
                .map_or_else(|| "none".to_owned(), |seed| seed.to_string())
        ));
        out.push_str(&format!("|storage={}", self.storage.directives().len()));
        out.push_str(&format!("|hazards={}", self.hazards.len()));
        for hazard in &self.hazards {
            out.push('|');
            out.push_str(&hazard.canonical());
        }
        out
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
            assert!(!fault.is_retryable(), "{} must not be retryable", fault.code());
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
