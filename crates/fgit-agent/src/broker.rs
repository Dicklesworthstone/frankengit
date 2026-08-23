//! The effect broker (`docs/AGENT_PROTOCOL.md` §9).
//!
//! Every consequential operation is authorized here before it happens, and
//! every acceptance reserves real, conserved budget from the run's region.
//!
//! # What this broker reserves, and what it deliberately does not
//!
//! §9 says every consequential operation *"uses an Asupersync-owned obligation
//! and produces a ledger record"*, and that the states follow the normative
//! lifecycle exactly. `fgit-resource` already owns that lifecycle and the
//! eleven concrete obligation classes, so this crate does not re-implement any
//! of it.
//!
//! It also does not *fabricate* it. The eleven kinds are specific — an
//! `ObjectAdmissionPermit` reserves against a real native oid and verified
//! length, a `SecretLease` against a real secret — and their reservation data
//! belongs to the component that actually performs the effect. A broker that
//! invented an oid so it could open an admission obligation would be filing a
//! fixture as production evidence.
//!
//! So the split is by who holds the facts. The broker reserves the **budget**,
//! which it does hold, through the run's [`ObligationLedger`]: a real
//! [`BudgetGrant`] that conserves, refuses on deficit, and must be released or
//! converted. The performer converts that grant into the typed obligation its
//! own class requires, with its own data. [`EffectGrant`] is that handoff, and
//! it is the typed boundary between the two.
//!
//! # Order of checks
//!
//! Authorization is decided before any budget moves. A refusal therefore never
//! consumes budget and never appends a record, which is what makes the
//! exhaustion stop in §9 clean rather than partial.

use core::fmt;

use fgit_resource::{
    BudgetGrant, LeakDisposition, ObligationLedger, RegionCloseOutcome, RegionId, ResourceVector,
    algebra::ResourceError,
};

use crate::capability::{Capability, CapabilityId, LogicalTime};
use crate::classes::{ClassSet, OperationClass};
use crate::intent::{IntentRun, RunId};

/// Opaque effect identity (`AGENT_PROTOCOL.md` §9, `effect_id`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct EffectId(u128);

impl EffectId {
    /// Builds an effect identity.
    #[must_use]
    pub const fn new(value: u128) -> Self {
        Self(value)
    }

    /// The raw value.
    #[must_use]
    pub const fn value(self) -> u128 {
        self.0
    }
}

impl fmt::Display for EffectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "effect:{:032x}", self.0)
    }
}

/// A request to perform one consequential operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectRequest {
    /// Stable identity, so an at-least-once retry is the same effect (§9).
    pub effect_id: EffectId,
    /// Which class of operation this is.
    pub operation: OperationClass,
    /// What performing it will cost.
    pub cost: ResourceVector,
    /// Commitment to the canonical input, so the record names what was asked.
    pub input_commitment: [u8; 32],
}

/// An accepted effect: its record, and the budget reserved for it.
///
/// The [`BudgetGrant`] is the live reservation. Dropping it without releasing
/// or converting it is a leak the region reports at close, which is the point:
/// an accepted effect is a responsibility, not a return value.
#[derive(Debug)]
pub struct EffectGrant {
    record: EffectRecord,
    budget: BudgetGrant,
}

impl EffectGrant {
    /// The ledger record for this acceptance.
    #[must_use]
    pub const fn record(&self) -> &EffectRecord {
        &self.record
    }

    /// Takes the budget reservation, to convert into a typed obligation.
    ///
    /// `BudgetGrant` is itself `#[must_use]`, so the responsibility survives
    /// this handoff without restating it here.
    pub fn into_budget(self) -> BudgetGrant {
        self.budget
    }
}

/// What the broker recorded about one accepted effect (`§9 EffectRecord`).
///
/// This carries the fields the slice establishes. §9's `obligation_state`,
/// `terminal_outcome`, `output_commitments` and `reconciliation_evidence` are
/// written by the performer as the obligation moves, and are absent here rather
/// than defaulted, because a defaulted terminal outcome is the *"maybe it
/// happened"* §9 forbids.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectRecord {
    /// Stable effect identity.
    pub effect_id: EffectId,
    /// The run that authorized it.
    pub run_id: RunId,
    /// The capability presented.
    pub capability_id: CapabilityId,
    /// The operation class performed.
    pub operation: OperationClass,
    /// Commitment to the canonical input.
    pub input_commitment: [u8; 32],
    /// Budget reserved at acceptance.
    pub budget_reserved: ResourceVector,
    /// When the broker accepted it.
    pub accepted_at: LogicalTime,
}

/// Authorizes effects for one run and reserves their budget.
#[derive(Debug)]
pub struct EffectBroker {
    run: IntentRun,
    ledger: ObligationLedger,
    records: Vec<EffectRecord>,
}

impl EffectBroker {
    /// Opens a broker over `run`, with the run's budget as region capacity.
    #[must_use]
    pub fn open(run: IntentRun, region: RegionId) -> Self {
        let capacity = run.resource_budget();
        Self {
            run,
            ledger: ObligationLedger::root(region, LeakDisposition::RecordAndContinue, capacity),
            records: Vec::new(),
        }
    }

    /// The run this broker serves.
    #[must_use]
    pub const fn run(&self) -> &IntentRun {
        &self.run
    }

    /// Every effect accepted so far, in acceptance order.
    ///
    /// This is the evidence a refusal must leave intact.
    #[must_use]
    pub fn records(&self) -> &[EffectRecord] {
        &self.records
    }

    /// Authorizes one effect and reserves its budget.
    ///
    /// Checks run expiry, capability validity, class membership in both the run
    /// and the capability, the capability's own quota ceiling, and finally the
    /// run budget. Budget moves only after every authorization check passes.
    ///
    /// # Errors
    ///
    /// See [`BrokerRefusal`]. Every refusal leaves the record list and the
    /// remaining budget exactly as they were.
    pub fn request(
        &mut self,
        capability: &Capability,
        now: LogicalTime,
        request: &EffectRequest,
    ) -> Result<EffectGrant, BrokerRefusal> {
        if !self.run.is_open_at(now) {
            return Err(BrokerRefusal::RunExpired {
                now,
                expiry: self.run.expiry(),
            });
        }
        if !capability.is_valid_at(now) {
            return Err(BrokerRefusal::CapabilityNotValid {
                now,
                not_before: capability.not_before(),
                expires_at: capability.expires_at(),
            });
        }
        let allowed = self.run.allowed_operation_classes();
        if !allowed.contains(request.operation) {
            return Err(BrokerRefusal::OperationOutsideRun {
                requested: request.operation,
                allowed,
            });
        }
        let held = capability.operations();
        if !held.contains(request.operation) {
            return Err(BrokerRefusal::OperationOutsideCapability {
                requested: request.operation,
                held,
            });
        }
        if let Some(deficit) = capability.quota().first_deficit(&request.cost) {
            return Err(BrokerRefusal::CapabilityQuotaExceeded { deficit });
        }

        // Only now does anything move. `grant` is the conserving reservation:
        // it either takes the amount out of the region's pool or refuses with
        // the grade that fell short, so an exhausted run stops here with its
        // prior records and its remaining budget untouched.
        let budget = self
            .ledger
            .grant(request.cost)
            .map_err(|deficit| BrokerRefusal::BudgetExhausted { deficit })?;

        let record = EffectRecord {
            effect_id: request.effect_id,
            run_id: self.run.run_id(),
            capability_id: capability.id(),
            operation: request.operation,
            input_commitment: request.input_commitment,
            budget_reserved: request.cost,
            accepted_at: now,
        };
        self.records.push(record);
        Ok(EffectGrant { record, budget })
    }

    /// Closes the run's region, reporting quiescence or a containment failure.
    ///
    /// An [`EffectGrant`] whose budget was never released or converted is
    /// outstanding here, so a dropped acceptance surfaces as the containment
    /// failure it is rather than as silence.
    pub fn close(self) -> RegionCloseOutcome {
        self.ledger.close()
    }
}

/// Why the broker refused an effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerRefusal {
    /// The run's expiry has passed.
    RunExpired {
        /// The instant checked.
        now: LogicalTime,
        /// The run's expiry.
        expiry: LogicalTime,
    },
    /// The capability is not valid at this instant.
    CapabilityNotValid {
        /// The instant checked.
        now: LogicalTime,
        /// Start of the capability's window.
        not_before: LogicalTime,
        /// End of the capability's window.
        expires_at: LogicalTime,
    },
    /// The run does not allow this operation class at all.
    OperationOutsideRun {
        /// What was asked for.
        requested: OperationClass,
        /// What the run allows.
        allowed: ClassSet,
    },
    /// The run allows the class but the presented capability does not hold it.
    OperationOutsideCapability {
        /// What was asked for.
        requested: OperationClass,
        /// What the capability holds.
        held: ClassSet,
    },
    /// The effect costs more than the capability's own quota ceiling.
    CapabilityQuotaExceeded {
        /// The algebra's deficit, naming the grade and both amounts.
        deficit: ResourceError,
    },
    /// The run's remaining budget cannot cover the effect.
    BudgetExhausted {
        /// The algebra's deficit, naming the grade and both amounts.
        deficit: ResourceError,
    },
}

impl fmt::Display for BrokerRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RunExpired { now, expiry } => {
                write!(
                    formatter,
                    "intent run expired at {expiry}; effect requested at {now}"
                )
            }
            Self::CapabilityNotValid {
                now,
                not_before,
                expires_at,
            } => write!(
                formatter,
                "capability is valid over {not_before}..{expires_at}; effect requested at {now}"
            ),
            Self::OperationOutsideRun { requested, allowed } => write!(
                formatter,
                "the run does not allow {requested}; it allows {allowed}"
            ),
            Self::OperationOutsideCapability { requested, held } => write!(
                formatter,
                "the capability does not hold {requested}; it holds {held}"
            ),
            Self::CapabilityQuotaExceeded { deficit } => {
                write!(formatter, "effect exceeds the capability quota: {deficit}")
            }
            Self::BudgetExhausted { deficit } => {
                write!(
                    formatter,
                    "the run's budget cannot cover this effect: {deficit}"
                )
            }
        }
    }
}

impl core::error::Error for BrokerRefusal {}
