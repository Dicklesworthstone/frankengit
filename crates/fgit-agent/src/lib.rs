#![forbid(unsafe_code)]
//! Agent intent runs, attenuated capabilities, and the effect broker.
//!
//! This crate implements the slice of `docs/AGENT_PROTOCOL.md` that FG-030a
//! names: the capability model of §6 with attenuation-only delegation, the
//! Intent Run of §5 as the machine-enforced scope, and the effect broker of §9
//! that authorizes every consequential operation before it happens.
//!
//! # The one property everything here exists to hold
//!
//! Authority only ever narrows. A run cannot exceed its sponsor's grant, a
//! delegated capability cannot exceed its parent, and an effect cannot exceed
//! either the run or the capability presented for it. §6.2 states the rule for
//! delegation and §5.1 for the objective text; this crate makes both checkable
//! rather than aspirational.
//!
//! [`capability`] discharges that in two places, because it fails in two
//! places: widening is *unrepresentable* through the API, and *refused* by the
//! verifier when it arrives as bytes. Neither substitutes for the other, and
//! the module documents why.
//!
//! # What is deliberately not here
//!
//! The Context Packet (§7), the `TreeFS` workspace (§8), Evidence-Carrying
//! Change (§10), verification and review (§11), the refresh relations of §4.3,
//! and revocation interpreted at a canonical position (§6.3) are all outside
//! this slice. They are named here so their absence reads as scope rather than
//! as coverage: §6.3 in particular is a real property this crate does *not*
//! deliver — [`Capability::is_valid_at`] checks a window, which is freshness,
//! not revocation.
//!
//! The obligation lifecycle is not reimplemented either. `fgit-resource` owns
//! it, and [`broker`] explains exactly which half of an effect's reservation
//! this crate holds and which half belongs to the component that performs it.

pub mod broker;
pub mod capability;
pub mod classes;
pub mod intent;

pub use broker::{BrokerRefusal, EffectBroker, EffectGrant, EffectId, EffectRecord, EffectRequest};
pub use capability::{
    AttenuationRefused, AttenuationRequest, Capability, CapabilityId, ChainRefused, IssueRefused,
    LogicalTime, SealRefused, SealedCapability, verify_chain,
};
pub use classes::{CLASS_COUNT, ClassSet, OperationClass, UnknownClassBits};
pub use intent::{AuthorityBasisRef, IntentRun, RunId, RunRefused};
