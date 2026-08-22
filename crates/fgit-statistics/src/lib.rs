#![forbid(unsafe_code)]
//! FG-054: the identity-bound statistical policy substrate of plan section 33.
//!
//! # What this crate is for
//!
//! Statistical adaptation without identity is how a system drifts into
//! unfalsifiable behaviour. Section 33 answers that with three obligations, and
//! this crate exists to make them mechanical rather than aspirational:
//!
//! * every evidence stream **binds** its identity — metric and units, source,
//!   population and selection policy, exact window and filtration, calibration
//!   profile, regime epoch and detector profile, candidate and fallback policy
//!   ids, arithmetic fingerprint, assumptions, and retained-observation bound;
//! * adaptive choices **publish** through stream-sequenced policy epochs;
//! * any evidence gap, support failure, regime alarm, numeric-bound violation or
//!   stale window **selects the pinned deterministic fallback**.
//!
//! # The arithmetic is integer, and that is not a style choice
//!
//! [`fgit_types::CanonicalScalar`] is sealed to the eight fixed-width integers.
//! `f32`, `f64`, `usize` and `isize` are all excluded, so a canonical body can
//! never contain a value whose bytes depend on rounding mode, `NaN` payload,
//! signed zero, or host width. Section 33.1 also requires an arithmetic
//! fingerprint precisely so a stream's numbers replay exactly.
//!
//! Section 33's mechanisms — CUSUM and Page-Hinkley statistics, conformal
//! quantiles, e-process wealth, Beta-Bernoulli posteriors, effective sample
//! size, Lyapunov drift — are conventionally floating point end to end. Here
//! they are **integer or fixed-point throughout**, not float-internally and
//! quantised at the boundary: a detector whose alarm depends on `f64`
//! accumulation is irreproducible across targets even when its published output
//! is an integer.
//!
//! # What this crate deliberately does not own
//!
//! Five things a statistics crate would naturally define for itself already have
//! an authoritative home, and duplicating any of them would create a second
//! source of truth for one identity:
//!
//! | concept | owner |
//! |---|---|
//! | policy epoch counter | [`fgit_types`] |
//! | coordination class vocabulary | `fgit-calm` |
//! | evidence record and its context | `fgit-evidence` |
//! | fixed-point probability | `fgit-witness` |
//! | canonical framing and digest preimage | `fgit-codec` |
//!
//! So the typed statistical body this crate will publish is bound into the
//! existing immutable evidence record **by digest**, as an artifact commitment:
//! `fgit-evidence` stays the identity and replay boundary, `fgit-codec` stays
//! the framing authority, and this crate contributes only the computable payload
//! that nobody else owns.
//!
//! # Status
//!
//! Implemented: the regime detector in [`regime`], with its assumptions
//! executable rather than documented; the fail-closed selection rule in
//! [`fallback`]; the typed evidence body in [`evidence`], which carries all
//! seven of `AGENTS.md` section 8's bindings as types and has canonical bytes;
//! and section 33.4's forbidden-decision boundary in [`authority`], where the
//! primary enforcement is that the permitted-decision enum has no variant for
//! identity, authorization, retention, deletion or ordering.
//!
//! The evidence body has **no digest identity yet**. Computing one requires
//! `frankengit/statistical-evidence/v1` to be registered in `fgit-crypto`'s
//! `DOMAIN_REGISTRY`, which is another crate's frozen surface and is routed to
//! its owner by mail under section 16.1. The canonical bytes do not depend on
//! that, so they are complete; the artifact commitment is what waits.
//!
//! The remaining mechanisms of the section 33 library — conformal bounds,
//! e-processes, bandit arm selection, off-policy evaluation with support and
//! effective-sample-size gates, Beta-Bernoulli expected loss, and Lyapunov
//! governors — are **not** implemented here yet, and this crate does not claim
//! them.

pub mod authority;
pub mod controller;
pub mod evidence;
pub mod fallback;
pub mod regime;

pub use authority::{
    AdmissibleShape, AdvisoryDecision, DecisionRefusal, EffectClass, ForbiddenTarget,
    ProposedTarget,
};
pub use controller::{ControllerConfig, ControllerRefusal, ControllerStep, RetryBackoffController};
pub use evidence::{
    AssumptionSet, BindingRefusal, RegimeBinding, SequenceWindow, StatisticalEvidenceBody,
};
pub use fallback::{FallbackTrigger, PolicyGate, PolicySelection};
pub use regime::{AssumptionFailure, Cusum, CusumConfig, Scaled, Shift};
