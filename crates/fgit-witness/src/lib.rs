#![forbid(unsafe_code)]
//! Conflict witnesses, overlap sketches, value-of-information refinement, and
//! the semantic rebase ladder.
//!
//! `docs/NORMATIVE_PROTOCOL_CONTRACTS.md` §12 and plan §15.5, §15.6, §16.4 and
//! §16.5 describe how a transaction that loses a head compare-and-exchange
//! decides whether it can be salvaged, and at what cost. This crate is that
//! machinery. It computes no digests, performs no I/O, and reads no clock: a
//! decision is a pure function of its declared inputs, and every decision comes
//! with a receipt naming them.
//!
//! ## The one safety property everything else serves
//!
//! §12's first obligation is that refinement "can only reduce a conservative
//! false-conflict set". Concretely: **overlap under a fine witness implies
//! overlap under every coarser one**, so refining can remove a conflict that
//! was never real but can never clear one that is. [`footprint::Footprint`]
//! carries the lattice, [`footprint::Footprint::subsumes`] is the order, and
//! the law is property-tested rather than asserted.
//!
//! ## What each module owns
//!
//! * [`footprint`] — the closed witness family vocabulary and the subsumption
//!   lattice over it.
//! * [`sketch`] — lossy overlap estimates that are **structurally incapable of
//!   proving absence**. A sealed trait keeps sketches away from the
//!   disjointness constructor, with a `compile_fail` doctest demonstrating it.
//! * [`voi`] — the bounded, deterministic value-of-information policy, whose
//!   default on any doubt is to retain the coarse conflict.
//! * [`ladder`] — the six rungs of §16.4. Rung 1 hands back a shared borrow of
//!   the capsule, so "reuses the capsule unchanged" is a property of the
//!   signature.
//! * [`retry`] — expected-loss backoff with a Beta-Bernoulli posterior, regime
//!   reset, and a starvation escalator the posterior cannot veto.
//!
//! ## Non-claims
//!
//! * **Nothing here authorizes anything.** §26 forbids a statistical artifact
//!   from deciding canonical questions, and §8 allows a model to "recommend or
//!   prioritize" but never to grant access or move refs. Sketches and
//!   posteriors here choose *which work to attempt and in what order*. The
//!   conflict decision itself always comes from exact comparison.
//! * **A sketch's silence is not disjointness.**
//!   [`sketch::OverlapEstimate::may_overlap`] returning `false` means this
//!   sketch found no evidence, which is absence of evidence.
//!   [`sketch::prove_disjoint`] is the only thing that decides, and it accepts
//!   only exact footprints.
//! * **Bounded, not proven.** The tests are property and unit tests over the
//!   lattice and the policies. They are `bounded_model` evidence about this
//!   crate; they say nothing about any integration until a caller is wired to
//!   it.
//! * **No floating point anywhere.** Probabilities and costs are fixed-point
//!   integers, because a float cannot be canonically encoded and a receipt has
//!   to reproduce exactly on every target.

pub mod footprint;
pub mod ladder;
pub mod retry;
pub mod sketch;
pub mod voi;

pub use footprint::{Footprint, Scope};
pub use ladder::{
    Climb, ClimbFailure, ConflictCertificate, Observations, Reused, Revalidation, Rung, climb,
    exact_revalidation,
};
pub use retry::{Action, Attempt, EscalationTrigger, Posterior, PriorityClass};
pub use sketch::{
    DisjointnessProof, OverlapEstimate, OverlapSketch, Probability, ProvesAbsence, prove_disjoint,
};
pub use voi::{Cost, Decision, Inputs, RetainReason};
