#![forbid(unsafe_code)]
//! The CALM coordination vocabulary, as a type rather than a spelling.
//!
//! `registries/calm_operations.tsv` classifies every named operation into one
//! of seven coordination classes defined by
//! [`docs/CALM_AND_OBLIGATIONS.md`](../../../docs/CALM_AND_OBLIGATIONS.md)
//! section 1. Until this crate existed, that closed set had **no first-party
//! representation at all**: the registry column was a string, `tools/registry-check`
//! validated the column *names*, and nothing in the tree could branch on a
//! class. A vocabulary only a document knows is a design note; the point of
//! naming it here is that code can now depend on it.
//!
//! # What this crate does and does not decide
//!
//! It supplies the vocabulary and the class semantics each row claims. It does
//! **not** route operations: no caller today can choose between a coordinated
//! and a coordination-free implementation of the same operation, so a class
//! consulted at a decision point would carry one constant value rather than a
//! branch. That deferral is recorded on `frankengit-fg012-obligations-yo3`
//! acceptance 5b, and this crate is what makes it discharge-able later without
//! inventing a vocabulary at that moment.
//!
//! # The two things worth testing today
//!
//! - **Class semantics.** Each class asserts a property its operations must
//!   have -- monotone union cannot invalidate an earlier result, coordinated
//!   operations must fail when their coordination is removed, and so on. A row
//!   whose class is wrong is a registry defect that ships silently unless the
//!   property is executable. See [`class`].
//! - **The conflict-absorbing lattice.** A non-canonical replica observing one
//!   transaction must never let ordering erase a contradiction: joining
//!   `Committed` and `Refused` yields a sticky `Conflict`, whatever order the
//!   observations arrive in. See [`lattice`].

pub mod class;
pub mod lattice;

pub use class::{ConformanceDirection, CoordinationClass};
pub use lattice::Observation;
