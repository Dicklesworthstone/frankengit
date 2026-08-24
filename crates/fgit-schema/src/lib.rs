#![forbid(unsafe_code)]
//! Schema descriptions of the canonical bodies, and a repository-owned
//! generator for the client artifacts derived from them.
//!
//! # What this crate is
//!
//! `fgit-codec` owns the canonical bodies and their encoding. This crate
//! **describes** four of them in a small, flat, non-recursive format
//! ([`descriptor`]), keeps those descriptions honest against the real Rust
//! types (`tests/conformance.rs`), and generates the artifacts a non-Rust
//! client needs: JSON Schema, `TypeScript`, and Python ([`emit`]).
//!
//! # What this crate deliberately does NOT do
//!
//! **It does not generate Rust types or codecs.** `fgit-codec` owns those, and
//! emitting a second copy would fork the one authoritative definition —
//! forbidden by AGENTS.md §4 (no fake final abstraction) and §10 (normative
//! schemas live in exactly one place). Generating them and then
//! hand-maintaining the originals is precisely the drift a staleness gate
//! exists to prevent, one level up. What replaces the duplication is stronger
//! than it would have been: a conformance test proving each descriptor agrees
//! with the body it claims to describe, so drift is a red test rather than a
//! second source of truth.
//!
//! **It does not generate an `OpenAPI` paths document.** That describes a served
//! surface `fg048b` owns and that the 2026-08-24 ruling removed from this
//! bead's scope. The payload half — JSON Schema — is generated here and is what
//! an `OpenAPI` document would reference.
//!
//! **It does not describe `decision-batch`.** That body carries sequences of
//! nested structures and a payload-carrying tagged union; the format is
//! non-recursive by design. [`registry::descriptor_for`] refuses it by name
//! with the exact missing construct, so the gap is actionable rather than
//! invisible.
//!
//! # No proc macro, no build script
//!
//! The generator is a **binary** — `fgit-schema-gen` — invoked as a
//! repository-owned command. There is no `build.rs` and no derive macro, per
//! the ruling and AGENTS.md §3.3. Generation happens when a human or a lane
//! runs the command; the fast lane runs it in `check` mode only, so a verify
//! run never writes to the tree.
//!
//! # Determinism
//!
//! Every emitter is a pure function of [`registry::DESCRIBED`]. No clock, no
//! environment, no filesystem read, no hash map. That is what makes
//! [`gate::check`] meaningful: a difference can only come from a descriptor
//! change, never from the machine that ran it.

pub mod descriptor;
pub mod emit;
pub mod error;
pub mod gate;
pub mod registry;

pub use descriptor::{Cardinality, FieldDescriptor, FieldType, ScalarWidth, SchemaDescriptor};
pub use error::SchemaRefusal;
pub use registry::{DESCRIBED, descriptor_for};

/// Directory, relative to the crate root, holding the committed artifacts.
pub const GENERATED_DIR: &str = "generated";
