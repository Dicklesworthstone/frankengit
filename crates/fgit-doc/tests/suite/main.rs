//! The `fgit-doc` integration suite.
//!
//! Every group is a module of one binary rather than a binary of its own, so
//! the shared corpus and invariant helpers are genuinely used by the crate
//! that compiles them and need no dead-code exemption.

mod common;

mod adversarial;
mod anchors;
mod batch;
mod determinism;
mod render;
mod spans;
