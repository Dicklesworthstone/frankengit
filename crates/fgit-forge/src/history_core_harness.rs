#![forbid(unsafe_code)]
//! Isolated native-history core tests, using actual production source modules.
//!
//! This intentionally excludes the node, transports and authority adapters;
//! passing it is not node integration evidence. No production APIs or owning
//! crates are mocked. The source fixtures inside each module remain its normal
//! unit tests. Keeping this harness beside history.rs lets ordinary module
//! resolution find that production module's children without rewriting them.
//!
//! Set CARGO_TARGET_DIR to a private build directory, then run from the checkout:
//!
//! ```text
//! python3 scripts/test_history_core.py
//! ```
//!
//! Alternatively pass --target-dir to select that private directory explicitly.
//! The runner builds the real types, crypto and diff libraries locked/offline
//! with one job. Cargo's JSON receipts supply both .rlib and .rmeta externs and
//! every transitive artifact directory, including nonstandard build layouts.
//! It compiles this harness and executes its tests with one test thread.

#[path = "preparation/source.rs"]
pub mod preparation;
pub mod history;
