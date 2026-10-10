//! Standalone production-file ownership tests, independent of the CLI runtime.
//! Can also be run with rustc --edition=2024 --test on this file.
#![forbid(unsafe_code)]
#[path = "../src/bundle/verify/local_files.rs"]
mod local_files;
