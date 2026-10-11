//! Real Unix file ownership/publication tests, independent of the node runtime.
//! Also runnable with rustc --edition=2024 --test on this file.
#![forbid(unsafe_code)]
#[path = "../src/bundle/stream_export/local_file.rs"]
mod local_file;
