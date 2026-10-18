#![forbid(unsafe_code)]
//! Compile the actual production filesystem module without a Git/runtime mock.
//! This is also directly runnable with pinned rustc --edition=2024 --test.
#[path = "../src/bundle/recover/filesystem.rs"]
mod filesystem;
