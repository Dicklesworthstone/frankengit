#![forbid(unsafe_code)]
//! Trusted-local source recovery shared by `fg backup` and its legacy executable.
//! These top-level host operations own and drain their runtimes; they are not
//! request handlers and never shell out to a helper executable or Git engine.
#[path = "backup/repository/mod.rs"]
mod repository;

include!("backup/host.rs");
