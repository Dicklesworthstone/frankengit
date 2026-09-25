#![forbid(unsafe_code)]
//! Compatibility executable; the shared node adapter also serves `fg backup`.
use fgit_node::source_retrieval::backup;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match backup::run(&args, &mut std::io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", backup::error_json(&error));
            ExitCode::from(2)
        }
    }
}

// Preserve the original focused binary test target and repository:: test names.
// Production calls the library above; tests compile the SAME host and repository
// sources, not a second implementation or an independent verification oracle.
#[cfg(test)]
pub use fgit_node::{LoopbackReceiveSession, NodeConfig, NodeRequestContext, OneNode};
#[cfg(test)]
#[path = "../source_retrieval/backup/repository/mod.rs"]
mod repository;
#[cfg(test)]
include!("../source_retrieval/backup/host.rs");
