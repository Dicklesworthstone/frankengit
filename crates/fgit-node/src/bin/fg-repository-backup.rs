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

// Recovery unit tests live in source_retrieval::backup in the owning library.
// repository_backup_command exercises this executable through real processes.
