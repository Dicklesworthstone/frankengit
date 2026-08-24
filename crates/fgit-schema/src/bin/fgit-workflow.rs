#![forbid(unsafe_code)]
//! The repository-owned workflow lowering command.
//!
//! ```text
//! fgit-workflow lower <file>            print the canonical graph
//! fgit-workflow check <file> <golden>   refuse if the graph differs
//! ```
//!
//! Exit codes are the contract: `0` clean, `1` refused or stale, `2` usage.
//! A lane distinguishes "the workflow is not in the subset" from "you called
//! the command wrongly" without parsing text.
//!
//! # Why this exists as a command
//!
//! AGENTS.md §12: workflow YAML may not contain correctness logic unavailable
//! through a repository-owned command. This is that command — the lowering a
//! CI adapter would perform is reproducible here, by hand, with no runner.

use std::path::PathBuf;
use std::process::ExitCode;

use fgit_schema::workflow::{Limits, compile};

fn usage() -> ExitCode {
    eprintln!("usage: fgit-workflow <lower|check> <file> [golden]");
    eprintln!();
    eprintln!("  lower <file>            print the canonical workflow graph");
    eprintln!("  check <file> <golden>   refuse if the graph differs from the golden");
    eprintln!();
    eprintln!("exit 0 clean, 1 refused or stale, 2 usage");
    ExitCode::from(2)
}

fn read(path: &PathBuf) -> Result<String, ExitCode> {
    std::fs::read_to_string(path).map_err(|error| {
        eprintln!("fgit-workflow: cannot read {}: {error}", path.display());
        ExitCode::from(1)
    })
}

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    let (Some(mode), Some(source_path)) = (arguments.next(), arguments.next()) else {
        return usage();
    };
    let golden_path = arguments.next();
    if arguments.next().is_some() {
        return usage();
    }
    let source_path = PathBuf::from(source_path);
    let source = match read(&source_path) {
        Ok(text) => text,
        Err(code) => return code,
    };

    // The refusal is the product here as much as the graph is: a workflow
    // outside the subset must say which construct and where, not merely fail.
    let graph = match compile(&source, &Limits::DEFAULT) {
        Ok(graph) => graph,
        Err(refusal) => {
            eprintln!("{}: {refusal}", source_path.display());
            eprintln!("fgit-workflow: refused ({})", refusal.kind());
            return ExitCode::from(1);
        }
    };

    match mode.as_str() {
        "lower" => {
            print!("{}", graph.canonical_bytes());
            ExitCode::SUCCESS
        }
        "check" => {
            let Some(golden_path) = golden_path else {
                return usage();
            };
            let golden_path = PathBuf::from(golden_path);
            let golden = match read(&golden_path) {
                Ok(text) => text,
                Err(code) => return code,
            };
            let produced = graph.canonical_bytes();
            if let Some(offset) = fgit_schema::gate::first_difference(&golden, &produced) {
                eprintln!(
                    "fgit-workflow: {} is stale: differs from the lowering at byte {offset}",
                    golden_path.display()
                );
                eprintln!(
                    "fgit-workflow: run `fgit-workflow lower {}` and commit the result",
                    source_path.display()
                );
                return ExitCode::from(1);
            }
            println!(
                "fgit-workflow: {} matches the lowering of {}",
                golden_path.display(),
                source_path.display()
            );
            ExitCode::SUCCESS
        }
        _ => usage(),
    }
}
