#![forbid(unsafe_code)]
//! The repository-owned schema generator.
//!
//! Two modes, and the separation is the point:
//!
//! ```text
//! fgit-schema-gen generate [dir]   write the artifacts
//! fgit-schema-gen check    [dir]   refuse if the committed artifacts are stale
//! ```
//!
//! `check` never writes. A gate that repairs what it finds cannot fail, so the
//! fast lane runs `check` and a human runs `generate`. `dir` defaults to
//! `crates/fgit-schema/generated` resolved from the crate root, so the command
//! works from anywhere in the tree without arguments.
//!
//! Exit codes are part of the contract: `0` clean, `1` stale or missing, `2`
//! usage. A lane distinguishes "the artifacts drifted" from "the command was
//! called wrongly" without parsing text.

use std::path::PathBuf;
use std::process::ExitCode;

use fgit_schema::gate;
use fgit_schema::registry;

/// Where the artifacts live when no directory is given.
fn default_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(fgit_schema::GENERATED_DIR)
}

fn usage() -> ExitCode {
    eprintln!("usage: fgit-schema-gen <generate|check> [directory]");
    eprintln!();
    eprintln!("  generate   write the schema artifacts, creating the directory if needed");
    eprintln!("  check      refuse if any committed artifact differs from the descriptors");
    eprintln!();
    eprintln!("exit 0 clean, 1 stale or missing, 2 usage");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    let Some(mode) = arguments.next() else {
        return usage();
    };
    let directory = arguments
        .next()
        .map_or_else(default_directory, PathBuf::from);
    if arguments.next().is_some() {
        return usage();
    }

    // A duplicate family would make descriptor resolution depend on slice
    // order, so it is refused before anything is written or compared rather
    // than producing an artifact that is merely arbitrary.
    if let Err(refusal) = registry::check_families_unique() {
        eprintln!("fgit-schema-gen: {refusal}");
        return ExitCode::from(1);
    }

    match mode.as_str() {
        "generate" => match gate::write(&directory) {
            Ok(count) => {
                println!(
                    "fgit-schema-gen: wrote {count} artifact(s) to {}",
                    directory.display()
                );
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!(
                    "fgit-schema-gen: could not write to {}: {error}",
                    directory.display()
                );
                ExitCode::from(1)
            }
        },
        "check" => match gate::check(&directory) {
            Ok(count) => {
                println!(
                    "fgit-schema-gen: {count} artifact(s) are byte-identical to the descriptors"
                );
                ExitCode::SUCCESS
            }
            Err(refusal) => {
                eprintln!("fgit-schema-gen: {refusal}");
                eprintln!(
                    "fgit-schema-gen: run `cargo run -p fgit-schema --bin fgit-schema-gen -- generate` and commit the result"
                );
                ExitCode::from(1)
            }
        },
        _ => usage(),
    }
}
