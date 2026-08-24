#![forbid(unsafe_code)]

//! Generate or check the FG-041 Lean test vectors.
//!
//! ```text
//! fgit-proof-bridge-gen generate [goldens-dir] [out-dir]
//! fgit-proof-bridge-gen check    [goldens-dir] [out-dir]
//! ```
//!
//! Exit 0 clean, 1 stale or missing, 2 usage. The same three codes
//! `fgit-schema-gen` uses, because a second vocabulary for the same idea is a
//! second thing to remember.

use std::path::PathBuf;
use std::process::ExitCode;

const DEFAULT_GOLDENS: &str = "crates/fgit-reference/tests/goldens";
const DEFAULT_OUT: &str = "proofs/fg041/generated";

fn usage() -> ExitCode {
    eprintln!("usage: fgit-proof-bridge-gen <generate|check> [goldens-dir] [out-dir]");
    eprintln!("  goldens-dir defaults to {DEFAULT_GOLDENS}");
    eprintln!("  out-dir     defaults to {DEFAULT_OUT}");
    eprintln!("exit 0 clean, 1 stale or missing, 2 usage");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        return usage();
    };
    let goldens = PathBuf::from(args.next().unwrap_or_else(|| DEFAULT_GOLDENS.to_owned()));
    let out = PathBuf::from(args.next().unwrap_or_else(|| DEFAULT_OUT.to_owned()));
    if args.next().is_some() {
        return usage();
    }

    let projected = match fgit_proof_bridge::project_corpus(&goldens) {
        Ok(projected) => projected,
        Err(refusal) => {
            eprintln!("fgit-proof-bridge-gen: cannot project the corpus: {refusal:?}");
            return ExitCode::from(1);
        }
    };
    if projected.is_empty() {
        // An empty corpus renders a syntactically valid file that asserts
        // nothing, and a gate over it would pass forever. Refusing is the only
        // reading that cannot become a false green.
        eprintln!(
            "fgit-proof-bridge-gen: no .fgtrace goldens under {}",
            goldens.display()
        );
        return ExitCode::from(1);
    }
    let rendered = fgit_proof_bridge::render(&projected);

    match command.as_str() {
        "generate" => match fgit_proof_bridge::write(&out, &rendered) {
            Ok(bytes) => {
                println!(
                    "fgit-proof-bridge-gen: wrote {}/{} ({bytes} bytes, {} traces)",
                    out.display(),
                    fgit_proof_bridge::ARTIFACT,
                    projected.len()
                );
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("fgit-proof-bridge-gen: cannot write: {error}");
                ExitCode::from(1)
            }
        },
        "check" => match fgit_proof_bridge::check(&out, &rendered) {
            Ok(bytes) => {
                println!(
                    "fgit-proof-bridge-gen: {}/{} is current ({bytes} bytes, {} traces)",
                    out.display(),
                    fgit_proof_bridge::ARTIFACT,
                    projected.len()
                );
                ExitCode::SUCCESS
            }
            Err(refusal) => {
                eprintln!("fgit-proof-bridge-gen: {refusal:?}");
                ExitCode::from(1)
            }
        },
        _ => usage(),
    }
}
