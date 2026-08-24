#![forbid(unsafe_code)]

//! Repository-owned release-attempt runner entrypoint.
//!
//! The only currently supported invocation is a wiring probe called from the
//! deliberately dormant release lane. Target execution needs a caller-supplied
//! on-disk attempt root, exact matrix, and `fgit-runner` obligation; accepting
//! ambient defaults here would be the forbidden fake release path.

use std::process::ExitCode;

fn main() -> ExitCode {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if matches!(arguments.as_slice(), [argument] if argument == "--release-gate-probe") {
        println!(
            "{} is wired; target execution remains caller-scoped and release publication remains refused",
            fgit_release::ATTEMPT_RUNNER_ENTRYPOINT
        );
        return ExitCode::SUCCESS;
    }
    eprintln!(
        "usage: {} --release-gate-probe; target execution requires a caller-supplied matrix and fgit-runner obligation",
        fgit_release::ATTEMPT_RUNNER_ENTRYPOINT
    );
    ExitCode::from(2)
}
