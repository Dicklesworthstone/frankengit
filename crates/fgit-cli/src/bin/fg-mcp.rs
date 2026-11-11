#![forbid(unsafe_code)]
//! Operator-scoped Model Context Protocol server with independent read, write, and recovery grants.
fn main() -> std::process::ExitCode {
    match fgit_cli::mcp::run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("fg-mcp: {error}");
            std::process::ExitCode::from(2)
        }
    }
}
