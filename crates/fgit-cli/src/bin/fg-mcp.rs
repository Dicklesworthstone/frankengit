#![forbid(unsafe_code)]
//! Operator-scoped read-only Model Context Protocol server.
#[path = "../mcp/mod.rs"]
mod mcp;
fn main() -> std::process::ExitCode {
    match mcp::run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => { eprintln!("fg-mcp: {error}"); std::process::ExitCode::from(2) }
    }
}
