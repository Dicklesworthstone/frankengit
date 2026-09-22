#![forbid(unsafe_code)]

use std::process::Command;

#[test]
fn fg_mcp_help_dispatch() {
    let output = Command::new(env!("CARGO_BIN_EXE_fg"))
        .arg("mcp")
        .arg("--help")
        .output()
        .expect("run fg mcp --help");
    assert!(
        output.status.success(),
        "fg mcp --help failed: {:?}",
        output
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Separate policy-inspection profile"));
}
