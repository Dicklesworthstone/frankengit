#![forbid(unsafe_code)]
use std::{path::Path, process::Command};
#[test]
fn fresh_process_protection_enforces_direct_write_guards_and_retains_policy_ownership() {
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/e2e/protection_smoke.py");
    let output = Command::new("python3")
        .arg(script)
        .arg("--fg")
        .arg(env!("CARGO_BIN_EXE_fg"))
        .output()
        .expect("launch native policy lifecycle");
    assert!(
        output.status.success(),
        "native policy campaign failed: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 campaign report");
    assert!(stdout.contains("PROTECTION_CLI format=sha1 "));
    assert!(stdout.contains("PROTECTION_CLI format=sha256 "));
    print!("{stdout}");
}
