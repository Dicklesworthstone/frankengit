#![forbid(unsafe_code)]
use std::{path::Path, process::Command};
#[test]
fn fresh_process_repository_protection_preserves_administration_and_recovery() {
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/e2e/protection_smoke.py");
    let output = Command::new("python3")
        .arg(script)
        .arg("--fg")
        .arg(env!("CARGO_BIN_EXE_fg"))
        .output()
        .expect("launch bounded native protection campaign");
    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("PROTECTION_CLI format=sha1 "));
    assert!(stdout.contains("PROTECTION_CLI format=sha256 "));
    print!("{stdout}");
}
