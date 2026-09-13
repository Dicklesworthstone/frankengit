#![forbid(unsafe_code)]
//! Each operation opens, uses, and closes the real file-backed native node.
#[test]
fn native_branch_cli_lifecycle_and_recovery_in_both_hash_formats() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/e2e/branch_smoke.py");
    let output = std::process::Command::new("python3")
        .arg(script)
        .arg("--fg")
        .arg(env!("CARGO_BIN_EXE_fg"))
        .output()
        .expect("launch Python branch campaign");
    assert!(output.status.success(), "native branch CLI campaign failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    let report = String::from_utf8(output.stdout).unwrap();
    assert!(report.contains("BRANCH_LIFECYCLE format=sha1 passed"));
    assert!(report.contains("BRANCH_LIFECYCLE format=sha256 passed"));
    print!("{report}");
}
