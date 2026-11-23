#![forbid(unsafe_code)]
//! Each operation opens, uses, and closes the real file-backed native node.
#[test]
fn native_branch_cli_lifecycle_and_recovery_in_both_hash_formats() {
    let script =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/e2e/branch_smoke.py");
    let output = std::process::Command::new("python3")
        .arg(script)
        .arg("--fg")
        .arg(env!("CARGO_BIN_EXE_fg"))
        .output()
        .expect("launch Python branch campaign");
    assert!(
        output.status.success(),
        "native branch CLI campaign failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = String::from_utf8(output.stdout).unwrap();
    assert!(report.contains("BRANCH_LIFECYCLE format=sha1 passed"));
    assert!(report.contains("BRANCH_LIFECYCLE format=sha256 passed"));
    print!("{report}");
}

#[test]
fn native_atomic_branch_transaction_cli_in_both_hash_formats() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/e2e/branch_transaction_smoke.py");
    let output = std::process::Command::new("python3")
        .arg(script)
        .arg("--fg")
        .arg(env!("CARGO_BIN_EXE_fg"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = String::from_utf8(output.stdout).unwrap();
    assert!(report.contains("BRANCH_TRANSACTION format=sha1 passed"));
    assert!(report.contains("BRANCH_TRANSACTION format=sha256 passed"));
    print!("{report}");
}

#[test]
fn native_default_branch_cli_policy_and_recovery_in_both_hash_formats() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/e2e/default_branch_smoke.py");
    let output = std::process::Command::new("python3")
        .arg(script)
        .arg("--fg")
        .arg(env!("CARGO_BIN_EXE_fg"))
        .output()
        .expect("launch default-branch campaign");
    assert!(
        output.status.success(),
        "native default-branch CLI campaign failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = String::from_utf8(output.stdout).unwrap();
    for format in ["sha1", "sha256"] {
        for layout in ["legacy", "ref-merkle-v2"] {
            let expected = format!("DEFAULT_BRANCH format={format} layout={layout} passed");
            assert!(report.contains(&expected), "missing {expected}: {report}");
        }
    }
    print!("{report}");
}
