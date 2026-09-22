#![forbid(unsafe_code)]
use std::{path::Path, process::Command};
#[test]
fn fresh_nodes_create_native_root_history_and_advance_without_import() {
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/e2e/initial_commit_smoke.py");
    let output = Command::new("python3")
        .arg(script)
        .arg("--fg")
        .arg(env!("CARGO_BIN_EXE_fg"))
        .output()
        .expect("launch native initial-commit campaign");
    assert!(
        output.status.success(),
        "initial-commit campaign failed: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("INITIAL_COMMIT_CLI format=sha1 "));
    assert!(text.contains("INITIAL_COMMIT_CLI format=sha256 "));
    print!("{text}");
}
