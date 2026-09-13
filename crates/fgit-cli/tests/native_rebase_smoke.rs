#![forbid(unsafe_code)]

use std::{path::Path, process::Command};

#[test]
fn fresh_process_rebase_preserves_native_history_and_exports_complete_bundles() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/e2e/rebase_smoke.py");
    let output = Command::new("python3")
        .arg(script)
        .arg("--fg")
        .arg(env!("CARGO_BIN_EXE_fg"))
        .output()
        .expect("launch the bounded native rebase campaign");
    assert!(
        output.status.success(),
        "native rebase campaign failed: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("campaign output is UTF-8");
    assert!(stdout.contains("REBASE_CLI format=sha1 "));
    assert!(stdout.contains("REBASE_CLI format=sha256 "));
    print!("{stdout}");
}
