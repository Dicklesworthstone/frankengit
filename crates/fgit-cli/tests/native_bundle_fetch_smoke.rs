#![forbid(unsafe_code)]
use std::{path::Path, process::Command};
#[test]
fn fresh_process_bundle_fetch_preserves_atomic_updates_and_native_bytes() {
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/e2e/bundle_fetch_smoke.py");
    let output = Command::new("python3")
        .arg(script)
        .arg("--fg")
        .arg(env!("CARGO_BIN_EXE_fg"))
        .output()
        .expect("launch native bundle fetch campaign");
    assert!(
        output.status.success(),
        "bundle fetch campaign failed: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 test report");
    assert!(stdout.contains("BUNDLE_FETCH_CLI format=sha1 "));
    assert!(stdout.contains("BUNDLE_FETCH_CLI format=sha256 "));
    print!("{stdout}");
}
