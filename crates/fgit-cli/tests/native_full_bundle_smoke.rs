#![forbid(unsafe_code)]
use std::{path::Path, process::Command};

#[test]
fn fresh_process_full_bundle_transfer_preserves_native_objects_and_atomic_refs() {
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/e2e/full_bundle_smoke.py");
    let output = Command::new("python3")
        .arg(script)
        .arg("--fg")
        .arg(env!("CARGO_BIN_EXE_fg"))
        .output()
        .expect("launch bounded native bundle campaign");
    assert!(
        output.status.success(),
        "bundle campaign failed: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 campaign output");
    assert!(stdout.contains("FULL_BUNDLE_CLI format=sha1 "));
    assert!(stdout.contains("FULL_BUNDLE_CLI format=sha256 "));
    print!("{stdout}");
}
