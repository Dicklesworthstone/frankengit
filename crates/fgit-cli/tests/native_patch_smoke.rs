#![forbid(unsafe_code)]
use std::{path::Path, process::Command};

#[test]
fn exact_patch_preparation_publication_and_recovery_cross_real_process_boundaries() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/e2e/patch_smoke.py");
    let output = Command::new("python3").arg(script).arg("--fg").arg(env!("CARGO_BIN_EXE_fg"))
        .output().expect("run the real patch CLI campaign");
    assert!(output.status.success(), "patch campaign failed {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(), String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("PATCH_CLI format=sha1 "));
    assert!(text.contains("PATCH_CLI format=sha256 "));
    print!("{text}");
}
