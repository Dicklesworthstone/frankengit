#![forbid(unsafe_code)]
use std::{path::Path, process::Command};
#[test]
fn native_tags_survive_fresh_process_retries_and_bundle_transfer() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/e2e/tag_smoke.py");
    let result = Command::new("python3").arg(script).arg("--fg").arg(env!("CARGO_BIN_EXE_fg"))
        .output().expect("launch native tag campaign");
    assert!(result.status.success(), "tag campaign failed: {:?}\nstdout:\n{}\nstderr:\n{}",
        result.status.code(), String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(stdout.contains("NATIVE_TAG_CLI format=sha1 "));
    assert!(stdout.contains("NATIVE_TAG_CLI format=sha256 "));
    print!("{stdout}");
}
