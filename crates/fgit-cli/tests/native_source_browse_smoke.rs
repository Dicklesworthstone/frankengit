#![forbid(unsafe_code)]
use std::{path::Path,process::Command};
#[test]
fn fresh_process_source_reads_feed_exact_patch_publication() {
    let script=Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/e2e/source_browse_smoke.py");
    let output=Command::new("python3").arg(script).arg("--fg").arg(env!("CARGO_BIN_EXE_fg"))
        .output().expect("launch source browse campaign");
    assert!(output.status.success(),"source browse campaign failed: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),String::from_utf8_lossy(&output.stdout),String::from_utf8_lossy(&output.stderr));
    let text=String::from_utf8(output.stdout).expect("UTF-8 campaign output");
    assert!(text.contains("SOURCE_BROWSE_CLI format=sha1 "));
    assert!(text.contains("SOURCE_BROWSE_CLI format=sha256 "));print!("{text}");
}
