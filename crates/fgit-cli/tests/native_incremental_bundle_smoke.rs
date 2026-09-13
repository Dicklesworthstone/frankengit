#![forbid(unsafe_code)]
use std::{path::Path, process::Command};
#[test]
fn fresh_process_incremental_bundles_synchronize_exact_refs_without_bypassing_protection() {
    let output = Command::new("python3")
        .arg(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../scripts/e2e/incremental_bundle_smoke.py"),
        )
        .arg("--fg")
        .arg(env!("CARGO_BIN_EXE_fg"))
        .output()
        .expect("launch native incremental-bundle campaign");
    assert!(
        output.status.success(),
        "native campaign failed {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    for format in ["sha1", "sha256"] {
        assert!(text.contains(&format!("INCREMENTAL_BUNDLE_CLI format={format} ")));
    }
    print!("{text}");
}
