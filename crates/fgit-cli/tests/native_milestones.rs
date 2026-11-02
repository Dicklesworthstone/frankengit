#![forbid(unsafe_code)]
//! Real CLI process boundaries, authority recovery and pinned progress counts.
#[test]
fn native_milestone_lifecycle_membership_and_recovery_in_both_formats() {
    let helper = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/e2e/helpers/milestones.py");
    let output = std::process::Command::new("python3")
        .arg(helper)
        .arg("--fg")
        .arg(env!("CARGO_BIN_EXE_fg"))
        .output()
        .expect("launch actual fg milestone campaign");
    assert!(
        output.status.success(),
        "native milestone campaign failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("MILESTONE_LIFECYCLE format=sha1 passed"));
    assert!(text.contains("MILESTONE_LIFECYCLE format=sha256 passed"));
}
