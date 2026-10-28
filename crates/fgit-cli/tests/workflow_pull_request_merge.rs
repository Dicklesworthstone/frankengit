#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Real CLI and HTTP-owned exact PR candidate CI with canonical protection.

fn campaign(name: &str) {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/e2e/helpers")
        .join(format!("{name}.py"));
    let output = std::env::temp_dir().join(format!(
        "fg-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("current time after epoch")
            .as_nanos()
    ));
    std::fs::create_dir(&output).expect("create native candidate CI campaign directory");
    let status = std::process::Command::new("python3")
        .arg(script)
        .arg(env!("CARGO_BIN_EXE_fg"))
        .arg(&output)
        .status()
        .expect("start real native candidate CI campaign");
    assert!(
        status.success(),
        "candidate CI campaign failed: {status}; retained outputs: {}",
        output.display()
    );
    std::fs::remove_dir_all(output).expect("remove successful candidate CI campaign fixture");
}

#[test]
fn foreground_watch_checks_the_exact_candidate_before_protected_merge() {
    campaign("workflow_pull_request_merge_watch");
}

#[test]
fn http_service_owns_candidate_execution_reporting_and_restart() {
    campaign("workflow_pull_request_merge_service");
}
