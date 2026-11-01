#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Real server-owned build/test artifact delivery, HTTP reads and restart.

#[test]
fn http_workflow_artifacts_keep_exact_producer_custody_across_jobs_and_restart() {
    let campaign = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/e2e/helpers/workflow_http_artifacts.py");
    let output = std::env::temp_dir().join(format!(
        "fg-http-workflow-artifacts-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("current time after epoch")
            .as_nanos()
    ));
    std::fs::create_dir(&output).expect("create HTTP workflow artifact campaign directory");
    let status = std::process::Command::new("python3")
        .arg(campaign)
        .arg(env!("CARGO_BIN_EXE_fg"))
        .arg(&output)
        .status()
        .expect("start actual native artifact workflow campaign");
    assert!(
        status.success(),
        "HTTP artifact workflow campaign failed: {status}; retained outputs: {}",
        output.display()
    );
    std::fs::remove_dir_all(output).expect("remove successful artifact workflow campaign fixture");
}
