#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! One real HTTP process owns serving, native workflow execution and check drain.

#[test]
fn http_service_executes_native_workflows_without_broadening_network_grants() {
    let campaign = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/e2e/helpers/workflow_http_service.py");
    let output = std::env::temp_dir().join(format!(
        "fg-http-workflow-cli-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("current time after epoch")
            .as_nanos()
    ));
    std::fs::create_dir(&output).expect("create private HTTP workflow campaign directory");
    let status = std::process::Command::new("python3")
        .arg(campaign)
        .arg(env!("CARGO_BIN_EXE_fg"))
        .arg(&output)
        .status()
        .expect("start real native HTTP workflow service campaign");
    assert!(
        status.success(),
        "HTTP workflow campaign failed: {status}; retained outputs: {}",
        output.display()
    );
    std::fs::remove_dir_all(output).expect("remove successful HTTP workflow campaign fixture");
}
