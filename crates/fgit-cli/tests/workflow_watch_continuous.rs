#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Real subprocess coverage of service lifetime, canonical reporting and drain.

#[test]
fn continuous_native_watch_refreshes_attempts_and_preserves_original_execution_custody() {
    let campaign = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/e2e/helpers/workflow_watch_continuous.py");
    let output = std::env::temp_dir().join(format!(
        "fg-continuous-workflow-cli-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("current time after epoch")
            .as_nanos()
    ));
    std::fs::create_dir(&output).expect("create private campaign directory");
    let status = std::process::Command::new("python3")
        .arg(campaign)
        .arg(env!("CARGO_BIN_EXE_fg"))
        .arg(&output)
        .status()
        .expect("start real native continuous-workflow campaign");
    assert!(
        status.success(),
        "continuous-workflow campaign failed: {status}; retained outputs: {}",
        output.display()
    );
    std::fs::remove_dir_all(output).expect("remove successful campaign fixture");
}
