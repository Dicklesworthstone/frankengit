#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Actual HTTP-owned native PR discovery, check recovery and retained capacity.

#[test]
fn native_pr_collection_discovers_work_and_preserves_original_execution_custody() {
    let campaign = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/e2e/helpers/workflow_pull_request_collection.py");
    let output = std::env::temp_dir().join(format!(
        "fg-pull-request-collection-cli-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("current time after epoch")
            .as_nanos()
    ));
    std::fs::create_dir(&output).expect("create native PR collection campaign directory");
    let status = std::process::Command::new("python3")
        .arg(campaign)
        .arg(env!("CARGO_BIN_EXE_fg"))
        .arg(&output)
        .status()
        .expect("start actual native PR collection campaign");
    assert!(
        status.success(),
        "PR collection campaign failed: {status}; retained outputs: {}",
        output.display()
    );
    std::fs::remove_dir_all(output).expect("remove successful native PR collection fixture");
}
