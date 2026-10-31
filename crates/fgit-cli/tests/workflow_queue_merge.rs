#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Real foreground queue selection, candidate execution and guarded landing.

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
    std::fs::create_dir(&output).expect("create queue candidate CI campaign directory");
    let status = std::process::Command::new("python3")
        .arg(script)
        .arg(env!("CARGO_BIN_EXE_fg"))
        .arg(&output)
        .status()
        .expect("start real native queue candidate CI campaign");
    assert!(
        status.success(),
        "queue candidate CI campaign failed: {status}; retained outputs: {}",
        output.display()
    );
    std::fs::remove_dir_all(output).expect("remove successful queue candidate CI campaign fixture");
}

#[test]
fn queue_watch_executes_and_reports_the_exact_head_before_guarded_landing() {
    campaign("workflow_queue_merge_watch");
}

#[test]
fn http_owned_queue_controller_follows_reorder_and_recovers_without_replay() {
    campaign("workflow_queue_merge_service");
}
