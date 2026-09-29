#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Execute the native workflow/publication/PR campaign against this Cargo-built
//! binary. Every operation reopens the durable node in a new process.

#[test]
fn trusted_workflow_evidence_publishes_exact_pr_checks_and_recovers_terminal_retries() {
    let campaign = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/e2e/workflow_publication_smoke.py");
    let status = std::process::Command::new("python3")
        .arg(campaign)
        .arg("--fg")
        .arg(env!("CARGO_BIN_EXE_fg"))
        .status()
        .expect("start the required native workflow publication campaign");
    assert!(
        status.success(),
        "workflow publication campaign failed: {status}"
    );
}

#[test]
fn event_dispatch_preserves_child_custody_publication_and_no_replay_boundaries() {
    let campaign = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/e2e/workflow_dispatch_smoke.py");
    let status = std::process::Command::new("python3")
        .arg(campaign)
        .arg("--fg")
        .arg(env!("CARGO_BIN_EXE_fg"))
        .status()
        .expect("start the required native workflow dispatch campaign");
    assert!(
        status.success(),
        "workflow dispatch campaign failed: {status}"
    );
}
