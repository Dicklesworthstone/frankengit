#![forbid(unsafe_code)]
//! Exercise the repository's native PR campaign against this exact Cargo-built
//! binary. The Python driver creates native Git bytes independently and starts
//! a fresh fg process for each operation; it never shells out to upstream Git.

#[test]
fn native_pr_lifecycle_merge_and_historical_recovery() {
    let campaign = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/e2e/pull_request_smoke.py");
    let status = std::process::Command::new("python3")
        .arg(campaign)
        .arg("--fg")
        .arg(env!("CARGO_BIN_EXE_fg"))
        .status()
        .expect("start the required native PR campaign driver");
    assert!(status.success(), "native PR campaign failed: {status}");
}
