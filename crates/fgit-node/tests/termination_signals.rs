#![forbid(unsafe_code)]
//! Once installed, SIGTERM and SIGINT are latched drain requests instead of
//! ending the process. This test binary signals itself with the stock `kill`.

use std::process::Command;
use std::time::{Duration, Instant};

use fgit_node::TerminationSignals;

fn signal_self(name: &str) {
    let status = Command::new("kill")
        .arg(format!("-{name}"))
        .arg(std::process::id().to_string())
        .status()
        .expect("the kill utility runs");
    assert!(status.success(), "kill -{name} failed");
}

fn observed(signals: &TerminationSignals) -> bool {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(10) {
        if signals.requested() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

#[test]
fn sigterm_and_sigint_become_latched_drain_requests() {
    let terminate = TerminationSignals::install().expect("unix delivers SIGTERM and SIGINT");
    // Twin: installation alone is not a request.
    assert!(!terminate.requested());
    signal_self("TERM");
    assert!(observed(&terminate), "SIGTERM is observed");
    // The process is still here, and the request stays set.
    assert!(terminate.requested());

    // Only deliveries after installation count, and SIGINT is honoured too.
    let interrupt = TerminationSignals::install().expect("a second installation");
    assert!(
        !interrupt.requested(),
        "an earlier SIGTERM does not carry over"
    );
    signal_self("INT");
    assert!(observed(&interrupt), "SIGINT is observed");
    assert!(terminate.requested());
}
