//! Listener lifetime is independent of the finite envelope of every request.
//!
//! A controlled service keeps one profile, credential source and set of quotas
//! across its entire lifetime. It never simulates continuous serving by opening
//! a succession of bounded servers (which would reset the quotas).

use std::io;
use std::net::TcpListener;
use std::path::Path;
use std::time::Duration;

use fgit_types::PrincipalId;

use super::{CredentialSource, MAX_SESSIONS, NodeSmartHttpRefusal, OneNode};
use crate::GitDaemonServerReceipt;

pub(super) enum Acceptance<'a> {
    Bounded {
        max_sessions: usize,
        idle_timeout: Duration,
    },
    UntilStopped(&'a dyn Fn() -> io::Result<bool>),
}

impl Acceptance<'_> {
    pub(super) fn valid(&self) -> bool {
        match self {
            Self::Bounded {
                max_sessions,
                idle_timeout,
            } => (1..=MAX_SESSIONS).contains(max_sessions) && !idle_timeout.is_zero(),
            Self::UntilStopped(_) => true,
        }
    }

    /// Called even while the in-flight limit is full. Returning false retires
    /// acceptance only; the caller still joins every previously accepted child.
    /// Control errors and unwinding panics take that same draining exit path.
    pub(super) fn keep_accepting(
        &self,
        accepted: usize,
        active: usize,
        idle: Duration,
    ) -> io::Result<bool> {
        match self {
            Self::Bounded {
                max_sessions,
                idle_timeout,
            } => Ok(accepted < *max_sessions && (active != 0 || idle < *idle_timeout)),
            Self::UntilStopped(stop) => {
                let stopped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stop()))
                    .map_err(|_| io::Error::other("HTTP stop control panicked"))??;
                if stopped {
                    return Ok(false);
                }
                // Count every accepted connection without wrapping a receipt.
                // This is a machine-counter boundary, not a configured request cap.
                if accepted == usize::MAX {
                    return Err(io::Error::other("HTTP lifetime counter exhausted"));
                }
                Ok(true)
            }
        }
    }
}

impl OneNode {
    /// Serve the Git-only static-credential profile until the owner requests stop.
    ///
    /// `should_stop` is polled on the accepting thread, including while all
    /// connection slots are busy. It must be bounded and nonblocking; `Ok(true)`
    /// stops new acceptance, while a control error stops with an error AFTER
    /// draining accepted children. Callbacks must not panic: unwinding panics
    /// are converted to errors, but a panic-abort build cannot recover them.
    /// Stopping does not cancel or roll back accepted writes.
    /// Every request keeps its existing ingress/processing/response deadlines,
    /// authentication and resource ceilings. The listener remains loopback-only.
    ///
    /// No lifetime request cap or idle retirement applies. Quotas and accounting
    /// survive all requests; this is not a loop around the bounded entry point.
    /// The caller owns node shutdown after this method has returned.
    pub fn serve_smart_http_until_stopped(
        &self,
        listener: &TcpListener,
        max_in_flight: usize,
        credential_digest: [u8; 32],
        principal: PrincipalId,
        allow_receive: bool,
        should_stop: &dyn Fn() -> io::Result<bool>,
    ) -> Result<GitDaemonServerReceipt, NodeSmartHttpRefusal> {
        self.serve_smart_http_with_source_lifetime(
            listener,
            max_in_flight,
            CredentialSource::Static {
                digest: credential_digest,
                principal,
            },
            allow_receive,
            false,
            false,
            false,
            false,
            Acceptance::UntilStopped(should_stop),
        )
    }

    /// Continuously serve independently enabled repository endpoints using a
    /// credential table that is still re-read for EVERY authentication.
    ///
    /// Flags remain independent ceilings, not grants. Current credential scopes,
    /// repository incarnation, policy checks, mutation/recovery/read quotas and
    /// native publication paths are unchanged. No endpoint is implicitly enabled.
    /// Stop and drain semantics are those of `serve_smart_http_until_stopped`.
    pub fn serve_repository_http_until_stopped(
        &self,
        listener: &TcpListener,
        max_in_flight: usize,
        credentials_file: &Path,
        allow_receive: bool,
        allow_issues: bool,
        allow_outcomes: bool,
        allow_pulls: bool,
        allow_source: bool,
        should_stop: &dyn Fn() -> io::Result<bool>,
    ) -> Result<GitDaemonServerReceipt, NodeSmartHttpRefusal> {
        self.serve_smart_http_with_source_lifetime(
            listener,
            max_in_flight,
            self.smart_http_credentials_source(credentials_file),
            allow_receive,
            allow_issues,
            allow_outcomes,
            allow_pulls,
            allow_source,
            Acceptance::UntilStopped(should_stop),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn bounded_service_keeps_its_request_and_idle_contract() {
        let policy = Acceptance::Bounded {
            max_sessions: 2,
            idle_timeout: Duration::from_secs(1),
        };
        assert!(policy.valid());
        assert!(policy.keep_accepting(1, 0, Duration::ZERO).unwrap());
        assert!(!policy.keep_accepting(2, 0, Duration::ZERO).unwrap());
        assert!(!policy.keep_accepting(2, 1, Duration::ZERO).unwrap());
        assert!(
            policy
                .keep_accepting(1, 1, Duration::from_secs(60))
                .unwrap()
        );
        assert!(!policy.keep_accepting(1, 0, Duration::from_secs(1)).unwrap());
    }

    #[test]
    fn continuous_service_survives_old_lifetime_and_idle_limits() {
        let stop = Cell::new(false);
        let control = || Ok(stop.get());
        let policy = Acceptance::UntilStopped(&control);
        assert!(policy.valid());
        for accepted in [0, 1024, MAX_SESSIONS, MAX_SESSIONS + 1] {
            for active in [0, 16] {
                assert!(
                    policy
                        .keep_accepting(accepted, active, Duration::MAX)
                        .unwrap()
                );
            }
        }
        stop.set(true);
        for active in [0, 16] {
            assert!(!policy.keep_accepting(1024, active, Duration::ZERO).unwrap());
        }
    }

    #[test]
    fn control_failure_is_an_error_not_successful_retirement() {
        let control = || {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "stop unavailable",
            ))
        };
        let error = Acceptance::UntilStopped(&control)
            .keep_accepting(1, 16, Duration::ZERO)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let permitted = || Ok(true);
        assert!(
            !Acceptance::UntilStopped(&permitted)
                .keep_accepting(1, 16, Duration::ZERO)
                .unwrap()
        );
    }

    #[test]
    fn a_panicking_control_returns_to_the_callers_drain_path() {
        let control = || -> io::Result<bool> { panic!("planted control failure") };
        let error = Acceptance::UntilStopped(&control)
            .keep_accepting(1, 1, Duration::ZERO)
            .unwrap_err();
        assert_eq!(error.to_string(), "HTTP stop control panicked");
        let permitted = || Ok(false);
        assert!(
            Acceptance::UntilStopped(&permitted)
                .keep_accepting(1, 1, Duration::ZERO)
                .unwrap()
        );
    }

    #[test]
    fn receipt_counter_never_wraps_but_stop_at_the_boundary_is_allowed() {
        let keep_running = || Ok(false);
        let policy = Acceptance::UntilStopped(&keep_running);
        assert!(
            policy
                .keep_accepting(usize::MAX - 1, 0, Duration::ZERO)
                .unwrap()
        );
        assert!(
            policy
                .keep_accepting(usize::MAX, 0, Duration::ZERO)
                .is_err()
        );
        let stop = || Ok(true);
        assert!(
            !Acceptance::UntilStopped(&stop)
                .keep_accepting(usize::MAX, 0, Duration::ZERO)
                .unwrap()
        );
    }

    #[test]
    fn invalid_bounded_lifetimes_are_not_reinterpreted_as_continuous() {
        for (max_sessions, idle_timeout) in [
            (0, Duration::from_secs(1)),
            (MAX_SESSIONS + 1, Duration::from_secs(1)),
            (1, Duration::ZERO),
        ] {
            assert!(
                !Acceptance::Bounded {
                    max_sessions,
                    idle_timeout
                }
                .valid()
            );
        }
        assert!(
            Acceptance::Bounded {
                max_sessions: MAX_SESSIONS,
                idle_timeout: Duration::from_secs(1),
            }
            .valid()
        );
    }
}
