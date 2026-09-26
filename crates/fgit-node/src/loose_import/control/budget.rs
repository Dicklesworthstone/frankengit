//! Reserve import work before reading the source; never replenish it mid-import.
use crate::loose_import::MAX_IMPORT_TOTAL_OBJECT_BYTES;
use crate::{
    GitDaemonSessionDeadline, GitDaemonSessionTimeout, GitDaemonSessionWorkScaling,
    NodeRequestContext, OneNode,
};

fn reserved_deadline(
    base: GitDaemonSessionTimeout,
    scaling: GitDaemonSessionWorkScaling,
    explicit: Option<GitDaemonSessionTimeout>,
) -> GitDaemonSessionDeadline {
    let deadline = GitDaemonSessionDeadline::new(
        explicit.unwrap_or(base),
        if explicit.is_some() {
            // An explicit operator timeout is a ceiling, not a base to extend.
            GitDaemonSessionWorkScaling::FLAT
        } else {
            scaling
        },
    );
    // This is an up-front reservation against the import profile's enforced
    // expanded-byte ceiling, NOT an assertion about bytes already read. No
    // session, receipt, transaction identity or publication observes this local
    // accounting object. Reuse the receive formula instead of a second policy.
    deadline.note_admitted(MAX_IMPORT_TOTAL_OBJECT_BYTES as usize);
    deadline
}

impl OneNode {
    /// Mints the single bounded context for a local source import.
    ///
    /// The default reserves the existing import profile's maximum expanded
    /// bytes using the node's receive work-scaling policy and session base.
    /// Poll and cost allowances use the SAME receive-admission calculation.
    /// It does not scan a mutable directory before the clock starts, change
    /// the import's byte/object limits, or mint another budget after staging.
    ///
    /// `Some(timeout)` selects a strict wall-clock ceiling without a byte-earned
    /// extension. All dimensions remain bounded by the owning runtime's root.
    /// Keep this context alive and pass it to
    /// [`Self::import_loose_git_directory_durable_in`] for both source validation
    /// and canonical publication. The `_in` method continues to honor any
    /// caller-supplied context verbatim, including a smaller or cancelled one.
    #[must_use]
    pub fn import_request_context(
        &self,
        timeout: Option<GitDaemonSessionTimeout>,
    ) -> NodeRequestContext {
        let deadline = reserved_deadline(
            self.git_daemon_session_timeout,
            self.git_daemon_session_work_scaling,
            timeout,
        );
        NodeRequestContext {
            authority: self
                .receive_admission_authority_context(MAX_IMPORT_TOTAL_OBJECT_BYTES, &deadline),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NodeConfig, loose_import::checkpoint_request};
    use fgit_runtime::Exhaustion;
    use fgit_types::{PrincipalId, RefusalCode, RepositoryId, TenantId};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    static NEXT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn default_reservation_uses_receive_scaling_and_its_hard_ceiling() {
        let base = GitDaemonSessionTimeout::DEFAULT;
        let scaling = GitDaemonSessionWorkScaling::DEFAULT;
        let reserved = reserved_deadline(base, scaling, None);
        let reference = GitDaemonSessionDeadline::new(base, scaling);
        reference.note_admitted(MAX_IMPORT_TOTAL_OBJECT_BYTES as usize);
        assert_eq!(reserved.budget(), reference.budget());
        let flat = reserved_deadline(base, GitDaemonSessionWorkScaling::FLAT, None);
        assert!(reserved.budget() > flat.budget());
        assert!(reserved.budget() <= flat.budget().saturating_add(scaling.max_extension()));
    }

    #[test]
    fn explicit_timeout_is_not_extended_by_the_reserved_bytes() {
        for seconds in [1, 15, 600] {
            let duration = Duration::from_secs(seconds);
            let timeout = GitDaemonSessionTimeout::try_new(duration).unwrap();
            let reserved = reserved_deadline(
                GitDaemonSessionTimeout::DEFAULT,
                GitDaemonSessionWorkScaling::DEFAULT,
                Some(timeout),
            );
            assert_eq!(reserved.budget(), duration);
        }
    }

    #[test]
    fn reservation_keeps_custom_scaling_and_does_not_reset_elapsed_time() {
        let scaling =
            GitDaemonSessionWorkScaling::try_new(Duration::from_secs(1), Duration::from_secs(2))
                .unwrap();
        let base = GitDaemonSessionTimeout::try_new(Duration::from_secs(3)).unwrap();
        let mut reserved = reserved_deadline(base, scaling, None);
        assert_eq!(reserved.budget(), Duration::from_secs(5));
        reserved.started -= Duration::from_secs(6);
        assert!(reserved.remaining().is_err());
        assert!(reserved.remaining().is_err());
    }

    #[test]
    fn native_import_context_is_finite_and_expired_context_stops_before_source_io() {
        let root = std::env::temp_dir().join(format!(
            "fg-import-budget-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&root).unwrap();
        let (mut node, _) = OneNode::init(
            NodeConfig::new(
                root.join("node"),
                TenantId::from_bytes([0xf1; 16]),
                RepositoryId::from_bytes([0xf2; 16]),
            )
            .with_worker_threads(2),
        )
        .unwrap();
        node.bring_into_service(fgit_types::HeadGeneration::FIRST)
            .unwrap();
        let before = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        let live = node.import_request_context(None);
        let native = live.authority().attached_native_cx().unwrap();
        let budget = native.budget();
        assert!(budget.deadline.is_some());
        assert!(budget.cost_quota.is_some());
        assert!(budget.poll_quota < u32::MAX);
        assert!(u64::from(budget.poll_quota) >= MAX_IMPORT_TOTAL_OBJECT_BYTES / 64);
        assert!(budget.cost_quota.unwrap() >= MAX_IMPORT_TOTAL_OBJECT_BYTES / 8);
        assert!(checkpoint_request(&live).is_ok());

        let tiny = GitDaemonSessionTimeout::try_new(Duration::from_nanos(1)).unwrap();
        let expired = node.import_request_context(Some(tiny));
        // Bounded waiting outside production; ensure the one-nanosecond deadline
        // has elapsed without a timing-sensitive minimum source size.
        std::thread::sleep(Duration::from_millis(1));
        let error = node
            .runtime()
            .block_on(node.import_loose_git_directory_durable_in(
                &expired,
                &root.join("source-must-not-be-read"),
                PrincipalId::from_bytes([0xf3; 16]),
                b"expired-import-budget",
            ))
            .unwrap_err();
        assert!(matches!(error,
            crate::NodeSourceImportRefusal::Staging(error)
                if matches!(*error, crate::LooseGitImportRefusal::Interrupted {
                    code: RefusalCode::ResourceBudgetExceeded,
                    exhaustion: Some(Exhaustion::Deadline),
                })
        ));
        let after = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        assert_eq!(before.receipt().generation(), after.receipt().generation());
        assert!(checkpoint_request(&expired).is_err());
        assert!(checkpoint_request(&live).is_ok());
        node.shutdown().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}
