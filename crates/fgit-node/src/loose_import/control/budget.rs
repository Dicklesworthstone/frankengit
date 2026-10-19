//! Reserve import work before reading the source; never replenish it mid-import.
use crate::loose_import::graph::MAX_REACHABLE_OBJECT_BYTES;
use crate::{
    GitDaemonSessionDeadline, GitDaemonSessionTimeout, GitDaemonSessionWorkScaling,
    NodeRequestContext, OneNode,
};

#[cfg(test)]
fn reserved_deadline(
    base: GitDaemonSessionTimeout,
    scaling: GitDaemonSessionWorkScaling,
    explicit: Option<GitDaemonSessionTimeout>,
) -> GitDaemonSessionDeadline {
    reserved_deadline_for_bytes(base, scaling, explicit, MAX_REACHABLE_OBJECT_BYTES)
}

fn reserved_deadline_for_bytes(
    base: GitDaemonSessionTimeout,
    scaling: GitDaemonSessionWorkScaling,
    explicit: Option<GitDaemonSessionTimeout>,
    maximum_bytes: u64,
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
    deadline.note_admitted(usize::try_from(maximum_bytes).unwrap_or(usize::MAX));
    deadline
}

impl OneNode {
    /// Mints the single bounded context for a local source import.
    ///
    /// The default reserves the existing import profile's maximum expanded
    /// bytes (512 MiB of reachable native bodies, independently of the smaller
    /// eager pack-cache envelope) using the receive work-scaling policy and base.
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
        self.import_context_for_bytes(timeout, MAX_REACHABLE_OBJECT_BYTES)
    }

    /// Reserve a single explicitly bounded disk-backed import before source I/O.
    /// `maximum_bytes` must be in 1..=16 GiB and fit this platform. Pass the same
    /// ceiling to `import_loose_git_directory_with_byte_limit_durable_in`.
    /// An explicit timeout remains a strict ceiling, not a renewable allowance.
    pub fn import_request_context_with_byte_limit(
        &self,
        timeout: Option<GitDaemonSessionTimeout>,
        maximum_bytes: u64,
    ) -> Result<NodeRequestContext, crate::LooseGitImportRefusal> {
        crate::loose_import::profile::validate_limit(maximum_bytes)?;
        Ok(self.import_context_for_bytes(timeout, maximum_bytes))
    }

    fn import_context_for_bytes(
        &self,
        timeout: Option<GitDaemonSessionTimeout>,
        maximum_bytes: u64,
    ) -> NodeRequestContext {
        let deadline = reserved_deadline_for_bytes(
            self.git_daemon_session_timeout,
            self.git_daemon_session_work_scaling,
            timeout,
            maximum_bytes,
        );
        NodeRequestContext {
            authority: self.receive_admission_authority_context(maximum_bytes, &deadline),
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
        reference.note_admitted(MAX_REACHABLE_OBJECT_BYTES as usize);
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
        assert!(u64::from(budget.poll_quota) >= MAX_REACHABLE_OBJECT_BYTES / 64);
        assert!(budget.cost_quota.unwrap() >= MAX_REACHABLE_OBJECT_BYTES / 8);
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

    fn temp_root(prefix: &str) -> std::path::PathBuf {
        let base = if std::path::Path::new("/dev/shm").is_dir() {
            std::path::PathBuf::from("/dev/shm")
        } else {
            std::env::temp_dir()
        };
        let root = base.join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&root).unwrap();
        root
    }

    fn encode_pack_entry_header(kind: u8, mut size: usize, out: &mut Vec<u8>) {
        let mut byte = (kind << 4) | ((size as u8) & 0x0f);
        size >>= 4;
        while size != 0 {
            out.push(byte | 0x80);
            byte = (size as u8) & 0x7f;
            size >>= 7;
        }
        out.push(byte);
    }

    fn encode_delta_varint(mut value: usize, out: &mut Vec<u8>) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    fn zlib_stored(bytes: &[u8]) -> Vec<u8> {
        let mut result = vec![0x78, 0x01];
        let chunks = bytes.chunks(65_535);
        let count = chunks.len();
        for (index, chunk) in chunks.enumerate() {
            result.push(u8::from(index + 1 == count));
            let n = u16::try_from(chunk.len()).unwrap();
            result.extend_from_slice(&n.to_le_bytes());
            result.extend_from_slice(&(!n).to_le_bytes());
            result.extend_from_slice(chunk);
        }
        let (a, b) = bytes.iter().fold((1_u32, 0_u32), |(a, b), byte| {
            let a = (a + u32::from(*byte)) % 65_521;
            (a, (b + a) % 65_521)
        });
        result.extend_from_slice(&((b << 16) | a).to_be_bytes());
        result
    }

    fn stage_multi_hundred_mib_repository(source: &std::path::Path) -> (fgit_types::GitOid, u64) {
        use fgit_crypto::{DigestHasher, GitObjectKind, Sha1Hasher, git_object_id, sha1_digest};
        use fgit_pack::{PackLimits, build_pack_index_v2};
        use fgit_types::{GitHashAlgorithm, GitOid, GitOidSha1};

        const BASE_LEN: usize = 65_536;
        const FULL_COPIES: usize = 383;
        const TAIL_COPY_LEN: usize = BASE_LEN - 8;
        const DELTA_BLOB_LEN: usize = FULL_COPIES * BASE_LEN + TAIL_COPY_LEN + 8; // 24 MiB
        const DELTA_BLOB_COUNT: usize = 9; // 9 * 24 MiB = 216 MiB

        std::fs::create_dir_all(source.join("objects/pack")).unwrap();
        std::fs::create_dir_all(source.join("refs/heads")).unwrap();
        std::fs::write(source.join("HEAD"), b"ref: refs/heads/main\n").unwrap();

        let base_blob: Vec<u8> = (0..BASE_LEN)
            .map(|i| ((i.wrapping_mul(31)).wrapping_add(7)) as u8)
            .collect();
        let base_blob_id = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, &base_blob);

        let mut prefix_hasher = Sha1Hasher::new();
        prefix_hasher.update(format!("blob {DELTA_BLOB_LEN}\0").as_bytes());
        for _ in 0..FULL_COPIES {
            prefix_hasher.update(&base_blob);
        }
        prefix_hasher.update(&base_blob[..TAIL_COPY_LEN]);

        let mut pack = b"PACK\0\0\0\x02".to_vec();
        let entry_count = u32::try_from(1 + DELTA_BLOB_COUNT + 2).unwrap();
        pack.extend_from_slice(&entry_count.to_be_bytes());
        let mut locations = Vec::with_capacity(entry_count as usize);

        // 1. Base blob (64 KiB)
        let base_offset = u64::try_from(pack.len()).unwrap();
        encode_pack_entry_header(3, base_blob.len(), &mut pack);
        pack.extend_from_slice(&zlib_stored(&base_blob));
        locations.push((base_blob_id, base_offset));

        // 2. Nine 24 MiB REF_DELTA blobs (216 MiB total reconstructed closure)
        let mut tree_body = Vec::new();
        tree_body.extend_from_slice(b"100644 base.bin\0");
        tree_body.extend_from_slice(base_blob_id.as_bytes());

        for index in 0..DELTA_BLOB_COUNT {
            let suffix = format!("blob-{index:02}\n");
            assert_eq!(suffix.len(), 8);
            let mut hasher = prefix_hasher.clone();
            hasher.update(suffix.as_bytes());
            let blob_id = GitOid::from(GitOidSha1::from_bytes(hasher.finish()));

            let mut delta_program = Vec::new();
            encode_delta_varint(BASE_LEN, &mut delta_program);
            encode_delta_varint(DELTA_BLOB_LEN, &mut delta_program);
            // 0x80 encodes copy from offset 0 with implicit length 0x1_0000 (65,536).
            delta_program.resize(delta_program.len() + FULL_COPIES, 0x80);
            // Copy 65,528 (0xfff8) bytes from offset 0.
            delta_program.extend_from_slice(&[0xb0, 0xf8, 0xff]);
            // Insert 8 trailing bytes.
            delta_program.push(8);
            delta_program.extend_from_slice(suffix.as_bytes());

            let offset = u64::try_from(pack.len()).unwrap();
            encode_pack_entry_header(7, delta_program.len(), &mut pack);
            pack.extend_from_slice(base_blob_id.as_bytes());
            pack.extend_from_slice(&zlib_stored(&delta_program));
            locations.push((blob_id, offset));

            tree_body.extend_from_slice(format!("100644 blob-{index:02}.bin\0").as_bytes());
            tree_body.extend_from_slice(blob_id.as_bytes());
        }

        // 3. Tree and commit
        let tree_id = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Tree, &tree_body);
        let tree_offset = u64::try_from(pack.len()).unwrap();
        encode_pack_entry_header(2, tree_body.len(), &mut pack);
        pack.extend_from_slice(&zlib_stored(&tree_body));
        locations.push((tree_id, tree_offset));

        let commit_body = format!(
            "tree {tree_id}\nauthor FrankenGit <fg@example.invalid> 1 +0000\ncommitter FrankenGit <fg@example.invalid> 1 +0000\n\nmulti-hundred-mib import fixture\n"
        )
        .into_bytes();
        let commit_id = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Commit, &commit_body);
        let commit_offset = u64::try_from(pack.len()).unwrap();
        encode_pack_entry_header(1, commit_body.len(), &mut pack);
        pack.extend_from_slice(&zlib_stored(&commit_body));
        locations.push((commit_id, commit_offset));

        let trailer = sha1_digest(&pack);
        pack.extend_from_slice(&trailer);

        let idx = build_pack_index_v2(
            &pack,
            GitHashAlgorithm::Sha1,
            &locations,
            &PackLimits::default(),
            &mut || true,
        )
        .unwrap();

        std::fs::write(source.join("objects/pack/fixture.pack"), &pack).unwrap();
        std::fs::write(source.join("objects/pack/fixture.idx"), &idx).unwrap();
        std::fs::write(source.join("refs/heads/main"), format!("{commit_id}\n")).unwrap();

        let total_bytes = u64::try_from(
            BASE_LEN + DELTA_BLOB_COUNT * DELTA_BLOB_LEN + tree_body.len() + commit_body.len(),
        )
        .unwrap();
        (commit_id, total_bytes)
    }

    #[test]
    fn multi_hundred_mib_loose_import_completes_under_default_budget_and_smaller_budget_refuses_without_ref_change()
     {
        let root = temp_root("fg-import-multi-hundred-mib");
        let source = root.join("source.git");
        let (expected_commit, expected_total_bytes) = stage_multi_hundred_mib_repository(&source);
        assert!(
            expected_total_bytes > 200 * 1024 * 1024,
            "fixture must exceed 200 MiB (got {expected_total_bytes} bytes)"
        );

        let (mut node, _) = OneNode::init(
            NodeConfig::new(
                root.join("node"),
                TenantId::from_bytes([0xf4; 16]),
                RepositoryId::from_bytes([0xf5; 16]),
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

        // 1. Refusal twin: an explicit smaller operator budget refuses mid-import
        // before canonical publication, leaving refs and authority generation untouched.
        let smaller_timeout = GitDaemonSessionTimeout::try_new(Duration::from_millis(5)).unwrap();
        let smaller_cx = node.import_request_context(Some(smaller_timeout));
        let refusal = node
            .runtime()
            .block_on(node.import_loose_git_directory_durable_in(
                &smaller_cx,
                &source,
                PrincipalId::from_bytes([0xf6; 16]),
                b"multi-hundred-mib-smaller-budget",
            ))
            .unwrap_err();
        assert!(
            matches!(
                refusal,
                crate::NodeSourceImportRefusal::Staging(ref error)
                    if matches!(
                        **error,
                        crate::LooseGitImportRefusal::Interrupted {
                            code: RefusalCode::ResourceBudgetExceeded,
                            exhaustion: Some(Exhaustion::Deadline),
                        }
                    )
            ),
            "expected ResourceBudgetExceeded(Deadline) staging refusal, got {refusal:?}"
        );
        let after_refusal = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        assert_eq!(
            before.receipt().generation(),
            after_refusal.receipt().generation()
        );
        let materialized_after_refusal = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert!(materialized_after_refusal.snapshot().refs.is_empty());

        // 2. Positive path: the default import_request_context(None) carries finite
        // poll, cost, and deadline bounds scaled to MAX_REACHABLE_OBJECT_BYTES (512 MiB)
        // and completes the >200 MiB import cleanly.
        let default_cx = node.import_request_context(None);
        let native = default_cx.authority().attached_native_cx().unwrap();
        let budget = native.budget();
        assert!(budget.deadline.is_some());
        assert!(budget.cost_quota.is_some());
        assert!(budget.poll_quota < u32::MAX);

        let imported = node
            .runtime()
            .block_on(node.import_loose_git_directory_durable_in(
                &default_cx,
                &source,
                PrincipalId::from_bytes([0xf6; 16]),
                b"multi-hundred-mib-default-budget",
            ))
            .expect("multi-hundred-MiB local import completes under default budget");
        assert_eq!(imported.commands.len(), 1);
        assert!(matches!(
            imported.commands[0].terminal.outcome,
            fgit_types::DecisionOutcome::Committed { .. }
        ));
        let materialized = node
            .runtime()
            .block_on(node.materialize_admission_in(&default_cx))
            .unwrap();
        let main_ref = fgit_types::RefName::try_new(b"refs/heads/main").unwrap();
        assert_eq!(
            materialized.snapshot().refs.get(&main_ref),
            Some(&expected_commit)
        );
        assert_eq!(
            materialized.selected_closure().closure().objects().len(),
            12
        );

        let after_commit = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        assert!(after_commit.receipt().generation() > before.receipt().generation());

        node.shutdown().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}
