use super::*;

#[test]
fn configured_capacity_keeps_one_request_lane_and_refuses_overflow() {
    assert!(validate_capacity(0, 0).is_err());
    assert!(validate_capacity(1, 0).is_ok());
    assert!(validate_capacity(2, 1).is_ok());
    assert!(validate_capacity(2, 2).is_err());
    assert!(validate_capacity(3, 2).is_ok());
    assert!(validate_capacity(usize::MAX, usize::MAX).is_err());
}

#[cfg(unix)]
mod native {
    use super::*;
    use crate::NodeConfig;
    use crate::index_maintenance::IndexKind;
    use fgit_types::{GitHashAlgorithm, HeadGeneration, RefName, RepositoryId, TenantId};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicU64;
    use std::time::Instant;
    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        node: Option<OneNode>,
    }
    impl Fixture {
        fn new(format: GitHashAlgorithm) -> Self {
            let root = std::env::temp_dir().join(format!(
                "fg-index-owner-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            let (mut node, _) = OneNode::init(
                NodeConfig::new(
                    root.join("node"),
                    TenantId::from_bytes([0x51; 16]),
                    RepositoryId::from_bytes([0x52; 16]),
                )
                .with_object_format(format)
                .with_worker_threads(2),
            )
            .unwrap();
            node.bring_into_service(HeadGeneration::FIRST).unwrap();
            for name in ["lexical", "symbols"] {
                let directory = root.join(name);
                fs::create_dir(&directory).unwrap();
                fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self {
                root,
                node: Some(node),
            }
        }
        fn node(&self) -> &OneNode {
            self.node.as_ref().unwrap()
        }
        fn group(&self, initialize: bool) -> MaintenanceGroup {
            MaintenanceGroup::try_new(
                [
                    ("lexical", IndexKind::Lexical),
                    ("symbols", IndexKind::Symbols),
                ]
                .into_iter()
                .map(|(name, kind)| {
                    MaintenanceConfig::try_new(
                        kind,
                        self.node().object_format(),
                        self.root.join(name),
                        initialize,
                        Duration::from_secs(1),
                        vec![RefName::try_new(b"refs/heads/main").unwrap()],
                    )
                    .unwrap()
                })
                .collect(),
            )
            .unwrap()
        }
        fn head(&self) -> Vec<u8> {
            self.node()
                .runtime()
                .block_on(self.node().authenticate_authority_head())
                .unwrap()
                .receipt()
                .body()
                .to_vec()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            if let Some(node) = self.node.take() {
                node.shutdown().unwrap();
            }
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn acquired_group_can_drain_before_activation_and_resume_without_attempts() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let fixture = Fixture::new(format);
            let head = fixture.head();
            let owner = SourceIndexService::start(fixture.node(), fixture.group(true), None)
                .unwrap()
                .unwrap();
            assert!(!owner.finished());
            let before: Vec<_> = ["lexical", "symbols"]
                .iter()
                .map(|name| fs::read(fixture.root.join(name).join("checkpoint")).unwrap())
                .collect();
            let receipts = owner.finish().unwrap();
            assert_eq!(receipts.len(), 2);
            assert!(
                receipts
                    .iter()
                    .all(|r| r.passes == 0 && r.attempts == 0 && r.pending == 0)
            );
            let resumed = SourceIndexService::start(fixture.node(), fixture.group(false), None)
                .unwrap()
                .unwrap();
            assert!(
                resumed
                    .finish()
                    .unwrap()
                    .iter()
                    .all(|r| r.passes == 0 && r.attempts == 0)
            );
            for (index, name) in ["lexical", "symbols"].iter().enumerate() {
                assert_eq!(
                    fs::read(fixture.root.join(name).join("checkpoint")).unwrap(),
                    before[index]
                );
                assert!(!fixture.root.join(name).join("run.lock").exists());
            }
            assert_eq!(fixture.head(), head);
        }
    }

    #[test]
    fn refused_second_progress_owner_never_launches_the_first_and_retains_resume_state() {
        let fixture = Fixture::new(GitHashAlgorithm::Sha1);
        let head = fixture.head();
        fs::set_permissions(
            fixture.root.join("symbols"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let error = SourceIndexService::start(fixture.node(), fixture.group(true), None)
            .err()
            .unwrap();
        assert!(error.to_string().contains("private"), "{error}");
        assert!(!fixture.root.join("lexical/run.lock").exists());
        assert_eq!(fixture.head(), head);
        let lexical = MaintenanceConfig::try_new(
            IndexKind::Lexical,
            GitHashAlgorithm::Sha1,
            fixture.root.join("lexical"),
            false,
            Duration::from_secs(1),
            vec![RefName::try_new(b"refs/heads/main").unwrap()],
        )
        .unwrap();
        let owner = SourceIndexService::start(fixture.node(), lexical.into(), None)
            .unwrap()
            .unwrap();
        assert_eq!(owner.finish().unwrap()[0].attempts, 0);
    }

    #[test]
    fn a_finished_child_stops_and_releases_siblings_without_owner_polling() {
        let fixture = Fixture::new(GitHashAlgorithm::Sha256);
        let mut owner = SourceIndexService::start(fixture.node(), fixture.group(true), None)
            .unwrap()
            .unwrap();
        owner.activate().unwrap();
        fs::write(fixture.root.join("lexical/stop"), b"").unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        // Deliberately never call owner.finished/request_stop during the wait.
        // The child's completion must cancel its sibling even with idle stdio.
        while ["lexical", "symbols"]
            .iter()
            .any(|name| fixture.root.join(name).join("run.lock").exists())
        {
            assert!(
                Instant::now() < deadline,
                "a sibling retained progress after group stop"
            );
            fixture.node().runtime().wait_for(Duration::from_millis(10));
        }
        assert_eq!(owner.finish().unwrap().len(), 2);
    }

    #[test]
    fn namespace_format_and_live_ownership_are_checked_before_launch() {
        let fixture = Fixture::new(GitHashAlgorithm::Sha1);
        let wrong = MaintenanceConfig::try_new(
            IndexKind::Lexical,
            GitHashAlgorithm::Sha256,
            fixture.root.join("lexical"),
            true,
            Duration::from_secs(1),
            vec![RefName::try_new(b"refs/heads/main").unwrap()],
        )
        .unwrap();
        assert!(SourceIndexService::start(fixture.node(), wrong.into(), None).is_err());
        assert!(!fixture.root.join("lexical/checkpoint").exists());
        let owner = SourceIndexService::start(fixture.node(), fixture.group(true), None)
            .unwrap()
            .unwrap();
        assert!(SourceIndexService::start(fixture.node(), fixture.group(false), None).is_err());
        assert!(!owner.finished());
        assert!(owner.finish().unwrap().iter().all(|r| r.attempts == 0));
    }
}
