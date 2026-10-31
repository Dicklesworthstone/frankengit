use super::*;

fn reference(value: &str) -> RefName {
    RefName::try_new(value.as_bytes()).unwrap()
}

#[test]
fn service_scope_cannot_widen_or_remove_schedule_bounds() {
    let make = |interval, refs| {
        MaintenanceConfig::try_new(
            IndexKind::Symbols,
            GitHashAlgorithm::Sha256,
            PathBuf::from("/private-progress"),
            false,
            interval,
            refs,
        )
    };
    let allowed = make(
        Duration::from_secs(5),
        vec![reference("refs/heads/z"), reference("refs/heads/a")],
    )
    .unwrap();
    assert_eq!(allowed.kind(), IndexKind::Symbols);
    assert_eq!(allowed.format(), GitHashAlgorithm::Sha256);
    assert_eq!(allowed.directory(), Path::new("/private-progress"));
    assert!(!allowed.initialize());
    assert_eq!(allowed.interval(), Duration::from_secs(5));
    assert_eq!(allowed.refs()[0].as_bytes(), b"refs/heads/a");
    assert_eq!(allowed.attempt_timeout(), Duration::from_secs(300));
    for interval in [
        Duration::ZERO,
        Duration::from_millis(1500),
        Duration::from_secs(3601),
    ] {
        assert!(make(interval, vec![reference("refs/heads/main")]).is_err());
        assert!(allowed.clone().with_attempt_timeout(interval).is_err());
    }
    assert_eq!(
        allowed
            .with_attempt_timeout(Duration::from_secs(1))
            .unwrap()
            .attempt_timeout(),
        Duration::from_secs(1)
    );
    assert!(make(Duration::from_secs(1), Vec::new()).is_err());
    assert!(
        make(
            Duration::from_secs(1),
            vec![reference("refs/heads/main"), reference("refs/heads/main")],
        )
        .is_err()
    );
    if let Ok(head) = RefName::try_new(b"HEAD") {
        assert!(make(Duration::from_secs(1), vec![head]).is_err());
    }
    let refs = (0..32)
        .map(|number| reference(&format!("refs/heads/r{number:02}")))
        .collect::<Vec<_>>();
    assert!(make(Duration::from_secs(3600), refs.clone()).is_ok());
    let mut too_many = refs;
    too_many.push(reference("refs/heads/extra"));
    assert!(make(Duration::from_secs(1), too_many).is_err());
    let too_wide = (0..32)
        .map(|number| reference(&format!("refs/heads/r{number:02}{}", "x".repeat(600))))
        .collect();
    assert!(make(Duration::from_secs(1), too_wide).is_err());
    assert!(
        MaintenanceConfig::try_new(
            IndexKind::Lexical,
            GitHashAlgorithm::Sha1,
            PathBuf::new(),
            true,
            Duration::from_secs(1),
            vec![reference("refs/heads/main")],
        )
        .is_err()
    );
}

#[test]
fn maintenance_groups_keep_independent_profiles_and_refuse_conflicting_owners() {
    let make = |kind, format, directory| {
        MaintenanceConfig::try_new(
            kind,
            format,
            PathBuf::from(directory),
            false,
            Duration::from_secs(1),
            vec![reference("refs/heads/main")],
        )
        .unwrap()
    };
    let lexical = make(IndexKind::Lexical, GitHashAlgorithm::Sha1, "/lexical");
    let symbols = make(IndexKind::Symbols, GitHashAlgorithm::Sha1, "/symbols");
    let group = MaintenanceGroup::try_new(vec![symbols.clone(), lexical.clone()]).unwrap();
    assert_eq!(group.configs().len(), 2);
    assert_eq!(group.configs()[0].kind(), IndexKind::Lexical);
    assert_eq!(group.configs()[0].directory(), Path::new("/lexical"));
    assert_eq!(group.configs()[1].kind(), IndexKind::Symbols);
    assert_eq!(group.configs()[1].directory(), Path::new("/symbols"));
    assert_eq!(MaintenanceGroup::from(lexical.clone()).configs().len(), 1);
    assert!(MaintenanceGroup::try_new(Vec::new()).is_err());
    assert!(MaintenanceGroup::try_new(vec![lexical.clone(), symbols, lexical.clone()]).is_err());
    assert!(
        MaintenanceGroup::try_new(vec![
            lexical.clone(),
            make(IndexKind::Lexical, GitHashAlgorithm::Sha1, "/other"),
        ])
        .is_err()
    );
    assert!(
        MaintenanceGroup::try_new(vec![
            lexical.clone(),
            make(IndexKind::Symbols, GitHashAlgorithm::Sha1, "/lexical"),
        ])
        .is_err()
    );
    assert!(
        MaintenanceGroup::try_new(vec![
            lexical,
            make(IndexKind::Symbols, GitHashAlgorithm::Sha256, "/symbols"),
        ])
        .is_err()
    );
}

#[test]
fn attempt_timeout_meets_inherited_budgets_without_replacing_other_limits() {
    use fgit_runtime::{BudgetPolicy, ClassLimits};
    for inherited_timeout in [
        Some(Duration::from_secs(7)),
        Some(Duration::from_secs(3600)),
        None,
    ] {
        let background = ClassLimits {
            timeout: inherited_timeout,
            poll_quota: 19,
            cost_quota: Some(23),
            priority: 4,
        };
        let inherited = BudgetPolicy::finite_defaults()
            .with_class_limits(BudgetClass::BackgroundController, background)
            .unwrap();
        let node = NodeConfig::new(
            PathBuf::from("/unused-node"),
            TenantId::from_bytes([1; 16]),
            RepositoryId::from_bytes([2; 16]),
        )
        .with_runtime_budgets(inherited);
        let bounded = bounded_node_config(node, Duration::from_secs(300))
            .unwrap()
            .runtime_budgets();
        let actual = bounded.limits_for(BudgetClass::BackgroundController);
        assert_eq!(
            actual.timeout,
            Some(
                inherited_timeout
                    .unwrap_or(Duration::from_secs(300))
                    .min(Duration::from_secs(300))
            )
        );
        assert_eq!(actual.poll_quota, 19);
        assert_eq!(actual.cost_quota, Some(23));
        assert_eq!(actual.priority, 4);
        for class in BudgetClass::finite_classes()
            .into_iter()
            .chain([BudgetClass::NodeRoot])
        {
            if class != BudgetClass::BackgroundController {
                assert_eq!(bounded.limits_for(class), inherited.limits_for(class));
            }
        }
    }
}

#[cfg(unix)]
mod native {
    use super::*;
    use std::cell::Cell;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "fg-maintenance-service-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
            NodeConfig::new(
                self.0.join("node"),
                TenantId::from_bytes([1; 16]),
                RepositoryId::from_bytes([2; 16]),
            )
            .with_object_format(format)
            .with_worker_threads(2)
        }

        fn initialize(&self, format: GitHashAlgorithm) -> NodeConfig {
            let config = self.config(format);
            let (node, _) = OneNode::init(config.clone()).unwrap();
            node.shutdown().unwrap();
            config
        }

        fn progress(&self) -> PathBuf {
            let path = self.0.join("maintenance");
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            path
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn config(
        kind: IndexKind,
        format: GitHashAlgorithm,
        directory: &Path,
        initialize: bool,
    ) -> MaintenanceConfig {
        MaintenanceConfig::try_new(
            kind,
            format,
            directory.to_path_buf(),
            initialize,
            Duration::from_secs(1),
            vec![reference("refs/heads/main")],
        )
        .unwrap()
    }

    #[test]
    fn ready_requires_bound_exclusive_progress_and_stop_prevents_first_attempt() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            for kind in [IndexKind::Lexical, IndexKind::Symbols] {
                let root = Scratch::new();
                let node = root.initialize(format);
                let directory = root.progress();
                let control = MaintenanceControl::default();
                let called = Cell::new(false);
                let receipt = run_service_with_ready(
                    node,
                    config(kind, format, &directory, true),
                    control.clone(),
                    || {
                        assert!(directory.join("run.lock").is_file());
                        let checkpoint = fs::read_to_string(directory.join("checkpoint")).unwrap();
                        assert!(checkpoint.contains(format.as_str()));
                        assert_eq!(checkpoint.contains("symbols1"), kind == IndexKind::Symbols);
                        called.set(true);
                        control.request_stop();
                        Ok(())
                    },
                )
                .unwrap();
                assert!(called.get());
                assert_eq!(receipt, MaintenanceReceipt::default());
                assert!(!directory.join("run.lock").exists());
                assert!(directory.join("owner.lock").is_file());
            }
        }
    }

    #[test]
    fn stopped_startup_preserves_pending_recovery_and_releases_healthy_ownership() {
        for kind in [IndexKind::Lexical, IndexKind::Symbols] {
            let root = Scratch::new();
            let node_config = root.initialize(GitHashAlgorithm::Sha1);
            let node = OneNode::open_existing(node_config.clone()).unwrap();
            let binding = kind.bind(format!(
                "{} {} {} sha1",
                node.tenant_id(),
                node.repository_id(),
                node.repository_incarnation_id(),
            ));
            node.shutdown().unwrap();
            let directory = root.progress();
            let reference = b"refs/heads/main";
            let state = State::new(binding, &[reference.to_vec()]).unwrap();
            let mut progress = ProgressFile::open(&directory, true, state).unwrap();
            progress.state.begin_preparation(reference).unwrap();
            progress.arm(reference, [9; 32]).unwrap();
            progress.release().unwrap();
            let checkpoint = fs::read(directory.join("checkpoint")).unwrap();
            let control = MaintenanceControl::default();
            control.request_stop();
            let called = Cell::new(false);
            let receipt = run_service_with_ready(
                node_config,
                config(kind, GitHashAlgorithm::Sha1, &directory, false),
                control,
                || {
                    called.set(true);
                    Ok(())
                },
            )
            .unwrap();
            assert!(!called.get());
            assert_eq!(receipt.pending, 1);
            assert_eq!(receipt.attempts, 0);
            assert_eq!(fs::read(directory.join("checkpoint")).unwrap(), checkpoint);
            assert!(!directory.join("run.lock").exists());
        }
    }

    #[test]
    fn bad_resume_and_foreign_profile_never_announce_readiness_or_reset_progress() {
        let root = Scratch::new();
        let node = root.initialize(GitHashAlgorithm::Sha1);
        let directory = root.progress();
        let called = Cell::new(false);
        let missing = run_service_with_ready(
            node.clone(),
            config(
                IndexKind::Lexical,
                GitHashAlgorithm::Sha1,
                &directory,
                false,
            ),
            MaintenanceControl::default(),
            || {
                called.set(true);
                Ok(())
            },
        );
        assert!(matches!(missing, Err(MaintenanceError::Progress(_))));
        assert!(!called.get());
        assert!(!directory.join("checkpoint").exists());
        let control = MaintenanceControl::default();
        run_service_with_ready(
            node.clone(),
            config(IndexKind::Lexical, GitHashAlgorithm::Sha1, &directory, true),
            control.clone(),
            || {
                control.request_stop();
                Ok(())
            },
        )
        .unwrap();
        let checkpoint = fs::read(directory.join("checkpoint")).unwrap();
        let foreign = run_service_with_ready(
            node.clone(),
            config(
                IndexKind::Symbols,
                GitHashAlgorithm::Sha1,
                &directory,
                false,
            ),
            MaintenanceControl::default(),
            || {
                called.set(true);
                Ok(())
            },
        );
        assert!(matches!(foreign, Err(MaintenanceError::Progress(_))));
        assert!(!called.get());
        assert_eq!(fs::read(directory.join("checkpoint")).unwrap(), checkpoint);
        let control = MaintenanceControl::default();
        run_service_with_ready(
            node,
            config(
                IndexKind::Lexical,
                GitHashAlgorithm::Sha1,
                &directory,
                false,
            ),
            control.clone(),
            || {
                control.request_stop();
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(fs::read(directory.join("checkpoint")).unwrap(), checkpoint);
    }

    #[test]
    fn readiness_failure_and_existing_stop_release_only_after_effect_free_shutdown() {
        let root = Scratch::new();
        let node = root.initialize(GitHashAlgorithm::Sha1);
        let directory = root.progress();
        let failed = run_service_with_ready(
            node.clone(),
            config(IndexKind::Lexical, GitHashAlgorithm::Sha1, &directory, true),
            MaintenanceControl::default(),
            || Err(io::Error::other("listener readiness failed")),
        );
        assert!(matches!(failed, Err(MaintenanceError::Ready(_))));
        assert!(!directory.join("run.lock").exists());
        let checkpoint = fs::read(directory.join("checkpoint")).unwrap();
        fs::write(directory.join("stop"), b"stop before readiness").unwrap();
        let called = Cell::new(false);
        let stopped = run_service_with_ready(
            node.clone(),
            config(
                IndexKind::Lexical,
                GitHashAlgorithm::Sha1,
                &directory,
                false,
            ),
            MaintenanceControl::default(),
            || {
                called.set(true);
                Ok(())
            },
        );
        assert!(matches!(stopped, Err(MaintenanceError::Ready(_))));
        assert!(!called.get());
        assert!(!directory.join("run.lock").exists());
        assert_eq!(fs::read(directory.join("checkpoint")).unwrap(), checkpoint);
        fs::remove_file(directory.join("stop")).unwrap();
        let control = MaintenanceControl::default();
        run_service_with_ready(
            node,
            config(
                IndexKind::Lexical,
                GitHashAlgorithm::Sha1,
                &directory,
                false,
            ),
            control.clone(),
            || {
                control.request_stop();
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(fs::read(directory.join("checkpoint")).unwrap(), checkpoint);
    }

    #[test]
    fn external_stop_cancels_original_context_and_keeps_polling_until_owner_returns() {
        let root = Scratch::new();
        let (mut node, _) = OneNode::init(root.config(GitHashAlgorithm::Sha1)).unwrap();
        let generation = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap()
            .receipt()
            .generation();
        node.bring_into_service(generation).unwrap();
        let directory = root.progress();
        let request = node.outbox_delivery_context();
        let reference = reference("refs/heads/main");
        let control = MaintenanceControl::default();
        let mut stop = Stop {
            control: Some(control.clone()),
            ..Stop::default()
        };
        let started = Cell::new(false);
        let drained = Cell::new(false);
        // This exercises controller ownership, not a simulated publication.
        // The original future returns only after its actual native context has
        // observed cancellation, so timer scheduling cannot fake completion.
        let future = async {
            started.set(true);
            control.request_stop();
            for _ in 0..4 {
                asupersync::time::sleep(node.runtime().now(), TICK).await;
                let result = node
                    .reconcile_source_index_local_in(
                        &request,
                        &reference,
                        None,
                        None,
                        Default::default(),
                        Default::default(),
                    )
                    .await;
                match result {
                    Err(NodeWorkspaceRefusal::Cancelled { .. }) => {
                        drained.set(true);
                        return "original owner drained";
                    }
                    Err(NodeWorkspaceRefusal::RefUnavailable) => {}
                    other => panic!("unexpected native stop observation: {other:?}"),
                }
            }
            panic!("original request did not observe cooperative stop");
        };
        let result = drive(&node, &request, &directory, future, &mut stop);
        assert_eq!(result, "original owner drained");
        assert!(started.get() && drained.get() && stop.requested);

        // The same cancelled context stays cancelled; an independent permitted
        // attempt uses a fresh context and reaches ordinary current-ref checks.
        assert!(matches!(
            node.runtime()
                .block_on(node.reconcile_source_index_local_in(
                    &request,
                    &reference,
                    None,
                    None,
                    Default::default(),
                    Default::default(),
                )),
            Err(NodeWorkspaceRefusal::Cancelled { .. })
        ));
        let fresh = node.outbox_delivery_context();
        let mut live_stop = Stop::default();
        assert_eq!(
            drive(&node, &fresh, &directory, async { 7 }, &mut live_stop),
            7
        );
        assert!(matches!(
            node.runtime()
                .block_on(node.reconcile_source_index_local_in(
                    &fresh,
                    &reference,
                    None,
                    None,
                    Default::default(),
                    Default::default(),
                )),
            Err(NodeWorkspaceRefusal::RefUnavailable)
        ));
        node.shutdown().unwrap();
    }
}
