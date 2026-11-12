//! Real cooperative stops and fresh-owner recovery retain original job facts.
use super::*;
use std::time::Instant;

fn cancellable_fixture(format: GitHashAlgorithm, mode: Mode) -> Fixture {
    fixture_with_command(format, mode, |root| {
        format!(
            "printf x >> '{}'; if test ! -f '{}'; then printf ready > '{}'; sleep 30 & wait; fi",
            root.join("executed").display(),
            root.join("release").display(),
            root.join("ready-to-cancel").display(),
        )
    })
}

fn cancel_active(f: &Fixture, mode: Mode) -> Retained {
    let request = f.node().command_request_context(None);
    let ready = f.root.join("ready-to-cancel");
    let (json, retained) = std::thread::scope(|scope| {
        let observer = scope.spawn(|| {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut started = false;
            while Instant::now() < deadline {
                if fs::read(&ready).is_ok_and(|bytes| bytes == b"ready") {
                    started = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            request.cancel();
            assert!(
                started,
                "a real workflow process must start before the stop"
            );
        });
        let result = poll_with_request(f, mode, &request);
        observer.join().unwrap();
        result.unwrap()
    });
    assert!(json.contains("\"execution_settled\":true"), "{json}");
    assert!(json.contains("\"request_interrupted\":true"), "{json}");
    assert!(json.contains("\"workspaces_closed\":true"), "{json}");
    assert!(json.contains("\"outcome\":\"cancelled\""), "{json}");
    assert!(json.contains("\"succeeded\":false"), "{json}");
    let retained = retained.unwrap();
    assert_eq!(
        &fs::read(retained.event.join("check-sources")).unwrap()[..8],
        b"FGWCS002"
    );
    assert!(retained.manifest.contains("\"conclusion\":\"cancelled\""));
    assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"x");
    retained
}

#[test]
fn closed_cancellation_recovers_original_cancelled_checks_once_in_every_watch_mode() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for mode in [Mode::Ref, Mode::PullRequest, Mode::Queue] {
            let mut f = cancellable_fixture(format, mode);
            let retained = cancel_active(&f, mode);
            let settled = fs::read(retained.event.join("settled")).unwrap();
            let handoff = fs::read(retained.event.join("check-sources")).unwrap();
            let owner = fs::read(retained.child.join("execution.owner")).unwrap();
            let journal = fs::read(retained.child.join("check-proposals.journal")).unwrap();
            fs::remove_file(retained.event.join("settled")).unwrap();
            fs::remove_file(retained.child.join("report.json")).unwrap();
            fs::remove_file(retained.child.parent().unwrap().join("report.json")).unwrap();
            f.reopen();
            let (committed, previous, lines, error) = publish(&f, mode);
            assert!(error.is_none(), "{mode:?}: {error:?}");
            assert_eq!((committed, previous), (1, 0));
            assert_eq!(lines[0], retained.manifest);
            assert!(lines[1].contains("\"conclusion\":\"cancelled\""));
            assert!(lines[1].contains("\"command_committed\":true"));
            assert_eq!(fs::read(retained.event.join("settled")).unwrap(), settled);
            assert_eq!(
                fs::read(retained.event.join("check-sources")).unwrap(),
                handoff
            );
            assert_eq!(
                fs::read(retained.child.join("execution.owner")).unwrap(),
                owner
            );
            assert_eq!(
                fs::read(retained.child.join("check-proposals.journal")).unwrap(),
                journal
            );
            assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"x");
            assert_refs(&f, mode, retained.commit);
            let before = generation(f.node());
            let (repeated, dispatch) = poll(&f, mode).unwrap();
            assert!(
                repeated.contains("\"state\":\"previously_settled\""),
                "{repeated}"
            );
            assert!(dispatch.is_none());
            let (committed, previous, lines, error) = publish(&f, mode);
            assert!(error.is_none(), "{error:?}");
            assert_eq!((committed, previous), (0, 1));
            assert!(lines.is_empty());
            assert_eq!(generation(f.node()), before);
            assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"x");
        }
    }
}

fn checksum(bytes: &mut Vec<u8>) {
    let end = bytes.len() - 32;
    let digest = sha256_digest(&bytes[..end]);
    bytes[end..].copy_from_slice(&digest);
}

#[test]
fn cancelled_evidence_needs_its_v2_terminal_proof_and_exact_original_plan() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = cancellable_fixture(format, Mode::Ref);
        let retained = cancel_active(&f, Mode::Ref);
        fs::remove_file(retained.event.join("settled")).unwrap();
        let path = retained.event.join("check-sources");
        let original = fs::read(&path).unwrap();
        let terminal = original.len() - 32 - 37;
        for mutation in 0..5 {
            let mut changed = original.clone();
            match mutation {
                0 => {
                    changed.truncate(terminal);
                    changed[..8].copy_from_slice(b"FGWCS001");
                    changed.extend([0; 32]);
                }
                1 => changed[terminal + 5] ^= 1,
                2 => changed[terminal..terminal + 4].copy_from_slice(&2u32.to_be_bytes()),
                3 => changed[terminal + 4] = 0,
                4 => {
                    // A valid v2 empty prefix must not hide a real child.
                    let count = 73 + format.digest_len();
                    let suffix = changed[terminal..terminal + 37].to_vec();
                    changed.truncate(count);
                    changed.extend(0u32.to_be_bytes());
                    changed.extend(suffix);
                    changed.extend([0; 32]);
                }
                _ => unreachable!(),
            }
            checksum(&mut changed);
            fs::write(&path, &changed).unwrap();
            f.reopen();
            let before = generation(f.node());
            let (committed, previous, lines, error) = publish(&f, Mode::Ref);
            assert!(error.is_some(), "{format:?} mutation {mutation}");
            assert_eq!((committed, previous), (0, 0));
            assert!(lines.is_empty());
            assert!(!retained.event.join("settled").exists());
            assert!(!retained.event.join("reported").exists());
            assert_eq!(generation(f.node()), before);
            assert_eq!(fs::read(&path).unwrap(), changed);
            assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"x");
        }
        fs::write(path, original).unwrap();
        f.reopen();
        let (committed, previous, lines, error) = publish(&f, Mode::Ref);
        assert!(error.is_none(), "{error:?}");
        assert_eq!((committed, previous), (1, 0));
        assert_eq!(lines[0], retained.manifest);
        assert!(lines[1].contains("\"conclusion\":\"cancelled\""));
    }
}

fn advance_source(f: &mut Fixture) {
    let format = f.source.algorithm();
    let source = f.node().read_git_object(f.source).unwrap();
    let tree = std::str::from_utf8(source.payload())
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .strip_prefix("tree ")
        .unwrap();
    let tree = GitOid::from_hex(format, tree).unwrap();
    let mut objects = Objects(BTreeMap::new());
    let next = objects.put(
        format,
        GitObjectKind::Commit,
        commit_bytes(tree, &[f.source], "next event after a closed stop"),
    );
    let limits = PackLimits::default();
    let plan = PackPlanner::new(
        format,
        PackWriteProfile::COMPRESSED_NO_DELTA_V1,
        limits.clone(),
    )
    .plan_selected(&objects, &[next], &mut || true)
    .unwrap();
    let (pack, _) = PackWriter::new(limits).write(&plan, &mut || true).unwrap();
    let mut bundle = match format {
        GitHashAlgorithm::Sha1 => b"# v2 git bundle\n".to_vec(),
        GitHashAlgorithm::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".to_vec(),
    };
    bundle.extend_from_slice(
        format!("-{} original source\n{next} refs/heads/topic\n\n", f.source).as_bytes(),
    );
    bundle.extend_from_slice(&pack);
    let imported = f
        .node()
        .runtime()
        .block_on(f.node().import_incremental_git_bundle_durable_in(
            &f.node().command_request_context(None),
            &session(b"advance-after-closed-cancellation"),
            &bundle,
            &[(source_ref(), Some(f.source))],
            Default::default(),
        ))
        .unwrap();
    assert!(
        imported
            .commands
            .iter()
            .all(|row| matches!(row.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    f.source = next;
}

#[test]
fn the_same_ref_watch_can_execute_a_later_event_after_a_clean_stop() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = cancellable_fixture(format, Mode::Ref);
        let cancelled = cancel_active(&f, Mode::Ref);
        f.reopen();
        let first = publish(&f, Mode::Ref);
        assert!(first.3.is_none(), "{:?}", first.3);
        assert_eq!(first.0, 1);
        fs::write(f.root.join("release"), b"continue").unwrap();
        advance_source(&mut f);
        let (json, next) = poll(&f, Mode::Ref).unwrap();
        assert!(json.contains("\"state\":\"dispatched\""), "{json}");
        assert!(json.contains("\"execution_settled\":true"), "{json}");
        assert!(json.contains("\"succeeded\":true"), "{json}");
        let next = next.unwrap();
        assert_ne!(next.event, cancelled.event);
        assert_ne!(next.commit, cancelled.commit);
        assert_eq!(
            &fs::read(next.event.join("check-sources")).unwrap()[..8],
            b"FGWCS001"
        );
        let published = publish(&f, Mode::Ref);
        assert!(published.3.is_none(), "{:?}", published.3);
        assert_eq!((published.0, published.1), (1, 1));
        assert!(
            published
                .2
                .iter()
                .any(|line| line.contains("\"conclusion\":\"success\""))
        );
        assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"xx");
    }
}

#[test]
fn service_stop_retains_cancelled_publication_without_an_execution_reconciliation_fence() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = cancellable_fixture(format, Mode::Ref);
        let watch = WorkflowWatchConfig::try_new(
            format,
            source_ref(),
            b"ci".to_vec(),
            f.parent(),
            vec![b"ci".to_vec()],
            Duration::from_millis(20),
        )
        .unwrap()
        .with_publisher(OWNER);
        let control = WorkflowWatchControl::default();
        let ready = f.root.join("ready-to-cancel");
        let receipt = std::thread::scope(|scope| {
            let observer = scope.spawn(|| {
                let deadline = Instant::now() + Duration::from_secs(10);
                let mut started = false;
                while Instant::now() < deadline {
                    if fs::read(&ready).is_ok_and(|bytes| bytes == b"ready") {
                        started = true;
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                control.request_stop();
                assert!(started, "the owned service must start its real workflow");
            });
            let result =
                run_service_with_ready(f.config.clone(), watch.clone(), control.clone(), || Ok(()));
            observer.join().unwrap();
            result.unwrap()
        });
        assert_eq!(receipt.dispatched, 1);
        assert!(receipt.interrupted);
        assert!(receipt.non_green);
        assert!(!receipt.requires_reconciliation, "{receipt:?}");
        assert!(receipt.publication_pending);
        assert_eq!(receipt.checks_committed, 0);
        assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"x");
        let control = WorkflowWatchControl::default();
        let restarted = run_service_with_ready(f.config.clone(), watch, control.clone(), || {
            control.request_stop();
            Ok(())
        })
        .unwrap();
        assert_eq!(restarted.checks_committed, 1);
        assert_eq!(restarted.polls, 0);
        assert!(!restarted.requires_reconciliation);
        assert!(!restarted.publication_pending);
        assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"x");
    }
}
