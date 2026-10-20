use super::*;
fn publisher() -> PrincipalId {
    PrincipalId::from_bytes([0xb3; 16])
}
fn head(f: &Fixture) -> fgit_types::RepositoryAuthorityHeadId {
    f.node()
        .runtime()
        .block_on(
            f.node()
                .materialize_admission_in(&f.node().command_request_context(None)),
        )
        .unwrap()
        .basis()
        .id()
}
macro_rules! report {
    ($f:expr,$observe:expr) => {{
        let n = $f.node();
        n.runtime()
            .block_on(n.publish_trusted_ref_workflow_checks_in(
                &n.command_request_context(None),
                &reference(),
                b"ci",
                &$f.parent(),
                publisher(),
                $observe,
            ))
    }};
}
#[test]
fn settled_jobs_publish_once_and_publisher_substitution_cannot_rekey_them() {
    for fmt in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(fmt, "push", "true");
        assert!(poll!(f).unwrap().dispatch().unwrap().succeeded());
        let before = head(&f);
        let mut receipts = Vec::new();
        let result = report!(f, |s: &str| {
            receipts.push(s.to_owned());
            Ok(())
        });
        assert!(result.error.is_none(), "{result:?}");
        assert_eq!(result.committed, 1);
        assert_eq!(result.refused, 0);
        assert_ne!(head(&f), before);
        let after = head(&f);
        assert_eq!(f.count(), "x");
        assert!(
            receipts
                .iter()
                .any(|s| s.contains("\"conclusion\":\"success\""))
        );
        f.reopen();
        let repeat = report!(f, |_: &str| Ok(()));
        assert_eq!(repeat.previously_reported, 1);
        assert_eq!(repeat.committed, 0);
        assert_eq!(head(&f), after);
        assert_eq!(poll!(f).unwrap().state(), "previously_settled");
        assert_eq!(f.count(), "x");
        let n = f.node();
        let changed = n
            .runtime()
            .block_on(n.publish_trusted_ref_workflow_checks_in(
                &n.command_request_context(None),
                &reference(),
                b"ci",
                &f.parent(),
                PrincipalId::from_bytes([8; 16]),
                |_| Ok(()),
            ));
        assert!(changed.error.unwrap().contains("publisher differs"));
        assert_eq!(head(&f), after);
    }
}
#[test]
fn lost_receipt_recovers_original_decision_and_refuses_new_stale_checks() {
    for fmt in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(
            fmt,
            "push",
            "true\n  second:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: true",
        );
        assert!(poll!(f).unwrap().dispatch().unwrap().succeeded());
        let mut first = String::new();
        let interrupted = report!(f, |s: &str| {
            if s.contains("workflow_check_set_decision") {
                first = s.into();
                return Err("receiver disconnected".into());
            }
            Ok(())
        });
        assert_eq!(interrupted.committed, 1);
        assert!(interrupted.error.is_some());
        f.reopen();
        f.advance();
        let mut replay = Vec::new();
        let resumed = report!(f, |s: &str| {
            replay.push(s.to_owned());
            Ok(())
        });
        assert!(resumed.error.is_none(), "{resumed:?}");
        assert_eq!(resumed.committed, 1);
        assert_eq!(resumed.refused, 1);
        assert!(replay.contains(&first), "original decision changed");
        assert!(replay.iter().any(|s| s.contains("TargetRefMoved")));
        assert_eq!(f.count(), "x");
        assert!(poll!(f).unwrap().dispatch().unwrap().succeeded());
        assert_eq!(f.count(), "xx");
        let fresh = report!(f, |_: &str| Ok(()));
        assert_eq!(fresh.committed, 2);
        assert_eq!(fresh.refused, 0);
    }
}
#[test]
fn corrupt_or_legacy_handoffs_and_acknowledgements_never_admit_checks() {
    let f = Fixture::new(GitHashAlgorithm::Sha1, "push", "true");
    let poll = poll!(f).unwrap();
    let event = poll
        .dispatch()
        .unwrap()
        .run_directory
        .parent()
        .unwrap()
        .to_owned();
    let handoff = event.join("check-sources");
    let original = fs::read(&handoff).unwrap();
    let before = head(&f);
    fs::remove_file(&handoff).unwrap();
    let missing = report!(f, |_: &str| panic!("must preflight first"));
    assert!(missing.error.is_some());
    assert_eq!(head(&f), before);
    fs::write(&handoff, &original).unwrap();
    fs::set_permissions(&handoff, fs::Permissions::from_mode(0o600)).unwrap();
    let mut corrupt = original.clone();
    corrupt[15] ^= 1;
    fs::write(&handoff, corrupt).unwrap();
    assert!(
        report!(f, |_: &str| panic!("invalid source must not publish"))
            .error
            .is_some()
    );
    assert_eq!(head(&f), before);
    fs::write(&handoff, original).unwrap();
    assert_eq!(report!(f, |_: &str| Ok(())).committed, 1);
    let after = head(&f);
    fs::write(event.join("reported"), [5; 32]).unwrap();
    assert!(report!(f, |_: &str| panic!("invalid ack")).error.is_some());
    assert_eq!(head(&f), after);
}
#[test]
fn ordinary_failed_jobs_report_failure_but_unresolved_execution_is_not_publishable() {
    let f = Fixture::new(GitHashAlgorithm::Sha1, "push", "exit 7");
    let polled = poll!(f).unwrap();
    assert!(!polled.dispatch().unwrap().succeeded());
    assert!(!polled.requires_reconciliation());
    let mut output = String::new();
    let result = report!(f, |s: &str| {
        output.push_str(s);
        Ok(())
    });
    assert!(result.error.is_none());
    assert_eq!(result.committed, 1);
    assert!(output.contains("\"conclusion\":\"failure\""));
    let event = polled.dispatch().unwrap().run_directory.parent().unwrap();
    fs::remove_file(event.join("settled")).unwrap();
    assert!(
        report!(f, |_: &str| panic!("unresolved must not submit"))
            .error
            .unwrap()
            .contains("unresolved")
    );
}
#[test]
fn pre_cancelled_reporting_and_foreign_journal_pins_have_no_canonical_effect() {
    let f = Fixture::new(GitHashAlgorithm::Sha256, "push", "true");
    let request = f.node().command_request_context(None);
    request.cancel();
    let stopped = f
        .node()
        .runtime()
        .block_on(f.node().publish_trusted_ref_workflow_checks_in(
            &request,
            &reference(),
            b"ci",
            &f.parent(),
            publisher(),
            |_| panic!("cancelled"),
        ));
    assert!(stopped.error.is_some());
    assert_eq!(fs::read_dir(f.parent()).unwrap().count(), 0);
    let polled = poll!(f).unwrap();
    let run = &polled.dispatch().unwrap().runs()[0];
    let bytes = fs::read(run.run_directory.join("check-proposals.journal")).unwrap();
    let before = head(&f);
    fs::write(
        run.run_directory.join("check-proposals.journal"),
        &bytes[..bytes.len() - 1],
    )
    .unwrap();
    assert!(
        report!(f, |_: &str| panic!("wrong pin before admission"))
            .error
            .is_some()
    );
    assert_eq!(head(&f), before);
    fs::write(run.run_directory.join("check-proposals.journal"), bytes).unwrap();
    assert_eq!(report!(f, |_: &str| Ok(())).committed, 1);
}
