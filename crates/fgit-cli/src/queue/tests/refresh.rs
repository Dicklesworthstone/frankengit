//! Refresh retains an explicit original PR payload and exact queue guards.

use super::*;
use fgit_forge::event::pull_request::PullRequestAction;

fn refresh_args() -> Vec<String> {
    let mut args = input("land");
    args[0] = "refresh".into();
    args.extend([
        "--expected-recorded-target-tip".into(),
        "cc".repeat(20),
        "--title".into(),
        "Existing queue head é".into(),
        "--body".into(),
        "Preserve this body exactly.\nNo implicit approvals.\n".into(),
    ]);
    args
}

#[test]
fn refresh_binds_original_metadata_and_old_and_live_target_in_both_hash_formats() {
    for (format, width) in [("sha1", 20), ("sha256", 32)] {
        let mut args = refresh_args();
        args.extend(["--object-format", format].map(str::to_owned));
        replace(&mut args, "--expected-source-tip", &"aa".repeat(width));
        replace(&mut args, "--expected-target-tip", &"bb".repeat(width));
        replace(
            &mut args,
            "--expected-recorded-target-tip",
            &"cc".repeat(width),
        );
        let parsed = options::parse(&args).unwrap();
        let Operation::Refresh {
            principal,
            key,
            command,
            body_file,
        } = parsed.operation
        else {
            panic!("refresh fixture");
        };
        assert_eq!(principal, PrincipalId::from_hex(&"33".repeat(16)).unwrap());
        assert_eq!(
            key,
            fgit_authority::IdempotencyKey::new(b"private-stable-queue-key".to_vec()).unwrap()
        );
        assert!(body_file.is_none());
        assert_eq!(command.number.get(), 7);
        assert_eq!(command.expected_queue_version.get(), 2);
        assert_eq!(command.expected_policy_epoch.get(), 1);
        assert_eq!(
            command.expected_recorded_target_tip.to_string(),
            "cc".repeat(width)
        );
        let pull = &command.pull_request;
        assert_eq!(pull.number.get(), 42);
        assert_eq!(
            pull.expected_version,
            ExpectedVersion::Exactly(AggregateVersion::try_new(3).unwrap())
        );
        assert_eq!(pull.action, PullRequestAction::Update);
        assert_eq!(pull.data.source_ref.as_bytes(), b"refs/heads/topic");
        assert_eq!(pull.data.target_ref.as_bytes(), b"refs/heads/main");
        assert_eq!(pull.data.source_tip.to_string(), "aa".repeat(width));
        assert_eq!(pull.data.target_tip.to_string(), "bb".repeat(width));
        assert_eq!(pull.data.title, "Existing queue head é");
        assert_eq!(
            pull.data.body,
            "Preserve this body exactly.\nNo implicit approvals.\n"
        );
        assert_eq!(pull.data.source_tip.algorithm(), parsed.format);
        assert_eq!(
            command
                .proposed_event(principal, parsed.format)
                .unwrap()
                .version
                .get(),
            4
        );
    }
}

#[test]
fn refresh_requires_full_original_command_and_rejects_unrelated_options() {
    for flag in [
        "--trusted-local",
        "--principal",
        "--expected-incarnation",
        "--idempotency-key",
        "--expected-version",
        "--expected-policy-epoch",
        "--pull-request",
        "--expected-pull-version",
        "--source-ref",
        "--target-ref",
        "--expected-source-tip",
        "--expected-recorded-target-tip",
        "--expected-target-tip",
        "--title",
        "--body",
    ] {
        let mut args = refresh_args();
        remove(&mut args, flag);
        assert!(options::parse(&args).is_err(), "missing {flag}");
    }
    for (flag, value) in [
        ("--priority", "9"),
        ("--entry", "42"),
        ("--reason", "base-moved"),
        ("--method", "merge"),
        ("--force", "true"),
        ("--bundle", "candidate.bundle"),
        ("--passed-check", "true"),
        ("--expected-head", "ambient-latest"),
    ] {
        let mut args = refresh_args();
        args.extend([flag, value].map(str::to_owned));
        assert!(options::parse(&args).is_err(), "refresh accepted {flag}");
    }
    let mut duplicate = refresh_args();
    duplicate.extend(["--title", "replace original"].map(str::to_owned));
    assert!(options::parse(&duplicate).is_err());
}

#[test]
fn refresh_advances_only_pr_version_and_requires_a_distinct_native_target() {
    let mut maximum_queue = refresh_args();
    replace(
        &mut maximum_queue,
        "--expected-version",
        &u64::MAX.to_string(),
    );
    assert!(
        options::parse(&maximum_queue).is_ok(),
        "refresh does not advance the queue stream"
    );
    for (flag, value) in [
        ("--expected-version", "0"),
        ("--expected-version", "02"),
        ("--expected-pull-version", "0"),
        ("--expected-pull-version", "18446744073709551615"),
        ("--expected-policy-epoch", "0"),
        ("--source-ref", "refs/heads/main"),
        ("--target-ref", "refs/tags/main"),
        ("--title", " "),
        ("--title", "line\nbreak"),
    ] {
        let mut args = refresh_args();
        replace(&mut args, flag, value);
        assert!(
            options::parse(&args).is_err(),
            "refresh accepted invalid {flag}"
        );
    }
    for flag in [
        "--expected-recorded-target-tip",
        "--expected-target-tip",
        "--expected-source-tip",
    ] {
        for value in ["00".repeat(20), "dd".repeat(32)] {
            let mut args = refresh_args();
            replace(&mut args, flag, &value);
            assert!(
                options::parse(&args).is_err(),
                "refresh accepted invalid {flag}"
            );
        }
    }
    let mut unchanged = refresh_args();
    replace(
        &mut unchanged,
        "--expected-recorded-target-tip",
        &"bb".repeat(20),
    );
    assert!(
        options::parse(&unchanged).is_err(),
        "a no-op must not seal a new update"
    );
    let mut title = refresh_args();
    replace(&mut title, "--title", &"x".repeat(257));
    assert!(options::parse(&title).is_err());
}

#[test]
fn refresh_accepts_explicit_empty_body_or_one_file_and_reads_it_before_repository_io() {
    let mut empty = refresh_args();
    replace(&mut empty, "--body", "");
    assert!(options::parse(&empty).is_ok());
    let mut both = refresh_args();
    both.extend(["--body-file", "existing-body.txt"].map(str::to_owned));
    assert!(options::parse(&both).is_err());
    let mut file = refresh_args();
    remove(&mut file, "--body");
    let root = std::env::temp_dir().join(format!(
        "fg-queue-refresh-body-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let body_path = root.join("missing-body.txt");
    let storage = root.join("must-not-open-node");
    file[1] = storage.to_str().unwrap().into();
    file.extend(["--body-file".into(), body_path.to_str().unwrap().into()]);
    let parsed = options::parse(&file).unwrap();
    let Operation::Refresh {
        command, body_file, ..
    } = parsed.operation
    else {
        panic!()
    };
    assert_eq!(body_file.as_ref(), Some(&body_path));
    assert!(
        command.pull_request.data.body.is_empty(),
        "parsing does not read files"
    );
    let error = run_to(&file, &mut Vec::new()).unwrap_err();
    assert!(error.contains("PR body metadata"), "{error}");
    assert!(
        !root.exists(),
        "missing body must not open or initialize storage"
    );
    replace(&mut file, "--body-file", "");
    assert!(options::parse(&file).is_err());
}

#[test]
fn refresh_receipts_preserve_terminal_identity_without_claiming_ref_movement() {
    let options = options::parse(&refresh_args()).unwrap();
    for committed in [true, false] {
        let (tx, terminal) = terminal(committed);
        let report = output::publication(&options, incarnation(), tx, &terminal, None).unwrap();
        assert!(report.contains("\"name\":\"refresh\""));
        assert!(report.contains("\"expected_version\":2"));
        assert!(report.contains("\"expected_pull_request_version\":3"));
        assert!(report.contains("\"expected_policy_epoch\":1"));
        assert!(report.contains(&format!(
            "\"expected_recorded_target_tip\":\"{}\"",
            "cc".repeat(20)
        )));
        assert!(report.contains(&format!("\"expected_target_tip\":\"{}\"", "bb".repeat(20))));
        assert!(report.contains("\"refs_changed\":false"));
        assert!(report.contains(&format!("\"tx_id\":\"{tx}\"")));
        assert!(!report.contains("private-stable-queue-key"));
        assert!(!report.contains("unopened-queue-node"));
        let mut bytes = Vec::new();
        assert_eq!(
            finish(&mut bytes, &options, incarnation(), tx, &terminal, None).unwrap(),
            if committed { 0 } else { 3 }
        );
        let error = finish(
            &mut Vec::new(),
            &options,
            incarnation(),
            tx,
            &terminal,
            Some("shutdown failed"),
        )
        .unwrap_err();
        assert!(
            error.contains(&tx.to_string()),
            "known outcome must survive cleanup failure"
        );
    }
    let mut help = Vec::new();
    assert_eq!(
        run_to(&["refresh".into(), "--help".into()], &mut help).unwrap(),
        0
    );
    assert!(
        String::from_utf8(help)
            .unwrap()
            .contains("--expected-recorded-target-tip")
    );
}
