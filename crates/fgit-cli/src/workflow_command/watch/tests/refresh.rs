use super::*;

fn refresh_args() -> Vec<String> {
    let mut input = landing_args();
    input.extend([
        "--refresh-queue-head".into(),
        "--refresh-principal".into(),
        "77".repeat(16),
    ]);
    input
}

#[test]
fn automatic_refresh_requires_its_own_grant_and_retains_four_explicit_identities() {
    for input in [args(), merge_args(), queue_args(), landing_args()] {
        assert!(options(&input).unwrap().queue_refresh_principal.is_none());
    }
    let parsed = options(&refresh_args()).unwrap();
    assert_eq!(parsed.merge_queue, Some(7));
    assert_eq!(
        parsed.queue_refresh_principal,
        Some(fgit_types::PrincipalId::from_bytes([0x77; 16])),
    );
    assert_eq!(
        parsed.landing_principal,
        Some(fgit_types::PrincipalId::from_bytes([0x66; 16])),
    );
    assert_eq!(
        parsed.publisher,
        Some(fgit_types::PrincipalId::from_bytes([0x55; 16])),
    );
    assert_eq!(
        parsed.merge_candidate.unwrap().principal,
        fgit_types::PrincipalId::from_bytes([0x33; 16]),
    );
    // An operator can deliberately select the same principal for two roles;
    // merely configuring one role never grants the other.
    let mut same = refresh_args();
    let at = same
        .iter()
        .position(|value| value == "--refresh-principal")
        .unwrap();
    same[at + 1] = "66".repeat(16);
    let parsed = options(&same).unwrap();
    assert_eq!(parsed.queue_refresh_principal, parsed.landing_principal);

    let mut continuous = refresh_args();
    continuous.extend([
        "--continuous".into(),
        "--stop-file".into(),
        "/private/queue.stop".into(),
        "--attempt-timeout-secs".into(),
        "120".into(),
    ]);
    let parsed = options(&continuous).unwrap();
    assert!(parsed.queue_refresh_principal.is_some());
    assert_eq!(parsed.attempt_timeout, Duration::from_secs(120));
}

#[test]
fn automatic_refresh_refuses_incomplete_authority_and_selection_before_repository_io() {
    for (flag, width) in [
        ("--refresh-queue-head", 1),
        ("--refresh-principal", 2),
        ("--land-queue-head", 1),
        ("--landing-principal", 2),
        ("--publish-checks", 1),
        ("--principal-id", 2),
        ("--expected-incarnation", 2),
        ("--merge-queue", 2),
        ("--merge-candidate-ref", 2),
        ("--merge-principal", 2),
        ("--merge-author", 2),
        ("--merge-committer", 2),
        ("--merge-timestamp", 2),
        ("--merge-message", 2),
        ("--trusted-local", 1),
    ] {
        let mut input = refresh_args();
        let at = input.iter().position(|value| value == flag).unwrap();
        input.drain(at..at + width);
        let expected = options(&input).err().expect(flag);
        assert_eq!(run(&input).unwrap_err(), expected, "{flag}");
    }
    let mut no_landing = refresh_args();
    for (flag, width) in [("--land-queue-head", 1), ("--landing-principal", 2)] {
        let at = no_landing.iter().position(|value| value == flag).unwrap();
        no_landing.drain(at..at + width);
    }
    assert!(
        options(&no_landing)
            .unwrap_err()
            .contains("requires --land-queue-head")
    );
    for extra in [
        vec!["--refresh-queue-head"],
        vec!["--refresh-principal", "77777777777777777777777777777777"],
        vec!["--refresh-principal"],
        vec!["--pull-request", "7"],
        vec!["--merge-method", "squash"],
    ] {
        let mut input = refresh_args();
        input.extend(extra.into_iter().map(str::to_owned));
        assert!(options(&input).is_err(), "{input:?}");
    }
    for invalid in [
        "",
        "77",
        "not-a-principal",
        "--publish-checks",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        let mut input = refresh_args();
        let at = input
            .iter()
            .position(|value| value == "--refresh-principal")
            .unwrap();
        input[at + 1] = invalid.into();
        assert!(options(&input).is_err(), "{invalid:?}");
    }
    let mut pr = refresh_args();
    let at = pr
        .iter()
        .position(|value| value == "--merge-queue")
        .unwrap();
    pr[at] = "--pull-request".into();
    assert!(options(&pr).is_err());
    let mut tag = refresh_args();
    tag[4] = "refs/tags/v1".into();
    assert!(options(&tag).is_err());
}

#[test]
fn refresh_flags_in_literal_workflow_metadata_never_authorize_a_pr_update() {
    for literal in ["--refresh-queue-head", "--refresh-principal"] {
        let mut input = landing_args();
        let at = input
            .iter()
            .position(|value| value == "--merge-message")
            .unwrap();
        input[at + 1] = literal.into();
        let parsed = options(&input).unwrap();
        assert!(parsed.queue_refresh_principal.is_none());
        assert_eq!(
            parsed.merge_candidate.unwrap().metadata.message,
            literal.as_bytes()
        );
    }
    let mut input = refresh_args();
    input[4] = "726566732f68656164732fff".into();
    input.push("--ref-hex".into());
    let parsed = options(&input).unwrap();
    assert_eq!(parsed.execution.reference.as_bytes(), b"refs/heads/\xff");
    assert!(parsed.queue_refresh_principal.is_some());
}

#[test]
fn refresh_receipts_keep_waiting_original_recovery_and_refused_counts_explicit() {
    let mut summary = Summary {
        publication_enabled: true,
        queue_landing_enabled: true,
        queue_refresh_enabled: true,
        refreshes_committed: 1,
        refreshes_previously_decided: 2,
        refreshes_waiting: 3,
        ..Default::default()
    };
    let mut output = Vec::new();
    assert_eq!(finish(&mut output, &summary, None, None).unwrap(), 0);
    let text = String::from_utf8(output).unwrap();
    for field in [
        "\"queue_refresh_enabled\":true",
        "\"refreshes_committed\":1",
        "\"refreshes_refused\":0",
        "\"refreshes_previously_decided\":2",
        "\"refreshes_waiting\":3",
        "\"refresh_pending\":false",
        "\"requires_reconciliation\":false",
    ] {
        assert!(text.contains(field), "{field}: {text}");
    }
    summary.refresh_pending = true;
    assert_eq!(finish(&mut Vec::new(), &summary, None, None).unwrap(), 1);
    summary.refresh_pending = false;
    summary.refreshes_refused = 1;
    summary.non_green = true;
    assert_eq!(finish(&mut Vec::new(), &summary, None, None).unwrap(), 1);
    summary.reconcile = true;
    assert_eq!(
        finish(
            &mut Vec::new(),
            &summary,
            Some("refresh outcome unknown"),
            None
        )
        .unwrap(),
        2,
    );
}
