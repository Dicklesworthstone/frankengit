use super::*;

fn command(args: &[String]) -> ProtectionCommand {
    let Operation::Set { command, .. } = parse(args).unwrap().operation else {
        panic!("set")
    };
    command
}
fn selector(job: &str) -> String {
    format!(
        "refs/heads/main:{}:{}:{job}",
        "55".repeat(16),
        "66".repeat(32)
    )
}

#[test]
fn candidate_only_and_combined_requirements_round_trip_without_a_source_branch() {
    let mut args = input();
    let old = command(&args);
    assert!(
        old.protection.branches[0]
            .required_candidate_checks
            .is_empty()
    );
    args.extend(["--require-candidate-check".into(), selector("test:日本語")]);
    let mixed = command(&args);
    assert_eq!(
        mixed.protection.branches[0].reviewers,
        old.protection.branches[0].reviewers
    );
    assert_eq!(
        mixed.protection.branches[0].required_candidate_checks[0].job,
        "test:日本語"
    );
    let shown = policy_json(&mixed.protection).unwrap();
    assert!(shown.contains("\"required_candidate_checks\":[{"));
    assert!(shown.contains("\"job\":\"test:日本語\""));
    args.drain(15..17);
    let candidate_only = command(&args);
    assert!(candidate_only.protection.branches[0].reviewers.is_empty());
    assert_eq!(candidate_only.protection.branches[0].required_approvals, 0);
    assert!(
        candidate_only.protection.branches[0]
            .required_checks
            .is_empty()
    );
}

#[test]
fn candidate_selectors_are_closed_validated_and_share_the_total_check_bound() {
    for invalid in [
        "refs/heads/main".into(),
        selector(""),
        selector("bad\njob"),
        selector("test").replace("refs/heads/main", "refs/tags/main"),
        selector("test").replace(&"55".repeat(16), "not-a-principal"),
        selector("test").replace(&"66".repeat(32), &"66".repeat(31)),
    ] {
        let mut args = input();
        args.extend(["--require-candidate-check".into(), invalid]);
        assert!(parse(&args).is_err());
    }
    let mut duplicate = input();
    for _ in 0..2 {
        duplicate.extend(["--require-candidate-check".into(), selector("test")]);
    }
    assert!(parse(&duplicate).is_err());

    let mut args = input();
    for index in 0..31 {
        args.extend([
            "--require-candidate-check".into(),
            selector(&format!("job-{index:02}")),
        ]);
    }
    args.extend([
        "--require-check".into(),
        format!(
            "refs/heads/main:refs/heads/ci:{}:{}:ordinary",
            "55".repeat(16),
            "66".repeat(32)
        ),
    ]);
    let selected = command(&args);
    assert_eq!(
        selected.protection.branches[0]
            .required_candidate_checks
            .len(),
        31
    );
    assert_eq!(selected.protection.branches[0].required_checks.len(), 1);
    args.extend(["--require-candidate-check".into(), selector("overflow")]);
    assert!(parse(&args).is_err());
}

#[test]
fn candidate_order_is_canonical_and_does_not_turn_read_actions_into_writes() {
    let mut args = input();
    args.extend([
        "--require-candidate-check".into(),
        selector("z"),
        "--require-candidate-check".into(),
        selector("a"),
    ]);
    let selected = command(&args);
    assert_eq!(
        selected.protection.branches[0].required_candidate_checks[0].job,
        "a"
    );
    args.swap(18, 20);
    assert_eq!(command(&args), selected);
    args[0] = "show".into();
    assert!(parse(&args).is_err());
}
