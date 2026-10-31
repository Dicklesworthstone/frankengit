//! Queue observation, membership and code publication never imply one another.
use super::*;

fn base() -> Vec<String> {
    vec![
        "/unused".into(),
        "11".repeat(16),
        "22".repeat(16),
        "--trusted-local".into(),
    ]
}
fn identity(args: &mut Vec<String>) {
    args.extend([
        "--principal".into(),
        "ab".repeat(16),
        "--expected-incarnation".into(),
        "cd".repeat(16),
    ]);
}

#[test]
fn all_queue_grant_combinations_are_independent_and_writes_pin_the_operator() {
    for mask in 0..8 {
        let mut args = base();
        for (bit, name) in [
            (1, "--allow-queues"),
            (2, "--allow-queue-writes"),
            (4, "--allow-queue-landings"),
        ] {
            if mask & bit != 0 {
                args.push(name.into());
            }
        }
        if mask == 0 {
            assert!(parse_options(&args).is_err());
            continue;
        }
        if mask & 6 != 0 {
            assert!(parse_options(&args).is_err());
            let mut principal_only = args.clone();
            principal_only.extend(["--principal".into(), "ab".repeat(16)]);
            assert!(parse_options(&principal_only).is_err());
            identity(&mut args);
        }
        let options = parse_options(&args).unwrap();
        assert_eq!(options.queues.read, mask & 1 != 0);
        assert_eq!(options.queues.write, mask & 2 != 0);
        assert_eq!(options.queues.land, mask & 4 != 0);
        assert!(
            !options.writes.any()
                && !options.outcomes
                && !options.issues
                && !options.pulls
                && !options.source
        );
        let names: std::collections::BTreeSet<_> = backend::tools_for_options(&options)
            .into_iter()
            .map(|tool| tool.name)
            .collect();
        for (bit, name) in [
            (1, "frankengit_queue_list"),
            (1, "frankengit_queue_show"),
            (2, "frankengit_queue_enqueue"),
            (2, "frankengit_queue_dequeue"),
            (2, "frankengit_queue_reorder"),
            (4, "frankengit_queue_land"),
        ] {
            assert_eq!(names.contains(name), mask & bit != 0);
        }
        assert_eq!(
            names.len(),
            usize::from(mask & 1 != 0) * 2
                + usize::from(mask & 2 != 0) * 3
                + usize::from(mask & 4 != 0)
        );
        if mask & 6 != 0 {
            for name in ["--principal", "--expected-incarnation"] {
                let mut altered = args.clone();
                let at = altered.iter().position(|arg| arg == name).unwrap() + 1;
                altered[at] = altered[at].to_ascii_uppercase();
                assert!(parse_options(&altered).is_err(), "noncanonical {name}");
            }
        }
    }
}

#[test]
fn existing_grants_do_not_gain_queue_capabilities() {
    let mut args = base();
    args.extend(
        [
            "--allow-issues",
            "--allow-pulls",
            "--allow-source",
            "--allow-issue-writes",
            "--allow-pull-writes",
            "--allow-source-writes",
            "--allow-review-writes",
            "--allow-reviewed-merges",
            "--allow-outcomes",
        ]
        .map(str::to_owned),
    );
    identity(&mut args);
    let options = parse_options(&args).unwrap();
    assert!(!options.queues.any());
    assert!(
        backend::tools_for_options(&options)
            .iter()
            .all(|tool| !tool.name.starts_with("frankengit_queue_"))
    );
    for flag in [
        "--allow-queues",
        "--allow-queue-writes",
        "--allow-queue-landings",
    ] {
        let mut duplicate = args.clone();
        duplicate.extend([flag.into(), flag.into()]);
        assert!(parse_options(&duplicate).is_err());
    }
}
