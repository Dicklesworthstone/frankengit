use super::super::profile::Profile;
use super::*;

fn arguments() -> Vec<String> {
    [
        "replicate",
        "copies",
        "--verification-root",
        "scratch",
        "--trusted-local",
        "--candidate",
        "archive",
        "approval",
        "--expected-sha256",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--verification-instance",
        "992",
        "--trust-key",
        "public.pem",
        "--tenant-id",
        "11111111111111111111111111111111",
        "--repository-id",
        "22222222222222222222222222222222",
        "--incarnation-id",
        "33333333333333333333333333333333",
        "--object-format",
        "sha256",
        "--minimum-head-generation",
        "18446744073709551615",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn replace(args: &mut [String], flag: &str, value: &str) {
    let index = args.iter().position(|arg| arg == flag).unwrap();
    args[index + 1] = value.into();
}

#[test]
fn independent_trust_and_native_profiles_are_required_and_preserved() {
    let basic = arguments();
    assert_eq!(basic.len(), 24);
    let parsed = parse(&basic).unwrap();
    assert_eq!(parsed.selection.operation, selection::Operation::Verify);
    assert_eq!(parsed.selection.instance.raw(), 992);
    assert!(!parsed.selection.resume);
    assert!(parsed.selection.reconstruction.is_none());
    assert!(parsed.selection.replica_failover.is_none());
    assert!(parsed.selection.witness.is_none());
    assert_eq!(
        parsed.max_read_bytes,
        6 * Profile::default().transfer.max_archive_bytes
    );
    let mut full = basic.clone();
    full.extend(
        [
            "--max-archive-bytes",
            "1099511627776",
            "--max-blob-bytes",
            "536870912",
            "--max-objects",
            "1000000",
            "--timeout-secs",
            "86400",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    let parsed = parse(&full).unwrap();
    assert_eq!(parsed.selection.profile.transfer.max_archive_bytes, 1 << 40);
    assert_eq!(parsed.selection.profile.transfer.max_blob_bytes, 512 << 20);
    assert_eq!(parsed.selection.profile.transfer.max_objects, 1_000_000);
    assert_eq!(parsed.selection.profile.timeout.as_secs(), 86400);
    assert_eq!(parsed.max_read_bytes, 6 << 40);
    for flag in [
        "--verification-root",
        "--expected-sha256",
        "--verification-instance",
        "--trust-key",
        "--tenant-id",
        "--repository-id",
        "--incarnation-id",
        "--object-format",
        "--minimum-head-generation",
    ] {
        let mut missing = full.clone();
        let at = missing.iter().position(|arg| arg == flag).unwrap();
        missing.drain(at..at + 2);
        assert!(parse(&missing).is_err(), "{flag}");
    }
    let mut untrusted = full.clone();
    untrusted.retain(|arg| arg != "--trusted-local");
    assert!(parse(&untrusted).is_err());
    let mut no_candidates = full;
    let at = no_candidates
        .iter()
        .position(|arg| arg == "--candidate")
        .unwrap();
    no_candidates.drain(at..at + 3);
    assert!(parse(&no_candidates).is_err());
}

#[test]
fn finite_actual_read_budget_is_independent_of_failover_and_other_limits() {
    for failover in [false, true] {
        let mut basic = arguments();
        if failover {
            basic.push("--replica-failover".into());
        }
        basic.extend(["--max-archive-bytes".into(), "1024".into()]);
        let parsed = parse(&basic).unwrap();
        assert_eq!(parsed.max_read_bytes, 6144);
        assert_eq!(parsed.selection.replica_failover.is_some(), failover);
        for budget in [1, 4096, MAX_READ_BYTES] {
            let mut exact = basic.clone();
            exact.extend(["--max-read-bytes".into(), budget.to_string()]);
            let parsed = parse(&exact).unwrap();
            assert_eq!(parsed.max_read_bytes, budget);
            assert_eq!(parsed.selection.profile.transfer.max_archive_bytes, 1024);
            assert_eq!(
                parsed.selection.profile.transfer.max_blob_bytes,
                Profile::default().transfer.max_blob_bytes
            );
            assert_eq!(
                parsed.selection.profile.transfer.max_objects,
                Profile::default().transfer.max_objects
            );
            assert_eq!(parsed.selection.profile.timeout, Profile::default().timeout);
        }
        for value in [
            "0",
            "01",
            "+1",
            "-1",
            " 1",
            "1.0",
            "74766790688769",
            "18446744073709551616",
        ] {
            let mut invalid = basic.clone();
            invalid.extend(["--max-read-bytes".into(), value.into()]);
            assert!(parse(&invalid).is_err(), "{value}");
        }
        let mut duplicate = basic;
        duplicate.extend(
            ["--max-read-bytes", "4096", "--max-read-bytes", "4096"]
                .into_iter()
                .map(str::to_owned),
        );
        assert!(parse(&duplicate).is_err());
    }
}

#[test]
fn exact_candidate_ceiling_keeps_all_optional_controls_and_lexical_order() {
    let mut maximum = arguments();
    replace(&mut maximum, "--candidate", "copy-63");
    for index in (0..63).rev() {
        maximum.extend([
            "--candidate".into(),
            format!("copy-{index:02}"),
            "approval".into(),
        ]);
    }
    maximum.extend(
        [
            "--max-archive-bytes",
            "1099511627776",
            "--max-blob-bytes",
            "1099511627776",
            "--max-objects",
            "1000000",
            "--timeout-secs",
            "86400",
            "--witness",
            "independent-witness",
            "--replica-failover",
            "--max-read-bytes",
            "74766790688768",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    assert_eq!(maximum.len(), 226);
    let parsed = parse(&maximum).unwrap();
    assert_eq!(parsed.selection.candidates.len(), 64);
    assert!(
        parsed
            .selection
            .candidates
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    assert!(parsed.selection.witness.is_some());
    assert!(parsed.selection.replica_failover.is_some());
    assert_eq!(parsed.max_read_bytes, MAX_READ_BYTES);
    maximum.extend(["--candidate".into(), "copy-64".into(), "approval".into()]);
    assert!(parse(&maximum).is_err());
    let mut duplicate = arguments();
    duplicate.extend(
        ["--candidate", "unused/../archive", "./approval"]
            .into_iter()
            .map(str::to_owned),
    );
    assert!(
        parse(&duplicate)
            .unwrap_err()
            .contains("distinct normalized")
    );
    let mut alias = arguments();
    alias.extend(
        ["--candidate", "archive", "second-approval"]
            .into_iter()
            .map(str::to_owned),
    );
    assert_eq!(parse(&alias).unwrap().selection.candidates.len(), 2);
}

#[test]
fn replica_directory_is_separate_from_every_source_control_and_native_root() {
    for path in [
        "/",
        "scratch",
        "scratch/child",
        "archive",
        "archive/child",
        "approval",
        "public.pem",
    ] {
        let mut invalid = arguments();
        invalid[1] = path.into();
        assert!(parse(&invalid).is_err(), "{path}");
    }
    for flag in ["--verification-root", "--candidate", "--trust-key"] {
        let mut invalid = arguments();
        replace(&mut invalid, flag, "copies/nested/input");
        assert!(parse(&invalid).is_err(), "{flag}");
    }
    let mut approval_inside = arguments();
    let at = approval_inside
        .iter()
        .position(|arg| arg == "--candidate")
        .unwrap();
    approval_inside[at + 2] = "copies/approval".into();
    assert!(parse(&approval_inside).is_err());
    for witness in [
        "copies",
        "copies/witness",
        "scratch",
        "archive",
        "public.pem",
    ] {
        let mut invalid = arguments();
        invalid.extend(["--witness".into(), witness.into()]);
        assert!(parse(&invalid).is_err(), "{witness}");
    }
    let mut beneath_witness = arguments();
    beneath_witness[1] = "witness/copies".into();
    beneath_witness.extend(["--witness".into(), "witness".into()]);
    assert!(parse(&beneath_witness).is_err());
    let mut normalized = arguments();
    normalized[1] = "unused/../copies".into();
    assert_eq!(
        parse(&normalized).unwrap().directory,
        std::env::current_dir().unwrap().join("copies")
    );
}

#[test]
fn unsupported_publication_modes_duplicate_controls_and_unbounded_inputs_refuse() {
    for option in ["--resume", "--reconstruct-catalog", "--reconstruction-root"] {
        let mut invalid = arguments();
        invalid.push(option.into());
        if option != "--resume" {
            invalid.push("unused".into());
        }
        assert!(parse(&invalid).is_err(), "{option}");
    }
    for (flag, value) in [
        ("--verification-root", "other-scratch"),
        ("--force", "yes"),
        ("--approval", "single-approval"),
        ("--destination-instance", "992"),
        ("--max-objects", "1000001"),
        ("--max-archive-bytes", "1099511627777"),
        ("--max-blob-bytes", "1099511627777"),
        ("--timeout-secs", "86401"),
    ] {
        let mut invalid = arguments();
        invalid.extend([flag.into(), value.into()]);
        assert!(parse(&invalid).is_err(), "{flag}");
    }
    for flag in ["--trusted-local", "--replica-failover"] {
        let mut invalid = arguments();
        invalid.push(flag.into());
        if flag == "--replica-failover" {
            invalid.push(flag.into());
        }
        assert!(parse(&invalid).is_err(), "{flag}");
    }
    for value in ["", "archive\0suffix"] {
        let mut invalid = arguments();
        replace(&mut invalid, "--candidate", value);
        assert!(parse(&invalid).is_err());
    }
    let mut oversized = arguments();
    oversized[1] = "x".repeat(8193);
    assert!(parse(&oversized).is_err());
    let mut aggregate = arguments();
    for number in 0..40 {
        aggregate.extend([
            "--candidate".into(),
            format!("{number}-{}", "x".repeat(8000)),
            "approval".into(),
        ]);
    }
    assert!(parse(&aggregate).is_err());
    let mut incomplete = arguments();
    incomplete.extend(["--candidate".into(), "archive-only".into()]);
    assert!(parse(&incomplete).is_err());
}
