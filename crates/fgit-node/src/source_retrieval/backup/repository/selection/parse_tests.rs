use super::*;

fn arguments(operation: &str) -> Vec<String> {
    [
        operation,
        "destination",
        "--trusted-local",
        "--candidate",
        "archive",
        "approval",
        "--expected-sha256",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        if operation == "recover" {
            "--destination-instance"
        } else {
            "--verification-instance"
        },
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

#[test]
fn native_modes_require_all_independent_inputs_and_propagate_each_profile_limit() {
    for operation in ["verify-selected", "recover"] {
        let basic = arguments(operation);
        assert_eq!(basic.len(), 22);
        let parsed = parse(&basic).unwrap();
        assert_eq!(parsed.instance.raw(), 992);
        assert!(!parsed.resume);
        assert!(parsed.witness.is_none());
        assert!(parsed.replica_failover.is_none());
        assert!(parsed.reconstruction.is_none());
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
        assert_eq!(parsed.profile.transfer.max_archive_bytes, 1 << 40);
        assert_eq!(parsed.profile.transfer.max_blob_bytes, 512 << 20);
        assert_eq!(parsed.profile.transfer.max_objects, 1_000_000);
        assert_eq!(parsed.profile.timeout.as_secs(), 86400);
        for at in [6, 8, 10, 12, 14, 16, 18, 20] {
            let mut missing = full.clone();
            missing.drain(at..at + 2);
            assert!(parse(&missing).is_err(), "missing {}", full[at]);
        }
        let mut untrusted = full.clone();
        untrusted.remove(2);
        assert!(parse(&untrusted).is_err());
        let mut no_candidates = full.clone();
        no_candidates.drain(3..6);
        assert!(parse(&no_candidates).is_err());
        let mut resumed = basic.clone();
        resumed.push("--resume".into());
        assert_eq!(parse(&resumed).is_ok(), operation == "recover");
        resumed.push("--resume".into());
        assert!(parse(&resumed).is_err());
        for (flag, value) in [
            ("--approval", "single-approval"),
            ("--max-objects", "1000001"),
            ("--force", "yes"),
            ("--max-archive-bytes", "0"),
            ("--expected-sha256", "00"),
            ("--minimum-head-generation", "1"),
        ] {
            let mut bad = basic.clone();
            bad.extend([flag.into(), value.into()]);
            assert!(parse(&bad).is_err(), "{flag}");
        }
        let mut wrong_instance = basic;
        wrong_instance[8] = if operation == "recover" {
            "--verification-instance"
        } else {
            "--destination-instance"
        }
        .into();
        assert!(parse(&wrong_instance).is_err());
    }
}

#[test]
fn replica_failover_requires_explicit_opt_in_and_a_separate_finite_read_allowance() {
    for operation in ["verify-selected", "recover"] {
        let basic = arguments(operation);
        let mut defaulted = basic.clone();
        defaulted.push("--replica-failover".into());
        let parsed = parse(&defaulted).unwrap();
        assert_eq!(
            parsed.replica_failover,
            Some(7 * parsed.profile.transfer.max_archive_bytes)
        );
        let mut narrowed = defaulted.clone();
        narrowed.extend(["--max-archive-bytes".into(), "1024".into()]);
        assert_eq!(parse(&narrowed).unwrap().replica_failover, Some(7168));
        narrowed.extend(["--max-read-bytes".into(), "1".into()]);
        let parsed = parse(&narrowed).unwrap();
        assert_eq!(parsed.replica_failover, Some(1));
        assert_eq!(parsed.profile.transfer.max_archive_bytes, 1024);
        assert_eq!(
            parsed.profile.transfer.max_blob_bytes,
            Profile::default().transfer.max_blob_bytes
        );
        assert_eq!(
            parsed.profile.transfer.max_objects,
            Profile::default().transfer.max_objects
        );
        let mut unrequested = basic;
        unrequested.extend(["--max-read-bytes".into(), "100".into()]);
        assert!(
            parse(&unrequested)
                .unwrap_err()
                .contains("requires explicit")
        );
        for value in [
            "0",
            "01",
            "-1",
            "+1",
            "75866302316545",
            "18446744073709551616",
        ] {
            let mut bad = defaulted.clone();
            bad.extend(["--max-read-bytes".into(), value.into()]);
            assert!(parse(&bad).is_err(), "{value}");
        }
        let mut duplicate = defaulted.clone();
        duplicate.push("--replica-failover".into());
        assert!(parse(&duplicate).is_err());
        let mut duplicate_budget = narrowed;
        duplicate_budget.extend(["--max-read-bytes".into(), "100".into()]);
        assert!(parse(&duplicate_budget).is_err());
        defaulted.extend([
            "--max-read-bytes".into(),
            MAX_REPLICA_READ_BYTES.to_string(),
        ]);
        assert_eq!(
            parse(&defaulted).unwrap().replica_failover,
            Some(MAX_REPLICA_READ_BYTES)
        );
    }
    let mut maximum = arguments("recover");
    for index in 1..64 {
        maximum.extend([
            "--candidate".into(),
            format!("replica-{index}"),
            "approval".into(),
        ]);
    }
    maximum.extend([
        "--max-archive-bytes".into(),
        "1099511627776".into(),
        "--max-blob-bytes".into(),
        "1099511627776".into(),
        "--max-objects".into(),
        "1000000".into(),
        "--timeout-secs".into(),
        "86400".into(),
        "--witness".into(),
        "independent-witness".into(),
        "--resume".into(),
        "--replica-failover".into(),
        "--max-read-bytes".into(),
        MAX_REPLICA_READ_BYTES.to_string(),
    ]);
    assert_eq!(maximum.len(), 225);
    assert_eq!(
        parse(&maximum).unwrap().replica_failover,
        Some(MAX_REPLICA_READ_BYTES)
    );
}

#[test]
fn optional_witness_is_bounded_unique_and_separate_from_every_protected_name() {
    for operation in ["verify-selected", "recover"] {
        let basic = arguments(operation);
        let mut witnessed = basic.clone();
        witnessed.extend(["--witness".into(), "independent-witness".into()]);
        assert!(parse(&witnessed).unwrap().witness.is_some());
        witnessed.extend(["--witness".into(), "second-witness".into()]);
        assert!(parse(&witnessed).is_err());
        for path in [
            "/",
            "destination",
            "destination/witness",
            "archive",
            "archive/witness",
            "approval",
            "public.pem",
            "public.pem/witness",
        ] {
            let mut bad = basic.clone();
            bad.extend(["--witness".into(), path.into()]);
            assert!(parse(&bad).is_err(), "{path}");
        }
        for at in [1, 4, 5, 11] {
            let mut bad = basic.clone();
            bad[at] = "witness/nested/name".into();
            bad.extend(["--witness".into(), "witness".into()]);
            assert!(parse(&bad).is_err(), "{at}");
        }
    }
    let mut maximum = arguments("recover");
    for index in 1..64 {
        maximum.extend([
            "--candidate".into(),
            format!("copy-{index}"),
            "approval".into(),
        ]);
    }
    maximum.extend([
        "--max-archive-bytes".into(),
        "1099511627776".into(),
        "--max-blob-bytes".into(),
        "1099511627776".into(),
        "--max-objects".into(),
        "1000000".into(),
        "--timeout-secs".into(),
        "86400".into(),
        "--witness".into(),
        "independent-witness".into(),
        "--resume".into(),
    ]);
    assert_eq!(maximum.len(), 222);
    let parsed = parse(&maximum).unwrap();
    assert_eq!(parsed.candidates.len(), 64);
    assert!(parsed.resume && parsed.witness.is_some());
}

#[test]
fn candidate_limit_duplicate_normalization_and_deterministic_order_are_explicit() {
    let basic = arguments("recover");
    let mut maximum = basic.clone();
    maximum[4] = "copy-63".into();
    for number in (0..63).rev() {
        maximum.extend([
            "--candidate".into(),
            format!("copy-{number:02}"),
            "approval".into(),
        ]);
    }
    let parsed = parse(&maximum).unwrap();
    assert_eq!(parsed.candidates.len(), MAX_CANDIDATES);
    assert!(parsed.candidates.windows(2).all(|pair| pair[0] < pair[1]));
    maximum.extend(["--candidate".into(), "copy-64".into(), "approval".into()]);
    assert!(parse(&maximum).is_err());
    let mut duplicate = basic.clone();
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
    let mut alias = basic.clone();
    alias.extend(
        ["--candidate", "archive", "other-approval"]
            .into_iter()
            .map(str::to_owned),
    );
    assert_eq!(parse(&alias).unwrap().candidates.len(), 2);
    let mut incomplete = basic;
    incomplete.extend(
        ["--candidate", "archive-only"]
            .into_iter()
            .map(str::to_owned),
    );
    assert!(parse(&incomplete).is_err());
}

#[test]
fn candidate_and_control_paths_cannot_overlap_native_destination_or_scratch() {
    let basic = arguments("verify-selected");
    for path in [
        "archive",
        "approval",
        "public.pem",
        "archive/child",
        "approval/child",
        "/",
    ] {
        let mut bad = basic.clone();
        bad[1] = path.into();
        assert!(parse(&bad).is_err(), "{path}");
    }
    for at in [4, 5, 11] {
        let mut bad = basic.clone();
        bad[at] = "destination/nested/input".into();
        assert!(parse(&bad).is_err());
    }
    for instance in ["0", "01", "-1", "+1", "9223372036854775808"] {
        let mut bad = basic.clone();
        bad[9] = instance.into();
        assert!(parse(&bad).is_err());
    }
    let mut nul = basic;
    nul[4] = "archive\0suffix".into();
    assert!(parse(&nul).is_err());
    assert_eq!(
        normalized(Path::new("/tmp/root"), Path::new("a/../archive")).unwrap(),
        PathBuf::from("/tmp/root/archive")
    );
}

#[test]
fn direct_reconstruction_requires_paired_exclusive_paths_and_its_own_read_profile() {
    for operation in ["verify-selected", "recover"] {
        let basic = arguments(operation);
        for flag in ["--reconstruct-catalog", "--reconstruction-root"] {
            let mut missing = basic.clone();
            missing.extend([flag.into(), "only-one-option".into()]);
            assert!(parse(&missing).unwrap_err().contains("required together"));
        }
        let mut direct = basic.clone();
        direct.extend([
            "--reconstruct-catalog".into(),
            "archive.chunks".into(),
            "--reconstruction-root".into(),
            "assembly-private".into(),
        ]);
        let parsed = parse(&direct).unwrap();
        let reconstruction = parsed.reconstruction.as_ref().unwrap();
        assert!(parsed.replica_failover.is_none());
        assert_eq!(
            reconstruction.max_read_bytes,
            8 * parsed.profile.transfer.max_archive_bytes
        );
        assert!(reconstruction.catalog.ends_with("archive.chunks"));
        assert!(reconstruction.root.ends_with("assembly-private"));
        let mut narrowed = direct.clone();
        narrowed.extend(["--max-archive-bytes".into(), "1024".into()]);
        assert_eq!(
            parse(&narrowed)
                .unwrap()
                .reconstruction
                .unwrap()
                .max_read_bytes,
            8192
        );
        narrowed.extend(["--max-read-bytes".into(), "1".into()]);
        let parsed = parse(&narrowed).unwrap();
        assert_eq!(parsed.reconstruction.unwrap().max_read_bytes, 1);
        assert_eq!(parsed.profile.transfer.max_archive_bytes, 1024);
        assert_eq!(
            parsed.profile.transfer.max_blob_bytes,
            Profile::default().transfer.max_blob_bytes
        );
        assert_eq!(
            parsed.profile.transfer.max_objects,
            Profile::default().transfer.max_objects
        );
        for value in [
            "0",
            "01",
            "+1",
            "-1",
            "76965813944321",
            "18446744073709551616",
        ] {
            let mut bad = direct.clone();
            bad.extend(["--max-read-bytes".into(), value.into()]);
            assert!(parse(&bad).is_err(), "{operation}: {value}");
        }
        for maximum in [MAX_REPLICA_READ_BYTES + 1, MAX_RECONSTRUCTION_READ_BYTES] {
            let mut permitted = direct.clone();
            permitted.extend(["--max-read-bytes".into(), maximum.to_string()]);
            assert_eq!(
                parse(&permitted)
                    .unwrap()
                    .reconstruction
                    .unwrap()
                    .max_read_bytes,
                maximum
            );
        }
        for flag in ["--reconstruct-catalog", "--reconstruction-root"] {
            let mut duplicate = direct.clone();
            duplicate.extend([flag.into(), "other".into()]);
            assert!(parse(&duplicate).is_err());
        }
        let mut mixed = direct.clone();
        mixed.push("--replica-failover".into());
        assert!(parse(&mixed).unwrap_err().contains("mutually exclusive"));
        let mut duplicate_budget = narrowed;
        duplicate_budget.extend(["--max-read-bytes".into(), "100".into()]);
        assert!(parse(&duplicate_budget).is_err());
        direct.push("--resume".into());
        assert_eq!(parse(&direct).is_ok(), operation == "recover");
    }
    let mut maximum = arguments("recover");
    for index in 1..64 {
        maximum.extend([
            "--candidate".into(),
            format!("copy-{index}"),
            "approval".into(),
        ]);
    }
    maximum.extend([
        "--max-archive-bytes".into(),
        "1099511627776".into(),
        "--max-blob-bytes".into(),
        "1099511627776".into(),
        "--max-objects".into(),
        "1000000".into(),
        "--timeout-secs".into(),
        "86400".into(),
        "--witness".into(),
        "independent-witness".into(),
        "--resume".into(),
        "--reconstruct-catalog".into(),
        "archive.chunks".into(),
        "--reconstruction-root".into(),
        "assembly-private".into(),
        "--max-read-bytes".into(),
        MAX_RECONSTRUCTION_READ_BYTES.to_string(),
    ]);
    assert_eq!(maximum.len(), 228);
    let parsed = parse(&maximum).unwrap();
    assert!(parsed.resume && parsed.witness.is_some());
    assert_eq!(parsed.candidates.len(), 64);
    assert_eq!(
        parsed.reconstruction.unwrap().max_read_bytes,
        MAX_RECONSTRUCTION_READ_BYTES
    );
}

#[test]
fn direct_private_root_is_bounded_and_separate_from_all_named_inputs_and_controls() {
    for operation in ["verify-selected", "recover"] {
        let mut basic = arguments(operation);
        basic.extend([
            "--witness".into(),
            "witness".into(),
            "--reconstruct-catalog".into(),
            "archive.chunks".into(),
        ]);
        for path in [
            "/",
            "destination",
            "destination/assembly",
            "archive",
            "archive/assembly",
            "approval",
            "public.pem",
            "archive.chunks",
            "archive.chunks/assembly",
            "witness",
            "witness/assembly",
        ] {
            let mut bad = basic.clone();
            bad.extend(["--reconstruction-root".into(), path.into()]);
            assert!(parse(&bad).is_err(), "{operation}: {path}");
        }
        for at in [1, 4, 5, 11, 23, 25] {
            let mut bad = basic.clone();
            bad[at] = "assembly/nested/input".into();
            bad.extend(["--reconstruction-root".into(), "assembly".into()]);
            assert!(parse(&bad).is_err(), "{operation}: {at}");
        }
        let mut permitted = basic.clone();
        permitted.extend(["--reconstruction-root".into(), "assembly/../private".into()]);
        assert!(
            parse(&permitted)
                .unwrap()
                .reconstruction
                .unwrap()
                .root
                .ends_with("private")
        );
        let mut oversized = basic;
        oversized.extend(["--reconstruction-root".into(), "x".repeat(8193)]);
        assert!(parse(&oversized).is_err());
    }
}
