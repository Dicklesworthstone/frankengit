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
