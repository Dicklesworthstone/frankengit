use super::*;

fn arguments(operation: &str) -> Vec<String> {
    let mut args: Vec<String> = [
        operation,
        "original",
        "recovered",
        "--trusted-local",
        "--verification-root",
        "scratch",
        "--verification-instance",
        "9",
        "--expected-sha256",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--approval",
        "approval",
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
    .collect();
    if operation == "reconstruct" {
        args.extend(["--replica".into(), "replica".into()]);
    }
    args
}

#[test]
fn independent_authentication_and_all_resource_limits_are_mandatory_and_bounded() {
    let basic = arguments("catalog");
    assert_eq!(basic.len(), 24);
    let parsed = parse(&basic).unwrap();
    assert_eq!(parsed.operation, Operation::Catalog);
    assert_eq!(parsed.max_read_bytes, 4 << 30);
    let mut explicit = basic.clone();
    explicit.extend(
        [
            "--max-archive-bytes",
            "1099511627776",
            "--max-blob-bytes",
            "536870912",
            "--max-objects",
            "1000000",
            "--timeout-secs",
            "86400",
            "--max-read-bytes",
            "73667279060992",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    let parsed = parse(&explicit).unwrap();
    assert_eq!(parsed.max_read_bytes, MAX_READ_BYTES);
    assert_eq!(parsed.profile.transfer.max_archive_bytes, 1 << 40);
    assert_eq!(parsed.profile.transfer.max_blob_bytes, 512 << 20);
    assert_eq!(parsed.profile.transfer.max_objects, 1_000_000);
    assert_eq!(parsed.profile.timeout.as_secs(), 86400);
    for at in [4, 6, 8, 10, 12, 14, 16, 18, 20, 22] {
        let mut missing = explicit.clone();
        missing.drain(at..at + 2);
        assert!(parse(&missing).is_err(), "missing {}", explicit[at]);
    }
    let mut untrusted = explicit.clone();
    untrusted.remove(3);
    assert!(parse(&untrusted).is_err());
    for value in [
        "0",
        "01",
        "+1",
        "-1",
        " 1",
        "1.0",
        "73667279060993",
        "18446744073709551616",
    ] {
        let mut bad = basic.clone();
        bad.extend(["--max-read-bytes".into(), value.into()]);
        assert!(parse(&bad).is_err(), "{value}");
    }
    for extra in [
        ["--replica", "copy"],
        ["--verification-root", "other"],
        ["--force", "yes"],
        ["--max-objects", "1000001"],
        ["--verification-instance", "2"],
        ["--expected-sha256", "00"],
    ] {
        let mut bad = basic.clone();
        bad.extend(extra.into_iter().map(str::to_owned));
        assert!(parse(&bad).is_err());
    }
}

#[test]
fn replicas_are_explicit_bounded_and_deduplicated_after_lexical_normalization() {
    let mut none = arguments("reconstruct");
    none.truncate(24);
    assert!(parse(&none).is_err());
    let mut maximum = none.clone();
    for index in (0..MAX_REPLICAS).rev() {
        maximum.extend(["--replica".into(), format!("copy-{index:02}")]);
    }
    let parsed = parse(&maximum).unwrap();
    assert_eq!(parsed.replicas.len(), 64);
    assert!(parsed.replicas.windows(2).all(|pair| pair[0] < pair[1]));
    maximum.extend(["--replica".into(), "extra".into()]);
    assert!(parse(&maximum).is_err());
    let mut duplicate = arguments("reconstruct");
    duplicate.extend(["--replica".into(), "unused/.././replica".into()]);
    assert!(
        parse(&duplicate)
            .unwrap_err()
            .contains("distinct normalized")
    );
    let base = Path::new("/tmp/root");
    assert_eq!(normalized(base, Path::new("a/../link")), base.join("link"));
    assert_eq!(
        normalized(base, Path::new("/../../x/../link")),
        PathBuf::from("/link")
    );
    let mut paths = arguments("reconstruct");
    paths[25] = "a/../link".into();
    assert!(parse(&paths).unwrap().replicas[0].ends_with("link"));
}

#[test]
fn output_and_scratch_cannot_alias_inputs_controls_or_each_other() {
    let basic = arguments("reconstruct");
    for input in ["original", "approval", "public.pem", "replica"] {
        let mut bad = basic.clone();
        bad[2] = format!("a/../{input}");
        assert!(parse(&bad).is_err());
        let mut bad = basic.clone();
        bad[5] = input.into();
        assert!(parse(&bad).is_err());
        bad[5] = format!("{input}/scratch");
        assert!(parse(&bad).is_err());
    }
    for value in ["recovered", "recovered/child", "/"] {
        let mut bad = basic.clone();
        bad[5] = value.into();
        assert!(parse(&bad).is_err());
    }
    let mut descendant = basic.clone();
    descendant[1] = "scratch/archive".into();
    assert!(parse(&descendant).is_err());
    let mut nul = basic;
    nul[1] = "archive\0suffix".into();
    assert!(parse(&nul).is_err());
}
