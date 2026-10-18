use super::*;
fn args(operation: &str) -> Vec<String> {
    [
        operation,
        "/unopened/artifacts",
        &"1".repeat(32),
        &"2".repeat(32),
        &"3".repeat(32),
        "--trusted-local",
        "--trust-domain",
        "build",
    ]
    .iter()
    .map(|s| (*s).into())
    .collect()
}
fn put() -> Vec<String> {
    let mut values = args("put");
    values.extend(
        [
            "--source",
            "/unopened/input",
            "--payload-sha256",
            &"a".repeat(64),
            "--payload-bytes",
            "0",
            "--kind",
            "ci_artifact",
            "--media-type",
            "application/octet-stream",
        ]
        .iter()
        .map(|s| (*s).into()),
    );
    values
}
#[test]
fn artifact_options_bind_exact_identity_before_storage() {
    let values = put();
    let parsed = options::parse(&values).unwrap();
    let options::Selection::Put { identity, .. } = parsed.selection else {
        panic!()
    };
    let mut pinned = values.clone();
    pinned.extend(["--expected-id".into(), output::hash(identity.artifact_id())]);
    assert!(options::parse(&pinned).is_ok());
    *pinned.last_mut().unwrap() = "b".repeat(64);
    assert!(options::parse(&pinned).is_err());
    for kind in [
        "ci_artifact",
        "build_log",
        "release_asset",
        "sbom",
        "signature",
        "provenance",
        "git_lfs",
    ] {
        let mut variant = values.clone();
        let index = variant.iter().position(|s| s == "--kind").unwrap() + 1;
        variant[index] = kind.into();
        assert!(options::parse(&variant).is_ok());
    }
}
#[test]
fn artifact_options_refuse_ambiguous_unbounded_and_cross_operation_inputs() {
    let values = put();
    for (flag, value) in [
        ("--payload-bytes", "01"),
        ("--payload-bytes", "67108865"),
        ("--source", "/a/../b"),
        ("--source", "/a//b"),
        ("--source", "/a/./b"),
        ("--source", "relative"),
        ("--kind", "unknown"),
        ("--trust-domain", "../other"),
        ("--payload-sha256", "ABC"),
        ("--media-type", "bad\nheader"),
    ] {
        let mut invalid = values.clone();
        let index = invalid.iter().position(|s| s == flag).unwrap() + 1;
        invalid[index] = value.into();
        assert!(options::parse(&invalid).is_err(), "{flag} {value}");
    }
    let mut missing = values.clone();
    missing.retain(|s| s != "--trusted-local");
    assert!(options::parse(&missing).is_err());
    for suffix in [
        vec!["--trusted-local"],
        vec!["--id", "bad"],
        vec!["--ttl-secs", "0"],
        vec!["--max-payload-mib", "513"],
    ] {
        let mut invalid = values.clone();
        invalid.extend(suffix.into_iter().map(String::from));
        assert!(options::parse(&invalid).is_err());
    }
    let mut read = args("inspect");
    read.extend(["--id".into(), "a".repeat(64)]);
    assert!(options::parse(&read).is_ok());
    read.extend(["--source".into(), "/input".into()]);
    assert!(options::parse(&read).is_err());
    let mut export = args("export");
    export.extend(["--id".into(), "a".repeat(64)]);
    assert!(options::parse(&export).is_err());
    export.extend(["--output".into(), "/new/file".into()]);
    assert!(options::parse(&export).is_ok());
}
#[test]
fn artifact_output_failure_keeps_completed_receipt() {
    struct Broken(bool);
    impl std::io::Write for Broken {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.0 {
                Ok(bytes.len())
            } else {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
    }
    for flush in [false, true] {
        let mut errors = Vec::new();
        assert_eq!(
            output::completed(
                &mut Broken(flush),
                &mut errors,
                "{\"artifact_id\":\"original\"}"
            ),
            4
        );
        let text = String::from_utf8(errors).unwrap();
        assert!(text.contains("\"retained_result\":{\"artifact_id\":\"original\"}"));
    }
}

#[cfg(target_os = "linux")]
mod storage;
