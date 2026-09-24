use super::*;
fn arguments() -> Vec<String> {
    vec![
        "recover".into(),
        "/private/workflow".into(),
        "11".repeat(16),
        "22".repeat(16),
        "--journal-id".into(),
        "33".repeat(32),
    ]
}
fn with(extra: &[&str]) -> Vec<String> {
    let mut args = arguments();
    args.extend(extra.iter().map(|s| (*s).to_owned()));
    args
}
#[test]
fn history_defaults_and_explicit_selectors_parse_without_io() {
    let parsed = parse(&arguments()).unwrap();
    assert_eq!(parsed.timeout_ms, 30_000);
    assert!(matches!(
        parsed.selection,
        Selection::History {
            at: None,
            after: None,
            count: 32,
            bytes: 1_048_576
        }
    ));
    let checkpoint = format!("72:{}", "ab".repeat(32));
    let after = "12".repeat(32);
    let parsed = parse(&with(&[
        "--at-pin",
        &checkpoint,
        "--minimum-pin",
        &checkpoint,
        "--after-batch",
        &after,
        "--limit",
        "1",
        "--page-bytes",
        "512",
        "--timeout-ms",
        "60",
    ]))
    .unwrap();
    assert!(matches!(
        parsed.selection,
        Selection::History {
            at: Some(_),
            after: Some(_),
            count: 1,
            bytes: 512
        }
    ));
    assert_eq!(parsed.timeout_ms, 60);
}
#[test]
fn export_requires_exact_membership_selector_and_never_accepts_paging_flags() {
    let root = "aa".repeat(32);
    let parsed = parse(&with(&[
        "--batch",
        &root,
        "--evidence",
        &root,
        "--output",
        "/private/recovered.bin",
    ]))
    .unwrap();
    assert!(matches!(
        parsed.selection,
        Selection::Export {
            evidence: Some(_),
            ..
        }
    ));
    for flags in [
        vec!["--batch", root.as_str()],
        vec!["--evidence", root.as_str()],
        vec!["--output", "/private/data"],
        vec![
            "--batch",
            root.as_str(),
            "--output",
            "/private/data",
            "--limit",
            "1",
        ],
        vec!["--batch", root.as_str(), "--output", "relative"],
    ] {
        assert!(parse(&with(&flags)).is_err());
    }
}
#[test]
fn bad_domains_pins_flags_paths_and_bounds_refuse_before_io() {
    for extra in [
        vec!["--force"],
        vec!["--trusted-local"],
        vec!["--limit", "0"],
        vec!["--limit", "129"],
        vec!["--limit", "01"],
        vec!["--limit", "+1"],
        vec!["--page-bytes", "8388609"],
        vec!["--timeout-ms", "60001"],
        vec!["--at-pin", "72:ab"],
        vec!["--batch", "abcd"],
        vec!["--limit", "1", "--limit", "2"],
        vec!["--limit"],
    ] {
        assert!(parse(&with(&extra)).is_err(), "{extra:?}");
    }
    let root = "ab".repeat(32);
    for prefix in ["0", "71", "073", "4294967297", "18446744073709551616"] {
        assert!(pin(&format!("{prefix}:{root}")).is_err());
    }
    assert!(parse(&with(&["--after-batch", &root])).is_err());
    for bad in ["relative", "/private/../data", "/private/"] {
        let mut args = arguments();
        args[1] = bad.into();
        assert!(parse(&args).is_err());
    }
    for bad in ["AB".repeat(32), "ab".repeat(31), "ab".repeat(33)] {
        assert!(digest(&bad).is_err());
    }
    let mut args = arguments();
    args[2] = "AB".repeat(16);
    assert!(parse(&args).is_err());
    let mut args = arguments();
    args[1] = "x".repeat(4097);
    assert!(parse(&args).is_err());
}
#[test]
fn recovery_status_is_read_success_and_output_errors_are_not_success() {
    let mut out = Vec::new();
    assert_eq!(
        write_reply(&mut out, "{\"conclusion\":\"failure\"}").unwrap(),
        0
    );
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("broken output"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    assert!(write_reply(&mut Broken, "{}").is_err());
    struct Unflushed;
    impl Write for Unflushed {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("flush failure"))
        }
    }
    assert!(write_reply(&mut Unflushed, "{}").is_err());
}

#[cfg(target_os = "linux")]
mod disk {
    use super::*;
    use std::fs::{self, File, OpenOptions};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "fg-cli-recovery-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn sha(bytes: &[u8]) -> [u8; 32] {
        fgit_crypto::sha256_digest(bytes)
    }
    fn number(out: &mut Vec<u8>, n: u64) {
        out.extend_from_slice(&n.to_be_bytes());
    }
    fn field(out: &mut Vec<u8>, bytes: &[u8]) {
        number(out, bytes.len() as u64);
        out.extend_from_slice(bytes);
    }
    fn private(path: &std::path::Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    // Independent small wire fixture for recovery intake. These bytes claim no
    // actual execution/producer authority. The node tests use the real workflow
    // coordinator; this CLI fixture checks the saved-file interface end to end.
    struct Saved {
        temp: Temp,
        args: Vec<String>,
        completed: Vec<u8>,
        evidence: Vec<u8>,
        orphan: [u8; 32],
    }
    impl Saved {
        fn new(sha256: bool) -> Self {
            let temp = Temp::new();
            let marker = b"test-only original marker, no execution claim";
            private(&temp.0.join("attempt.json"), marker);
            let mut args = arguments();
            args[1] = temp.0.to_str().unwrap().into();
            args[5] = hex(&sha(marker));
            let mut bytes = b"FGCJ0001".to_vec();
            bytes.extend_from_slice(&[0x11; 16]);
            bytes.extend_from_slice(&[0x22; 16]);
            bytes.extend_from_slice(&sha(marker));
            let mut tail = sha(&bytes);
            let queued = proposal(sha256, None);
            append(&mut bytes, &mut tail, &[&[1], queued.as_slice()].concat());
            let evidence = b"exact tool bytes\0\xff\nnot a green check".to_vec();
            append(
                &mut bytes,
                &mut tail,
                &[&[3], sha(&evidence).as_slice(), evidence.as_slice()].concat(),
            );
            let orphan = sha(b"unreferenced private bytes");
            append(
                &mut bytes,
                &mut tail,
                &[&[3], orphan.as_slice(), b"unreferenced private bytes"].concat(),
            );
            let completed = proposal(sha256, Some(sha(&evidence)));
            append(
                &mut bytes,
                &mut tail,
                &[&[1], completed.as_slice()].concat(),
            );
            for body in [&queued, &completed] {
                append(
                    &mut bytes,
                    &mut tail,
                    &[
                        &[2],
                        sha(body).as_slice(),
                        sha(b"downstream custody").as_slice(),
                    ]
                    .concat(),
                );
            }
            private(&temp.0.join("check-proposals.journal"), &bytes);
            File::open(&temp.0).unwrap().sync_all().unwrap();
            Self {
                temp,
                args,
                completed,
                evidence,
                orphan,
            }
        }
        fn args(&self, extra: &[String]) -> Vec<String> {
            let mut args = self.args.clone();
            args.extend_from_slice(extra);
            args
        }
    }
    fn proposal(sha256: bool, evidence: Option<[u8; 32]>) -> Vec<u8> {
        let mut bytes = b"FGCP0001".to_vec();
        bytes.extend_from_slice(&[0x11; 16]);
        bytes.extend_from_slice(&[0x22; 16]);
        for label in [b"run".as_slice(), b"attempt", b"head"] {
            bytes.extend_from_slice(&sha(label));
        }
        bytes.push(if sha256 { 2 } else { 1 });
        bytes.extend(vec![3; if sha256 { 32 } else { 20 }]);
        bytes.extend_from_slice(&sha(b"graph"));
        field(&mut bytes, b"fixture");
        bytes.push(1);
        number(&mut bytes, if evidence.is_some() { 1 } else { 0 });
        number(&mut bytes, 1);
        field(&mut bytes, b"job");
        bytes.push(if evidence.is_some() { 3 } else { 1 });
        bytes.push(if evidence.is_some() { 2 } else { 0 });
        bytes.push(u8::from(evidence.is_some()));
        if let Some(evidence) = evidence {
            bytes.extend_from_slice(&evidence);
        }
        number(&mut bytes, 0);
        bytes
    }
    fn append(bytes: &mut Vec<u8>, tail: &mut [u8; 32], payload: &[u8]) {
        let length = (payload.len() as u32).to_be_bytes();
        let mut preimage = b"frankengit/check-custody-frame/v1\0".to_vec();
        preimage.extend_from_slice(tail);
        preimage.extend_from_slice(&length);
        preimage.extend_from_slice(payload);
        *tail = sha(&preimage);
        bytes.extend_from_slice(&length);
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(tail);
    }

    #[test]
    fn offline_command_reads_acknowledged_history_in_both_native_domains() {
        for sha256 in [false, true] {
            let saved = Saved::new(sha256);
            let path = saved.temp.0.join("check-proposals.journal");
            let before = fs::read(&path).unwrap();
            let mut output = Vec::new();
            assert_eq!(
                execute(parse(&saved.args).unwrap(), &mut output, &|| true).unwrap(),
                0
            );
            let text = String::from_utf8(output).unwrap();
            assert!(text.contains("\"pending_batches\":0"));
            assert!(text.contains("\"retained_batches\":2"));
            assert_eq!(text.matches("\"delivery\":\"acknowledged\"").count(), 2);
            assert!(text.contains(if sha256 {
                "\"object_format\":\"sha256\""
            } else {
                "\"object_format\":\"sha1\""
            }));
            assert!(text.contains("\"execution_completion\":\"not_asserted\""));
            assert_eq!(fs::read(path).unwrap(), before);
            assert!(!saved.temp.0.join("execution.owner").exists());
            assert!(!saved.temp.0.join("report.json").exists());
        }
    }
    #[test]
    fn exact_batch_and_referenced_evidence_export_without_consuming_history() {
        let saved = Saved::new(false);
        let before = fs::read(saved.temp.0.join("check-proposals.journal")).unwrap();
        for evidence in [false, true] {
            let path = saved.temp.0.join(if evidence {
                "evidence.bin"
            } else {
                "batch.bin"
            });
            let mut extra = vec![
                "--batch".into(),
                hex(&sha(&saved.completed)),
                "--output".into(),
                path.to_str().unwrap().into(),
            ];
            if evidence {
                extra.extend(["--evidence".into(), hex(&sha(&saved.evidence))]);
            }
            let args = saved.args(&extra);
            let mut output = Vec::new();
            assert_eq!(
                execute(parse(&args).unwrap(), &mut output, &|| true).unwrap(),
                0
            );
            assert_eq!(
                fs::read(&path).unwrap(),
                if evidence {
                    &saved.evidence
                } else {
                    &saved.completed
                }
                .as_slice()
            );
            let metadata = fs::metadata(&path).unwrap();
            assert_eq!(metadata.mode() & 0o777, 0o600);
            assert_eq!(metadata.nlink(), 1);
            assert!(execute(parse(&args).unwrap(), &mut Vec::new(), &|| true).is_err());
        }
        assert_eq!(
            fs::read(saved.temp.0.join("check-proposals.journal")).unwrap(),
            before
        );
        let destination = saved.temp.0.join("orphan.bin");
        let args = saved.args(&[
            "--batch".into(),
            hex(&sha(&saved.completed)),
            "--evidence".into(),
            hex(&saved.orphan),
            "--output".into(),
            destination.to_str().unwrap().into(),
        ]);
        assert!(execute(parse(&args).unwrap(), &mut Vec::new(), &|| true).is_err());
        assert!(!destination.exists());
    }
    #[test]
    fn malformed_scope_corruption_and_pre_cancel_do_not_create_output() {
        let saved = Saved::new(false);
        let mut args = saved.args.clone();
        args[5] = "00".repeat(32);
        assert!(execute(parse(&args).unwrap(), &mut Vec::new(), &|| true).is_err());
        assert!(execute(parse(&saved.args).unwrap(), &mut Vec::new(), &|| false).is_err());
        let path = saved.temp.0.join("check-proposals.journal");
        let mut bytes = fs::read(&path).unwrap();
        bytes.push(0);
        fs::write(path, &bytes).unwrap();
        assert!(execute(parse(&saved.args).unwrap(), &mut Vec::new(), &|| true).is_err());
        assert_eq!(fs::read_dir(&saved.temp.0).unwrap().count(), 2);
    }
    #[test]
    fn published_artifact_survives_a_lost_json_response() {
        let saved = Saved::new(false);
        let path = saved.temp.0.join("kept.bin");
        let args = saved.args(&[
            "--batch".into(),
            hex(&sha(&saved.completed)),
            "--output".into(),
            path.to_str().unwrap().into(),
        ]);
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("broken output"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let error = execute(parse(&args).unwrap(), &mut Broken, &|| true).unwrap_err();
        assert!(error.contains("exact recovered bytes remain"));
        assert_eq!(fs::read(path).unwrap(), saved.completed);
    }
    #[test]
    fn publication_refuses_symlinks_and_nonprivate_output_parents() {
        let temp = Temp::new();
        let target = temp.0.join("output");
        symlink(temp.0.join("missing"), &target).unwrap();
        assert!(publication::publish(&target, b"bytes", &|| true).is_err());
        assert!(
            fs::symlink_metadata(&target)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        fs::remove_file(&target).unwrap();
        fs::set_permissions(&temp.0, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(publication::publish(&target, b"bytes", &|| true).is_err());
        assert!(!target.exists());
        fs::set_permissions(&temp.0, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(publication::publish(&target, b"bytes", &|| false).is_err());
        assert!(!target.exists());
    }
    #[test]
    fn cancellation_and_target_race_keep_partial_bytes_off_the_destination() {
        use std::cell::Cell;
        let temp = Temp::new();
        let target = temp.0.join("output");
        let calls = Cell::new(0);
        assert!(
            publication::publish(&target, &vec![7; 32 * 1024], &|| {
                calls.set(calls.get() + 1);
                calls.get() < 3
            })
            .is_err()
        );
        assert!(!target.exists());
        assert!(fs::read_dir(&temp.0).unwrap().any(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".partial")
        }));
        let injected = Cell::new(false);
        assert!(
            publication::publish(&target, b"recovered", &|| {
                if !injected.replace(true) {
                    return true;
                }
                if !target.exists() {
                    private(&target, b"other writer");
                }
                true
            })
            .is_err()
        );
        assert_eq!(fs::read(target).unwrap(), b"other writer");
    }
}
