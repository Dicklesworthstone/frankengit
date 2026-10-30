use super::*;

fn arguments(extra: &[&str]) -> Vec<String> {
    [
        "export",
        "/storage",
        "11111111111111111111111111111111",
        "22222222222222222222222222222222",
        "/output/source.bundle",
        "--streaming",
        "--trusted-local",
    ]
    .into_iter()
    .chain(extra.iter().copied())
    .map(str::to_owned)
    .collect()
}

#[test]
fn streaming_options_keep_byte_object_and_work_bounds_independent() {
    let defaults = parse(&arguments(&[])).unwrap();
    assert_eq!(defaults.format, GitHashAlgorithm::Sha1);
    assert_eq!(defaults.query.timeout, Duration::from_secs(300));
    assert_eq!(
        defaults.query.limits.pack.max_input_bytes,
        128 * 1024 * 1024
    );
    assert_eq!(
        defaults.query.limits.pack.max_total_expanded_bytes,
        128 * 1024 * 1024
    );
    assert_eq!(
        defaults.query.limits.pack.max_object_bytes,
        32 * 1024 * 1024
    );
    assert_eq!(
        defaults.query.limits.max_streamed_blob_bytes,
        32 * 1024 * 1024
    );
    assert_eq!(defaults.query.limits.pack.max_entries, 100_000);
    assert_eq!(defaults.query.limits.pack.max_index_entries, 100_000);
    assert_eq!(defaults.query.limits.envelope.max_references, 4096);
    assert_eq!(defaults.query.limits.max_graph_edges, 1_000_000);
    assert_eq!(defaults.query.limits.max_compression_work, 1_000_000_000);
    let wide = parse(&arguments(&[
        "--max-output-mib",
        "16384",
        "--max-expanded-mib",
        "4096",
        "--max-object-mib",
        "1",
        "--max-blob-mib",
        "16384",
        "--max-objects",
        "3",
        "--max-refs",
        "2",
        "--max-edges",
        "1",
        "--max-compression-work",
        "7",
        "--timeout-secs",
        "3600",
        "--object-format",
        "sha256",
    ]))
    .unwrap();
    assert_eq!(
        wide.query.limits.envelope.max_bundle_bytes as u64,
        16_384 * MIB
    );
    assert_eq!(wide.query.limits.pack.max_input_bytes as u64, 16_384 * MIB);
    assert_eq!(
        wide.query.limits.pack.max_total_expanded_bytes as u64,
        4096 * MIB
    );
    assert_eq!(wide.query.limits.pack.max_object_bytes as u64, MIB);
    assert_eq!(
        wide.query.limits.max_streamed_blob_bytes as u64,
        16_384 * MIB
    );
    assert_eq!(wide.query.limits.pack.max_entries, 3);
    assert_eq!(wide.query.limits.pack.max_index_entries, 3);
    assert_eq!(wide.query.limits.envelope.max_references, 2);
    assert_eq!(
        wide.query.limits.envelope.max_header_bytes,
        defaults.query.limits.envelope.max_header_bytes
    );
    assert_eq!(wide.query.limits.max_graph_edges, 1);
    assert_eq!(wide.query.limits.max_compression_work, 7);
    assert_eq!(wide.query.timeout, Duration::from_secs(3600));
    assert_eq!(wide.format, GitHashAlgorithm::Sha256);
}

#[test]
fn every_limit_has_a_permitted_boundary_and_refused_successor() {
    for (flag, ceiling) in [
        ("--max-output-mib", 16_384_u64),
        ("--max-expanded-mib", 16_384),
        ("--max-object-mib", 32),
        ("--max-blob-mib", 16_384),
        ("--max-objects", 1_000_000),
        ("--max-refs", 1_000_000),
        ("--max-edges", 8_000_000),
        ("--max-compression-work", 1_000_000_000_000),
        ("--timeout-secs", 3600),
    ] {
        assert!(parse(&arguments(&[flag, "1"])).is_ok(), "{flag}");
        assert!(
            parse(&arguments(&[flag, &ceiling.to_string()])).is_ok(),
            "{flag}"
        );
        for value in [
            "0".to_owned(),
            (ceiling + 1).to_string(),
            "18446744073709551616".into(),
        ] {
            assert!(
                parse(&arguments(&[flag, &value])).is_err(),
                "{flag}={value}"
            );
        }
    }
    for invalid in ["", "01", "-1", "+1", "1.0", "1e3", " 1", "1 "] {
        assert!(
            parse(&arguments(&["--timeout-secs", invalid])).is_err(),
            "{invalid:?}"
        );
    }
}

#[test]
fn explicit_mode_and_local_grant_are_required_without_mutation_options() {
    for missing in ["--streaming", "--trusted-local"] {
        let args: Vec<_> = arguments(&[])
            .into_iter()
            .filter(|arg| arg != missing)
            .collect();
        assert!(parse(&args).is_err());
    }
    for extra in [
        vec!["--streaming"],
        vec!["--trusted-local"],
        vec!["--max-refs", "2", "--max-refs", "3"],
        vec!["--principal", "33333333333333333333333333333333"],
        vec!["--idempotency-key", "never-used"],
        vec!["--force"],
        vec!["--object-format", "sha512"],
        vec!["--max-output-mib"],
    ] {
        assert!(parse(&arguments(&extra)).is_err(), "{extra:?}");
    }
    let mut import = arguments(&[]);
    import[0] = "import".into();
    assert!(parse(&import).is_err());
    let mut nul = arguments(&[]);
    nul[4].push('\0');
    assert!(parse(&nul).is_err());
    let mut oversized = arguments(&[]);
    oversized[4] = "x".repeat(4097);
    assert!(parse(&oversized).is_err());
    let mut excessive = arguments(&[]);
    excessive.extend(std::iter::repeat_n("--streaming".into(), 40));
    assert!(parse(&excessive).is_err());
}

#[test]
fn help_requires_no_node_and_names_all_operator_bounds() {
    let mut output = Vec::new();
    let args = ["export", "--streaming", "--help"].map(str::to_owned);
    assert_eq!(run_with_output(&args, &mut output).unwrap(), 0);
    let help = String::from_utf8(output).unwrap();
    for name in [
        "--streaming",
        "--trusted-local",
        "--max-output-mib",
        "--max-compression-work",
        "--max-edges",
        "--max-blob-mib",
    ] {
        assert!(help.contains(name));
    }
}

struct BrokenOutput {
    fail_flush: bool,
    bytes: Vec<u8>,
}
impl Write for BrokenOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if !self.fail_flush {
            return Err(std::io::Error::other("injected observer disconnect"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other("injected observer flush failure"))
    }
}

#[test]
fn receipt_observer_failure_never_erases_durable_publication() {
    for fail_flush in [false, true] {
        let mut output = BrokenOutput {
            fail_flush,
            bytes: Vec::new(),
        };
        let error = emit_receipt(&mut output, "{\"bundle_created\":true}").unwrap_err();
        assert!(error.contains("publication_state=durable"));
        assert!(error.contains("bundle_created=true"));
        assert!(error.contains("file was created"));
        assert!(!error.contains("no bundle"));
        if fail_flush {
            assert_eq!(output.bytes, b"{\"bundle_created\":true}\n");
        }
    }
}
