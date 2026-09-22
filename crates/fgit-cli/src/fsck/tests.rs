use super::*;

fn oid(byte: u8, format: GitHashAlgorithm) -> GitOid {
    let width = match format {
        GitHashAlgorithm::Sha1 => 20,
        GitHashAlgorithm::Sha256 => 32,
    };
    GitOid::from_hex(format, &format!("{byte:02x}").repeat(width)).unwrap()
}

fn args(extra: &[&str]) -> Vec<String> {
    [
        "/unused",
        "11111111111111111111111111111111",
        "22222222222222222222222222222222",
        "--trusted-local",
    ]
    .into_iter()
    .chain(extra.iter().copied())
    .map(str::to_owned)
    .collect()
}

fn head(byte: u8) -> RepositoryAuthorityHeadId {
    parse_head(&format!("alg:1:{}", format!("{byte:02x}").repeat(32))).unwrap()
}

fn report() -> Report {
    Report {
        head: head(1),
        generation: 7,
        closure_root: "closure\nroot".into(),
        references: 1,
        objects: 2,
        payload_bytes: 9,
        graph: Some(GraphReport {
            objects: 2,
            references: 1,
            local_edges: 1,
            external_gitlinks: 0,
            payload_bytes: 9,
        }),
    }
}

#[test]
fn complete_scan_reads_every_selected_object_once_in_both_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let ids = BTreeSet::from([oid(1, format), oid(2, format)]);
        let mut read = Vec::new();
        let bytes = check_objects(
            &ids,
            format,
            Limits::default(),
            |id| {
                read.push(id);
                Ok(if id == oid(1, format) { 0 } else { 7 })
            },
            || Ok(()),
        )
        .unwrap();
        assert_eq!(read, ids.iter().copied().collect::<Vec<_>>());
        assert_eq!(bytes, 7);
    }
}

#[test]
fn count_and_identity_refusals_precede_object_reads() {
    let ids = BTreeSet::from([oid(1, GitHashAlgorithm::Sha1)]);
    let read = |_| -> Result<u64, String> { panic!("must refuse before object I/O") };
    assert_eq!(
        check_objects(
            &ids,
            GitHashAlgorithm::Sha1,
            Limits {
                objects: 0,
                ..Default::default()
            },
            read,
            || Ok(())
        ),
        Err(Refusal::Limit("max-objects"))
    );
    assert!(matches!(
        check_objects(
            &ids,
            GitHashAlgorithm::Sha256,
            Limits::default(),
            read,
            || Ok(())
        ),
        Err(Refusal::ObjectFormat(_))
    ));
    let zero = oid(0, GitHashAlgorithm::Sha1);
    assert_eq!(
        check_objects(
            &BTreeSet::from([zero]),
            GitHashAlgorithm::Sha1,
            Limits::default(),
            read,
            || Ok(())
        ),
        Err(Refusal::ObjectFormat(zero))
    );
}

#[test]
fn budget_and_read_failures_never_return_partial_success() {
    let format = GitHashAlgorithm::Sha1;
    let ids = BTreeSet::from([oid(1, format), oid(2, format)]);
    assert_eq!(
        check_objects(
            &ids,
            format,
            Limits {
                bytes: 5,
                ..Default::default()
            },
            |_| Ok(3),
            || Ok(())
        ),
        Err(Refusal::Limit("max-bytes"))
    );
    assert_eq!(
        check_objects(
            &ids,
            format,
            Limits {
                object_bytes: 2,
                ..Default::default()
            },
            |_| Ok(3),
            || Ok(())
        ),
        Err(Refusal::Limit("max-object-bytes"))
    );
    assert!(matches!(
        check_objects(
            &ids,
            format,
            Limits::default(),
            |_| Err("payload commitment mismatch".into()),
            || Ok(())
        ),
        Err(Refusal::Object { .. })
    ));
    assert_eq!(
        check_objects(
            &ids,
            format,
            Limits::default(),
            |_| panic!("deadline must fence reads"),
            || Err(Refusal::Deadline)
        ),
        Err(Refusal::Deadline)
    );
}

#[test]
fn empty_selection_still_observes_deadline() {
    assert_eq!(
        check_objects(
            &BTreeSet::new(),
            GitHashAlgorithm::Sha1,
            Limits::default(),
            |_| panic!("no objects"),
            || Err(Refusal::Deadline)
        ),
        Err(Refusal::Deadline)
    );
}

#[test]
fn decimal_limits_reject_signs_whitespace_zero_and_overflow() {
    for text in [
        "",
        "0",
        "-1",
        "+1",
        " 1",
        "1 ",
        "1.0",
        "18446744073709551616",
    ] {
        assert!(positive(text, u64::MAX, "limit").is_err(), "{text}");
    }
    assert_eq!(positive("9", 9, "limit").unwrap(), 9);
    assert!(positive("10", 9, "limit").is_err());
}

#[test]
fn help_distinguishes_graph_integrity_from_objects_only_and_strict_fsck() {
    assert!(USAGE.contains("including\nadmitted history"));
    assert!(USAGE.contains("--objects-only"));
    assert!(USAGE.contains("not strict Git fsck"));
    assert!(USAGE.contains("not interrupt a blocking filesystem call"));
    assert!(USAGE.contains("Gitlinks are external data"));
}

#[test]
fn parser_accepts_defaults_and_every_explicit_option_together() {
    let defaults = parse(&args(&[])).unwrap();
    assert_eq!(defaults.format, GitHashAlgorithm::Sha1);
    assert_eq!(defaults.limits.objects, 100_000);
    assert_eq!(defaults.limits.bytes, 512 * MIB);
    assert_eq!(defaults.limits.object_bytes, 32 * MIB);
    assert_eq!(defaults.limits.seconds, 300);
    assert!(!defaults.objects_only);
    assert_eq!(defaults.max_edges, 1_000_000);
    assert!(defaults.expected_head.is_none());
    let token = head_token(head(2));
    let all = args(&[
        "--object-format",
        "sha256",
        "--expected-generation",
        "3",
        "--expected-head",
        &token,
        "--max-objects",
        "2",
        "--max-bytes",
        "16",
        "--max-object-bytes",
        "8",
        "--timeout-secs",
        "1",
        "--max-edges",
        "4",
    ]);
    assert_eq!(all.len(), 20);
    let options = parse(&all).unwrap();
    assert_eq!(options.format, GitHashAlgorithm::Sha256);
    assert_eq!(options.expected_generation, Some(3));
    assert_eq!(options.expected_head, Some(head(2)));
    assert_eq!(options.max_edges, 4);
    assert_eq!(
        (
            options.limits.objects,
            options.limits.bytes,
            options.limits.object_bytes,
            options.limits.seconds
        ),
        (2, 16, 8, 1)
    );
}

#[test]
fn parser_requires_authorization_and_rejects_duplicate_or_unknown_options() {
    let mut untrusted = args(&["--max-objects", "1"]);
    untrusted.remove(3);
    assert!(parse(&untrusted).unwrap_err().contains("--trusted-local"));
    assert!(
        parse(&args(&["--trusted-local"]))
            .unwrap_err()
            .contains("duplicate")
    );
    for (flag, value) in [
        ("--max-objects", "1"),
        ("--max-bytes", "1"),
        ("--max-object-bytes", "1"),
        ("--timeout-secs", "1"),
        ("--max-edges", "1"),
        ("--expected-generation", "1"),
        ("--object-format", "sha1"),
    ] {
        assert!(
            parse(&args(&[flag, value, flag, value]))
                .unwrap_err()
                .contains("duplicate"),
            "{flag}"
        );
        assert!(parse(&args(&[flag])).is_err(), "{flag}");
    }
    let token = head_token(head(1));
    assert!(
        parse(&args(&[
            "--expected-head",
            &token,
            "--expected-head",
            &token
        ]))
        .is_err()
    );
    assert!(parse(&args(&["--repair", "yes"])).is_err());
    assert!(parse(&args(&["--object-format", "md5"])).is_err());
}

#[test]
fn parser_enforces_all_numeric_and_argument_bounds() {
    for (flag, maximum) in [
        ("--max-objects", MAX_OBJECTS as u64),
        ("--max-bytes", MAX_BYTES),
        ("--max-object-bytes", 256 * MIB),
        ("--timeout-secs", 3600),
        ("--max-edges", MAX_EDGES as u64),
    ] {
        assert!(parse(&args(&[flag, &maximum.to_string()])).is_ok());
        assert!(parse(&args(&[flag, &(maximum + 1).to_string()])).is_err());
        assert!(parse(&args(&[flag, "0"])).is_err());
    }
    assert!(parse(&[]).is_err());
    let mut bad = args(&[]);
    bad[0] = String::new();
    assert!(parse(&bad).is_err());
    bad[0] = "x".repeat(8193);
    assert!(parse(&bad).is_err());
    bad = args(&[]);
    bad[1] = "not-a-tenant".into();
    assert!(parse(&bad).is_err());
    assert!(parse(&vec!["x".into(); 21]).is_err());
}

#[test]
fn snapshot_tokens_round_trip_without_accepting_ambiguous_encodings() {
    for byte in [1, 2, 255] {
        assert_eq!(parse_head(&head_token(head(byte))).unwrap(), head(byte));
    }
    for token in [
        "",
        "deadbeef",
        "alg:0:aa",
        "alg:01:aa",
        "alg:+1:aa",
        "alg:65536:aa",
        "alg:1:",
        "alg:1:a",
        "alg:1:AA",
        "alg:1:gg",
        "alg:1:aa:bb",
        "alg:1: aa",
    ] {
        assert!(parse_head(token).is_err(), "{token}");
    }
    assert!(parse_head(&format!("alg:1:{}", "ab".repeat(65))).is_err());
}

#[test]
fn exact_head_and_generation_are_independent_required_fences() {
    let mut options = parse(&args(&[])).unwrap();
    options.expected_head = Some(head(1));
    options.expected_generation = Some(7);
    assert_eq!(check_fences(&options, head(1), 7), Ok(()));
    assert_eq!(
        check_fences(&options, head(2), 7),
        Err(Refusal::ExpectedHead)
    );
    assert_eq!(
        check_fences(&options, head(1), 8),
        Err(Refusal::Generation {
            expected: 7,
            observed: 8
        })
    );
    options.expected_generation = None;
    assert_eq!(check_fences(&options, head(1), 8), Ok(()));
    assert_eq!(
        check_fences(&options, head(2), 8),
        Err(Refusal::ExpectedHead)
    );
}

#[test]
fn exact_budget_boundary_and_zero_byte_objects_are_valid() {
    let format = GitHashAlgorithm::Sha1;
    let ids = BTreeSet::from([oid(1, format), oid(2, format)]);
    let limits = Limits {
        objects: 2,
        bytes: 6,
        object_bytes: 6,
        ..Default::default()
    };
    assert_eq!(
        check_objects(&ids, format, limits, |_| Ok(3), || Ok(())),
        Ok(6)
    );
    assert_eq!(
        check_objects(
            &ids,
            format,
            limits,
            |id| Ok(if id == oid(1, format) { 6 } else { 0 }),
            || Ok(())
        ),
        Ok(6)
    );
}

#[test]
fn corrupt_object_stops_the_scan_and_keeps_its_identity() {
    let format = GitHashAlgorithm::Sha256;
    let ids = BTreeSet::from([oid(1, format), oid(2, format), oid(3, format)]);
    let mut seen = Vec::new();
    let result = check_objects(
        &ids,
        format,
        Limits::default(),
        |id| {
            seen.push(id);
            if id == oid(2, format) {
                Err("checksum".into())
            } else {
                Ok(1)
            }
        },
        || Ok(()),
    );
    assert_eq!(
        result,
        Err(Refusal::Object {
            oid: oid(2, format),
            detail: "checksum".into()
        })
    );
    assert_eq!(seen, vec![oid(1, format), oid(2, format)]);
}

#[test]
fn deadline_after_a_read_and_byte_overflow_are_incomplete() {
    let format = GitHashAlgorithm::Sha1;
    let ids = BTreeSet::from([oid(1, format), oid(2, format)]);
    let mut reads = 0;
    let mut checkpoints = 0;
    let result = check_objects(
        &ids,
        format,
        Limits::default(),
        |_| {
            reads += 1;
            Ok(1)
        },
        || {
            checkpoints += 1;
            if checkpoints == 2 {
                Err(Refusal::Deadline)
            } else {
                Ok(())
            }
        },
    );
    assert_eq!(result, Err(Refusal::Deadline));
    assert_eq!(reads, 1);
    assert_eq!(
        check_objects(
            &ids,
            format,
            Limits {
                bytes: u64::MAX,
                object_bytes: u64::MAX,
                ..Default::default()
            },
            |_| Ok(u64::MAX),
            || Ok(())
        ),
        Err(Refusal::Limit("max-bytes"))
    );
}

#[test]
fn complete_receipt_carries_scope_snapshot_and_escaped_strings() {
    let options = parse(&args(&[])).unwrap();
    let mut output = Vec::new();
    assert_eq!(finish(&mut output, &options, Ok(report()), None), Ok(0));
    let text = String::from_utf8(output).unwrap();
    assert_eq!(text.lines().count(), 1);
    assert!(text.ends_with('\n'));
    for field in [
        "\"type\":\"repository_fsck\"",
        "\"authority_generation\":7",
        "\"objects_verified\":2",
        "\"payload_bytes_verified\":9",
        "\"complete\":true",
        "\"object_graph_verified\":true",
        "\"physical_orphans_scanned\":false",
        "\"node_closed\":true",
        "\"graph_profile\":\"native-closure-v1\"",
        "\"local_edges_verified\":1",
        "\"graph_acyclic\":true",
    ] {
        assert!(text.contains(field), "{field}: {text}");
    }
    assert!(text.contains(&format!(
        "\"selected_closure_root\":{}",
        quote("closure\nroot")
    )));
    assert!(text.contains(&format!(
        "\"snapshot_token\":{}",
        quote(&head_token(head(1)))
    )));
}

#[test]
fn failed_audit_or_shutdown_never_emits_a_success_receipt() {
    let options = parse(&args(&[])).unwrap();
    let mut output = Vec::new();
    let error = finish(
        &mut output,
        &options,
        Ok(report()),
        Some("close failed".into()),
    )
    .unwrap_err();
    assert!(error.contains("close failed"));
    assert!(output.is_empty());
    let error = finish(
        &mut output,
        &options,
        Err(Refusal::SnapshotChanged),
        Some("close failed".into()),
    )
    .unwrap_err();
    assert!(error.contains("authority_snapshot_changed"));
    assert!(error.contains("close failed"));
    assert!(output.is_empty());
    assert!(finish(&mut output, &options, Err(Refusal::Deadline), None).is_err());
    assert!(output.is_empty());
}

struct BrokenOutput {
    on_flush: bool,
    written: usize,
}
impl Write for BrokenOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if !self.on_flush {
            return Err(std::io::ErrorKind::BrokenPipe.into());
        }
        self.written += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
}

#[test]
fn write_and_flush_failures_cannot_report_success() {
    let options = parse(&args(&[])).unwrap();
    for on_flush in [false, true] {
        let mut output = BrokenOutput {
            on_flush,
            written: 0,
        };
        let error = finish(&mut output, &options, Ok(report()), None).unwrap_err();
        assert!(error.contains("fsck receipt output incomplete"));
        assert_eq!(output.written > 0, on_flush);
    }
}

#[test]
fn objects_only_is_explicit_and_cannot_accept_graph_only_options() {
    let options = parse(&args(&["--objects-only"])).unwrap();
    assert!(options.objects_only);
    assert!(parse(&args(&["--objects-only", "--objects-only"])).is_err());
    assert!(parse(&args(&["--objects-only", "--max-edges", "7"])).is_err());
    assert!(parse(&args(&["--max-edges", "7", "--objects-only"])).is_err());
    let mut bytes_report = report();
    bytes_report.graph = None;
    let mut output = Vec::new();
    assert_eq!(finish(&mut output, &options, Ok(bytes_report), None), Ok(0));
    let text = String::from_utf8(output).unwrap();
    for field in [
        "\"object_graph_verified\":false",
        "\"graph_profile\":null",
        "\"local_edges_verified\":null",
        "\"external_gitlinks\":null",
        "\"graph_acyclic\":null",
    ] {
        assert!(text.contains(field), "{field}: {text}");
    }
}

#[test]
fn absent_or_inconsistent_graph_evidence_cannot_claim_complete_default_fsck() {
    let options = parse(&args(&[])).unwrap();
    let mut cases = Vec::new();
    let mut absent = report();
    absent.graph = None;
    cases.push(absent);
    for field in 0..3 {
        let mut mismatch = report();
        let graph = mismatch.graph.as_mut().unwrap();
        match field {
            0 => graph.objects += 1,
            1 => graph.references += 1,
            _ => graph.payload_bytes += 1,
        }
        cases.push(mismatch);
    }
    for report in cases {
        let mut output = Vec::new();
        assert!(
            finish(&mut output, &options, Ok(report), None)
                .unwrap_err()
                .contains("accounting mismatch")
        );
        assert!(output.is_empty());
    }
    let objects_only = parse(&args(&["--objects-only"])).unwrap();
    let mut output = Vec::new();
    assert!(finish(&mut output, &objects_only, Ok(report()), None).is_err());
    assert!(output.is_empty());
}

#[test]
fn node_graph_refusals_preserve_budget_snapshot_and_graph_causes_without_fallback() {
    for (name, flag) in [
        ("objects", "max-objects"),
        ("object bytes", "max-object-bytes"),
        ("payload bytes", "max-bytes"),
        ("edges", "max-edges"),
    ] {
        assert_eq!(
            graph_error(GraphAuditRefusal::Graph(GraphRefusal::Limit(name))),
            Refusal::Limit(flag)
        );
    }
    assert_eq!(
        graph_error(GraphAuditRefusal::ExpectedHead),
        Refusal::ExpectedHead
    );
    assert_eq!(
        graph_error(GraphAuditRefusal::SnapshotChanged),
        Refusal::SnapshotChanged
    );
    assert_eq!(
        graph_error(GraphAuditRefusal::ExpectedGeneration {
            expected: 1,
            observed: 2
        }),
        Refusal::Generation {
            expected: 1,
            observed: 2
        }
    );
    let graph = GraphRefusal::MissingTarget {
        source: None,
        target: oid(9, GitHashAlgorithm::Sha1),
    };
    assert_eq!(
        graph_error(GraphAuditRefusal::Graph(graph.clone())),
        Refusal::Graph(graph.clone())
    );
    let mut output = Vec::new();
    let error = finish(
        &mut output,
        &parse(&args(&[])).unwrap(),
        Err(Refusal::Graph(graph)),
        None,
    )
    .unwrap_err();
    assert!(error.contains("graph_target_outside_selection"));
    assert!(output.is_empty());
}

#[test]
fn failed_whole_read_cannot_mask_a_post_read_deadline() {
    let ids = BTreeSet::from([oid(1, GitHashAlgorithm::Sha1)]);
    let mut probes = 0;
    let result = check_objects(
        &ids,
        GitHashAlgorithm::Sha1,
        Limits::default(),
        |_| Err("storage failed".into()),
        || {
            probes += 1;
            if probes == 2 {
                Err(Refusal::Deadline)
            } else {
                Ok(())
            }
        },
    );
    assert_eq!(result, Err(Refusal::Deadline));
    assert_eq!(probes, 2);
}
