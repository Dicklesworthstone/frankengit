use super::*;
use fgit_crypto::{GitObjectKind, IdentityDomain, git_object_id, internal_object_id};
use fgit_forge::source_search::SourceMatch;
use fgit_forge::source_symbols::{SymbolMatch, SymbolSyntaxError, SymbolSyntaxErrorKind};
use fgit_types::{CodecVersion, RepositoryCommitId, SchemaFamily, SchemaId};

fn args() -> Vec<String> {
    vec!["node".into(), "11".repeat(16), "22".repeat(16), "refs/heads/main".into(),
        "--trusted-local".into(), "--name".into(), "needle".into()]
}
fn head() -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_internal_object_id(internal_object_id(
        IdentityDomain::RepositoryAuthorityHead,
        SchemaId::new(SchemaFamily::from_static("repository-authority-head"), 1, 0),
        CodecVersion::new(1, 0), b"symbol-cli-head",
    )).unwrap()
}
fn report() -> SymbolSearchReport {
    SymbolSearchReport {
        repository: RepositoryId::from_bytes([0x22; 16]),
        source_rcr: RepositoryCommitId::from_internal_object_id(internal_object_id(
            IdentityDomain::RepositoryCommitRecord,
            SchemaId::new(SchemaFamily::from_static("repository-commit-record"), 1, 0),
            CodecVersion::new(1, 0), b"symbol-cli-rcr",
        )).unwrap(),
        source_commit: git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Commit, b"commit"),
        source_tree: git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Tree, b"tree"),
        matches: Vec::new(), completion: SearchCompletion::Complete,
        files_selected: 1, files_read: 1, bytes_read: 32, bytes_searched: 32,
        non_regular_entries: 2, unsupported_language_files: 3, declarations_examined: 4,
        macro_bodies_skipped: 5, attributes_skipped: 6, work_units: u64::MAX,
    }
}

#[test]
fn parses_case_sensitive_names_kinds_byte_paths_and_both_native_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut args = args();
        args.extend([
            "--object-format", format.as_str(), "--match", "prefix", "--kind", "struct",
            "--kind", "function", "--path-hex", "737263ff", "--max-work", "1024",
        ].map(str::to_owned));
        let options = options::parse(&args).unwrap();
        assert_eq!(options.format, format);
        assert_eq!(options.query.name(), b"needle");
        assert_eq!(options.query.mode(), SymbolMatchMode::Prefix);
        assert_eq!(options.query.kinds(), &[SymbolKind::Function, SymbolKind::Struct]);
        assert_eq!(options.query.source_scope().prefixes()[0].as_bytes(), b"src\xff");
        assert_eq!(options.query.maximum_work(), 1024);
    }
}

#[test]
fn round_trips_snapshot_tokens_and_validates_commit_hash_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let commit = git_object_id(format, GitObjectKind::Commit, b"commit");
        let mut args = args();
        args.extend(["--object-format".into(), format.as_str().into(),
            "--expected-head".into(), head_token(head()),
            "--expected-commit".into(), commit.to_string()]);
        let options = options::parse(&args).unwrap();
        assert_eq!(options.expected_head, Some(head()));
        assert_eq!(options.expected_commit, Some(commit));
        *args.last_mut().unwrap() = "00".repeat(if format == GitHashAlgorithm::Sha1 { 20 } else { 32 });
        assert!(options::parse(&args).is_err());
        *args.last_mut().unwrap() = "11".repeat(if format == GitHashAlgorithm::Sha1 { 32 } else { 20 });
        assert!(options::parse(&args).is_err());
    }
}

#[test]
fn refuses_unsupported_queries_duplicates_limits_and_unqualified_pins() {
    for pair in [
        ["--name", "other"], ["--regex", ".*"], ["--after", "1"],
        ["--match", "fuzzy"], ["--kind", "reference"], ["--path", "../secret"],
        ["--path-hex", "ffz0"], ["--object-format", "SHA256"],
        ["--max-matches", "4097"], ["--max-work", "67108865"],
        ["--max-work", "18446744073709551616"], ["--max-work", "0"],
        ["--max-files", "01"], ["--max-files", "20001"], ["--max-bytes", "67108865"],
        ["--max-file-bytes", "8388609"], ["--expected-head", "1234"],
        ["--expected-head", "alg:01:abcd"], ["--expected-head", "alg:1:ABCD"],
    ] {
        let mut args = args();
        args.extend(pair.map(str::to_owned));
        assert!(options::parse(&args).is_err(), "{pair:?}");
    }
    for name in ["", "r#type", "a::b", "é", "1name", "a-b"] {
        let mut args = args();
        args[6] = name.into();
        assert!(options::parse(&args).is_err(), "{name}");
    }
    let mut args = args();
    args[6] = "x".repeat(129);
    assert!(options::parse(&args).is_err());
}

#[test]
fn requires_trust_full_ref_and_bounded_arguments_before_io() {
    let mut untrusted = args();
    untrusted.remove(4);
    assert!(options::parse(&untrusted).unwrap_err().contains("--trusted-local"));
    let mut duplicate = args(); duplicate.push("--trusted-local".into());
    assert!(options::parse(&duplicate).is_err());
    let mut short = args(); short[3] = "main".into();
    assert!(options::parse(&short).is_err());
    let mut missing = args(); missing.push("--kind".into());
    assert!(options::parse(&missing).is_err());
    let mut wide = args(); wide[0] = "x".repeat(8193);
    assert!(options::parse(&wide).is_err());
    let mut many = args(); many.extend(vec!["--trusted-local".into(); 321]);
    assert!(options::parse(&many).is_err());
    let mut paths = args();
    for _ in 0..129 { paths.extend(["--path", "src"].map(str::to_owned)); }
    assert!(options::parse(&paths).is_err());
    let mut kinds = args();
    for _ in 0..9 { kinds.extend(["--kind", "function"].map(str::to_owned)); }
    assert!(options::parse(&kinds).is_err());
}

#[test]
fn renders_provenance_exact_byte_spans_and_nonsemantic_scope_counters() {
    let options = options::parse(&args()).unwrap();
    let mut report = report();
    report.matches.push(SymbolMatch {
        name: b"type".to_vec(), kind: SymbolKind::Function, raw_identifier: true,
        location: SourceMatch {
            path: b"src/\xff\x1b\n.rs".to_vec(),
            blob: git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, b"fn r#type() {}\n"),
            byte_offset: 5, line: 1, byte_column: 6,
            excerpt: b"fn r#type() {}\n".to_vec(), excerpt_offset: 0, match_length: 4,
        },
    });
    let text = render(&options, head(), &report).unwrap();
    assert!(text.starts_with("{\"type\":\"source_symbol_search\""));
    assert!(text.contains(&format!("\"snapshot_token\":\"{}\"", head_token(head()))));
    assert!(text.contains("\"raw_identifier\":true"));
    assert!(text.contains("\"byte_offset\":5,\"line\":1,\"byte_column\":6"));
    assert!(text.contains("\"path_hex\":\"7372632fff1b0a2e7273\""));
    assert!(text.contains("\"unsupported_language_files\":3,\"declarations_examined\":4"));
    assert!(text.contains("\"macro_bodies_skipped\":5,\"attributes_skipped\":6"));
    assert!(text.contains("\"work_units\":\"18446744073709551615\""));
    assert!(text.is_ascii());
    assert!(!text.bytes().any(|byte| byte < 32));
}

#[test]
fn empty_completion_and_match_limit_have_different_exit_codes() {
    let options = options::parse(&args()).unwrap();
    let mut output = Vec::new();
    assert_eq!(finish(&mut output, &options, Ok((head(), report())), None).unwrap(), 0);
    assert!(String::from_utf8(output).unwrap().contains("\"complete\":true,\"truncated_reason\":null,\"match_count\":0"));
    let mut truncated = report(); truncated.completion = SearchCompletion::MatchLimit;
    let mut output = Vec::new();
    assert_eq!(finish(&mut output, &options, Ok((head(), truncated)), None).unwrap(), 3);
    assert!(String::from_utf8(output).unwrap().contains("\"complete\":false,\"truncated_reason\":\"match_limit\""));
}

#[test]
fn refusal_and_shutdown_failure_never_emit_a_success_receipt() {
    let options = options::parse(&args()).unwrap();
    for (operation, cleanup) in [
        (Err("SnapshotMoved".into()), None),
        (Ok((head(), report())), Some("shutdown".into())),
        (Err("read".into()), Some("shutdown".into())),
    ] {
        let mut output = Vec::new();
        assert!(finish(&mut output, &options, operation, cleanup).is_err());
        assert!(output.is_empty());
    }
    let error: SymbolReadError<&str> = SymbolReadError::Syntax {
        path: b"\xff\x1b\n.rs".to_vec(),
        error: SymbolSyntaxError { kind: SymbolSyntaxErrorKind::UnbalancedDelimiter, byte_offset: 17 },
    };
    let message = read_error(error);
    assert!(message.contains("path_hex=ff1b0a2e7273"));
    assert!(message.contains("byte 17"));
    assert!(message.is_ascii());
    assert!(!message.bytes().any(|byte| byte == 0x1b || byte == b'\n'));
}

#[test]
fn output_budget_write_and_flush_errors_are_not_success() {
    let options = options::parse(&args()).unwrap();
    let mut oversized = report();
    oversized.matches.push(SymbolMatch {
        name: b"needle".to_vec(), kind: SymbolKind::Function, raw_identifier: false,
        location: SourceMatch {
            path: b"a.rs".to_vec(),
            blob: git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, b"blob"),
            byte_offset: 0, line: 1, byte_column: 1,
            excerpt: vec![0; MAX_OUTPUT_BYTES / 2], excerpt_offset: 0, match_length: 6,
        },
    });
    let mut output = Vec::new();
    assert!(finish(&mut output, &options, Ok((head(), oversized)), None).is_err());
    assert!(output.is_empty());
    struct Failure(bool);
    impl Write for Failure {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.0 { Ok(bytes.len()) } else { Err(std::io::ErrorKind::BrokenPipe.into()) }
        }
        fn flush(&mut self) -> std::io::Result<()> { Err(std::io::ErrorKind::BrokenPipe.into()) }
    }
    for flush_only in [false, true] {
        assert!(finish(&mut Failure(flush_only), &options, Ok((head(), report())), None).is_err());
    }
}
