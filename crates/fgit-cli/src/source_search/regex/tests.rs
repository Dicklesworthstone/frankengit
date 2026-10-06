use super::*;
use fgit_forge::source_search::{SourceMatch, SourceSearchReport};
use fgit_types::{GitHashAlgorithm, RepositoryCommitId};

fn args() -> Vec<String> {
    vec!["unused-node".into(), "11".repeat(16), "22".repeat(16), "refs/heads/main".into(),
        "--trusted-local".into(), "--pattern".into(), "x*".into()]
}
fn head() -> RepositoryAuthorityHeadId { parse_head(&format!("alg:1:{}", "33".repeat(32))).unwrap() }
fn report(input: &Input) -> RegexSearchReport {
    let oid = |s: &str| GitOid::from_hex(GitHashAlgorithm::Sha1, &s.repeat(20)).unwrap();
    RegexSearchReport {
        source: SourceSearchReport {
            repository: input.source.repository,
            source_rcr: RepositoryCommitId::from_digest(DigestAlgorithmId::try_new(1).unwrap(), CANONICAL_CODEC_VERSION,
                DigestBytes::try_new(&[4; 32]).unwrap()),
            source_commit: oid("11"), source_tree: oid("22"),
            matches: vec![SourceMatch { path: b"raw-\xff".to_vec(), blob: oid("33"), byte_offset: 0,
                line: 1, byte_column: 1, match_length: 1000, excerpt: vec![b'x'; 416], excerpt_offset: 0 }],
            completion: SearchCompletion::Complete, files_selected: 1, files_read: 1,
            bytes_read: 1000, bytes_searched: 1000, non_regular_entries: 0,
        }, program_states: input.query.state_count(), steps: 4000, lines_searched: 1,
    }
}
#[test]
fn regex_arguments_keep_native_bytes_case_and_shared_scope_limits() {
    let mut arguments = args();
    arguments.extend(["--path", "src", "--ignore-ascii-case", "--object-format", "sha256"].map(str::to_owned));
    let input = parse(&arguments).unwrap();
    assert_eq!(input.query.pattern(), b"x*");
    assert_eq!(input.query.case(), SearchCase::AsciiInsensitive);
    assert_eq!(input.query.prefixes()[0].as_bytes(), b"src");
    assert_eq!(input.source.format, GitHashAlgorithm::Sha256);
    arguments[5] = "--pattern-hex".into(); arguments[6] = "ff00".into();
    assert_eq!(parse(&arguments).unwrap().query.pattern(), &[255, 0]);
}
#[test]
fn trust_profiles_duplicates_patterns_and_bounds_fail_before_opening_storage() {
    let mut missing = args(); missing.remove(4);
    assert!(parse(&missing).is_err());
    for (flag, value) in [
        ("--pattern", "another"), ("--pattern-hex", "ff"), ("--literal", "x"),
        ("--principal", "admin"), ("--after", "1"), ("--max-regex-steps", "0"),
        ("--max-regex-steps", "67108865"), ("--max-matches", "4097"), ("--path", "../secret"),
    ] {
        let mut arguments = args(); arguments.extend([flag.into(), value.into()]);
        assert!(parse(&arguments).is_err(), "{flag}");
    }
    for pattern in ["", "(?=a)", "(a)\\1", "[", &"x".repeat(257)] {
        let mut arguments = args(); arguments[6] = pattern.into();
        assert!(parse(&arguments).is_err());
    }
    assert_eq!(super::super::run(&["--regex".into(), "--help".into()]).unwrap(), 0);
}
#[test]
fn snapshot_and_native_commit_pins_are_not_implicitly_refreshed_or_coerced() {
    let mut arguments = args();
    arguments.extend(["--expected-head".into(), head_token(head()), "--expected-commit".into(), "11".repeat(20)]);
    let input = parse(&arguments).unwrap();
    assert_eq!(input.head, Some(head()));
    assert!(render(&input, head(), &report(&input)).is_ok());
    let other = parse_head(&format!("alg:1:{}", "44".repeat(32))).unwrap();
    assert!(render(&input, other, &report(&input)).is_err());
    for value in ["alg:01:aa", "alg:1:", "alg:1:FF", "not-a-token"] { assert!(parse_head(value).is_err()); }
    for value in ["00".repeat(20), "FF".repeat(20), "11".repeat(32)] {
        let mut arguments = args(); arguments.extend(["--expected-commit".into(), value]);
        assert!(parse(&arguments).is_err());
    }
}
#[test]
fn complete_long_and_zero_width_results_are_distinct_from_truncated_match_prefixes() {
    let input = parse(&args()).unwrap();
    let mut native = report(&input);
    let mut output = Vec::new();
    assert_eq!(finish(&mut output, &input, Ok((head(), native.clone())), None).unwrap(), 0);
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("\"match_length\":1000"));
    assert!(text.contains("\"match_fully_in_excerpt\":false,\"match_bytes_hex\":null"));
    assert!(text.contains("\"path_hex\":\"7261772dff\""));
    native.source.matches[0].match_length = 0; native.source.matches[0].excerpt.clear();
    assert!(render(&input, head(), &native).unwrap().contains("\"match_bytes_hex\":\"\""));
    let mut args = args(); args.extend(["--max-matches".into(), "1".into()]);
    let input = parse(&args).unwrap();
    native.source.completion = SearchCompletion::MatchLimit; native.lines_searched = 2;
    assert_eq!(finish(&mut Vec::new(), &input, Ok((head(), native)), None).unwrap(), 3);
}
#[test]
fn read_cleanup_and_output_failures_never_emit_a_successful_read() {
    let input = parse(&args()).unwrap();
    let mut output = Vec::new();
    assert!(finish(&mut output, &input, Ok((head(), report(&input))), Some("failed".into())).is_err());
    assert!(output.is_empty());
    assert!(finish(&mut output, &input, Err("read failed".into()), None).is_err());
    assert!(output.is_empty());
    let mut native = report(&input); native.source.matches[0].byte_column = 0;
    assert!(finish(&mut output, &input, Ok((head(), native)), None).is_err());
    assert!(output.is_empty());
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> { Err(std::io::ErrorKind::BrokenPipe.into()) }
        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
    }
    assert!(finish(&mut Broken, &input, Ok((head(), report(&input))), None).is_err());
}
