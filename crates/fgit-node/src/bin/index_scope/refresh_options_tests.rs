//! The actual closed parser; every case completes before repository/file I/O.
use super::*;

fn arguments(format: &str) -> Vec<OsString> {
    [
        "refresh".to_owned(), "missing-node".into(), "31".repeat(16), "32".repeat(16),
        format.into(), "refs/heads/main".into(), "--trusted-local".into(),
        "--prefix".into(), "src".into(), "--candidate-file".into(), "private/next.json".into(),
        "--predecessor-token".into(), format!("alg:2:{}", "a".repeat(64)),
    ].into_iter().map(OsString::from).collect()
}
fn add(args: &mut Vec<OsString>, values: &[&str]) {
    args.extend(values.iter().map(|value| OsString::from(*value)));
}
fn remove(args: &mut Vec<OsString>, name: &str, width: usize) {
    let at = args.iter().position(|value| value == name).unwrap();
    drop(args.drain(at..at + width));
}

#[test]
fn refresh_requires_explicit_predecessor_record_trust_and_coverage() {
    for name in ["sha1", "sha256"] {
        let valid = arguments(name);
        let parsed = parse(&valid).unwrap();
        let Command::Refresh { predecessor, record, limits, reads } = parsed.command else {
            panic!("refresh selected another operation");
        };
        assert_eq!(predecessor, generation(&format!("alg:2:{}", "a".repeat(64))).unwrap());
        assert_eq!(record, PathBuf::from("private/next.json"));
        assert_eq!(limits.max_files, SearchLimits::default().max_files);
        assert_eq!(reads.max_payload_bytes, LexicalReadLimits::default().max_payload_bytes);
        for (flag, width) in [("--predecessor-token", 2), ("--candidate-file", 2),
            ("--prefix", 2), ("--trusted-local", 1)] {
            let mut bad = valid.clone(); remove(&mut bad, flag, width);
            assert!(parse(&bad).is_err(), "missing {flag}");
        }
        // Only explicit build can initialize a new scope; refresh never infers it.
        let mut build = valid;
        build[0] = "build".into(); remove(&mut build, "--predecessor-token", 2);
        assert!(matches!(parse(&build).unwrap().command, Command::Build { predecessor: None, .. }));
    }
}

#[test]
fn refresh_preserves_raw_scope_union_and_exact_native_source_pins() {
    for name in ["sha1", "sha256"] {
        let mut args = arguments(name);
        let width = if name == "sha1" { 40 } else { 64 };
        let commit = "b".repeat(width);
        let head = format!("alg:2:{}", "c".repeat(64));
        add(&mut args, &["--prefix", "src/nested", "--prefix-hex", "62696eff",
            "--expected-head", &head, "--expected-commit", &commit]);
        let parsed = parse(&args).unwrap();
        assert_eq!(parsed.scope, LexicalScope::new(&[b"src".to_vec(), b"bin\xff".to_vec()]).unwrap());
        assert_eq!(parsed.commit.unwrap().to_string(), commit);
        assert_eq!(parsed.head.unwrap().as_internal_object_id(),
            &identity(&head, IdentityDomain::RepositoryAuthorityHead).unwrap());
        assert!(matches!(parsed.command, Command::Refresh { .. }));
    }
}

#[test]
fn refresh_limits_are_independent_finite_and_cannot_widen_defaults() {
    let mut args = arguments("sha1");
    add(&mut args, &["--max-files", "2", "--max-entries", "8", "--max-depth", "2",
        "--max-file-bytes", "10", "--max-source-bytes", "100", "--max-payload-bytes", "4096"]);
    let Command::Refresh { limits, reads, .. } = parse(&args).unwrap().command else { panic!() };
    assert_eq!((limits.max_files, limits.max_entries, limits.max_depth), (2, 8, 2));
    assert_eq!((limits.max_file_bytes, limits.max_total_bytes, reads.max_payload_bytes), (10, 100, 4096));
    for (flag, maximum) in [
        ("--max-files", SearchLimits::default().max_files),
        ("--max-entries", SearchLimits::default().max_entries),
        ("--max-depth", SearchLimits::default().max_depth),
        ("--max-file-bytes", SearchLimits::default().max_file_bytes),
        ("--max-source-bytes", SearchLimits::default().max_total_bytes),
        ("--max-payload-bytes", LexicalReadLimits::default().max_payload_bytes),
    ] {
        for value in ["0".into(), "01".into(), "+1".into(), "18446744073709551616".into(),
            (maximum + 1).to_string()] {
            let mut bad = arguments("sha1"); add(&mut bad, &[flag, &value]);
            assert!(parse(&bad).is_err(), "{flag} {value}");
        }
        let mut exact = arguments("sha1"); add(&mut exact, &[flag, &maximum.to_string()]);
        assert!(parse(&exact).is_ok());
    }
}

#[test]
fn refresh_refuses_search_recovery_and_duplicate_or_unknown_options() {
    for pair in [
        ["--term", "needle"], ["--channel", "content"], ["--filter-prefix", "src"],
        ["--limit", "1"], ["--after", "1"], ["--max-work", "1"],
        ["--minimum-index-number", "1"], ["--candidate", "anything"],
        ["--unknown", "1"], ["--candidate-file", "another"],
    ] {
        let mut bad = arguments("sha256"); add(&mut bad, &pair);
        assert!(parse(&bad).is_err(), "{pair:?}");
    }
    let mut bad = arguments("sha256");
    add(&mut bad, &["--max-payload-bytes", "1", "--max-payload-bytes", "2"]);
    assert!(parse(&bad).is_err());
    let mut bad = arguments("sha256");
    add(&mut bad, &["--predecessor-token", &format!("alg:2:{}", "a".repeat(64))]);
    assert!(parse(&bad).is_err());
    let mut bad = arguments("sha256"); add(&mut bad, &["--trusted-local"]);
    assert!(parse(&bad).is_err());
    // A read budget on build would be misleading: no previous index is read.
    let mut bad = arguments("sha1"); bad[0] = "build".into();
    add(&mut bad, &["--max-payload-bytes", "4096"]);
    assert!(parse(&bad).is_err());
}

#[test]
fn refresh_rejects_malformed_predecessors_and_wrong_hash_domain_source_pins() {
    for token in ["".into(), "alg:2:aa".into(), format!("alg:2:{}", "0".repeat(64)),
        format!("alg:1:{}", "a".repeat(64)), format!("alg:2:{}", "A".repeat(64))] {
        let mut bad = arguments("sha1"); *bad.last_mut().unwrap() = token.into();
        assert!(parse(&bad).is_err());
    }
    for (format, wrong_width) in [("sha1", 64), ("sha256", 40)] {
        let mut bad = arguments(format);
        add(&mut bad, &["--expected-commit", &"a".repeat(wrong_width)]);
        assert!(parse(&bad).is_err());
    }
    let mut bad = arguments("sha1");
    add(&mut bad, &["--prefix", "../outside"]);
    assert!(parse(&bad).is_err());
}
