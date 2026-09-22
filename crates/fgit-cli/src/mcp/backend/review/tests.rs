use super::*;
use fgit_forge::preparation::{CommitInput, MergeEntry, MergeObjectSource, MergeSourceError};
use fgit_forge::review::{ChangeKind, EntryIdentity, ReviewContent, ReviewedEntry, compare_source};

fn arguments(pr: bool) -> Object {
    object(if pr {
        [("number", text("7")), ("expected_version", text("1"))]
    } else {
        [
            ("before_ref", text("refs/heads/main")),
            ("after_ref", text("refs/heads/topic")),
        ]
    })
    .object()
    .unwrap()
    .clone()
}
fn oid(format: GitHashAlgorithm, n: u8) -> GitOid {
    GitOid::from_hex(format, &format!("{n:02x}").repeat(format.digest_len())).unwrap()
}
struct Source(GitHashAlgorithm);
impl MergeObjectSource for Source {
    fn checkpoint(&self) -> Result<(), MergeSourceError> {
        Ok(())
    }
    fn commit(&self, id: GitOid) -> Result<CommitInput, MergeSourceError> {
        if id == oid(self.0, 1) {
            return Ok(CommitInput {
                tree: oid(self.0, 2),
                parents: vec![],
            });
        }
        if id == oid(self.0, 3) {
            return Ok(CommitInput {
                tree: oid(self.0, 4),
                parents: vec![oid(self.0, 1)],
            });
        }
        Err(MergeSourceError::Unavailable(id))
    }
    fn tree(&self, id: GitOid) -> Result<Vec<MergeEntry>, MergeSourceError> {
        let blob = if id == oid(self.0, 2) {
            oid(self.0, 5)
        } else if id == oid(self.0, 4) {
            oid(self.0, 6)
        } else {
            return Err(MergeSourceError::Unavailable(id));
        };
        Ok(vec![MergeEntry {
            name: b"file".to_vec(),
            mode: 0o100644,
            oid: blob,
        }])
    }
    fn blob(&self, id: GitOid) -> Result<Vec<u8>, MergeSourceError> {
        if id == oid(self.0, 5) {
            return Ok(b"old\r\n\xff no final LF".to_vec());
        }
        if id == oid(self.0, 6) {
            return Ok(b"new\r\n\xff no final LF".to_vec());
        }
        Err(MergeSourceError::Unavailable(id))
    }
}
fn report(format: GitHashAlgorithm, query: &Query) -> SourceReview {
    let (before_reference, after_reference, pull_request) = match &query.selection {
        ReviewSelection::References { before, after } => (before.clone(), after.clone(), None),
        ReviewSelection::PullRequest {
            number,
            expected_version,
        } => (
            RefName::try_new(b"refs/heads/main").unwrap(),
            RefName::try_new(b"refs/heads/topic").unwrap(),
            Some((*number, expected_version.unwrap())),
        ),
    };
    SourceReview {
        repository_id: RepositoryId::from_bytes([9; 16]),
        source_head: parse_head(&format!("alg:1:{}", "ab".repeat(32))).unwrap(),
        before_reference,
        after_reference,
        pull_request,
        comparison: compare_source(
            &Source(format),
            format,
            oid(format, 1),
            oid(format, 3),
            &query.options,
        )
        .unwrap(),
    }
}

#[test]
fn every_grant_combination_uses_the_same_discovery_and_dispatch_conjunction() {
    for source in [false, true] {
        for pulls in [false, true] {
            let names: Vec<_> = tools(source, pulls)
                .into_iter()
                .map(|tool| tool.name)
                .collect();
            assert_eq!(names.contains(&COMPARE), source);
            assert_eq!(names.contains(&PULL_DIFF), source && pulls);
            for name in [COMPARE, PULL_DIFF, "shell", "frankengit_pull_merge"] {
                assert_eq!(permitted(source, pulls, name), names.contains(&name));
            }
        }
    }
}

#[test]
fn requests_bind_pr_version_refs_and_native_domains_without_coercion() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let args = arguments(false);
        assert_eq!(
            parse(&args, false, format).unwrap().options.mode,
            ComparisonMode::Direct
        );
        assert_eq!(
            parse(&arguments(true), true, format).unwrap().options.mode,
            ComparisonMode::MergeBase
        );
        for bad in [
            text("0"),
            text("01"),
            text("-1"),
            text("18446744073709551616"),
            json::number(1),
            Value::Null,
        ] {
            let mut args = arguments(true);
            args.insert("expected_version".into(), bad);
            assert!(parse(&args, true, format).is_err());
        }
        let mut missing = arguments(true);
        missing.remove("expected_version");
        assert!(parse(&missing, true, format).is_err());
        let mut raw = args.clone();
        raw.remove("before_ref");
        raw.insert("before_ref_hex".into(), text(hex(b"refs/heads/\xff")));
        assert!(parse(&raw, false, format).is_ok());
        raw.insert("before_ref".into(), text("refs/heads/main"));
        assert!(parse(&raw, false, format).is_err());
        for value in [
            "/etc/passwd",
            "HEAD",
            "refs/heads/../secret",
            "refs/heads/a\n",
        ] {
            let mut bad = args.clone();
            bad.insert("before_ref".into(), text(value));
            assert!(parse(&bad, false, format).is_err());
        }
        let mut pin = args.clone();
        pin.insert("expected_before".into(), text(oid(format, 1).to_string()));
        assert!(parse(&pin, false, format).is_ok());
        for value in [
            "00".repeat(format.digest_len()),
            "AA".repeat(format.digest_len()),
            "ab".repeat(format.digest_len() - 1),
        ] {
            pin.insert("expected_before".into(), text(value));
            assert!(parse(&pin, false, format).is_err());
        }
    }
}

#[test]
fn input_limits_are_inclusive_and_paths_cannot_smuggle_authority() {
    let format = GitHashAlgorithm::Sha1;
    for (key, min, max) in [
        ("max_changes", 1, 128),
        ("max_blob_bytes", 1, 1_048_576),
        ("max_output_bytes", 1, 262_144),
        ("max_diff_work", 1, 1_000_000),
        ("context_lines", 0, 20),
    ] {
        for n in [min, max] {
            let mut args = arguments(false);
            args.insert(key.into(), json::number(n));
            assert!(parse(&args, false, format).is_ok(), "{key}={n}");
        }
        let mut args = arguments(false);
        args.insert(key.into(), json::number(max + 1));
        assert!(parse(&args, false, format).is_err());
        args.insert(key.into(), text(min.to_string()));
        assert!(parse(&args, false, format).is_err());
    }
    for value in [
        Value::Null,
        text("src"),
        Value::Array(vec![text("")]),
        Value::Array(vec![text("2e2e2f736563726574")]),
        Value::Array(vec![text("00")]),
        Value::Array(vec![text("61"), text("61")]),
        Value::Array(
            (0..33)
                .map(|n| text(hex(format!("p{n}").as_bytes())))
                .collect(),
        ),
    ] {
        let mut args = arguments(false);
        args.insert("paths_hex".into(), value);
        assert!(parse(&args, false, format).is_err());
    }
    for key in [
        "principal",
        "storage",
        "repository",
        "command",
        "idempotency_key",
        "expected_version",
    ] {
        let mut args = arguments(false);
        args.insert(key.into(), text("ignored"));
        assert!(parse(&args, false, format).is_err());
    }
    let mut args = arguments(false);
    args.insert(
        "paths_hex".into(),
        Value::Array(vec![text("7a"), text("61")]),
    );
    assert_eq!(
        parse(&args, false, format).unwrap().options.paths,
        [b"a".to_vec(), b"z".to_vec()]
    );
    let mut paths: Vec<_> = (0..4)
        .map(|n| text(hex(format!("{n}{}", "x".repeat(4095)).as_bytes())))
        .collect();
    args.insert("paths_hex".into(), Value::Array(paths.clone()));
    assert!(parse(&args, false, format).is_ok());
    paths.push(text("61"));
    args.insert("paths_hex".into(), Value::Array(paths));
    assert!(parse(&args, false, format).is_err());
}

#[test]
fn native_text_hunks_remain_exact_and_read_only_in_both_hash_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for pr in [false, true] {
            let query = parse(&arguments(pr), pr, format).unwrap();
            let report = report(format, &query);
            let fields = output::render(report.repository_id, format, &query, &report).unwrap();
            assert_eq!(fields["complete"], Value::Bool(true));
            assert_eq!(fields["repository_changed"], Value::Bool(false));
            assert_eq!(fields["merge_permission"], Value::Null);
            let Value::Array(entries) = &fields["entries"] else {
                panic!("entries")
            };
            let content = entries[0].object().unwrap()["content"].object().unwrap();
            let Value::Array(hunks) = &content["hunks"] else {
                panic!("hunks")
            };
            let hunk = hunks[0].object().unwrap();
            assert_eq!(
                unhex(hunk["before_hex"].text().unwrap(), 1024).unwrap(),
                b"old\r\n\xff no final LF"
            );
            assert_eq!(
                unhex(hunk["after_hex"].text().unwrap(), 1024).unwrap(),
                b"new\r\n\xff no final LF"
            );
            let bytes = Value::Object(fields).encode(MAX_RESULT_BYTES).unwrap();
            assert!(
                !bytes.contains("\\ufffd"),
                "no replacement-character decoding"
            );
            assert!(json::parse(bytes.as_bytes()).is_ok());
        }
    }
}

#[test]
fn corrupted_or_misbound_native_results_never_become_complete_successes() {
    let format = GitHashAlgorithm::Sha256;
    let mut query = parse(&arguments(false), false, format).unwrap();
    let valid = report(format, &query);
    let check = |report: &SourceReview| output::render(valid.repository_id, format, &query, report);
    let mut bad = valid.clone();
    bad.repository_id = RepositoryId::from_bytes([8; 16]);
    assert!(check(&bad).is_err());
    let mut bad = valid.clone();
    bad.before_reference = RefName::try_new(b"refs/heads/else").unwrap();
    assert!(check(&bad).is_err());
    let mut bad = valid.clone();
    bad.comparison.before_tree = oid(GitHashAlgorithm::Sha1, 2);
    assert!(check(&bad).is_err());
    let mut bad = valid.clone();
    bad.comparison
        .entries
        .push(bad.comparison.entries[0].clone());
    assert!(check(&bad).is_err());
    let mut bad = valid.clone();
    bad.comparison.entries[0].path = b"../secret".to_vec();
    assert!(check(&bad).is_err());
    let mut bad = valid.clone();
    bad.comparison.entries[0].kind = ChangeKind::Added;
    assert!(check(&bad).is_err());
    let mut bad = valid.clone();
    if let ReviewContent::Text { hunks, .. } = &mut bad.comparison.entries[0].content {
        hunks[0].old.byte_end += 1;
    }
    assert!(check(&bad).is_err());
    query.expected_after = Some(oid(format, 9));
    assert!(output::render(valid.repository_id, format, &query, &valid).is_err());
    query.expected_after = None;
    query.options.limits.max_output_bytes = 1;
    assert!(output::render(valid.repository_id, format, &query, &valid).is_err());
    let pr_query = parse(&arguments(true), true, format).unwrap();
    let mut pr_report = report(format, &pr_query);
    pr_report.pull_request = Some((PullRequestNumber::FIRST, AggregateVersion::FIRST));
    assert!(output::render(valid.repository_id, format, &pr_query, &pr_report).is_err());
}

#[test]
fn binary_mode_only_and_gitlink_changes_are_explicit_not_empty_text() {
    let format = GitHashAlgorithm::Sha1;
    let query = parse(&arguments(false), false, format).unwrap();
    let mut report = report(format, &query);
    let file = EntryIdentity {
        mode: 0o100644,
        oid: oid(format, 5),
    };
    report.comparison.entries = vec![
        ReviewedEntry {
            path: b"a".to_vec(),
            before: Some(file),
            after: Some(EntryIdentity {
                oid: oid(format, 6),
                ..file
            }),
            kind: ChangeKind::Modified,
            content: ReviewContent::Binary {
                before_bytes: 10,
                after_bytes: 12,
            },
        },
        ReviewedEntry {
            path: b"b".to_vec(),
            before: Some(file),
            after: Some(EntryIdentity {
                mode: 0o100755,
                ..file
            }),
            kind: ChangeKind::ModeChanged,
            content: ReviewContent::Identical,
        },
        ReviewedEntry {
            path: b"c".to_vec(),
            before: None,
            after: Some(EntryIdentity {
                mode: 0o160000,
                oid: oid(format, 7),
            }),
            kind: ChangeKind::Added,
            content: ReviewContent::ObjectOnly,
        },
    ];
    let out = output::render(report.repository_id, format, &query, &report).unwrap();
    let Value::Array(entries) = &out["entries"] else {
        panic!("entries")
    };
    for (entry, expected) in entries.iter().zip(["binary", "identical", "object_only"]) {
        let content = entry.object().unwrap()["content"].object().unwrap();
        assert_eq!(content["kind"].text(), Some(expected));
        assert!(!content.contains_key("hunks"));
    }
}
