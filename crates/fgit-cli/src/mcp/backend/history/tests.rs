use super::*;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::history::{BlameLine, BlameResult, HistoryCommit, HistoryPage};

fn args(blame: bool) -> Object {
    let mut args = object([("reference", text("refs/heads/main"))])
        .object()
        .unwrap()
        .clone();
    if blame {
        args.insert("path_hex".into(), text(hex(b"file")));
    }
    args
}
fn oid(format: GitHashAlgorithm, byte: u8) -> GitOid {
    GitOid::from_hex(format, &format!("{byte:02x}").repeat(format.digest_len())).unwrap()
}
fn record(format: GitHashAlgorithm, n: u8, parents: Vec<GitOid>) -> HistoryCommit {
    let tree = oid(format, n);
    let mut body = format!("tree {tree}\n").into_bytes();
    for parent in &parents {
        body.extend_from_slice(format!("parent {parent}\n").as_bytes());
    }
    body.extend_from_slice(b"author A <a@example.invalid> 1 +0000\ncommitter C <c@example.invalid> 1 +0000\n\nraw \xff metadata\n");
    HistoryCommit {
        id: git_object_id(format, GitObjectKind::Commit, &body),
        tree,
        parents,
        body,
    }
}
fn log_report(format: GitHashAlgorithm) -> HistoryPage {
    let root = record(format, 2, vec![]);
    let child = record(format, 3, vec![root.id]);
    HistoryPage {
        tip: child.id,
        total_commits: 2,
        after: 0,
        next_after: None,
        commits: vec![child, root],
    }
}
fn blame_report(format: GitHashAlgorithm) -> BlameResult {
    let page = log_report(format);
    let (child, root) = (&page.commits[0], &page.commits[1]);
    let lines = vec![
        BlameLine {
            line: 0,
            byte_start: 0,
            byte_end: 4,
            origin_commit: child.id,
            origin_blob: oid(format, 4),
            origin_line: 0,
            origin_byte_start: 0,
            origin_byte_end: 4,
        },
        BlameLine {
            line: 1,
            byte_start: 4,
            byte_end: 10,
            origin_commit: root.id,
            origin_blob: oid(format, 5),
            origin_line: 0,
            origin_byte_start: 0,
            origin_byte_end: 6,
        },
    ];
    let mut origins = page.commits.clone();
    origins.sort_by_key(|row| row.id);
    BlameResult {
        tip: page.tip,
        tree: child.tree,
        blob: oid(format, 4),
        path: b"file".to_vec(),
        total_lines: 2,
        first_line: 0,
        end_line: 2,
        content_byte_start: 0,
        content: b"new\nsame\r\n".to_vec(),
        lines,
        origins,
        graph_commits: 2,
        comparisons: 1,
        algorithms: vec![],
    }
}

#[test]
fn history_arguments_refuse_coercion_unknown_fields_and_unpinned_continuations() {
    for blame in [false, true] {
        let format = GitHashAlgorithm::Sha1;
        let valid = args(blame);
        assert!(parse(&valid, blame, format).is_ok());
        for key in [
            "storage",
            "principal",
            "tenant",
            "repository",
            "shell",
            "idempotency_key",
            "first_parent",
        ] {
            let mut bad = valid.clone();
            bad.insert(key.into(), text("ignored"));
            assert!(parse(&bad, blame, format).is_err());
        }
        let cursor = if blame { "first_line" } else { "after" };
        for value in [
            json::number(1),
            text("01"),
            text("-1"),
            text("1"),
            text("18446744073709551616"),
        ] {
            let mut bad = valid.clone();
            bad.insert(cursor.into(), value);
            assert!(parse(&bad, blame, format).is_err());
        }
        let mut pinned = valid.clone();
        pinned.insert(cursor.into(), text("1"));
        pinned.insert(
            "expected_head".into(),
            text(format!("alg:1:{}", "ab".repeat(32))),
        );
        assert!(parse(&pinned, blame, format).is_ok());
        for value in [
            json::number(0),
            json::number(if blame { 201 } else { 21 }),
            text("1"),
            Value::Null,
        ] {
            let mut bad = valid.clone();
            bad.insert("limit".into(), value);
            assert!(parse(&bad, blame, format).is_err());
        }
        let mut raw = valid.clone();
        raw.remove("reference");
        raw.insert("reference_hex".into(), text(hex(b"refs/heads/\xff")));
        assert!(parse(&raw, blame, format).is_ok());
        raw.insert("reference".into(), text("refs/heads/main"));
        assert!(parse(&raw, blame, format).is_err());
    }
    for path in [
        b"".as_slice(),
        b"../secret",
        b"/etc/passwd",
        b"a//b",
        b"a\0b",
    ] {
        let mut bad = args(true);
        bad.insert("path_hex".into(), text(hex(path)));
        assert!(parse(&bad, true, GitHashAlgorithm::Sha1).is_err());
    }
}

#[test]
fn commit_pages_preserve_original_metadata_order_and_exact_tail_cursor() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut query = parse(&args(false), false, format).unwrap();
        let full = log_report(format);
        let result = output::log(format, &query, &full).unwrap();
        assert_eq!(result["total_commits"].text(), Some("2"));
        assert_eq!(result["next_after"], Value::Null);
        let Value::Array(rows) = &result["commits"] else {
            panic!("commits")
        };
        assert_eq!(
            rows[0].object().unwrap()["author_authenticated"],
            Value::Bool(false)
        );
        assert_eq!(
            unhex(rows[0].object().unwrap()["body_hex"].text().unwrap(), 65536).unwrap(),
            full.commits[0].body
        );
        query.limit = 1;
        let first = HistoryPage {
            next_after: Some(1),
            commits: vec![full.commits[0].clone()],
            ..full.clone()
        };
        assert_eq!(
            output::log(format, &query, &first).unwrap()["complete"],
            Value::Bool(false)
        );
        query.after = 1;
        let last = HistoryPage {
            after: 1,
            commits: vec![full.commits[1].clone()],
            ..full.clone()
        };
        assert_eq!(
            output::log(format, &query, &last).unwrap()["complete"],
            Value::Bool(true)
        );
        query.after = 2;
        let empty = HistoryPage {
            after: 2,
            commits: vec![],
            ..full
        };
        assert!(output::log(format, &query, &empty).is_ok());
    }
}

#[test]
fn short_missing_reordered_or_corrupt_history_never_becomes_successful_empty_data() {
    let format = GitHashAlgorithm::Sha256;
    let query = parse(&args(false), false, format).unwrap();
    let valid = log_report(format);
    let mut bad = valid.clone();
    bad.commits.pop();
    assert!(output::log(format, &query, &bad).is_err());
    let mut bad = valid.clone();
    bad.next_after = Some(1);
    assert!(output::log(format, &query, &bad).is_err());
    let mut bad = valid.clone();
    bad.commits.reverse();
    assert!(output::log(format, &query, &bad).is_err());
    let mut bad = valid.clone();
    bad.commits[0].body.push(1);
    assert!(output::log(format, &query, &bad).is_err());
    let mut bad = valid.clone();
    bad.commits[0].tree = oid(GitHashAlgorithm::Sha1, 8);
    assert!(output::log(format, &query, &bad).is_err());
    let mut bad = valid.clone();
    bad.total_commits = 0;
    assert!(output::log(format, &query, &bad).is_err());
    let mut pin = query;
    pin.expected_commit = Some(oid(format, 9));
    let head = parse_head(&format!("alg:1:{}", "ab".repeat(32))).unwrap();
    assert!(check_pin(&pin, format, head, valid.tip).is_err());
    pin.expected_commit = Some(valid.tip);
    assert!(check_pin(&pin, format, head, valid.tip).is_ok());
}

#[test]
fn blame_pages_preserve_exact_bytes_and_full_origin_coverage_without_authorship_claims() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut query = parse(&args(true), true, format).unwrap();
        let full = blame_report(format);
        let result = output::blame(format, &query, &full).unwrap();
        assert_eq!(result["bytes_hex"].text(), Some("6e65770a73616d650d0a"));
        assert_eq!(result["complete"], Value::Bool(true));
        assert_eq!(result["human_authorship_proven"], Value::Bool(false));
        assert_eq!(result["attribution_complete"], Value::Bool(true));
        query.limit = 1;
        let mut first = full.clone();
        first.end_line = 1;
        first.lines.truncate(1);
        first.content = b"new\n".to_vec();
        first
            .origins
            .retain(|row| row.id == first.lines[0].origin_commit);
        assert_eq!(
            output::blame(format, &query, &first).unwrap()["next_first_line"].text(),
            Some("1")
        );
        query.after = 1;
        let mut last = full.clone();
        last.first_line = 1;
        last.content_byte_start = 4;
        last.content = b"same\r\n".to_vec();
        last.lines.remove(0);
        last.origins
            .retain(|row| row.id == last.lines[0].origin_commit);
        assert_eq!(
            output::blame(format, &query, &last).unwrap()["next_first_line"],
            Value::Null
        );
        query.after = 2;
        let mut end = full;
        end.first_line = 2;
        end.lines.clear();
        end.content.clear();
        end.origins.clear();
        end.content_byte_start = 10;
        assert!(output::blame(format, &query, &end).is_ok());
    }
}

#[test]
fn misbound_blame_spans_missing_origins_and_oversized_content_refuse() {
    let format = GitHashAlgorithm::Sha1;
    let query = parse(&args(true), true, format).unwrap();
    let valid = blame_report(format);
    let mut bad = valid.clone();
    bad.lines[0].byte_end += 1;
    assert!(output::blame(format, &query, &bad).is_err());
    let mut bad = valid.clone();
    bad.lines[0].origin_byte_end += 1;
    assert!(output::blame(format, &query, &bad).is_err());
    let mut bad = valid.clone();
    bad.origins.pop();
    assert!(output::blame(format, &query, &bad).is_err());
    let mut bad = valid.clone();
    bad.content[0] = 0;
    assert!(output::blame(format, &query, &bad).is_err());
    let mut bad = valid.clone();
    bad.content = vec![b'x'; MAX_CONTENT_BYTES + 1];
    assert!(output::blame(format, &query, &bad).is_err());
    let mut bad = valid.clone();
    bad.path = b"other".to_vec();
    assert!(output::blame(format, &query, &bad).is_err());
    let mut bad = valid.clone();
    bad.lines[0].origin_commit = oid(format, 8);
    assert!(output::blame(format, &query, &bad).is_err());
    let mut bad = valid;
    bad.origins[0].body.push(1);
    assert!(output::blame(format, &query, &bad).is_err());
}
