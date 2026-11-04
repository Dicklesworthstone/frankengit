use super::*;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::history::HistoryCommit;
use fgit_forge::history::first_parent::FirstParentPage;

#[path = "first_parent_integration_tests.rs"]
mod integration;

fn args() -> Object {
    object([
        ("reference", text("refs/heads/main")),
        ("first_parent", Value::Bool(true)),
        ("limit", json::number(2)),
    ])
    .object()
    .unwrap()
    .clone()
}

fn head() -> RepositoryAuthorityHeadId {
    parse_head(&format!("alg:1:{}", "ab".repeat(32))).unwrap()
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

fn page(format: GitHashAlgorithm) -> FirstParentPage {
    let root = record(format, 2, vec![]);
    // Side-parent identity remains visible without claiming to traverse it.
    let child = record(format, 3, vec![root.id, oid(format, 4)]);
    FirstParentPage {
        tip: child.id,
        after: 0,
        next_after: None,
        root_reached: true,
        visited_commits: 2,
        visited_parent_edges: 2,
        metadata_bytes: child.body.len() + root.body.len(),
        commits: vec![child, root],
    }
}

#[test]
fn first_parent_arguments_require_explicit_mode_and_keep_dag_and_blame_defaults() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let valid = args();
        let parsed = parse(&valid, false, format).unwrap();
        assert!(parsed.first_parent.is_some());
        assert_eq!(parsed.after, 0);
        assert!(parsed.path.is_none() && parsed.log_path.is_none());
        let mut dag = valid.clone();
        dag.remove("first_parent");
        assert!(parse(&dag, false, format).unwrap().first_parent.is_none());
        dag.insert("after".into(), text("0"));
        dag.insert("path_hex".into(), text(hex(b"file")));
        assert!(parse(&dag, false, format).unwrap().first_parent.is_none());

        for value in [
            Value::Bool(false),
            text("true"),
            json::number(1),
            Value::Null,
        ] {
            let mut bad = valid.clone();
            bad.insert("first_parent".into(), value);
            assert_eq!(
                parse(&bad, false, format).err().unwrap().code,
                "invalid_first_parent"
            );
        }
        for (name, value) in [
            ("after", text("0")),
            ("after", text("1")),
            ("path_hex", text(hex(b"file"))),
            ("path_hex", Value::Null),
        ] {
            let mut bad = valid.clone();
            bad.insert(name.into(), value);
            assert_eq!(
                parse(&bad, false, format).err().unwrap().code,
                "conflicting_history_modes"
            );
        }
        let mut bad = valid.clone();
        bad.remove("first_parent");
        bad.insert("cursor".into(), text("anything"));
        assert_eq!(
            parse(&bad, false, format).err().unwrap().code,
            "cursor_requires_first_parent"
        );
        bad.insert("first_parent".into(), Value::Bool(false));
        assert_eq!(
            parse(&bad, false, format).err().unwrap().code,
            "invalid_first_parent"
        );
        let mut blame = valid.clone();
        blame.insert("path_hex".into(), text(hex(b"file")));
        assert_eq!(
            parse(&blame, true, format).err().unwrap().code,
            "unknown_argument"
        );
        blame.remove("first_parent");
        assert!(parse(&blame, true, format).unwrap().first_parent.is_none());
        blame.insert("cursor".into(), text("anything"));
        assert_eq!(
            parse(&blame, true, format).err().unwrap().code,
            "unknown_argument"
        );

        for (field, values) in [
            ("limit", [json::number(0), json::number(21), text("2")]),
            (
                "max_commits",
                [json::number(0), json::number(4097), text("2")],
            ),
        ] {
            for value in values {
                let mut bad = valid.clone();
                bad.insert(field.into(), value);
                assert_eq!(
                    parse(&bad, false, format).err().unwrap().code,
                    "invalid_history_limit"
                );
            }
        }
    }
}

#[test]
fn cursor_binds_raw_reference_hash_domain_head_and_bounded_offset_without_a_separate_pin() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let reference = RefName::try_new(b"refs/heads/\xff").unwrap();
        let cursor = FirstParentCursor {
            source_head: head(),
            reference: reference.clone(),
            tip: oid(format, 3),
            after: 2,
        };
        let mut valid = args();
        valid.remove("reference");
        valid.insert("reference_hex".into(), text(hex(reference.as_bytes())));
        valid.insert("cursor".into(), text(cursor.encode()));
        let parsed = parse(&valid, false, format).unwrap();
        assert_eq!(parsed.after, 2);
        assert_eq!(parsed.first_parent.unwrap().cursor, Some(cursor.clone()));
        assert!(
            parsed.expected_head.is_none(),
            "the cursor itself pins the head"
        );
        valid.insert("expected_head".into(), text(head_token(head())));
        valid.insert("expected_commit".into(), text(cursor.tip.to_string()));
        assert!(parse(&valid, false, format).is_ok());
        let mut bad = valid.clone();
        bad.insert("expected_commit".into(), text(oid(format, 9).to_string()));
        assert_eq!(
            parse(&bad, false, format).err().unwrap().code,
            "cursor_commit_mismatch"
        );
        let mut bad = valid.clone();
        bad.insert(
            "expected_head".into(),
            text(format!("alg:1:{}", "cd".repeat(32))),
        );
        assert_eq!(
            parse(&bad, false, format).err().unwrap().code,
            "cursor_head_mismatch"
        );
        let mut bad = valid.clone();
        bad.insert("reference_hex".into(), text(hex(b"refs/heads/other")));
        assert_eq!(
            parse(&bad, false, format).err().unwrap().code,
            "invalid_first_parent_cursor"
        );
        let mut bad = valid.clone();
        bad.remove("expected_commit");
        let other = match format {
            GitHashAlgorithm::Sha1 => GitHashAlgorithm::Sha256,
            GitHashAlgorithm::Sha256 => GitHashAlgorithm::Sha1,
        };
        assert_eq!(
            parse(&bad, false, other).err().unwrap().code,
            "invalid_first_parent_cursor"
        );
        bad.insert("max_commits".into(), json::number(1));
        assert_eq!(
            parse(&bad, false, format).err().unwrap().code,
            "invalid_history_options"
        );
        for value in [
            String::new(),
            "x".repeat(4097),
            cursor.encode().replacen("fgfp1/", "fgfp2/", 1),
            format!("{}/extra", cursor.encode()),
            cursor.encode().replace("/2", "/02"),
        ] {
            let mut bad = valid.clone();
            bad.insert("cursor".into(), text(value));
            assert_eq!(
                parse(&bad, false, format).err().unwrap().code,
                "invalid_first_parent_cursor"
            );
        }
        for value in [Value::Null, Value::Bool(true), json::number(1)] {
            let mut bad = valid.clone();
            bad.insert("cursor".into(), value);
            assert_eq!(
                parse(&bad, false, format).err().unwrap().code,
                "expected_string"
            );
        }
    }
}

#[test]
fn first_parent_schemas_expose_closed_fields_only_on_log() {
    let schema = input_schema(false);
    let fields = schema.object().unwrap()["properties"].object().unwrap();
    let declared: std::collections::BTreeSet<_> = fgit_schema::mcp::find_tool(LOG)
        .unwrap()
        .input_fields
        .iter()
        .map(|field| field.name)
        .collect();
    let served: std::collections::BTreeSet<_> = fields.keys().map(String::as_str).collect();
    assert_eq!(served, declared);
    assert_eq!(
        fields["first_parent"].object().unwrap()["type"].text(),
        Some("boolean")
    );
    assert_eq!(
        fields["first_parent"].object().unwrap()["const"],
        Value::Bool(true)
    );
    assert!(
        !fields["first_parent"]
            .object()
            .unwrap()
            .contains_key("default")
    );
    assert_eq!(
        fields["cursor"].object().unwrap()["maxLength"].unsigned(),
        Some(4096)
    );
    assert_eq!(
        schema.object().unwrap()["additionalProperties"],
        Value::Bool(false)
    );
    let blame = input_schema(true);
    let fields = blame.object().unwrap()["properties"].object().unwrap();
    assert!(!fields.contains_key("first_parent") && !fields.contains_key("cursor"));
}

#[test]
fn first_parent_pages_preserve_exact_records_and_report_only_visited_work() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let full = page(format);
        let mut query = parse(&args(), false, format).unwrap();
        let report = output::first_parent(format, &query, head(), &full).unwrap();
        assert_eq!(report["profile"].text(), Some("first-parent-prefix-v1"));
        assert_eq!(report["scope"].text(), Some("first_parent_chain"));
        assert_eq!(report["complete"], Value::Bool(true));
        assert_eq!(report["root_reached"], Value::Bool(true));
        assert_eq!(report["visited_commits"].text(), Some("2"));
        assert_eq!(report["visited_parent_edges"].text(), Some("2"));
        assert_eq!(report["next_cursor"], Value::Null);
        assert!(!report.contains_key("total_commits") && !report.contains_key("next_after"));
        let Value::Array(rows) = &report["commits"] else {
            panic!("commits")
        };
        assert_eq!(
            rows[0].object().unwrap()["body_hex"].text(),
            Some(hex(&full.commits[0].body).as_str())
        );
        assert_eq!(
            rows[0].object().unwrap()["author_authenticated"],
            Value::Bool(false)
        );
        assert_eq!(
            rows[0].object().unwrap()["parents"],
            Value::Array(
                full.commits[0]
                    .parents
                    .iter()
                    .map(|id| text(id.to_string()))
                    .collect()
            )
        );

        let first = FirstParentPage {
            next_after: Some(1),
            root_reached: false,
            visited_commits: 1,
            metadata_bytes: full.commits[0].body.len(),
            commits: vec![full.commits[0].clone()],
            ..full.clone()
        };
        query.limit = 1;
        query.first_parent.as_mut().unwrap().limit = 1;
        let first_result = output::first_parent(format, &query, head(), &first).unwrap();
        assert_eq!(
            first_result["complete"],
            Value::Bool(true),
            "page completed; older history remains unread"
        );
        assert_eq!(first_result["root_reached"], Value::Bool(false));
        let cursor =
            FirstParentCursor::decode(first_result["next_cursor"].text().unwrap()).unwrap();
        assert_eq!(
            cursor,
            first.continuation(head(), &query.reference).unwrap()
        );
        query.after = cursor.after;
        query.first_parent.as_mut().unwrap().cursor = Some(cursor);
        let last = FirstParentPage {
            after: 1,
            commits: vec![full.commits[1].clone()],
            ..full.clone()
        };
        let last_result = output::first_parent(format, &query, head(), &last).unwrap();
        assert_eq!(last_result["next_cursor"], Value::Null);
        assert_eq!(last_result["visited_commits"].text(), Some("2"));
        assert_eq!(
            last_result["metadata_bytes"].text(),
            Some(full.metadata_bytes.to_string().as_str())
        );
        // Exactly-at-end still proves the skipped prefix, returning no rows.
        query.after = 2;
        query
            .first_parent
            .as_mut()
            .unwrap()
            .cursor
            .as_mut()
            .unwrap()
            .after = 2;
        let empty = FirstParentPage {
            after: 2,
            commits: vec![],
            ..full
        };
        assert!(output::first_parent(format, &query, head(), &empty).is_ok());
    }
}

#[test]
fn malformed_first_parent_reports_fail_closed_beside_their_permitted_page() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let query = parse(&args(), false, format).unwrap();
        let valid = page(format);
        assert!(output::first_parent(format, &query, head(), &valid).is_ok());
        let changes: [fn(&mut FirstParentPage); 13] = [
            |p| p.commits.reverse(),
            |p| {
                p.commits.pop();
            },
            |p| p.commits[0].body.push(b'x'),
            |p| p.commits[0].parents.reverse(),
            |p| p.root_reached = false,
            |p| p.next_after = Some(2),
            |p| p.after = 1,
            |p| p.visited_commits = 1,
            |p| p.visited_parent_edges = 0,
            |p| p.visited_parent_edges += 1,
            |p| p.metadata_bytes -= 1,
            |p| p.metadata_bytes += 1,
            |p| p.commits[1] = p.commits[0].clone(),
        ];
        for change in changes {
            let mut bad = valid.clone();
            change(&mut bad);
            assert!(
                output::first_parent(format, &query, head(), &bad).is_err(),
                "{bad:?}"
            );
        }
        let mut bad = valid.clone();
        bad.tip = oid(format, 7);
        assert!(output::first_parent(format, &query, head(), &bad).is_err());
        let mut bad = valid.clone();
        bad.metadata_bytes = MAX_METADATA_BYTES + 1;
        assert!(output::first_parent(format, &query, head(), &bad).is_err());
        let mut bad = valid.clone();
        bad.visited_parent_edges = query.limits.max_edges + 1;
        assert!(output::first_parent(format, &query, head(), &bad).is_err());
        let other = match format {
            GitHashAlgorithm::Sha1 => GitHashAlgorithm::Sha256,
            GitHashAlgorithm::Sha256 => GitHashAlgorithm::Sha1,
        };
        let mut bad = valid.clone();
        bad.commits[0].tree = oid(other, 3);
        assert!(output::first_parent(format, &query, head(), &bad).is_err());
        let mut bad = valid.clone();
        bad.commits[0].parents[1] = oid(other, 4);
        assert!(output::first_parent(format, &query, head(), &bad).is_err());
        let mut pinned = query;
        pinned.expected_head = Some(parse_head(&format!("alg:1:{}", "cd".repeat(32))).unwrap());
        assert!(output::first_parent(format, &pinned, head(), &valid).is_err());
        pinned.expected_head = Some(head());
        pinned.expected_commit = Some(oid(format, 9));
        assert!(output::first_parent(format, &pinned, head(), &valid).is_err());
        pinned.expected_commit = Some(valid.tip);
        assert!(output::first_parent(format, &pinned, head(), &valid).is_ok());
    }
}
