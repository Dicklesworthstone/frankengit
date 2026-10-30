use super::*;

fn args(extra: &[&str]) -> Vec<String> {
    [
        "node",
        &"11".repeat(16),
        &"22".repeat(16),
        "refs/heads/main",
        "--trusted-local",
    ]
    .into_iter()
    .chain(extra.iter().copied())
    .map(str::to_owned)
    .collect()
}
fn authority_head() -> RepositoryAuthorityHeadId {
    parse_head(&format!("alg:1:{}", "ab".repeat(32))).unwrap()
}
fn cursor(format: GitHashAlgorithm, reference: RefName) -> FirstParentCursor {
    FirstParentCursor {
        source_head: authority_head(),
        reference,
        tip: GitOid::from_hex(format, &"11".repeat(format.digest_len())).unwrap(),
        after: 1,
    }
}

#[test]
fn explicit_first_parent_mode_preserves_other_history_modes_and_limits() {
    let options = super::super::parse(&args(&["--first-parent"]), false).unwrap();
    let Query::FirstParent(query) = options.query else {
        panic!("first-parent query");
    };
    assert_eq!(query.limit, 50);
    assert_eq!(query.limits, HistoryLimits::default());
    assert!(query.cursor.is_none());
    assert!(matches!(
        super::super::parse(&args(&[]), false).unwrap().query,
        Query::Log(_)
    ));
    assert!(matches!(
        super::super::parse(&args(&["--path", "file"]), false)
            .unwrap()
            .query,
        Query::PathLog(_)
    ));
    for extra in [
        vec!["--first-parent", "--after", "0"],
        vec!["--first-parent", "--path", "file"],
        vec!["--first-parent", "--path-hex", "66"],
        vec!["--first-parent", "--first-parent"],
        vec!["--first-parent", "--limit", "0"],
        vec!["--first-parent", "--limit", "101"],
        vec!["--first-parent", "--max-commits", "4097"],
        vec!["--first-parent", "--max-edges", "16385"],
        vec!["--cursor", "not-a-cursor"],
    ] {
        assert!(
            super::super::parse(&args(&extra), false).is_err(),
            "{extra:?}"
        );
    }
    assert!(super::super::parse(&args(&["--first-parent", "--path", "file"]), true).is_err());
    let allowed = super::super::parse(
        &args(&[
            "--first-parent",
            "--limit",
            "1",
            "--max-commits",
            "1",
            "--max-edges",
            "1",
        ]),
        false,
    )
    .unwrap();
    let Query::FirstParent(query) = allowed.query else {
        panic!("first-parent query");
    };
    assert_eq!(
        (
            query.limit,
            query.limits.max_commits,
            query.limits.max_edges
        ),
        (1, 1, 1)
    );
}

#[test]
fn cursor_roundtrips_raw_reference_bytes_and_both_native_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let expected = cursor(format, RefName::try_new(b"refs/heads/\xff").unwrap());
        let token = encode_cursor(&expected);
        assert_eq!(parse_cursor(&token).unwrap(), expected);
        let mut input = args(&[]);
        input[3] = hex(expected.reference.as_bytes());
        input.extend([
            "--ref-hex".into(),
            "--first-parent".into(),
            "--cursor".into(),
            token,
            "--object-format".into(),
            format.as_str().into(),
            "--limit".into(),
            "1".into(),
        ]);
        let options = super::super::parse(&input, false).unwrap();
        let Query::FirstParent(query) = options.query else {
            panic!("first-parent query");
        };
        assert_eq!(query.cursor, Some(expected));
    }
}

#[test]
fn malformed_or_cross_selection_cursors_refuse_before_opening_a_node() {
    let original = cursor(
        GitHashAlgorithm::Sha1,
        RefName::try_new(b"refs/heads/main").unwrap(),
    );
    let token = encode_cursor(&original);
    assert!(super::super::parse(&args(&["--first-parent", "--cursor", &token]), false).is_ok());
    let mut wrong_ref = args(&["--first-parent", "--cursor", &token]);
    wrong_ref[3] = "refs/heads/topic".into();
    assert!(super::super::parse(&wrong_ref, false).is_err());
    assert!(
        super::super::parse(
            &args(&[
                "--first-parent",
                "--cursor",
                &token,
                "--object-format",
                "sha256"
            ]),
            false
        )
        .is_err()
    );
    let wrong_head = format!("alg:1:{}", "cd".repeat(32));
    assert!(
        super::super::parse(
            &args(&[
                "--first-parent",
                "--cursor",
                &token,
                "--expected-head",
                &wrong_head
            ]),
            false
        )
        .is_err()
    );
    let matching_head = head_token(original.source_head);
    assert!(
        super::super::parse(
            &args(&[
                "--first-parent",
                "--cursor",
                &token,
                "--expected-head",
                &matching_head
            ]),
            false
        )
        .is_ok()
    );
    for wrong in [
        format!("{token}/extra"),
        token.replacen("fgfp1/", "fgfp2/", 1),
        token.replacen("alg:1:", "alg:01:", 1),
        token.replacen("/sha1/", "/sha512/", 1),
        format!("{}/01", token.rsplit_once('/').unwrap().0),
        format!("{}/0", token.rsplit_once('/').unwrap().0),
        format!("{}/4097", token.rsplit_once('/').unwrap().0),
        format!("{}/18446744073709551616", token.rsplit_once('/').unwrap().0),
        "x".repeat(4097),
    ] {
        assert!(parse_cursor(&wrong).is_err(), "{wrong}");
    }
    let mut edge = original.clone();
    edge.after = 4096;
    assert_eq!(parse_cursor(&encode_cursor(&edge)).unwrap(), edge);
    edge.tip = GitOid::from_hex(GitHashAlgorithm::Sha1, &"00".repeat(20)).unwrap();
    assert!(parse_cursor(&encode_cursor(&edge)).is_err());
}

#[test]
fn first_parent_reports_no_total_and_validates_chain_cursor_and_budget_accounting() {
    let options = super::super::parse(&args(&["--first-parent", "--limit", "1"]), false).unwrap();
    let head = authority_head();
    let tip = GitOid::from_hex(GitHashAlgorithm::Sha1, &"11".repeat(20)).unwrap();
    let parent = GitOid::from_hex(GitHashAlgorithm::Sha1, &"22".repeat(20)).unwrap();
    let tree = GitOid::from_hex(GitHashAlgorithm::Sha1, &"33".repeat(20)).unwrap();
    let page = FirstParentPage {
        tip,
        after: 0,
        next_after: Some(1),
        root_reached: false,
        commits: vec![HistoryCommit {
            id: tip,
            tree,
            parents: vec![parent],
            body: b"claim\x1b[2J".to_vec(),
        }],
        visited_commits: 1,
        visited_parent_edges: 1,
        metadata_bytes: 9,
    };
    let json = render(&options, head, &page).unwrap();
    assert!(json.contains("\"profile\":\"first-parent-prefix-v1\""));
    assert!(json.contains("\"root_reached\":false"));
    assert!(json.contains("\"visited_commits\":1"));
    assert!(json.contains(&encode_cursor(
        &page.continuation(head, &options.reference).unwrap()
    )));
    assert!(!json.contains("total_commits"));
    assert!(!json.contains('\x1b'));
    for changed in 0..6 {
        let mut bad = page.clone();
        match changed {
            0 => bad.next_after = Some(2),
            1 => bad.visited_commits = 2,
            2 => bad.visited_parent_edges = HistoryLimits::default().max_edges + 1,
            3 => bad.metadata_bytes = 0,
            4 => bad.root_reached = true,
            _ => bad.commits[0].id = parent,
        }
        assert!(render(&options, head, &bad).is_err());
    }
    let mut root = page.clone();
    root.commits[0].parents.clear();
    root.root_reached = true;
    root.next_after = None;
    root.visited_parent_edges = 0;
    let root_json = render(&options, head, &root).unwrap();
    assert!(root_json.contains("\"next_cursor\":null"));
    assert!(root_json.contains("\"root_reached\":true"));

    let incoming = page.continuation(head, &options.reference).unwrap();
    let token = encode_cursor(&incoming);
    let continued = super::super::parse(
        &args(&["--first-parent", "--cursor", &token, "--limit", "1"]),
        false,
    )
    .unwrap();
    let later = FirstParentPage {
        after: 1,
        commits: vec![HistoryCommit {
            id: parent,
            tree,
            parents: vec![],
            body: b"root".to_vec(),
        }],
        next_after: None,
        root_reached: true,
        visited_commits: 2,
        metadata_bytes: 13,
        ..page
    };
    assert!(render(&continued, head, &later).is_ok());
    let other_head = parse_head(&format!("alg:1:{}", "cd".repeat(32))).unwrap();
    assert!(render(&continued, other_head, &later).is_err());
}
