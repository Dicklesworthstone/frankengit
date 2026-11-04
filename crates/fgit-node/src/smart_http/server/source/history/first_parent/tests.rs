use super::*;
use fgit_types::{CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes};
use fgit_wire::smart_http::head;

fn form(format: GitHashAlgorithm) -> String {
    format!("object_format={}&ref=refs/heads/main", format.as_str())
}

fn head() -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(1).unwrap(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[0x31; 32]).unwrap(),
    )
}

fn record(format: GitHashAlgorithm, parents: Vec<GitOid>, message: &[u8]) -> HistoryCommit {
    let tree = git_object_id(format, GitObjectKind::Tree, &[]);
    let mut body = format!("tree {tree}\n").into_bytes();
    for parent in &parents {
        body.extend_from_slice(format!("parent {parent}\n").as_bytes());
    }
    body.extend_from_slice(b"author Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\n");
    body.extend_from_slice(message);
    HistoryCommit {
        id: git_object_id(format, GitObjectKind::Commit, &body),
        tree,
        parents,
        body,
    }
}

fn sample(format: GitHashAlgorithm) -> (Command, FirstParentPage) {
    let root = record(format, vec![], b"root\n");
    let side = record(format, vec![], b"side\n");
    let merge = record(format, vec![root.id, side.id], b"merge\xff\n");
    let page = FirstParentPage {
        tip: merge.id,
        after: 0,
        next_after: Some(1),
        root_reached: false,
        visited_commits: 1,
        visited_parent_edges: merge.parents.len(),
        metadata_bytes: merge.body.len(),
        commits: vec![merge],
    };
    let query = Command::parse(
        format!("{}&first_parent=true&limit=1", form(format)).as_bytes(),
        format,
    )
    .unwrap();
    (query, page)
}

#[test]
fn explicit_profile_and_canonical_cursor_preserve_the_closed_log_selection() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let base = form(format);
        let full = Command::parse(base.as_bytes(), format).unwrap();
        assert!(full.first_parent.is_none());
        assert_eq!(full.options, LogOptions::default());
        let (query, page) = sample(format);
        let options = query.first_parent.unwrap();
        assert_eq!(options.limit, 1);
        assert!(options.cursor.is_none());
        let cursor = page
            .continuation(head(), &query.selection.reference)
            .unwrap();
        let encoded = cursor.encode();
        let form = format!(
            "{base}&first_parent=true&cursor={encoded}&limit=2&max_commits=3&max_edges=5&max_metadata_bytes=1024"
        );
        let parsed = Command::parse(form.as_bytes(), format).unwrap();
        let options = parsed.first_parent.unwrap();
        assert_eq!(options.cursor, Some(cursor));
        assert_eq!(options.limit, 2);
        assert_eq!(options.limits.max_commits, 3);
        assert_eq!(options.limits.max_edges, 5);
        assert_eq!(options.limits.max_metadata_bytes, 1024);
        assert_eq!(parsed.options.after, 1);
        assert!(parsed.path.is_none());
    }
}

#[test]
fn profile_conflicts_noncanonical_tokens_and_substituted_selection_refuse() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (query, page) = sample(format);
        let base = form(format);
        let token = page
            .continuation(head(), &query.selection.reference)
            .unwrap()
            .encode();
        for suffix in [
            "&first_parent=false",
            "&first_parent=1",
            "&first_parent=TRUE",
            "&first_parent=",
            "&first_parent=true&first_parent=true",
            "&first_parent=true&after=0",
            "&first_parent=true&after=1",
            "&first_parent=true&path_hex=61",
            "&first_parent=true&max_tree_entries=1",
            "&first_parent=true&max_cached_bytes=1",
            "&first_parent=true&cursor=",
            "&first_parent=true&cursor=fgfp1",
            "&first_parent=true&max_commits=4097",
            "&first_parent=true&max_edges=0",
            "&first_parent=true&max_metadata_bytes=4194305",
            "&first_parent=true&limit=0",
            "&first_parent=true&limit=101",
        ] {
            assert!(
                Command::parse((base.clone() + suffix).as_bytes(), format).is_err(),
                "{suffix}"
            );
        }
        for suffix in [
            format!("&cursor={token}"),
            format!("&first_parent=true&cursor={token}&cursor={token}"),
            format!(
                "&first_parent=true&cursor={token}&expected_head=alg:1:{}",
                "32".repeat(32)
            ),
            format!(
                "&first_parent=true&cursor={token}&expected_commit={}",
                "ab".repeat(format.digest_len())
            ),
            format!("&first_parent=true&cursor={}", "a".repeat(4097)),
            format!("&first_parent=true&cursor={token}/extra"),
        ] {
            assert!(Command::parse((base.clone() + &suffix).as_bytes(), format).is_err());
        }
        let other_ref = format!(
            "object_format={}&ref=refs/heads/other&first_parent=true&cursor={token}",
            format.as_str(),
        );
        assert!(Command::parse(other_ref.as_bytes(), format).is_err());
        let valid = format!("{base}&first_parent=true&cursor={token}");
        assert!(Command::parse(valid.as_bytes(), format).is_ok());
    }
}

#[test]
fn response_checks_account_for_the_visited_prefix_and_every_parent_header() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (query, page) = sample(format);
        let options = query.first_parent.as_ref().unwrap();
        let valid =
            |page: &FirstParentPage| validate_page(&query.selection, options, head(), page, format);
        assert!(valid(&page).is_ok());
        let mut invalid = Vec::new();
        let mut changed = page.clone();
        changed.root_reached = true;
        invalid.push(changed);
        let mut changed = page.clone();
        changed.next_after = None;
        invalid.push(changed);
        let mut changed = page.clone();
        changed.visited_commits += 1;
        invalid.push(changed);
        let mut changed = page.clone();
        changed.visited_parent_edges -= 1;
        invalid.push(changed);
        let mut changed = page.clone();
        changed.metadata_bytes -= 1;
        invalid.push(changed);
        let mut changed = page.clone();
        changed.metadata_bytes += 1;
        invalid.push(changed);
        let mut changed = page.clone();
        changed.tip = changed.commits[0].parents[0];
        invalid.push(changed);
        let mut changed = page.clone();
        changed.commits.clear();
        invalid.push(changed);
        for changed in invalid {
            assert!(valid(&changed).is_err(), "{changed:?}");
        }

        let root = record(format, vec![], b"root\n");
        let cursor = page
            .continuation(head(), &query.selection.reference)
            .unwrap();
        let mut options = options.clone();
        options.cursor = Some(cursor);
        let last = FirstParentPage {
            tip: page.tip,
            after: 1,
            next_after: None,
            root_reached: true,
            visited_commits: 2,
            visited_parent_edges: 2,
            metadata_bytes: page.metadata_bytes + root.body.len(),
            commits: vec![root],
        };
        assert!(validate_page(&query.selection, &options, head(), &last, format).is_ok());
        let empty = FirstParentPage {
            after: 2,
            commits: Vec::new(),
            ..last
        };
        options.cursor.as_mut().unwrap().after = 2;
        assert!(validate_page(&query.selection, &options, head(), &empty, format).is_ok());
    }
}

#[test]
fn prefix_work_empty_root_pages_and_terminal_back_edges_are_checked() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (query, _) = sample(format);
        let root = record(format, vec![], b"root\n");
        let middle = record(format, vec![root.id], b"middle\n");
        let tip = record(format, vec![middle.id], b"tip\n");
        let mut options = query.first_parent.clone().unwrap();
        options.cursor = Some(FirstParentCursor {
            source_head: head(),
            reference: query.selection.reference.clone(),
            tip: tip.id,
            after: 1,
        });
        let page = FirstParentPage {
            tip: tip.id,
            after: 1,
            next_after: Some(2),
            root_reached: false,
            commits: vec![middle.clone()],
            visited_commits: 2,
            visited_parent_edges: 2,
            metadata_bytes: tip.body.len() + middle.body.len(),
        };
        assert!(validate_page(&query.selection, &options, head(), &page, format).is_ok());
        // Counting only the returned commit's edge would omit work performed
        // while revalidating the cursor's skipped prefix.
        let mut undercharged = page;
        undercharged.visited_parent_edges = 1;
        assert!(validate_page(&query.selection, &options, head(), &undercharged, format).is_err());

        options.cursor.as_mut().unwrap().after = 3;
        let empty = FirstParentPage {
            tip: tip.id,
            after: 3,
            next_after: None,
            root_reached: true,
            commits: Vec::new(),
            visited_commits: 3,
            visited_parent_edges: 2,
            metadata_bytes: tip.body.len() + middle.body.len() + root.body.len(),
        };
        assert!(validate_page(&query.selection, &options, head(), &empty, format).is_ok());
        let mut no_bytes = empty.clone();
        no_bytes.metadata_bytes = 0;
        assert!(validate_page(&query.selection, &options, head(), &no_bytes, format).is_err());
        let mut no_commits = empty.clone();
        no_commits.visited_commits = 0;
        assert!(validate_page(&query.selection, &options, head(), &no_commits, format).is_err());
        let mut missing_edges = empty;
        missing_edges.visited_parent_edges = 1;
        assert!(validate_page(&query.selection, &options, head(), &missing_edges, format).is_err());

        options.cursor = None;
        options.limit = 2;
        let page = FirstParentPage {
            tip: tip.id,
            after: 0,
            next_after: Some(2),
            root_reached: false,
            visited_commits: 2,
            visited_parent_edges: 2,
            metadata_bytes: tip.body.len() + middle.body.len(),
            commits: vec![tip.clone(), middle.clone()],
        };
        assert!(validate_page(&query.selection, &options, head(), &page, format).is_ok());
        for next in [tip.id, middle.id] {
            let mut cycle = page.clone();
            cycle.commits[1].parents[0] = next;
            assert!(validate_page(&query.selection, &options, head(), &cycle, format).is_err());
        }
    }
}

#[test]
fn log_route_is_still_read_only_and_does_not_expand_sponsored_source_grants() {
    let bytes = b"POST /repo.git/api/v1/source/log HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n\r\n";
    let envelope = head::parse(bytes, HttpLimits::default()).unwrap().unwrap();
    let request = super::super::super::Request::parse(&envelope).unwrap();
    assert!(!request.is_mutation());
    assert_eq!(request.agent_operation(), None);
}

#[test]
fn first_parent_json_preserves_native_records_and_has_exact_output_and_cancellation_bounds() {
    use fgit_types::{RepositoryId, TenantId};
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "fg-first-parent-http-render-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
    ));
    let format = GitHashAlgorithm::Sha256;
    let (node, _) = OneNode::init(
        crate::NodeConfig::new(
            path.clone(),
            TenantId::from_bytes([0x33; 16]),
            RepositoryId::from_bytes([0x34; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(2),
    )
    .unwrap();
    let (query, page) = sample(format);
    let body = render(&node, &query, head(), &page, MAX_REPLY_BYTES, &mut || true).unwrap();
    for field in [
        "\"type\":\"source_first_parent_log\"",
        "\"profile\":\"first-parent-prefix-v1\"",
        "\"ordering\":\"stored-first-parent-v1\"",
        "\"read_only\":true",
        "\"transaction_created\":false",
        "\"published\":false",
        "\"author_identity_verified\":false",
        "\"page_complete\":true",
        "\"visited_commits\":1",
        "\"visited_parent_edges\":2",
        "\"body_hex\":",
    ] {
        assert!(body.contains(field), "{field}");
    }
    assert!(!body.contains("total_commits") && !body.contains("next_after"));
    assert!(
        body.contains(
            &page
                .continuation(head(), &query.selection.reference)
                .unwrap()
                .encode()
        )
    );
    assert_eq!(
        render(&node, &query, head(), &page, body.len(), &mut || true).unwrap(),
        body,
    );
    assert!(render(&node, &query, head(), &page, body.len() - 1, &mut || true).is_err());
    let mut polls = 0;
    assert!(
        render(&node, &query, head(), &page, MAX_REPLY_BYTES, &mut || {
            polls += 1;
            polls < 5
        })
        .is_err()
    );
    let mut corrupted = page;
    corrupted.commits[0].body[0] ^= 1;
    assert!(
        render(
            &node,
            &query,
            head(),
            &corrupted,
            MAX_REPLY_BYTES,
            &mut || true
        )
        .is_err()
    );
    node.shutdown().unwrap();
    std::fs::remove_dir_all(path).unwrap();
}
