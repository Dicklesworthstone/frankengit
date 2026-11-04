#![forbid(unsafe_code)]
//! Explicit recent-history queries through the production authenticated HTTP
//! listener. The ordinary DAG mode and the source grant remain independent.

#[path = "source_http/support.rs"]
mod support;
use support::*;

use fgit_authority::{IdempotencyKey, key_recovery::RequestRecovery};
use fgit_forge::history::first_parent::{FirstParentCursor, FirstParentOptions};
use fgit_forge::history::{HistoryCommit, LogOptions};
use fgit_node::{LoopbackReceiveSession, OneNode};
use fgit_types::{GitHashAlgorithm, RefName};

fn recent(format: GitHashAlgorithm) -> String {
    common(format) + "&first_parent=true"
}

#[test]
fn first_parent_pages_recheck_the_cursor_and_survive_reopen_without_a_transaction() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, main) = fixture(&root, format);
        let before = generation(&node);
        let (_, oracle) = node
            .runtime()
            .block_on(node.read_commit_history_in(
                &node.request_context(),
                &RefName::try_new(b"refs/heads/main").unwrap(),
                &Default::default(),
                None,
                LogOptions::default(),
            ))
            .unwrap();
        assert_eq!(oracle.total_commits, 2);
        let path = root.0.join("credentials");
        credentials(&node, &path);
        let server = Server::start(node, &path, 8, true, false);
        let query = recent(format);
        let first_query = format!("{query}&limit=1&max_commits=1");
        let first = post(&server.client, "log", 'a', &first_query, false);
        status(&first, 200);
        assert_eq!(text(&first.body, "type"), "source_first_parent_log");
        assert_eq!(text(&first.body, "profile"), "first-parent-prefix-v1");
        assert_eq!(text(&first.body, "ordering"), "stored-first-parent-v1");
        assert_eq!(text(&first.body, "source_commit"), main.to_string());
        assert_eq!(text(&first.body, "body_hex"), hex(&oracle.commits[0].body));
        assert_eq!(number(&first.body, "visited_commits"), 1);
        assert_eq!(number(&first.body, "visited_parent_edges"), 1);
        assert_eq!(
            number(&first.body, "metadata_bytes"),
            oracle.commits[0].body.len() as u64
        );
        assert!(first.body.contains("\"root_reached\":false"));
        assert!(first.body.contains("\"page_complete\":true"));
        assert!(first.body.contains("\"author_identity_verified\":false"));
        assert!(
            first
                .body
                .contains("\"transaction_created\":false,\"published\":false")
        );
        assert!(!first.body.contains("total_commits") && !first.body.contains("next_after"));
        let cursor = text(&first.body, "next_cursor");
        let decoded = FirstParentCursor::decode(cursor).unwrap();
        assert_eq!(decoded.reference.as_bytes(), b"refs/heads/main");
        assert_eq!(decoded.tip, main);
        assert_eq!(decoded.after, 1);
        let pin = token(&first);

        let full = post(
            &server.client,
            "log",
            'a',
            &(common(format) + "&limit=1&max_commits=1"),
            false,
        );
        status(&full, 413);
        assert!(!full.body.contains("body_hex"));
        let tail_query = format!("{query}&cursor={cursor}&limit=1");
        let tail = post(&server.client, "log", 'a', &tail_query, true);
        status(&tail, 200);
        assert_eq!(token(&tail), pin);
        assert_eq!(
            text(&tail.body, "object_id"),
            oracle.commits[1].id.to_string()
        );
        assert_eq!(text(&tail.body, "body_hex"), hex(&oracle.commits[1].body));
        assert_eq!(number(&tail.body, "after"), 1);
        assert_eq!(number(&tail.body, "visited_commits"), 2);
        assert!(tail.body.contains("\"root_reached\":true"));
        assert!(tail.body.contains("\"next_cursor\":null"));
        let limited = post(
            &server.client,
            "log",
            'a',
            &(tail_query.clone() + "&max_commits=1"),
            false,
        );
        status(&limited, 413);
        assert!(!limited.body.contains("body_hex"));

        let mut forged = decoded;
        forged.tip = oracle.commits[1].id;
        let refused = post(
            &server.client,
            "log",
            'a',
            &format!("{query}&cursor={}", forged.encode()),
            false,
        );
        status(&refused, 400);
        assert!(!refused.body.contains("body_hex"));
        status(
            &post(
                &server.client,
                "log",
                'a',
                &tail_query.replace("ref=refs/heads/main", "ref=refs/heads/other"),
                false,
            ),
            400,
        );
        let complete = post(&server.client, "log", 'a', &query, false);
        status(&complete, 200);
        assert!(complete.body.contains("\"root_reached\":true"));
        assert!(complete.body.contains("\"next_cursor\":null"));
        assert_eq!(number(&complete.body, "visited_commits"), 2);
        status(
            &post(
                &server.client,
                "log",
                'a',
                &format!("{query}&expected_commit={}", oracle.commits[1].id),
                false,
            ),
            409,
        );
        assert_eq!(server.finish().accepted_sessions(), 8);

        let node = reopen(&config);
        assert_eq!(generation(&node), before);
        let sentinel = LoopbackReceiveSession::authenticated(
            OWNER,
            IdempotencyKey::new(b"first-parent-read-must-not-seal".to_vec()).unwrap(),
        );
        assert!(matches!(
            node.runtime()
                .block_on(node.recover_transaction_in(&node.request_context(), &sentinel))
                .unwrap(),
            RequestRecovery::KeyNotObserved
        ));
        let server = Server::start(node, &path, 2, true, false);
        assert_eq!(post(&server.client, "log", 'a', &first_query, true), first);
        assert_eq!(post(&server.client, "log", 'a', &tail_query, false), tail);
        assert_eq!(server.finish().accepted_sessions(), 2);
        let node = reopen(&config);
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}

#[test]
fn first_parent_profile_preserves_read_scope_before_ingress_rotation_and_service_disable() {
    let format = GitHashAlgorithm::Sha1;
    let root = Scratch::new();
    let config = root.config(format);
    let (node, _) = fixture(&root, format);
    let before = generation(&node);
    let path = root.0.join("credentials");
    let header = credentials(&node, &path);
    let server = Server::start(node, &path, 9, true, false);
    let query = recent(format);
    let valid = post(&server.client, "log", 'a', &query, false);
    status(&valid, 200);
    let denied = exchange(
        &server.client,
        &request(
            &server.client,
            "/api/v1/source/log",
            'b',
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\r\nExpect: 100-continue\r\n",
            &[],
        ),
        true,
    );
    status(&denied, 403);
    status(&post(&server.client, "log", 'c', &query, false), 403);
    status(&post(&server.client, "log", 'd', &query, false), 401);
    let keyed = exchange(
        &server.client,
        &request(
            &server.client,
            "/api/v1/source/log",
            'a',
            &format!(
                "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: forbidden-first-parent-key\r\n",
                query.len(),
            ),
            query.as_bytes(),
        ),
        true,
    );
    status(&keyed, 400);
    let missing = post(
        &server.client,
        "log",
        'a',
        &query.replace("heads/main", "heads/missing"),
        false,
    );
    status(&missing, 404);
    assert!(!missing.body.contains("body_hex"));
    let mut foreign = server.client.clone();
    foreign.route = "/another.git".into();
    status(&post(&foreign, "log", 'a', &query, false), 404);
    replace(&path, &(header + &row('9', OWNER, "read")));
    status(&post(&server.client, "log", 'a', &query, false), 401);
    assert_eq!(post(&server.client, "log", '9', &query, true), valid);
    assert_eq!(server.finish().accepted_sessions(), 9);
    let node = reopen(&config);
    assert_eq!(generation(&node), before);
    let server = Server::start(node, &path, 1, false, false);
    let disabled = post(&server.client, "log", '9', &query, false);
    status(&disabled, 403);
    assert!(!disabled.body.contains("body_hex"));
    assert_eq!(server.finish().accepted_sessions(), 1);
}

#[test]
fn authority_movement_invalidates_the_first_parent_cursor_even_when_the_tip_is_unchanged() {
    let format = GitHashAlgorithm::Sha256;
    let root = Scratch::new();
    let config = root.config(format);
    let (node, main) = fixture(&root, format);
    let before = generation(&node);
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let server = Server::start(node, &path, 5, true, true);
    let query = recent(format);
    let first = post(
        &server.client,
        "log",
        'a',
        &(query.clone() + "&limit=1"),
        false,
    );
    status(&first, 200);
    let cursor = text(&first.body, "next_cursor");
    let pin = token(&first);
    let body = b"expected_version=0&title=Intervening+write&body=";
    let write = exchange(
        &server.client,
        &request(
            &server.client,
            "/api/v1/issues/1/open",
            'b',
            &format!(
                "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: first-parent-pin-race\r\n",
                body.len(),
            ),
            body,
        ),
        true,
    );
    status(&write, 200);
    let stale = post(
        &server.client,
        "log",
        'a',
        &format!("{query}&cursor={cursor}"),
        false,
    );
    status(&stale, 409);
    assert!(stale.body.contains("source_snapshot_moved"));
    assert!(!stale.body.contains("body_hex"));
    let current = post(
        &server.client,
        "log",
        'a',
        &format!("{query}&limit=1&expected_commit={main}"),
        true,
    );
    status(&current, 200);
    assert_ne!(token(&current), pin);
    assert_eq!(text(&current.body, "source_commit"), main.to_string());
    let tail = post(
        &server.client,
        "log",
        'a',
        &format!("{query}&cursor={}", text(&current.body, "next_cursor")),
        false,
    );
    status(&tail, 200);
    assert!(tail.body.contains("\"root_reached\":true"));
    assert_eq!(server.finish().accepted_sessions(), 5);
    let node = reopen(&config);
    assert_eq!(generation(&node), before + 1);
    node.shutdown().unwrap();
}

fn long_fixture(root: &Scratch, format: GitHashAlgorithm) -> (OneNode, Vec<HistoryCommit>) {
    use fgit_admission::{
        AdmissionContext, AdmissionLimits, PermittedObjectClosure, SourceImportOrigin,
        SourceImportReceipt, SourceRefUpdate, ValidatedClosure, permitted_object_closure_root,
        validate_source_import,
    };
    use fgit_crypto::{GitObjectKind, git_object_id};
    use fgit_git_object::ObjectType;
    use fgit_types::{DecisionOutcome, GitOid, HeadGeneration};
    use std::collections::BTreeSet;
    use std::fmt::Write as _;

    let (mut node, _) = OneNode::init(root.config(format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let tree = node
        .put_git_object(ObjectType::Tree, Vec::new())
        .unwrap()
        .identity();
    let mut ids = BTreeSet::from([tree]);
    let make = |parents: Vec<GitOid>, message: String| {
        let mut body = format!("tree {tree}\n");
        for parent in &parents {
            writeln!(body, "parent {parent}").unwrap();
        }
        writeln!(body, "author Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\n{message}").unwrap();
        let body = body.into_bytes();
        let id = node
            .put_git_object(ObjectType::Commit, body.clone())
            .unwrap()
            .identity();
        assert_eq!(git_object_id(format, GitObjectKind::Commit, &body), id);
        HistoryCommit {
            id,
            tree,
            parents,
            body,
        }
    };
    let mut history: Vec<HistoryCommit> = Vec::new();
    for index in 0..4097 {
        let parents = history.last().map(|row| vec![row.id]).unwrap_or_default();
        let commit = make(parents, format!("commit {index}"));
        ids.insert(commit.id);
        history.push(commit);
    }
    let side = make(vec![], "side-parent only".to_owned());
    ids.insert(side.id);
    let merge = make(
        vec![history.last().unwrap().id, side.id],
        "merge tip".to_owned(),
    );
    ids.insert(merge.id);
    let zero = GitOid::from_hex(format, &"0".repeat(format.digest_len() * 2)).unwrap();
    let imported = validate_source_import(
        &[SourceRefUpdate {
            old: zero,
            new: merge.id,
            ref_name: b"refs/heads/main".to_vec(),
        }],
        &SourceImportReceipt {
            object_format: format,
            object_count: u32::try_from(ids.len()).unwrap(),
            delete_only: false,
            origin: SourceImportOrigin::LocalGitDirectory,
        },
        ValidatedClosure {
            object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
                ids.clone(),
            ))
            .unwrap(),
            objects: ids,
        },
    )
    .unwrap();
    let context = AdmissionContext {
        head_key: node.authority_head_key().clone(),
        tenant_id: node.tenant_id(),
        repository_id: node.repository_id(),
        principal_id: OWNER,
        idempotency_key: IdempotencyKey::new(b"long-first-parent-http".to_vec()).unwrap(),
        object_format: format,
    };
    let result = node
        .runtime()
        .block_on(node.admit_validated_source_import_durable_in(
            &node.request_context(),
            &context,
            &imported,
            AdmissionLimits::default(),
        ))
        .unwrap();
    assert!(
        result
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    history.reverse();
    history.insert(0, merge);
    (node, history)
}

#[test]
fn a_long_repository_returns_recent_merge_history_without_walking_side_parent_bodies() {
    let format = GitHashAlgorithm::Sha256;
    let root = Scratch::new();
    let config = root.config(format);
    let (node, history) = long_fixture(&root, format);
    let before = generation(&node);
    let options = FirstParentOptions {
        limit: 2,
        ..FirstParentOptions::default()
    };
    let (_, native) = node
        .runtime()
        .block_on(node.read_first_parent_history_in(
            &node.request_context(),
            &RefName::try_new(b"refs/heads/main").unwrap(),
            &Default::default(),
            None,
            &options,
        ))
        .unwrap();
    assert_eq!(native.commits, history[..2]);
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let server = Server::start(node, &path, 3, true, false);
    let query = recent(format);
    let first = post(
        &server.client,
        "log",
        'a',
        &format!("{query}&limit=2&max_commits=2"),
        false,
    );
    status(&first, 200);
    assert_eq!(number(&first.body, "visited_commits"), 2);
    assert_eq!(number(&first.body, "visited_parent_edges"), 3);
    assert_eq!(
        text(&first.body, "source_commit"),
        history[0].id.to_string()
    );
    for row in &history[..2] {
        assert!(
            first
                .body
                .contains(&format!("\"object_id\":\"{}\"", row.id))
        );
        assert!(first.body.contains(&hex(&row.body)));
    }
    assert!(!first.body.contains(&hex(b"side-parent only")));
    let full = post(
        &server.client,
        "log",
        'a',
        &(common(format) + "&limit=2"),
        false,
    );
    status(&full, 413);
    assert!(!full.body.contains("body_hex"));
    let next = post(
        &server.client,
        "log",
        'a',
        &format!(
            "{query}&limit=2&max_commits=4&cursor={}",
            text(&first.body, "next_cursor")
        ),
        true,
    );
    status(&next, 200);
    assert_eq!(number(&next.body, "visited_commits"), 4);
    assert_eq!(number(&next.body, "after"), 2);
    assert_eq!(text(&next.body, "object_id"), history[2].id.to_string());
    assert_eq!(server.finish().accepted_sessions(), 3);
    let node = reopen(&config);
    assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
}
