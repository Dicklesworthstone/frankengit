#![forbid(unsafe_code)]
//! Production TCP reads over native PR history and real workflow observations.

#[path = "pull_request_http/support.rs"]
mod support;

use fgit_forge::event::workflow_check::WorkflowCheckId;
use fgit_types::GitHashAlgorithm;
use support::*;

#[test]
fn checks_read_requires_its_own_grant_and_preserves_the_selected_pr_snapshot() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, data) = fixture(&root, format);
        let before = generation(&node);
        let credentials = root.0.join("credentials");
        let header = grants(&node, &credentials);
        replace(
            &credentials,
            &(header.clone()
                + &row('a', OWNER, "pulls-read")
                + &row('b', OWNER, "pulls-write")
                + &row(
                    'd',
                    FOREIGN,
                    "read,receive,issues-read,issues-write,outcomes-read",
                )
                + &row('e', FOREIGN, "reviews-read,reviews-write,merges-write")),
        );
        let server = Server::start(node, &credentials, 16, true, false);
        let client = &server.client;
        committed(&post(
            client,
            7,
            "open",
            'b',
            "checks-open",
            &form(&data, 0),
            false,
        )); // 1
        let empty = get(client, "/api/v1/pulls/7/checks", 'a'); // 2
        status(&empty, 200);
        for field in [
            "\"type\":\"pull_request_checks\"",
            "\"number\":\"7\"",
            "\"pull_request_version\":\"1\"",
            "\"found\":true",
            "\"source_current\":true",
            "\"complete\":true",
            "\"checks\":[]",
            "\"scope\":\"trusted_workflow_observations\"",
            "\"merge_permission\":null",
        ] {
            assert!(
                empty.body.contains(field),
                "missing {field}: {}",
                empty.body
            );
        }
        assert!(
            empty
                .body
                .contains(&format!("\"source_tip\":\"{}\"", data.source_tip))
        );
        let head = token(&empty);
        for denied in ['b', 'd', 'e'] {
            status(&get(client, "/api/v1/pulls/7/checks", denied), 403); // 3..5
        }
        status(&get(client, "/api/v1/pulls/7/checks", 'z'), 401); // 6
        let absent = get(client, "/api/v1/pulls/8/checks", 'a'); // 7
        status(&absent, 404);
        assert!(absent.body.contains("\"found\":false"));
        assert!(absent.body.contains("\"source_head\":null"));
        assert!(absent.body.contains("\"source_ref_hex\":null"));
        assert!(absent.body.contains("\"checks\":[]"));
        let after = WorkflowCheckId::from_bytes([0; 32]).to_string();
        status(
            &get(
                client,
                &format!("/api/v1/pulls/7/checks?after={after}"),
                'a',
            ),
            400,
        ); // 8
        let mut updated = data.clone();
        updated.title = "changed after check snapshot".into();
        committed(&post(
            client,
            7,
            "update",
            'b',
            "checks-update",
            &form(&updated, 1),
            false,
        )); // 9
        let retained = get(
            client,
            &format!("/api/v1/pulls/7/checks?expected_head={head}"),
            'a',
        ); // 10
        status(&retained, 200);
        assert_eq!(retained.body, empty.body);
        let current = get(client, "/api/v1/pulls/7/checks", 'a'); // 11
        status(&current, 200);
        assert!(current.body.contains("\"pull_request_version\":\"2\""));
        assert_ne!(token(&current), head);
        let unknown = format!("alg:2:{}", "ff".repeat(32));
        status(
            &get(
                client,
                &format!("/api/v1/pulls/7/checks?expected_head={unknown}"),
                'a',
            ),
            409,
        ); // 12
        status(
            &exchange(
                client,
                &request(client, "POST", "/api/v1/pulls/7/checks", 'a', "", &[]),
                true,
            ),
            405,
        ); // 13
        status(
            &exchange(
                client,
                &request(
                    client,
                    "GET",
                    "/api/v1/pulls/7/checks",
                    'a',
                    "Idempotency-Key: no-write\r\n",
                    &[],
                ),
                true,
            ),
            400,
        ); // 14
        let continuation = get(
            client,
            &format!("/api/v1/pulls/7/checks?after={after}&limit=1&expected_head={head}"),
            'a',
        ); // 15
        status(&continuation, 200);
        assert!(continuation.body.contains("\"checks\":[]"));
        // A retained token never restores a revoked read grant.
        replace(&credentials, &(header + &row('a', OWNER, "read")));
        status(
            &get(
                client,
                &format!("/api/v1/pulls/7/checks?expected_head={head}"),
                'a',
            ),
            403,
        ); // 16
        assert_eq!(server.finish().accepted_sessions(), 16);
        let node = reopen(&config);
        assert_eq!(
            generation(&node),
            before + 2,
            "only open and update publish"
        );
        node.shutdown().unwrap();
    }
}

#[cfg(target_os = "linux")]
#[test]
fn actual_workflow_observations_are_paged_by_exact_ids_without_evidence_bodies() {
    use fgit_authority::IdempotencyKey;
    use fgit_forge::event::workflow_check::{NativeWorkflowCheck, WorkflowCheckRecord};
    use fgit_node::{LoopbackReceiveSession, OneNode};
    use fgit_runner::coordinator::CheckRunStatus;
    use fgit_runner::workflow::WorkflowLimits;
    use fgit_types::DecisionOutcome;
    use std::collections::BTreeMap;

    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, mut data) = fixture(&root, format);
        add_workflow(&root, &node, &mut data);
        let run = node
            .runtime()
            .block_on(node.run_trusted_workflow_in(
                &node.request_context(),
                &data.source_ref,
                b"workflow.yml",
                [1; 16],
                &root.0,
                &[b"workflow.yml".to_vec()],
                (None, Some(data.source_tip)),
                WorkflowLimits {
                    total_output_bytes: 8192,
                    ..Default::default()
                },
            ))
            .unwrap();
        let mut journal = run.open_check_journal(None, &|| true).unwrap();
        let history = journal
            .read_history(None, None, 128, 1024 * 1024, &|| true)
            .unwrap();
        let mut records: BTreeMap<WorkflowCheckId, WorkflowCheckRecord> = BTreeMap::new();
        for entry in history.entries() {
            for (index, fact) in entry.batch().facts().iter().enumerate() {
                if fact.status == CheckRunStatus::Completed {
                    let evidence = journal
                        .read_evidence(fact.receipt_commitment.unwrap())
                        .unwrap();
                    let record = OneNode::workflow_check_record_from_batch(
                        data.source_ref.clone(),
                        entry.batch(),
                        index,
                        &evidence,
                        &|| true,
                    )
                    .unwrap();
                    let id = NativeWorkflowCheck {
                        actor: OWNER,
                        record: record.clone(),
                    }
                    .id();
                    records.insert(id, record);
                }
            }
        }
        assert_eq!(
            records.len(),
            2,
            "both real jobs must produce terminal observations"
        );
        for (id, record) in &records {
            let session = LoopbackReceiveSession::authenticated(
                OWNER,
                IdempotencyKey::new(id.to_string().into_bytes()).unwrap(),
            );
            let (_, terminal) = node
                .runtime()
                .block_on(node.admit_trusted_workflow_check_in(
                    &node.request_context(),
                    &session,
                    record,
                    Default::default(),
                ))
                .unwrap();
            assert!(matches!(
                terminal.outcome,
                DecisionOutcome::Committed { .. }
            ));
        }
        let before = generation(&node);
        let credentials = root.0.join("credentials");
        grants(&node, &credentials);
        let server = Server::start(node, &credentials, 4, true, false);
        committed(&post(
            &server.client,
            7,
            "open",
            'b',
            "workflow-checks-open",
            &form(&data, 0),
            false,
        ));
        let first = get(&server.client, "/api/v1/pulls/7/checks?limit=1", 'a');
        status(&first, 200);
        let ids: Vec<_> = records.keys().copied().collect();
        assert!(first.body.contains(&format!("\"id\":\"{}\"", ids[0])));
        assert!(
            first
                .body
                .contains(&format!("\"next_after\":\"{}\"", ids[0]))
        );
        assert!(first.body.contains("\"complete\":false"));
        assert!(!first.body.contains(&format!("\"id\":\"{}\"", ids[1])));
        let second = get(
            &server.client,
            &format!(
                "/api/v1/pulls/7/checks?limit=1&after={}&expected_head={}",
                ids[0],
                token(&first),
            ),
            'a',
        );
        status(&second, 200);
        assert!(second.body.contains(&format!("\"id\":\"{}\"", ids[1])));
        assert!(second.body.contains("\"next_after\":null"));
        assert!(second.body.contains("\"complete\":true"));
        assert_eq!(token(&first), token(&second));
        let all = get(&server.client, "/api/v1/pulls/7/checks", 'a');
        status(&all, 200);
        assert!(all.body.contains("\"conclusion\":\"action_required\""));
        assert!(all.body.contains("\"conclusion\":\"failure\""));
        assert!(all.body.contains("\"merge_permission\":null"));
        assert!(!all.body.contains("\"evidence\":"));
        assert!(!all.body.contains("PRIVATE-EXECUTION-OUTPUT"));
        assert_eq!(server.finish().accepted_sessions(), 4);
        let node = reopen(&config);
        assert_eq!(
            generation(&node),
            before + 1,
            "only PR opening publishes during reads"
        );
        node.shutdown().unwrap();
    }
}

#[cfg(target_os = "linux")]
fn add_workflow(
    root: &Scratch,
    node: &fgit_node::OneNode,
    data: &mut fgit_forge::event::pull_request::PullRequestData,
) {
    use fgit_crypto::{GitObjectKind, git_object_id};
    use fgit_types::DecisionOutcome;
    use std::fs;
    let format = data.source_tip.algorithm();
    let source = root.0.join("source");
    let loose = |kind, label: &str, body: &[u8]| {
        let id = git_object_id(format, kind, body);
        let raw = [format!("{label} {}\0", body.len()).as_bytes(), body].concat();
        let length = u16::try_from(raw.len()).unwrap();
        let mut encoded = vec![0x78, 0x01, 0x01];
        encoded.extend(length.to_le_bytes());
        encoded.extend((!length).to_le_bytes());
        encoded.extend(&raw);
        let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| {
            let next = (a + u32::from(*byte)) % 65_521;
            (next, (b + next) % 65_521)
        });
        encoded.extend(((b << 16) | a).to_be_bytes());
        let hex = id.to_string();
        let path = source.join("objects").join(&hex[..2]);
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join(&hex[2..]), encoded).unwrap();
        id
    };
    let blob = loose(GitObjectKind::Blob, "blob", b"name: checks\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf PRIVATE-EXECUTION-OUTPUT\n  failure:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: false\n");
    let tree = loose(
        GitObjectKind::Tree,
        "tree",
        &[b"100644 workflow.yml\0".as_slice(), blob.as_bytes()].concat(),
    );
    let body = format!(
        "tree {tree}\nparent {}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nworkflow source\n",
        data.source_tip
    );
    data.source_tip = loose(GitObjectKind::Commit, "commit", body.as_bytes());
    fs::write(
        source.join("refs/heads/topic"),
        format!("{}\n", data.source_tip),
    )
    .unwrap();
    let imported = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &node.request_context(),
            &source,
            OWNER,
            b"workflow-http-source",
        ))
        .unwrap();
    assert!(
        imported
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
}
