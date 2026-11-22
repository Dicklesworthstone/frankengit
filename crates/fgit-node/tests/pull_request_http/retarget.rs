//! Live HTTP target switching uses the same durable native lifecycle.
use super::*;
use fgit_authority::{ExpectedOld, ProposedNew, RefCommand};
use fgit_types::RefName;

#[test]
fn retarget_http_keeps_identity_requires_write_and_replays_original_outcome_after_close_and_restart()
 {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, data) = fixture(&root, format);
        let release = RefName::try_new(b"refs/heads/release").unwrap();
        let session = LoopbackReceiveSession::authenticated(
            OWNER,
            IdempotencyKey::new(b"release".to_vec()).unwrap(),
        );
        let created = node
            .runtime()
            .block_on(node.admit_branch_updates_durable_in(
                &node.request_context(),
                &session,
                &[RefCommand {
                    name: release.clone(),
                    expected_old: ExpectedOld::Absent,
                    proposed_new: ProposedNew::Update(data.target_tip),
                    force: false,
                }],
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            created.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let before = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap()
            .snapshot()
            .refs
            .clone();
        let path = root.0.join("credentials");
        grants(&node, &path);
        let server = Server::start(node, &path, 9, true, true);
        let client = &server.client;
        committed(&post(
            client,
            7,
            "open",
            'b',
            "open",
            &form(&data, 0),
            false,
        )); // 1
        let mut changed = data.clone();
        changed.target_ref = release;
        status(
            &post(
                client,
                7,
                "retarget",
                'a',
                "read-only",
                &form(&changed, 1),
                false,
            ),
            403,
        ); // 2
        let implicit = post(
            client,
            7,
            "update",
            'b',
            "implicit",
            &form(&changed, 1),
            false,
        ); // 3
        status(&implicit, 409);
        assert!(implicit.body.contains("\"outcome\":\"refused\""));
        let original = post(
            client,
            7,
            "retarget",
            'b',
            "retarget",
            &form(&changed, 1),
            false,
        ); // 4
        committed(&original);
        assert!(original.body.contains("\"action\":\"retarget\""));
        let shown = get(client, "/api/v1/pulls/7", 'a'); // 5
        status(&shown, 200);
        for text in [
            "\"state\":\"open\"",
            "\"target_ref\":\"refs/heads/release\"",
            "\"version\":2",
        ] {
            assert!(shown.body.contains(text), "{shown:?}");
        }
        assert!(shown.body.contains(&OWNER.to_string()));
        assert_eq!(
            post(
                client,
                7,
                "retarget",
                'b',
                "retarget",
                &form(&changed, 1),
                true
            ),
            original
        ); // 6
        committed(&post(
            client,
            7,
            "close",
            'b',
            "close",
            &form(&changed, 2),
            false,
        )); // 7
        assert_eq!(
            post(
                client,
                7,
                "retarget",
                'b',
                "retarget",
                &form(&changed, 1),
                false
            ),
            original
        ); // 8
        let closed = get(client, "/api/v1/pulls/7", 'a'); // 9
        status(&closed, 200);
        assert!(closed.body.contains("\"state\":\"closed\""));
        server.finish();
        let node = reopen(&config);
        assert_eq!(
            node.runtime()
                .block_on(node.materialize_admission())
                .unwrap()
                .snapshot()
                .refs,
            before
        );
        let server = Server::start(node, &path, 2, true, true);
        assert_eq!(
            post(
                &server.client,
                7,
                "retarget",
                'b',
                "retarget",
                &form(&changed, 1),
                true
            ),
            original
        );
        let closed = get(&server.client, "/api/v1/pulls/7", 'a');
        status(&closed, 200);
        assert!(closed.body.contains("\"state\":\"closed\""));
        server.finish();
    }
}
