//! Real HTTP credentials, native branch publication, and historical recovery.

use super::*;
use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand};
use fgit_forge::ExpectedVersion;
use fgit_forge::event::protection::{ProtectionCommand, ReviewProtection, compile_ref_policy};
use fgit_node::LoopbackReceiveSession;
use fgit_types::{DecisionOutcome, RefusalCode};

fn install_authentication_policy(node: &OneNode, minimum: &str, key: &[u8]) {
    let request = node.request_context();
    let selected = node
        .runtime()
        .block_on(node.read_review_protection_in(&request))
        .unwrap();
    let snapshot = compile_ref_policy(&format!(
        "policy authentication {{ rule required {{ when actor.authentication >= {minimum} then allow }} default deny \"stronger authentication required\" }}"
    ))
    .unwrap();
    let command = ProtectionCommand {
        expected_version: selected
            .version()
            .map_or(ExpectedVersion::NewStream, ExpectedVersion::Exactly),
        expected_epoch: selected.policy_epoch,
        protection: ReviewProtection {
            administrators: vec![OWNER],
            branches: Vec::new(),
            ref_policy: Some(snapshot),
        },
    };
    let result = node
        .runtime()
        .block_on(node.admit_review_protection_durable_in(
            &request,
            &LoopbackReceiveSession::authenticated(
                OWNER,
                IdempotencyKey::new(key.to_vec()).unwrap(),
            ),
            &command,
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        result.1.outcome,
        DecisionOutcome::Committed { .. }
    ));
}

fn publication_record(node: &OneNode, reply: &Reply) -> fgit_codec::RepositoryCommitRecord {
    let history = node
        .runtime()
        .block_on(node.snapshot_history_in(&node.request_context()))
        .unwrap();
    let tx = text(&reply.body, "tx_id");
    let records = history
        .iter()
        .flat_map(|batch| &batch.batch.committed_rcrs)
        .filter(|record| record.tx_id.to_string() == tx)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 1);
    records.into_iter().next().unwrap()
}

#[test]
fn http_authentication_policy_survives_reopen_and_cannot_reinterpret_a_terminal_retry() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, tip) = fixture(&root, format);
        install_authentication_policy(&node, "single_factor", b"require-http-token");

        // Supplying the same principal through the trusted embedding API does
        // not manufacture evidence that a credential authenticated this call.
        let operator = LoopbackReceiveSession::authenticated(
            OWNER,
            IdempotencyKey::new(b"operator-authentication-refusal".to_vec()).unwrap(),
        );
        let denied = node
            .runtime()
            .block_on(node.admit_branch_updates_durable_in(
                &node.request_context(),
                &operator,
                &[RefCommand {
                    name: RefName::try_new(b"refs/heads/operator-denied").unwrap(),
                    expected_old: ExpectedOld::Absent,
                    proposed_new: ProposedNew::Update(tip),
                    force: false,
                }],
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            denied.commands[0].terminal.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::ProtectedRefTransitionDenied,
                ..
            }
        ));

        let credentials = root.0.join("credentials");
        let header = grants(&node, &credentials);
        let form = create(format, "refs/heads/http-authenticated", tip);
        let server = BranchServer::start(node, &credentials, 3);
        let committed = change(&server.client, "create", "http-authenticated", &form, false);
        accepted(&committed);

        // Reloading the credentials file revokes the old secret, while a new
        // secret for the same principal still retrieves its original result.
        replace(&credentials, &(header + &row('f', OWNER, "receive")));
        let revoked = change(&server.client, "create", "http-authenticated", &form, false);
        status(&revoked, 401);
        let rotated_retry = exchange(
            &server.client,
            &wire(
                &server.client,
                "create",
                'f',
                "http-authenticated",
                &form,
                true,
            ),
            true,
        );
        assert_eq!(rotated_retry, committed);
        assert_eq!(server.finish().accepted_sessions(), 3);

        // Reopening must validate the original authenticated input evidence,
        // independently of the fact that this reader is an operator call.
        let reopened = reopen(&config);
        let original_record = publication_record(&reopened, &committed);
        let view = reopened
            .runtime()
            .block_on(reopened.materialize_admission())
            .unwrap();
        assert_eq!(
            view.snapshot()
                .refs
                .get(&RefName::try_new(b"refs/heads/http-authenticated").unwrap()),
            Some(&tip)
        );
        assert!(
            !view
                .snapshot()
                .refs
                .contains_key(&RefName::try_new(b"refs/heads/operator-denied").unwrap())
        );
        drop(view);
        install_authentication_policy(&reopened, "multi_factor", b"now-require-mfa");

        let server = BranchServer::start(reopened, &credentials, 2);
        let retry = exchange(
            &server.client,
            &wire(
                &server.client,
                "create",
                'f',
                "http-authenticated",
                &form,
                true,
            ),
            true,
        );
        assert_eq!(
            retry, committed,
            "a later policy cannot rewrite the original terminal result"
        );
        let fresh = exchange(
            &server.client,
            &wire(
                &server.client,
                "create",
                'f',
                "http-token-is-not-mfa",
                &create(format, "refs/heads/http-mfa-denied", tip),
                false,
            ),
            true,
        );
        refused(&fresh);
        assert_eq!(server.finish().accepted_sessions(), 2);

        let reopened = reopen(&config);
        assert_eq!(
            publication_record(&reopened, &committed),
            original_record,
            "the original RCR, principal snapshot, and policy roots survive rotation and retry"
        );
        let recovered = reopened
            .runtime()
            .block_on(reopened.recover_transaction_in(
                &reopened.request_context(),
                &LoopbackReceiveSession::authenticated(
                    OWNER,
                    IdempotencyKey::new(b"http-authenticated".to_vec()).unwrap(),
                ),
            ))
            .unwrap();
        assert!(matches!(
            recovered.terminal().unwrap().outcome,
            DecisionOutcome::Committed { .. }
        ));
        let view = reopened
            .runtime()
            .block_on(reopened.materialize_admission())
            .unwrap();
        assert!(
            !view
                .snapshot()
                .refs
                .contains_key(&RefName::try_new(b"refs/heads/http-mfa-denied").unwrap())
        );
        drop(view);
        reopened.shutdown().unwrap();
    }
}
