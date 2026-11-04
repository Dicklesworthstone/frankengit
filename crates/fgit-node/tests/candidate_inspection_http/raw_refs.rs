//! A real uploaded candidate remains inspectable when either selected PR
//! branch has non-UTF-8 bytes. Text is never substituted for those identities.
use super::*;
use fgit_authority::{ExpectedOld, ProposedNew, RefCommand};
use fgit_types::RefName;

#[test]
fn exact_raw_ref_subjects_cross_native_http_without_staging_or_authority_change() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, mut candidate) = resolved(&root, format, TEXT);
        let source = RefName::try_new(b"refs/heads/topic-\xff").unwrap();
        let target = RefName::try_new(b"refs/heads/main-\xfe").unwrap();
        let session = LoopbackReceiveSession::authenticated(
            OWNER,
            IdempotencyKey::new(b"raw-inspection-branches".to_vec()).unwrap(),
        );
        let commands = [
            RefCommand {
                name: source.clone(),
                expected_old: ExpectedOld::Absent,
                proposed_new: ProposedNew::Update(candidate.data.source_tip),
                force: false,
            },
            RefCommand {
                name: target.clone(),
                expected_old: ExpectedOld::Absent,
                proposed_new: ProposedNew::Update(candidate.data.target_tip),
                force: false,
            },
        ];
        let result = node
            .runtime()
            .block_on(node.admit_branch_updates_durable_in(
                &node.request_context(),
                &session,
                &commands,
                Default::default(),
            ))
            .unwrap();
        assert!(
            result.commands.iter().all(|command| matches!(
                command.terminal.outcome,
                DecisionOutcome::Committed { .. }
            ))
        );
        candidate.data.source_ref = source.clone();
        candidate.data.target_ref = target.clone();
        open_local(&node, &candidate);
        let before = generation(&node);
        let path = root.0.join("credentials");
        credentials(&node, &path);
        let server = Server::start(node, &path, 4, true, false);
        let command = format!(
            "object_format={}&pull_request_version=1&policy_epoch={}&source_ref_hex={}&target_ref_hex={}&source_tip={}&target_tip={}&merge_base={}&candidate_commit={}",
            format.as_str(),
            candidate.epoch.get(),
            hex(source.as_bytes()),
            hex(target.as_bytes()),
            candidate.data.source_tip,
            candidate.data.target_tip,
            candidate.binding.merge_base,
            candidate.binding.commit,
        );
        let send = |form: &str, token, chunked| {
            exchange(
                &server.client,
                &inspect_bytes(
                    &server.client,
                    1,
                    token,
                    form,
                    Some(&candidate.bundle),
                    chunked,
                ),
                true,
            )
        };
        let inspected = send(&command, 'd', false);
        status(&inspected, 200);
        assert!(inspected.body.contains("\"type\":\"candidate_inspection\""));
        assert!(inspected.body.contains("\"source_ref\":null"));
        assert!(inspected.body.contains("\"target_ref\":null"));
        assert_eq!(
            json_text(&inspected.body, "source_ref_hex"),
            hex(source.as_bytes())
        );
        assert_eq!(
            json_text(&inspected.body, "target_ref_hex"),
            hex(target.as_bytes())
        );
        assert_eq!(send(&command, 'd', true), inspected);
        status(
            &send(
                &(command.clone() + "&source_ref=refs/heads/topic"),
                'd',
                false,
            ),
            400,
        );
        status(&send(&command, 'e', false), 403);
        assert_eq!(server.finish().accepted_sessions(), 4);
        let node = reopen(&config);
        assert_eq!(generation(&node), before);
        assert!(node.read_git_object(candidate.binding.commit).is_err());
        node.shutdown().unwrap();
    }
}
