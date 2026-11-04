//! A real uploaded candidate remains inspectable when either selected PR
//! branch has non-UTF-8 bytes. Text is never substituted for those identities.
use super::*;
use fgit_authority::{ExpectedOld, ProposedNew, RefCommand};
use fgit_forge::preparation::resolution::{ConflictResolution, ResolutionChoice, ResolutionInputs};
use fgit_forge::preparation::{MergeMetadata, PreparationLimits};
use fgit_types::RefName;

fn raw_candidate(root: &Scratch, format: GitHashAlgorithm) -> (OneNode, Candidate) {
    let (node, mut candidate) = resolved(root, format, TEXT);
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
        result
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    candidate.data.source_ref = source.clone();
    candidate.data.target_ref = target.clone();
    // The bundle envelope binds its advertised target reference independently
    // of the candidate's native commit identity. Reconstruct with the actual
    // raw branch; changing only the PR subject must never rewrite that binding.
    let built = node
        .runtime()
        .block_on(node.prepare_resolved_merge_bundle_in(
            &node.request_context(),
            &target,
            &source,
            &RefVisibility::new(),
            None,
            ResolutionInputs {
                base: candidate.binding.merge_base,
                target: candidate.data.target_tip,
                source: candidate.data.source_tip,
            },
            &[ConflictResolution {
                path: PATH.to_vec(),
                choice: ResolutionChoice::File {
                    mode: 0o100755,
                    bytes: TEXT.to_vec(),
                },
            }],
            &MergeMetadata {
                author: "Inspector <inspect@example.invalid>".into(),
                committer: "Builder <build@example.invalid>".into(),
                timestamp: 1,
                message: b"Actual inspected candidate\n".to_vec(),
            },
            PreparationLimits::default(),
        ))
        .unwrap();
    assert_eq!(built.resolved.plan.commit, candidate.binding.commit);
    candidate.bundle = built.bundle;
    open_local(&node, &candidate);
    (node, candidate)
}

#[test]
fn exact_raw_ref_subjects_cross_native_http_without_staging_or_authority_change() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, candidate) = raw_candidate(&root, format);
        let source = candidate.data.source_ref.clone();
        let target = candidate.data.target_ref.clone();
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

#[test]
fn inspected_raw_candidate_keeps_exact_votes_merge_identity_and_rotated_recovery() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, candidate) = raw_candidate(&root, format);
        let before = generation(&node);
        let path = root.0.join("credentials");
        let header = credentials(&node, &path);
        let common = format!(
            "object_format={}&pull_request_version=1&policy_epoch={}&source_ref_hex={}&target_ref_hex={}&source_tip={}&target_tip={}&merge_base={}&candidate_commit={}",
            format.as_str(),
            candidate.epoch.get(),
            hex(candidate.data.source_ref.as_bytes()),
            hex(candidate.data.target_ref.as_bytes()),
            candidate.data.source_tip,
            candidate.data.target_tip,
            candidate.binding.merge_base,
            candidate.binding.commit,
        );
        let review = |version| {
            common.clone() + &format!("&expected_version={version}&reason=Exact+raw+candidate")
        };
        let merge = common.clone() + &format!("&required_reviewer={REVIEWER}");
        let server = Server::start(node, &path, 9, true, true);
        let inspected = exchange(
            &server.client,
            &inspect_bytes(
                &server.client,
                1,
                'd',
                &common,
                Some(&candidate.bundle),
                false,
            ),
            true,
        );
        status(&inspected, 200);
        assert_eq!(
            json_text(&inspected.body, "candidate_commit"),
            candidate.binding.commit.to_string()
        );
        for (action, version, key, bundle) in [
            (
                "reviews/request-changes",
                0,
                "raw-request-changes",
                Some(candidate.bundle.as_slice()),
            ),
            (
                "reviews/approve",
                1,
                "raw-approve",
                Some(candidate.bundle.as_slice()),
            ),
            ("reviews/withdraw", 2, "raw-withdraw", None),
        ] {
            accepted(&send(
                &server.client,
                action,
                'b',
                key,
                &review(version),
                bundle,
                false,
            ));
        }
        refused(&send(
            &server.client,
            "merge",
            'c',
            "raw-withdrawn-merge",
            &merge,
            Some(&candidate.bundle),
            false,
        ));
        let renewed = send(
            &server.client,
            "reviews/approve",
            'b',
            "raw-renew",
            &review(3),
            Some(&candidate.bundle),
            true,
        );
        accepted(&renewed);
        let published = send(
            &server.client,
            "merge",
            'c',
            "raw-land",
            &merge,
            Some(&candidate.bundle),
            true,
        );
        accepted(&published);
        assert_eq!(
            send(
                &server.client,
                "merge",
                'c',
                "raw-land",
                &merge,
                None,
                false
            ),
            published
        );
        assert_eq!(
            send(
                &server.client,
                "reviews/approve",
                'b',
                "raw-renew",
                &review(3),
                None,
                false
            ),
            renewed
        );
        assert_eq!(server.finish().accepted_sessions(), 9);
        let node = reopen(&config);
        assert_eq!(generation(&node), before + 6);
        let selected = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(
            selected.snapshot().refs[&candidate.data.target_ref],
            candidate.binding.commit
        );
        assert_eq!(
            selected.snapshot().refs[&candidate.data.source_ref],
            candidate.data.source_tip
        );
        assert!(node.read_git_object(candidate.binding.commit).is_ok());
        // A replacement credential recovers the original principal/key outcome
        // after write access is removed; it cannot reexecute the raw command.
        replace(&path, &(header + &row('f', MERGER, "outcomes-read")));
        let server = Server::start(node, &path, 3, true, true);
        let recovered = lookup(&server.client, 'f', "raw-land");
        status(&recovered, 200);
        assert!(recovered.body.contains("\"state\":\"committed\""));
        assert_eq!(
            json_text(&recovered.body, "tx_id"),
            json_text(&published.body, "tx_id")
        );
        status(
            &send(
                &server.client,
                "merge",
                'f',
                "raw-land",
                &merge,
                None,
                false,
            ),
            403,
        );
        status(&lookup(&server.client, 'c', "raw-land"), 401);
        assert_eq!(server.finish().accepted_sessions(), 3);
        let node = reopen(&config);
        assert_eq!(generation(&node), before + 6);
        node.shutdown().unwrap();
    }
}
