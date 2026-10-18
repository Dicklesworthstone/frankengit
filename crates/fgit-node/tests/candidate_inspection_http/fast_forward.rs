//! The served inspection/review/fast-forward routes share the same selected
//! native result, including a source tip whose direct parent is not the target.
use super::*;
use fgit_forge::event::protection::{ProtectedBranch, ProtectionCommand, ReviewProtection};
use fgit_forge::event::review::CandidateBinding;
use fgit_forge::preparation::MergeMetadata;
use fgit_types::PolicyEpoch;

fn source_candidate(root: &Scratch, format: GitHashAlgorithm) -> (OneNode, Candidate) {
    let (node, mut data) = fixture(root, format);
    let request = node.request_context();
    let patch = b"diff --git a/reviewed b/reviewed\nnew file mode 100644\n--- /dev/null\n+++ b/reviewed\n@@ -0,0 +1 @@\n+actual source content\n";
    let built = node
        .runtime()
        .block_on(node.prepare_trusted_patch_in(
            &request,
            &data.source_ref,
            data.source_tip,
            [0xf2; 16],
            patch,
            &MergeMetadata {
                author: "Author <author@example.invalid>".into(),
                committer: "Committer <committer@example.invalid>".into(),
                timestamp: 2,
                message: b"source tip for protected fast-forward\n".to_vec(),
            },
            Default::default(),
        ))
        .unwrap();
    let published = node
        .runtime()
        .block_on(node.apply_workspace_bundle_durable_in(
            &request,
            OWNER,
            b"http-ff-source",
            &data.source_ref,
            data.source_tip,
            built.candidate_commit,
            built.bundle_bytes(),
        ))
        .unwrap();
    assert!(matches!(
        published.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    data.source_tip = built.candidate_commit;
    let pack_start = built
        .bundle_bytes()
        .windows(2)
        .position(|pair| pair == b"\n\n")
        .unwrap()
        + 2;
    let mut bundle = format!(
        "# v3 git bundle\n@object-format={}\n-{} target\n{} {}\n\n",
        format.as_str(),
        data.target_tip,
        data.source_tip,
        std::str::from_utf8(data.target_ref.as_bytes()).unwrap(),
    )
    .into_bytes();
    bundle.extend_from_slice(&built.bundle_bytes()[pack_start..]);
    let protection = ProtectionCommand {
        expected_version: ExpectedVersion::NewStream,
        expected_epoch: PolicyEpoch::FIRST,
        protection: ReviewProtection {
            administrators: vec![OWNER],
            branches: vec![ProtectedBranch {
                name: data.target_ref.clone(),
                reviewers: vec![REVIEWER],
            }],
        },
    };
    let (_, terminal) = node
        .runtime()
        .block_on(node.admit_review_protection_durable_in(
            &request,
            &LoopbackReceiveSession::authenticated(
                OWNER,
                IdempotencyKey::new(b"protect-http-ff".to_vec()).unwrap(),
            ),
            &protection,
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    let candidate = Candidate {
        binding: CandidateBinding {
            merge_base: data.target_tip,
            commit: data.source_tip,
        },
        data,
        epoch: PolicyEpoch::FIRST.next().unwrap(),
        bundle,
    };
    (node, candidate)
}

fn fast_forward_form(candidate: &Candidate) -> String {
    format!(
        "object_format={}&pull_request_version=1&source_ref={}&target_ref={}&source_tip={}&target_tip={}",
        candidate.data.source_tip.algorithm().as_str(),
        encode(candidate.data.source_ref.as_bytes()),
        encode(candidate.data.target_ref.as_bytes()),
        candidate.data.source_tip,
        candidate.data.target_tip,
    )
}

#[test]
fn protected_source_tip_is_inspected_and_approved_before_http_fast_forward_and_restart_retry() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, candidate) = source_candidate(&root, format);
        let source_body = node
            .read_git_object(candidate.binding.commit)
            .unwrap()
            .payload()
            .to_vec();
        let parent = std::str::from_utf8(&source_body)
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("parent "))
            .unwrap()
            .to_owned();
        assert_ne!(parent, candidate.data.target_tip.to_string());
        let before_closure = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap()
            .selected_closure()
            .closure()
            .clone();
        let path = root.0.join("credentials");
        credentials(&node, &path);
        let server = Server::start(node, &path, 4, true, false);
        open(&server.client, &candidate); // 1
        let command = fast_forward_form(&candidate);
        let missing = send(
            &server.client,
            "fast-forward",
            'c',
            "before-exact-vote",
            &command,
            None,
            false,
        ); // 2
        refused(&missing);
        let inspected = inspect(&server.client, &candidate, 'd', true); // 3
        status(&inspected, 200);
        assert!(
            inspected
                .body
                .contains(&format!("\"parents\":[\"{parent}\"]"))
        );
        assert_eq!(
            json_text(&inspected.body, "candidate_commit_body_hex"),
            hex(&source_body)
        );
        assert!(inspected.body.contains(&format!(
            "\"after_hex\":\"{}\"",
            hex(b"actual source content\n")
        )));
        accepted(&send(
            &server.client,
            "reviews/approve",
            'b',
            "exact-http-ff-vote",
            &review_form(&candidate, 0),
            Some(&candidate.bundle),
            true,
        )); // 4
        assert_eq!(server.finish().accepted_sessions(), 4);

        let node = reopen(&config);
        let server = Server::start(node, &path, 4, true, false);
        assert_eq!(
            send(
                &server.client,
                "fast-forward",
                'c',
                "before-exact-vote",
                &command,
                None,
                false
            ),
            missing
        ); // 1
        let merged = send(
            &server.client,
            "fast-forward",
            'c',
            "approved-http-ff",
            &command,
            None,
            false,
        ); // 2
        accepted(&merged);
        assert!(
            merged
                .body
                .contains("\"type\":\"fast_forward_merge_publication\"")
        );
        assert!(merged.body.contains("\"action\":\"fast-forward\""));
        assert_eq!(
            send(
                &server.client,
                "fast-forward",
                'c',
                "approved-http-ff",
                &command,
                None,
                true
            ),
            merged
        ); // 3
        status(&inspect(&server.client, &candidate, 'd', false), 409); // 4
        assert_eq!(server.finish().accepted_sessions(), 4);
        let node = reopen(&config);
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
            candidate.binding.commit
        );
        assert_eq!(selected.selected_closure().closure(), &before_closure);
        assert_eq!(
            node.read_git_object(candidate.binding.commit)
                .unwrap()
                .payload(),
            source_body
        );
        node.shutdown().unwrap();
    }
}
