//! The same prepared two-parent object has no queue authority when submitted as
//! an ordinary PR merge; only the canonical queued batch may publish it.

use super::*;

#[test]
fn queue_only_two_parent_candidate_refuses_plain_merge_then_lands_and_recovers() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (scratch, node, pulls, _, _) = fixture(format, false);
        protect(
            &node,
            vec![super::super::protection::queue_only(
                pulls[0].data.target_ref.clone(),
            )],
            "candidate-requires-queue",
        );
        let prepared = prepare(
            &node,
            &subject(&node, &pulls[0]),
            1,
            MergeProfile::PathMergeV1,
        )
        .unwrap();
        let offered = offer(&prepared);
        let bundle = prepared.bundle.unwrap();
        let before = snapshot(&node);
        let ordinary = node
            .runtime()
            .block_on(node.apply_merge_bundle_durable_in(
                &node.request_context(),
                actor(),
                b"candidate-plain-bypass",
                offered.pull_request,
                ExpectedVersion::Exactly(offered.expected_pull_request_version),
                &offered.merge,
                &bundle,
            ))
            .unwrap();
        assert!(
            matches!(
                ordinary.1.outcome,
                DecisionOutcome::Refused {
                    code: RefusalCode::ProtectedRefTransitionDenied,
                    ..
                }
            ),
            "{ordinary:?}"
        );
        unchanged_publication(&before, &snapshot(&node));
        assert!(node.read_git_object(offered.merge.merge_commit).is_err());
        let original = committed(publish(&node, &offered, &bundle, "required-candidate").unwrap());
        assert_eq!(
            snapshot(&node).snapshot().refs[&offered.merge.target_ref],
            offered.merge.merge_commit
        );
        assert_eq!(read(&node, 1, None).queue.unwrap().version, version(3));
        assert!(read(&node, 1, None).queue.unwrap().is_empty());

        // A later policy cannot turn the original ordinary refusal into a
        // queued success or prevent recovery of the actual queued decision.
        protect(&node, Vec::new(), "clear-candidate-queue-rule");
        let head = snapshot(&node).basis().id();
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        assert_eq!(
            publish(&reopened, &offered, b"", "required-candidate").unwrap(),
            original
        );
        let recovered = reopened
            .runtime()
            .block_on(reopened.apply_merge_bundle_durable_in(
                &reopened.request_context(),
                actor(),
                b"candidate-plain-bypass",
                offered.pull_request,
                ExpectedVersion::Exactly(offered.expected_pull_request_version),
                &offered.merge,
                b"",
            ))
            .unwrap();
        assert_eq!(recovered, ordinary);
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(snapshot(&reopened).basis().id(), head);
        reopened.shutdown().unwrap();
    }
}
