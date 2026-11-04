//! Current canonical hide rules precede every source-commit comparison/read.
use super::*;
use fgit_authority::{
    PublicationOutcome, authority_head_identity, collect_cumulative_outcomes_async,
    publish_decisions_async, read_repository_incarnation_configuration_async,
    stage_hidden_ref_policy_async, stage_latest_repository_incarnation_configuration_async,
};
use fgit_chronicle::{PublicationBasis, PublicationPlan, ResultingRoots};
use fgit_codec::{
    CryptoBodyIdentity, DecodeLimits, HiddenRefPolicyBody, RepositoryAuthorityHeadBody,
    RepositoryIncarnationConfigurationBodyV2_1, decode_body,
};

fn hide_reference(fixture: &Fixture) {
    let node = fixture.node();
    let request = node.request_context();
    node.runtime().block_on(async {
        let authenticated = node.authenticate_authority_head_in(&request).await.unwrap();
        let receipt = authenticated.receipt();
        let prior: RepositoryAuthorityHeadBody =
            decode_body(receipt.body(), DecodeLimits::DEFAULT).unwrap();
        let original = read_repository_incarnation_configuration_async(
            &node.authority,
            request.authority(),
            &prior.configuration_root,
        )
        .await
        .unwrap();
        assert!(original.policy_root.is_none());
        let policy_root = stage_hidden_ref_policy_async(
            &node.authority,
            request.authority(),
            &HiddenRefPolicyBody {
                rules: vec![fixture.reference.as_bytes().to_vec()],
            },
        )
        .await
        .unwrap();
        let configuration_root = stage_latest_repository_incarnation_configuration_async(
            &node.authority,
            request.authority(),
            &RepositoryIncarnationConfigurationBodyV2_1 {
                root_layout: original.root_layout,
                object_format: original.object_format,
                repository_incarnation_id: original.repository_incarnation_id,
                policy_root: Some(policy_root),
            },
        )
        .await
        .unwrap();
        let basis = PublicationBasis::new(authority_head_identity(&prior).unwrap(), prior);
        let roots = ResultingRoots::carried_forward(&basis);
        let mut plan = PublicationPlan::open(basis).unwrap();
        plan.refuse(
            fgit_codec::harness::tx_id(),
            fgit_types::RefusalCode::QuotaExceeded,
            fgit_codec::harness::refusal_record_id(),
        );
        let outcomes =
            collect_cumulative_outcomes_async(&node.authority, request.authority(), &node.head_key)
                .await
                .unwrap();
        let publication = plan
            .seal(&CryptoBodyIdentity, roots, &outcomes, receipt.token())
            .unwrap();
        let mut head = publication.head().clone();
        head.configuration_root = configuration_root;
        // The same lower authority seam used by hidden_ref_policy_end_to_end
        // installs real policy while retaining every committed source root.
        assert!(matches!(
            publish_decisions_async(
                &node.authority,
                request.authority(),
                &node.head_key,
                receipt.token(),
                publication.batch(),
                &head,
                node.tenant_id,
            )
            .await
            .unwrap(),
            PublicationOutcome::Published(_)
        ));
    });
}

#[test]
fn current_commit_hidden_ref_and_absent_ref_remain_indistinguishable_after_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut fixture = Fixture::new(format, 2, None);
        let before = fixture.head();
        assert!(fixture.read().is_ok());
        hide_reference(&fixture);
        let hidden_head = fixture.head();
        assert_ne!(hidden_head, before);
        for reopened in [false, true] {
            if reopened {
                fixture.reopen();
            }
            let node = fixture.node();
            for reference in [
                fixture.reference.clone(),
                RefName::try_new(b"refs/heads/absent").unwrap(),
            ] {
                // Neither a stale head nor a different admitted object may
                // distinguish a hidden ref from an absent one.
                assert!(matches!(
                    node.runtime().block_on(node.read_source_commit_local_in(
                        &node.request_context(),
                        &reference,
                        Some(before),
                        Some(fixture.tree),
                    )),
                    Err(NodeWorkspaceRefusal::RefUnavailable)
                ));
            }
            assert_eq!(fixture.head(), hidden_head);
        }
    }
}
