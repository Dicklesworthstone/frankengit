//! Publish an actual canonical hide policy; an old index is never visibility.
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
        // Test fixture publication follows hidden_ref_policy_end_to_end: the
        // lower authority seam installs a policy-bearing configuration while
        // a real refusal-only batch carries every committed source root.
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
        let selected = node.materialize_admission_in(&request).await.unwrap();
        assert!(
            selected
                .snapshot()
                .hidden_refs
                .hides(fixture.reference.as_bytes())
        );
        assert_eq!(
            selected.snapshot().refs.get(&fixture.reference),
            Some(&fixture.commit)
        );
    });
}

#[test]
fn current_hidden_policy_refuses_both_saved_hydration_and_fresh_revalidation() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format);
        f.build_lexical();
        f.build_symbols();
        let query = query(Some(SymbolPolicy::Required));
        let report = f
            .query(&query, &Checkpoints::default(), InitialLimits::default())
            .unwrap();
        let generations = report.generations().clone();
        assert!(hydrate(&f, report.clone(), ContextLimits::default()).is_ok());
        hide_reference(&f);
        let before = f.head();
        assert!(matches!(
            hydrate(&f, report, ContextLimits::default()),
            Err(RetrievalError::Source(NodeWorkspaceRefusal::RefUnavailable))
        ));
        assert!(matches!(
            f.query(&query, &Checkpoints::default(), InitialLimits::default()),
            Err(RetrievalError::Source(NodeWorkspaceRefusal::RefUnavailable))
        ));
        assert_eq!(f.lexical.as_ref(), Some(&generations.lexical));
        assert_eq!(f.symbols, generations.symbols);
        assert_eq!(f.head(), before);
        f.reopen();
        assert!(matches!(
            f.query(&query, &Checkpoints::default(), InitialLimits::default()),
            Err(RetrievalError::Source(NodeWorkspaceRefusal::RefUnavailable))
        ));
        assert_eq!(f.head(), before);
    }
}
