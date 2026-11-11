//! Publish an actual canonical hide policy; an old index is never visibility.
use super::*;
use fgit_admission::merge::native::protection::publish_hidden_ref_policy_async;
use fgit_authority::read_repository_incarnation_configuration_async;
use fgit_codec::{DecodeLimits, HiddenRefPolicyBody, RepositoryAuthorityHeadBody, decode_body};

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
        let policy = HiddenRefPolicyBody {
            rules: vec![fixture.reference.as_bytes().to_vec()],
        };
        publish_hidden_ref_policy_async(
            &node.authority,
            request.authority(),
            &node.head_key,
            node.tenant_id,
            Some(&policy),
            fgit_codec::harness::tx_id(),
        )
        .await
        .unwrap();
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
