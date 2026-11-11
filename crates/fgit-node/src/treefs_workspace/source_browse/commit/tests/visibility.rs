//! Current canonical hide rules precede every source-commit comparison/read.
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
