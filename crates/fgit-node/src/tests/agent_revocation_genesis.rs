//! Explicit native genesis activation of canonical capability-revocation state.
//! No test installs a revocation generation by editing an existing head.

use super::{ScratchDirectory, test_config};
use crate::{NodeConfig, NodeInitialization, NodeRefusal, OneNode};

use fgit_agent::{
    AuthorityReadReceipt, CapabilityId, ClassSet, CurrentAuthorityCapabilityRevocationReadRefusal,
    CurrentAuthorityCapabilityRevocationReceipt, IntentRun, LogicalTime, OperationClass, RunId,
    read_current_authority_capability_revocations_async,
};
use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityLimits, CapabilityRevocationAuthorityFailure,
    ImmutableRead, RepositoryIncarnationConfigurationEvidence, body_key, outcome_index_root,
    read_head_selected_capability_revocation_generation_async,
    read_repository_incarnation_configuration_evidence_async,
};
use fgit_codec::{
    RepositoryIncarnationConfigurationBodyV2_1, RepositoryIncarnationConfigurationBodyV2_2,
    encode_body,
};
use fgit_crypto::IdentityDomain;
use fgit_resource::{Grade, ResourceVector};
use fgit_types::{GitHashAlgorithm, HeadGeneration, PolicyEpoch, RefName, RootLayoutVersion};

fn selected_configuration(
    node: &OneNode,
) -> (
    AuthenticatedHead,
    RepositoryIncarnationConfigurationEvidence,
) {
    let cx = node.authority_context();
    node.runtime().block_on(async {
        let head = node.authenticate_authority_head().await.unwrap();
        let configuration = read_repository_incarnation_configuration_evidence_async(
            &node.authority,
            &cx,
            &head.body().unwrap().configuration_root,
        )
        .await
        .unwrap();
        (head, configuration)
    })
}

fn fresh_revocations(
    node: &OneNode,
    head: &AuthenticatedHead,
) -> Result<
    CurrentAuthorityCapabilityRevocationReceipt,
    CurrentAuthorityCapabilityRevocationReadRefusal,
> {
    let authority =
        AuthorityReadReceipt::from_authenticated_head(head, LogicalTime::new(10), [0x51; 32])
            .unwrap();
    let run = IntentRun::new_authenticated(
        RunId::new(71),
        authority,
        ClassSet::from_classes(&[OperationClass::PublishRefTransaction]),
        ResourceVector::from_grades(&[(Grade::Bytes, 1024), (Grade::Objects, 4)]),
        LogicalTime::new(100),
    )
    .unwrap();
    let cx = node.authority_context();
    node.runtime()
        .block_on(read_current_authority_capability_revocations_async(
            &node.authority,
            &cx,
            node.tenant_id(),
            &node.head_key,
            &run,
            LogicalTime::new(20),
            10,
            4,
            8,
        ))
}

fn initialize(
    config: NodeConfig,
    agent_revocations: bool,
) -> Result<(OneNode, NodeInitialization), NodeRefusal> {
    if agent_revocations {
        OneNode::init_with_agent_revocations(config)
    } else {
        OneNode::init(config)
    }
}

#[test]
fn agent_revocation_genesis_is_canonical_and_survives_exact_retry_and_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for layout in [
            RootLayoutVersion::LegacyWholeBody,
            RootLayoutVersion::RefStateMerkleV1,
            RootLayoutVersion::RefStateAndObjectClosureMerkleV1,
        ] {
            let scratch = ScratchDirectory::new();
            let config = test_config(scratch.path().to_path_buf())
                .with_object_format(format)
                .with_root_layout(layout)
                .with_initial_branch(RefName::try_new(b"refs/heads/agents").unwrap());
            let (node, status) = OneNode::init_with_agent_revocations(config.clone()).unwrap();
            assert_eq!(status, NodeInitialization::Created);
            let (authenticated, evidence) = selected_configuration(&node);
            let head = authenticated.body().unwrap();
            let RepositoryIncarnationConfigurationEvidence::V2_2(configuration) = evidence else {
                panic!("the explicit profile must select the exact 2.2 body");
            };
            assert_eq!(head.generation, HeadGeneration::FIRST);
            assert_eq!(head.predecessor_head_id, None);
            assert_eq!(head.latest_decision_sequence, None);
            assert_eq!(configuration.root_layout, layout);
            assert_eq!(configuration.object_format, format);
            assert_eq!(
                configuration.repository_incarnation_id,
                node.repository_incarnation_id()
            );
            assert_eq!(configuration.policy_root, None);

            let cx = node.authority_context();
            let generation = node
                .runtime()
                .block_on(read_head_selected_capability_revocation_generation_async(
                    &node.authority,
                    &cx,
                    node.tenant_id(),
                    &authenticated,
                ))
                .unwrap();
            let body = generation.body();
            assert_eq!(body.tenant_id(), node.tenant_id());
            assert_eq!(body.repository_id(), node.repository_id());
            assert_eq!(
                body.repository_incarnation_id(),
                node.repository_incarnation_id()
            );
            assert_eq!(body.policy_epoch(), PolicyEpoch::FIRST);
            assert_eq!(body.predecessor_generation_id(), None);
            assert!(body.revoked_capability_ids().is_empty());
            assert_eq!(body.evidence_root(), outcome_index_root(&[]).unwrap());
            assert_eq!(
                configuration.capability_revocation_root,
                Some(generation.generation_root())
            );
            let exact = RepositoryIncarnationConfigurationBodyV2_2 {
                root_layout: layout,
                object_format: format,
                repository_incarnation_id: node.repository_incarnation_id(),
                policy_root: None,
                capability_revocation_root: Some(generation.generation_root()),
            };
            let stored = node
                .runtime()
                .block_on(AsyncAuthorityStore::read_immutable(
                    &node.authority,
                    &cx,
                    &body_key(IdentityDomain::RepositoryConfiguration, &exact).unwrap(),
                ))
                .unwrap();
            assert_eq!(stored, ImmutableRead::Present(encode_body(&exact).unwrap()));
            let fresh = fresh_revocations(&node, &authenticated).unwrap();
            assert_eq!(fresh.observed_at(), LogicalTime::new(20));
            assert_eq!(fresh.valid_until(), LogicalTime::new(30));
            assert!(!fresh.is_revoked(CapabilityId::new(77)));

            let selected = node
                .runtime()
                .block_on(node.materialize_admission())
                .unwrap();
            assert_eq!(
                selected.snapshot().head_target,
                Some(RefName::try_new(b"refs/heads/agents").unwrap())
            );
            assert!(selected.snapshot().refs.is_empty());
            let incarnation = node.repository_incarnation_id();
            node.shutdown().unwrap();

            // Reuse the complete configuration, including its minted incarnation.
            let (retry, status) = OneNode::init_with_agent_revocations(config).unwrap();
            assert_eq!(status, NodeInitialization::IdenticalRetry);
            assert_eq!(selected_configuration(&retry).1, evidence);
            assert_eq!(selected_configuration(&retry).0.body().unwrap(), head);
            assert_eq!(retry.repository_incarnation_id(), incarnation);
            retry.shutdown().unwrap();

            // Normal open reads canonical configuration, independently of the
            // fresh caller configuration's locally minted creation candidate.
            let reopened =
                OneNode::open_existing(test_config(scratch.path().to_path_buf())).unwrap();
            let (reopened_head, reopened_configuration) = selected_configuration(&reopened);
            assert_eq!(reopened_configuration, evidence);
            assert_eq!(reopened_head.body().unwrap(), head);
            assert_eq!(reopened.object_format(), format);
            assert_eq!(reopened_configuration.normalized().root_layout, layout);
            fresh_revocations(&reopened, &reopened_head).unwrap();
            reopened.shutdown().unwrap();
        }
    }
}

#[test]
fn ordinary_init_keeps_exact_v2_1_and_missing_revocation_state_refuses() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf()).with_object_format(format);
        let (node, status) = OneNode::init(config.clone()).unwrap();
        assert_eq!(status, NodeInitialization::Created);
        let (authenticated, evidence) = selected_configuration(&node);
        let expected = RepositoryIncarnationConfigurationBodyV2_1 {
            root_layout: RootLayoutVersion::LegacyWholeBody,
            object_format: format,
            repository_incarnation_id: node.repository_incarnation_id(),
            policy_root: None,
        };
        assert_eq!(
            evidence,
            RepositoryIncarnationConfigurationEvidence::V2_1(expected)
        );
        assert_eq!(evidence.normalized().capability_revocation_root, None);
        let cx = node.authority_context();
        let stored = node
            .runtime()
            .block_on(AsyncAuthorityStore::read_immutable(
                &node.authority,
                &cx,
                &body_key(IdentityDomain::RepositoryConfiguration, &expected).unwrap(),
            ))
            .unwrap();
        assert_eq!(
            stored,
            ImmutableRead::Present(encode_body(&expected).unwrap())
        );
        assert!(matches!(
            fresh_revocations(&node, &authenticated),
            Err(CurrentAuthorityCapabilityRevocationReadRefusal::Authority(error))
                if matches!(*error, CapabilityRevocationAuthorityFailure::ConfigurationHasNoRevocationRoot)
        ));
        let original_head = authenticated.body().unwrap();
        node.shutdown().unwrap();
        let (retry, status) = OneNode::init(config).unwrap();
        assert_eq!(status, NodeInitialization::IdenticalRetry);
        assert_eq!(selected_configuration(&retry).1, evidence);
        assert_eq!(
            selected_configuration(&retry).0.body().unwrap(),
            original_head
        );
        retry.shutdown().unwrap();
    }
}

#[test]
fn initialization_profile_conflicts_preserve_the_existing_canonical_head() {
    for agent_revocations in [false, true] {
        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf())
            .with_object_format(GitHashAlgorithm::Sha256)
            .with_root_layout(RootLayoutVersion::RefStateMerkleV1);
        let (node, status) = initialize(config.clone(), agent_revocations).unwrap();
        assert_eq!(status, NodeInitialization::Created);
        let (before, configuration) = selected_configuration(&node);
        let before_head = before.body().unwrap();
        let before_token = before.receipt().token();
        node.shutdown().unwrap();

        assert!(
            matches!(
                initialize(config.clone(), !agent_revocations),
                Err(NodeRefusal::HeadInitializationConflict)
            ),
            "initialization cannot migrate or downselect an existing profile"
        );
        let reopened = OneNode::open_existing(config.clone()).unwrap();
        let (after, after_configuration) = selected_configuration(&reopened);
        assert_eq!(after.body().unwrap(), before_head);
        assert_eq!(after.receipt().token(), before_token);
        assert_eq!(after_configuration, configuration);
        reopened.shutdown().unwrap();

        let (permitted, status) = initialize(config, agent_revocations).unwrap();
        assert_eq!(status, NodeInitialization::IdenticalRetry);
        assert_eq!(selected_configuration(&permitted).1, configuration);
        permitted.shutdown().unwrap();
    }
}

#[test]
fn keyed_agent_initialization_refuses_before_storage_and_preserves_ordinary_creation() {
    let scratch = ScratchDirectory::new();
    let config = test_config(scratch.path().to_path_buf())
        .with_creation_idempotency_key(b"agent-profile-is-not-in-the-creation-seal".to_vec());
    assert!(matches!(
        OneNode::init_with_agent_revocations(config.clone()),
        Err(NodeRefusal::CreationKeyWithAgentRevocations)
    ));
    assert!(
        !scratch.path().exists(),
        "the unsupported combination must refuse before opening components"
    );

    let (ordinary, status) = OneNode::init(config.clone()).unwrap();
    assert_eq!(status, NodeInitialization::Created);
    let (head, configuration) = selected_configuration(&ordinary);
    ordinary.shutdown().unwrap();
    assert!(matches!(
        OneNode::init_with_agent_revocations(config.clone()),
        Err(NodeRefusal::CreationKeyWithAgentRevocations)
    ));
    let (retry, status) = OneNode::init(config).unwrap();
    assert_eq!(status, NodeInitialization::IdenticalRetry);
    let (after, after_configuration) = selected_configuration(&retry);
    assert_eq!(after.body().unwrap(), head.body().unwrap());
    assert_eq!(after_configuration, configuration);
    retry.shutdown().unwrap();
}

#[test]
fn failed_revocation_staging_closes_components_and_cannot_publish_partial_genesis() {
    let scratch = ScratchDirectory::new();
    let config = test_config(scratch.path().to_path_buf());
    let bounded = config.clone().with_authority_limits(AuthorityLimits {
        immutable_slots: 0,
        ..AuthorityLimits::default()
    });
    assert!(
        matches!(
            OneNode::init_with_agent_revocations(bounded),
            Err(NodeRefusal::AgentRevocationInitialization(_))
        ),
        "failure staging the selected generation must be a typed initialization refusal"
    );
    assert!(
        matches!(
            OneNode::open_existing(config.clone()),
            Err(NodeRefusal::AuthorityHeadAbsent)
        ),
        "an incomplete bootstrap must not publish an authority head"
    );
    let (retry, status) = OneNode::init_with_agent_revocations(config).unwrap();
    assert_eq!(status, NodeInitialization::Created);
    let (head, _) = selected_configuration(&retry);
    fresh_revocations(&retry, &head).unwrap();
    retry.shutdown().unwrap();
}
