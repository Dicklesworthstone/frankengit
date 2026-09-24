//! Reference-policy and read-witness tests, not an execution oracle.
use super::*;
use crate::harness::{IdentityMint, RequestBuilder, label};
use crate::intent::{ForgeEntityId, ForgeIntent, IdempotencyKey};
use crate::state::{GenesisConfiguration, PrincipalCapabilities};
use fgit_types::{GitHashAlgorithm, GitOidSha1, MismatchPolicy, RegistryEpoch, SchemaFamily, SchemaId};

fn fixture(may_publish: bool) -> (RepositoryState, TransactionRequest, RefName) {
    let mut mint = IdentityMint::new(9501);
    let tenant = mint.tenant();
    let repository = mint.repository();
    let principal = mint.principal();
    let schema = SchemaId::new(SchemaFamily::from_static("fgit/txn-test"), 1, 0);
    let source = RefName::try_new(b"refs/heads/main").unwrap();
    let mut state = RepositoryState::genesis(GenesisConfiguration {
        tenant, repository, object_format: GitHashAlgorithm::Sha1, genesis_head_id: mint.head(),
        policy: PolicySnapshot {
            epoch: PolicyEpoch::FIRST,
            protected_scopes: BTreeSet::from([b"refs/heads".to_vec()]),
            principals: BTreeMap::from([(principal, PrincipalCapabilities {
                may_publish_forge: may_publish,
                ..PrincipalCapabilities::default()
            })]),
            max_intents_per_transaction: 64,
            supported_schemas: BTreeSet::from([schema]),
            supported_durability: BTreeSet::from([DurabilityProfile::CanonicalSource]),
        },
        format_registry_epoch: RegistryEpoch::FIRST,
    });
    state.head.body.roots.refs.insert(source.clone(), GitOid::Sha1(GitOidSha1::from_bytes([1; 20])));
    let request = RequestBuilder::new(tenant, repository, principal, schema, IdempotencyKey::new(label("check")))
        .statement(MismatchPolicy::TxnAbort, vec![Intent::Forge(ForgeIntent {
            stream: ForgeStreamId::new(label("check/one")),
            expected_position: ForgeStreamPosition::GENESIS,
            event: ForgeEventKind::WorkflowCheckObserved {
                check: ForgeEntityId::new(label("check/one")), source: source.clone(),
            },
        })]).build(&mut mint);
    (state, request, source)
}

#[test]
fn workflow_observation_names_a_source_without_ref_mutation_authority() {
    let (state, request, source) = fixture(true);
    let intent = &request.statements[0].intents[0];
    assert_eq!(named_ref(intent), Some(&source));
    let Intent::Forge(forge) = intent else { panic!("forge intent") };
    assert_eq!(forge.event.required_ref_effect(), None);
    let PreparedVerdict::Commit(effects) = evaluate(&state, &request).verdict else { panic!("metadata permission") };
    assert!(effects.refs.is_empty());
    assert!(effects.retention.is_empty());
    assert_eq!(effects.forge.len(), 1);
}

#[test]
fn workflow_observation_still_requires_forge_publication_capability() {
    let (state, request, _) = fixture(false);
    assert_eq!(evaluate(&state, &request).verdict,
        PreparedVerdict::Refuse(RefusalCode::CapabilityScopeViolation));
}

#[test]
fn refined_workflow_witness_is_not_reused_after_its_source_branch_moves() {
    let (state, request, source) = fixture(true);
    let witness = build_witness(&state, &request, WitnessGranularity::Refined);
    assert_eq!(witness.refs.get(&source), Some(&state.head.body.roots.refs.get(&source).copied()));
    assert!(witness.is_reusable_against(&state.head.body.roots, state.head.body.generation, state.head.body.configuration.epoch));
    let mut changed = state.head.body.roots.clone();
    changed.refs.insert(source, GitOid::Sha1(GitOidSha1::from_bytes([2; 20])));
    assert!(!witness.is_reusable_against(&changed, state.head.body.generation, state.head.body.configuration.epoch));
}
