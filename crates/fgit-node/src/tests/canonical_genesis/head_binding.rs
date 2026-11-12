//! The selected authority root must authenticate HEAD as well as direct refs.
//! Read substitution is confined to the test observer; real authority receipts
//! and the persisted head are unchanged in every negative case.

use super::*;
use crate::{
    ADMISSION_REF_STATE_KEY_PREFIX, read_historical_ref_state_in, ref_state_root,
    stage_immutable_frame,
};

fn state(target: Option<&[u8]>) -> CanonicalRefState {
    state_with_refs(BTreeMap::new(), target)
}

fn state_with_refs(refs: BTreeMap<RefName, GitOid>, target: Option<&[u8]>) -> CanonicalRefState {
    match target {
        Some(target) => {
            CanonicalRefState::new_with_head_target(refs, RefName::try_new(target).unwrap())
                .unwrap()
        }
        None => CanonicalRefState::new(refs),
    }
}

#[test]
fn authenticated_layouts_reject_changed_or_removed_head_without_a_head_transition() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for layout in [
            RootLayoutVersion::LegacyWholeBody,
            RootLayoutVersion::RefStateMerkleV2,
            RootLayoutVersion::RefStateAndObjectClosureMerkleV2,
        ] {
            let scratch = ScratchDirectory::new();
            let config = test_config(scratch.path().to_path_buf())
                .with_object_format(format)
                .with_root_layout(layout);
            let (mut node, _) = OneNode::init(config.clone()).unwrap();
            node.bring_into_service(HeadGeneration::FIRST).unwrap();
            for populated in [false, true] {
                if populated {
                    publish_tag(&node);
                }
                let original = selected(&node);
                let head = original.basis().body();
                assert_eq!(
                    original.snapshot().head_target,
                    Some(RefName::try_new(b"refs/heads/main").unwrap())
                );
                let key = admission_immutable_key(
                    ADMISSION_REF_STATE_KEY_PREFIX,
                    node.repository_id(),
                    head.ref_root,
                )
                .unwrap();
                for target in [Some(b"refs/heads/trunk".as_slice()), None] {
                    let changed = state_with_refs(original.snapshot().refs.clone(), target);
                    assert_ne!(ref_state_root(layout, &changed).unwrap(), head.ref_root);
                    let mut observed = Observe::new(&node);
                    observed.replace_read =
                        Some((key.clone(), Some(encode_body(&changed).unwrap())));
                    let request = node.request_context();
                    let refused = node.runtime().block_on(
                        node.admission_materializer.materialize_current_in(
                            &observed,
                            request.authority(),
                            &node.head_key,
                            node.repository_id(),
                            &|| false,
                        ),
                    );
                    assert!(
                        matches!(
                            refused,
                            Err(AdmissionMaterializationRefusal::CanonicalRoot(
                                RefusalCode::InternalInvariantBreach
                            ))
                        ),
                        "{format:?}/{layout:?}/{populated}: {refused:?}"
                    );
                    let historical = node.runtime().block_on(read_historical_ref_state_in(
                        &observed,
                        request.authority(),
                        node.repository_id(),
                        head,
                    ));
                    assert!(matches!(
                        historical,
                        Err(AdmissionMaterializationRefusal::CanonicalRoot(
                            RefusalCode::InternalInvariantBreach
                        ))
                    ));
                    assert_eq!(selected(&node).basis(), original.basis());
                }
            }
            let original = selected(&node);
            node.shutdown().unwrap();
            let reopened = OneNode::open_existing(config).unwrap();
            assert_eq!(
                selected(&reopened).snapshot().head_target,
                original.snapshot().head_target
            );
            assert_eq!(selected(&reopened).basis(), original.basis());
            reopened.shutdown().unwrap();
        }
    }
}

#[test]
fn old_merkle_creation_refuses_before_opening_storage() {
    for layout in [
        RootLayoutVersion::RefStateMerkleV1,
        RootLayoutVersion::RefStateAndObjectClosureMerkleV1,
    ] {
        let scratch = ScratchDirectory::new();
        let result =
            OneNode::init(test_config(scratch.path().to_path_buf()).with_root_layout(layout));
        assert!(
            matches!(result, Err(NodeRefusal::AdmissionMaterialization(refusal))
            if matches!(*refusal, AdmissionMaterializationRefusal::UnboundHeadLayout { layout: selected } if selected == layout))
        );
        assert!(
            !scratch.path().exists(),
            "unsafe initialization must stage nothing"
        );
    }
}

#[test]
fn historical_v1_head_and_its_absence_are_never_promoted_to_live_authority() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for layout in [
            RootLayoutVersion::RefStateMerkleV1,
            RootLayoutVersion::RefStateAndObjectClosureMerkleV1,
        ] {
            let scratch = ScratchDirectory::new();
            let config = test_config(scratch.path().to_path_buf()).with_object_format(format);
            let node = OneNode::open_components(config.clone()).unwrap();
            let request = node.request_context();
            let configuration = fgit_codec::RepositoryIncarnationConfigurationBodyV2_1 {
                root_layout: layout,
                object_format: format,
                repository_incarnation_id: node.repository_incarnation_id,
                policy_root: None,
            };
            let configuration_root = node
                .runtime()
                .block_on(
                    fgit_authority::stage_latest_repository_incarnation_configuration_async(
                        &node.authority,
                        request.authority(),
                        &configuration,
                    ),
                )
                .unwrap();
            let original = state(Some(b"refs/heads/main"));
            let root = ref_state_root(layout, &original).unwrap();
            let key =
                admission_immutable_key(ADMISSION_REF_STATE_KEY_PREFIX, node.repository_id(), root)
                    .unwrap();
            // Deliberately construct historical bytes through the raw test store.
            // The production staging API must refuse this incomplete commitment.
            assert!(matches!(
                node.runtime()
                    .block_on(node.admission_materializer.stage_ref_state_for_layout_in(
                        &node.authority,
                        request.authority(),
                        node.repository_id(),
                        layout,
                        original.clone(),
                    )),
                Err(AdmissionMaterializationRefusal::UnboundHeadLayout { .. })
            ));
            node.runtime()
                .block_on(stage_immutable_frame(
                    &node.authority,
                    request.authority(),
                    &key,
                    &encode_body(&original).unwrap(),
                ))
                .unwrap();
            let genesis = genesis_head(node.repository_id(), root, configuration_root).unwrap();
            initialize_embedded_repository(
                node.runtime(),
                &node.authority,
                request.authority(),
                &node.head_key,
                &genesis,
            )
            .unwrap();
            for substituted in [original, state(Some(b"refs/heads/trunk")), state(None)] {
                assert_eq!(
                    ref_state_root(layout, &substituted).unwrap(),
                    root,
                    "V1 historical root semantics must not be silently redefined"
                );
                let mut observed = Observe::new(&node);
                observed.replace_read =
                    Some((key.clone(), Some(encode_body(&substituted).unwrap())));
                let refused =
                    node.runtime()
                        .block_on(node.admission_materializer.materialize_current_in(
                            &observed,
                            request.authority(),
                            &node.head_key,
                            node.repository_id(),
                            &|| false,
                        ));
                assert!(
                    matches!(refused, Err(AdmissionMaterializationRefusal::UnboundHeadLayout { layout: selected }) if selected == layout),
                    "{format:?}/{layout:?}: {refused:?}"
                );
                let historical = node.runtime().block_on(read_historical_ref_state_in(
                    &observed,
                    request.authority(),
                    node.repository_id(),
                    &genesis,
                ));
                assert!(matches!(
                    historical,
                    Err(AdmissionMaterializationRefusal::UnboundHeadLayout { .. })
                ));
            }
            node.shutdown().unwrap();
            // The caller's default legacy setting cannot override the V1
            // layout authenticated by the persisted configuration.
            assert!(matches!(
                OneNode::open_existing(config),
                Err(NodeRefusal::AdmissionMaterialization(refusal))
                    if matches!(*refusal, AdmissionMaterializationRefusal::UnboundHeadLayout { layout: selected } if selected == layout)
            ));
        }
    }
}
