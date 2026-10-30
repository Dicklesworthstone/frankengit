//! Production selected-source reuse, including real merge construction and
//! independently reopened service children. Counters observe actual successful
//! commit body reads by SelectedSource, including the later native validator.

use super::tests::{fixture, metadata};
use super::*;
use fgit_forge::preparation::resolution::{ConflictResolution, ResolutionChoice, ResolutionInputs};
use fgit_forge::review::{ComparisonMode, ReviewOptions, ReviewSelection};

fn references() -> (RefName, RefName) {
    (
        RefName::try_new(b"refs/heads/main").unwrap(),
        RefName::try_new(b"refs/heads/topic").unwrap(),
    )
}

fn prepare(
    node: &OneNode,
    limits: PreparationLimits,
) -> Result<PreparedMergeBundle, NodeWorkspaceRefusal> {
    let (target, incoming) = references();
    node.runtime().block_on(node.prepare_merge_bundle_in(
        &node.request_context(),
        &target,
        &incoming,
        &RefVisibility::new(),
        &metadata(),
        limits,
    ))
}

fn reopen_shared(node: OneNode, cache_bytes: Option<usize>) -> OneNode {
    let mut config = node.service_config.clone();
    if let Some(bytes) = cache_bytes {
        config = config.with_ancestry_metadata_cache_bytes(bytes);
    }
    node.shutdown().unwrap();
    let mut reopened = OneNode::open_existing(config).unwrap();
    let generation = reopened
        .runtime()
        .block_on(reopened.authenticate_authority_head())
        .unwrap()
        .receipt()
        .generation();
    reopened.bring_into_service(generation).unwrap();
    reopened
}

#[test]
fn repeated_production_merge_preparation_reuses_metadata_across_service_children() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, _, _) = fixture(format, false);
        let cold = prepare(&node, PreparationLimits::default()).unwrap();
        assert!(matches!(cold.outcome, MergePreparation::Clean(_)));
        let cold_counts = node.ancestry_metadata_cache().test_counts();
        assert!(cold_counts.0 > 0);
        let warm = prepare(&node, PreparationLimits::default()).unwrap();
        let warm_counts = node.ancestry_metadata_cache().test_counts();
        let warm_reads = warm_counts.0 - cold_counts.0;
        assert!(
            warm_reads < cold_counts.0,
            "{cold_counts:?} -> {warm_counts:?}"
        );
        assert!(warm_counts.1 > cold_counts.1);
        assert_eq!(warm.source_head, cold.source_head);
        assert_eq!(warm.outcome, cold.outcome);
        assert_eq!(warm.bundle, cold.bundle);

        let node = reopen_shared(node, None);
        let before = node.ancestry_metadata_cache().test_counts();
        let reopened = prepare(&node, PreparationLimits::default()).unwrap();
        let after = node.ancestry_metadata_cache().test_counts();
        assert!(after.0 - before.0 < cold_counts.0);
        assert!(after.1 > before.1);
        assert_eq!(reopened.source_head, cold.source_head);
        assert_eq!(reopened.outcome, cold.outcome);
        assert_eq!(reopened.bundle, cold.bundle);

        // A fresh disabled cache is the real cold adapter, not another planner.
        let node = reopen_shared(node, Some(0));
        let disabled = prepare(&node, PreparationLimits::default()).unwrap();
        let disabled_counts = node.ancestry_metadata_cache().test_counts();
        assert!(disabled_counts.0 > warm_reads);
        assert_eq!(disabled_counts.1, 0);
        assert_eq!(disabled.outcome, cold.outcome);
        assert_eq!(disabled.bundle, cold.bundle);
        node.shutdown().unwrap();
    }
}

#[test]
fn warm_preparation_keeps_current_visibility_traversal_bounds_and_cancellation() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, _, _) = fixture(format, false);
        let permitted = prepare(&node, PreparationLimits::default()).unwrap();
        let narrow = PreparationLimits {
            max_commits: 1,
            ..PreparationLimits::default()
        };
        assert!(matches!(
            prepare(&node, narrow),
            Err(NodeWorkspaceRefusal::MergePreparation(
                PreparationError::Graph(fgit_diff::MergeBaseError::CommitLimitExceeded {
                    limit: 1
                })
            ))
        ));
        let (target, incoming) = references();
        let mut hidden = RefVisibility::new();
        hidden
            .push_rule(incoming.as_bytes(), &fgit_wire::WireLimits::default())
            .unwrap();
        let counts = node.ancestry_metadata_cache().test_counts();
        assert!(matches!(
            node.runtime().block_on(node.prepare_merge_bundle_in(
                &node.request_context(),
                &target,
                &incoming,
                &hidden,
                &metadata(),
                PreparationLimits::default(),
            )),
            Err(NodeWorkspaceRefusal::RefUnavailable)
        ));
        assert_eq!(node.ancestry_metadata_cache().test_counts(), counts);
        let cancelled = node.request_context();
        cancelled.authority().cancel();
        assert!(
            node.runtime()
                .block_on(node.prepare_merge_bundle_in(
                    &cancelled,
                    &target,
                    &incoming,
                    &RefVisibility::new(),
                    &metadata(),
                    PreparationLimits::default(),
                ))
                .is_err()
        );
        assert_eq!(node.ancestry_metadata_cache().test_counts(), counts);
        let recovered = prepare(&node, PreparationLimits::default()).unwrap();
        assert_eq!(recovered.source_head, permitted.source_head);
        assert_eq!(recovered.bundle, permitted.bundle);
        let node = reopen_shared(node, Some(0));
        assert!(matches!(
            prepare(&node, narrow),
            Err(NodeWorkspaceRefusal::MergePreparation(
                PreparationError::Graph(fgit_diff::MergeBaseError::CommitLimitExceeded {
                    limit: 1
                })
            ))
        ));
        assert_eq!(
            prepare(&node, PreparationLimits::default()).unwrap().bundle,
            permitted.bundle
        );
        node.shutdown().unwrap();
    }
}

fn with_source<T>(
    node: &OneNode,
    selected: &AuthoritySelectedClosure,
    limits: ParseLimits,
    action: impl FnOnce(&mut SelectedSource<'_>) -> T,
) -> T {
    let request = node.request_context();
    let exhaustion = Cell::new(None);
    let mut source = SelectedSource {
        inner: VerifiedFabricPackSource {
            fabric: &node.fabric,
            object_format: node.object_format,
            maximum_object_bytes: limits.max_object_bytes,
            database_context: request.authority(),
            database_exhaustion: &exhaustion,
            session_is_live: None,
        },
        selected,
        ancestry: Some(AncestryMetadataAccess::for_node(node)),
        limits,
        read_bytes: Cell::new(0),
        budget_failed: Cell::new(false),
    };
    action(&mut source)
}

fn stored_object_path(node: &OneNode, id: GitOid) -> std::path::PathBuf {
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    node.storage_root()
        .join("objects")
        .join(hex(&node.namespace))
        .join(hex(&id.algorithm().code_point().to_be_bytes()))
        .join(id.to_string())
}

struct ParkedObject {
    path: std::path::PathBuf,
    parked: std::path::PathBuf,
}
impl ParkedObject {
    fn new(node: &OneNode, id: GitOid) -> Self {
        let path = stored_object_path(node, id);
        let parked = path.with_extension("ancestry-parked");
        std::fs::rename(&path, &parked).unwrap();
        Self { path, parked }
    }
}
impl Drop for ParkedObject {
    fn drop(&mut self) {
        std::fs::rename(&self.parked, &self.path).unwrap();
    }
}

#[test]
fn selected_lookup_reuses_only_verified_metadata_and_never_extends_membership() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, target, _) = fixture(format, false);
        let request = node.request_context();
        let selected = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        let limits = ParseLimits {
            tree_reference_bytes: format.digest_len(),
            ..ParseLimits::default()
        };
        let original = with_source(
            &node,
            selected.selected_closure(),
            limits.clone(),
            |source| source.commit_with_date(target).unwrap(),
        );
        // Parking happens after authenticated selection and a complete verified
        // parse. Only this metadata read can succeed without the body: native
        // candidate validation and all ordinary byte disclosures keep their reads.
        {
            let _parked = ParkedObject::new(&node, target);
            with_source(
                &node,
                selected.selected_closure(),
                limits.clone(),
                |source| {
                    assert_eq!(source.commit_with_date(target).unwrap(), original);
                    source.ancestry = None;
                    assert_eq!(
                        source.commit(target),
                        Err(MergeSourceError::Unavailable(target))
                    );
                },
            );
            let mut narrower = selected.selected_closure().clone();
            let mut ids = narrower.closure().objects().clone();
            assert!(ids.remove(&target));
            narrower.closure = fgit_admission::PermittedObjectClosure::new(ids);
            narrower.root =
                fgit_admission::permitted_object_closure_root(&narrower.closure).unwrap();
            with_source(&node, &narrower, limits.clone(), |source| {
                assert_eq!(
                    source.commit(target),
                    Err(MergeSourceError::OutsideSelection)
                );
            });
        }
        assert_eq!(
            with_source(&node, selected.selected_closure(), limits, |source| {
                source.ancestry = None;
                source.commit_with_date(target).unwrap()
            }),
            original
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn cached_lookup_preserves_object_header_logical_byte_and_runtime_limits() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, target, _) = fixture(format, false);
        let selected = node
            .runtime()
            .block_on(node.materialize_admission_in(&node.request_context()))
            .unwrap();
        let limits = ParseLimits {
            tree_reference_bytes: format.digest_len(),
            ..ParseLimits::default()
        };
        let expected = with_source(
            &node,
            selected.selected_closure(),
            limits.clone(),
            |source| source.commit(target).unwrap(),
        );
        let body_bytes = node.read_git_object(target).unwrap().payload().len();
        for narrowed in [
            ParseLimits {
                max_object_bytes: body_bytes - 1,
                ..limits.clone()
            },
            ParseLimits {
                max_header_lines: 1,
                ..limits.clone()
            },
            ParseLimits {
                max_header_line_bytes: 1,
                ..limits.clone()
            },
        ] {
            with_source(&node, selected.selected_closure(), narrowed, |source| {
                assert_eq!(source.commit(target), Err(MergeSourceError::BudgetExceeded));
                assert_eq!(source.checkpoint(), Err(MergeSourceError::BudgetExceeded));
            });
        }
        with_source(
            &node,
            selected.selected_closure(),
            limits.clone(),
            |source| {
                source.read_bytes.set(MAX_READ_BYTES - body_bytes + 1);
                assert_eq!(source.commit(target), Err(MergeSourceError::BudgetExceeded));
            },
        );
        with_source(
            &node,
            selected.selected_closure(),
            limits.clone(),
            |source| {
                source.read_bytes.set(MAX_READ_BYTES - body_bytes);
                assert_eq!(source.commit(target).unwrap(), expected);
                assert_eq!(source.read_bytes.get(), MAX_READ_BYTES);
                assert_eq!(source.commit(target), Err(MergeSourceError::BudgetExceeded));
            },
        );
        with_source(
            &node,
            selected.selected_closure(),
            limits.clone(),
            |source| {
                source.inner.database_context.cancel();
                assert_eq!(source.commit(target), Err(MergeSourceError::Cancelled));
            },
        );
        with_source(&node, selected.selected_closure(), limits, |source| {
            assert_eq!(source.commit(target).unwrap(), expected);
        });
        node.shutdown().unwrap();
    }
}

#[test]
fn review_and_explicit_resolution_use_the_same_verified_metadata_owner() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, target, incoming) = fixture(format, true);
        let automatic = prepare(&node, PreparationLimits::default()).unwrap();
        let MergePreparation::Conflicted { base, .. } = automatic.outcome else {
            panic!("fixture must require an explicit content choice");
        };
        let (target_ref, incoming_ref) = references();
        let selection = ReviewSelection::References {
            before: target_ref.clone(),
            after: incoming_ref.clone(),
        };
        let options = ReviewOptions {
            mode: ComparisonMode::MergeBase,
            ..ReviewOptions::default()
        };
        let counts = node.ancestry_metadata_cache().test_counts();
        let review = node
            .runtime()
            .block_on(node.review_source_in(
                &node.request_context(),
                &selection,
                &RefVisibility::new(),
                Some(automatic.source_head),
                &options,
            ))
            .unwrap();
        let reviewed = node.ancestry_metadata_cache().test_counts();
        assert_eq!(
            reviewed.0, counts.0,
            "review needs no additional commit bodies"
        );
        assert!(reviewed.1 > counts.1);
        assert_eq!(review.source_head, automatic.source_head);
        assert_eq!(review.comparison.compared_before, base);
        let choices = [ConflictResolution {
            path: b"text".to_vec(),
            choice: ResolutionChoice::File {
                mode: 0o100644,
                bytes: b"explicit resolution\n".to_vec(),
            },
        }];
        let coordinates = ResolutionInputs {
            base,
            target,
            source: incoming,
        };
        let resolve = || {
            node.runtime()
                .block_on(node.prepare_resolved_merge_bundle_in(
                    &node.request_context(),
                    &target_ref,
                    &incoming_ref,
                    &RefVisibility::new(),
                    Some(automatic.source_head),
                    coordinates,
                    &choices,
                    &metadata(),
                    PreparationLimits::default(),
                ))
                .unwrap()
        };
        let first = resolve();
        let after_first = node.ancestry_metadata_cache().test_counts();
        assert!(after_first.1 > reviewed.1);
        let second = resolve();
        let after_second = node.ancestry_metadata_cache().test_counts();
        assert!(after_second.1 > after_first.1);
        assert_eq!(first.source_head, automatic.source_head);
        assert_eq!(first.bundle, second.bundle);
        assert_eq!(first.resolved, second.resolved);
        node.shutdown().unwrap();
    }
}
