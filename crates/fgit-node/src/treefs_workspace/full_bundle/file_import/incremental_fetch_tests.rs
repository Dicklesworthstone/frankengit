//! Mapped incremental intake uses the same real native graph, destination
//! authority and full-fetch recovery oracle as the enclosing fetch campaign.

use super::*;
use crate::StreamIncrementalBundleImportQuery;

fn write_incremental(
    source: &OneNode,
    path: &Path,
    names: &[&str],
    prerequisites: &[GitOid],
) -> Vec<u8> {
    let request = source.request_context();
    let bytes = source
        .runtime()
        .block_on(source.export_incremental_git_bundle_in(
            &request,
            &names.iter().map(|name| reference(name)).collect::<Vec<_>>(),
            prerequisites,
            &RefVisibility::new(),
            None,
        ))
        .unwrap()
        .1
        .bytes()
        .to_vec();
    fs::write(path, &bytes).unwrap();
    bytes
}

fn incremental_fetch(
    node: &OneNode,
    path: &Path,
    mappings: &[BundleRefMapping],
    key: &str,
    query: StreamIncrementalBundleImportQuery,
    limits: AdmissionLimits,
) -> Result<AdmissionResult, StreamBundleImportRefusal> {
    incremental_fetch_as(node, path, mappings, session(key), query, limits)
}

fn incremental_fetch_as(
    node: &OneNode,
    path: &Path,
    mappings: &[BundleRefMapping],
    session: LoopbackReceiveSession,
    query: StreamIncrementalBundleImportQuery,
    limits: AdmissionLimits,
) -> Result<AdmissionResult, StreamBundleImportRefusal> {
    let request = node.import_request_context(None);
    let mut input = fs::File::open(path).unwrap();
    node.runtime()
        .block_on(node.fetch_incremental_git_bundle_reader_durable_in(
            &request, &session, &mut input, mappings, query, limits,
        ))
}

fn native_refusal(error: &StreamBundleImportRefusal) -> Option<RefusalCode> {
    let StreamBundleImportRefusal::Node(workspace) = error else {
        return None;
    };
    let NodeWorkspaceRefusal::WorkspacePublication(receive) = workspace.as_ref() else {
        return None;
    };
    let NodeReceiveTransportRefusal::Admission(admission) = receive.as_ref() else {
        return None;
    };
    let fgit_admission::AdmissionError::Receive(ReceiveError::AuthoritativeRefusal(code)) =
        admission.as_ref()
    else {
        return None;
    };
    Some(*code)
}

fn staged_candidate_present(root: &Path) -> bool {
    fs::read_dir(root).unwrap().any(|entry| {
        let entry = entry.unwrap();
        entry
            .path()
            .extension()
            .is_some_and(|extension| extension == "stage")
            && entry.metadata().unwrap().len() > 0
    })
}

#[test]
fn mapped_incremental_subset_fanout_and_second_parent_history_share_full_fetch_identity() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let source = graph_fixture(&root, format);
        let full_path = root.0.join("full.bundle");
        let full = write_export(&source.node, &full_path, &RefVisibility::new());
        let target = Scratch::new();
        let destination = empty_node(&target, format);
        committed(file_fetch(
            &destination,
            &full_path,
            &[mapping(
                "refs/heads/base",
                "refs/remotes/upstream/main",
                None,
            )],
            "incremental-fetch-seed",
            Default::default(),
        ));
        let before = snapshot(&destination);
        let path = root.0.join("incremental-subset.bundle");
        write_incremental(
            &source.node,
            &path,
            &["refs/heads/main", "refs/heads/topic", "refs/heads/private"],
            &[source.base],
        );
        let subset = [mapping(
            "refs/heads/topic",
            "refs/remotes/upstream/main",
            Some(source.base),
        )];
        let first = committed(incremental_fetch(
            &destination,
            &path,
            &subset,
            "incremental-fetch-subset",
            Default::default(),
            AdmissionLimits {
                max_commands: 1,
                ..Default::default()
            },
        ));
        assert_eq!(
            buffered_fetch(&destination, &full, &subset, "incremental-fetch-subset").unwrap(),
            first,
        );
        assert_eq!(
            snapshot(&destination)
                .selected_closure()
                .closure()
                .objects(),
            &BTreeSet::from([source.base, source.child, source.tree, source.blob]),
        );
        assert_eq!(
            tip(&destination, "refs/remotes/upstream/main"),
            Some(source.child)
        );
        assert_not_placed(
            &destination,
            &[
                source.merge,
                source.other,
                source.private_tip,
                source.private_blob,
            ],
        );

        // One advertised source fans out to two destinations. Its first parent
        // is unrelated to the old tip; the accepted ancestry is the second.
        let path = root.0.join("incremental-second-parent.bundle");
        let bytes = write_incremental(&source.node, &path, &["refs/heads/main"], &[source.child]);
        let parsed =
            FullBundleInput::parse_incremental(&bytes, FullBundleLimits::default(), &mut || true)
                .unwrap();
        // Keep the existing pack and exact prerequisite; remove optional HEAD
        // so a single header-ref allowance is independent of two commands.
        let signature = match format {
            GitHashAlgorithm::Sha1 => "# v2 git bundle\n",
            GitHashAlgorithm::Sha256 => "# v3 git bundle\n@object-format=sha256\n",
        };
        let header = format!(
            "{signature}-{} prerequisite\n{} refs/heads/main\n\n",
            source.child, source.merge,
        );
        fs::write(&path, [header.as_bytes(), parsed.pack_bytes()].concat()).unwrap();
        let byte_destination = RefName::try_new(b"refs/heads/review-\xff").unwrap();
        let fanout = [
            mapping(
                "refs/heads/main",
                "refs/remotes/upstream/main",
                Some(source.child),
            ),
            BundleRefMapping {
                source: reference("refs/heads/main"),
                destination: byte_destination.clone(),
                expected_old: None,
            },
        ];
        let mut query = StreamIncrementalBundleImportQuery::default();
        query.bundle.limits.envelope.max_references = 1;
        let result = committed(incremental_fetch(
            &destination,
            &path,
            &fanout,
            "incremental-fetch-fanout",
            query,
            AdmissionLimits {
                max_commands: 2,
                ..Default::default()
            },
        ));
        assert_eq!(result.commands.len(), 2);
        assert_eq!(
            buffered_fetch(&destination, &full, &fanout, "incremental-fetch-fanout").unwrap(),
            result,
        );
        let after = snapshot(&destination);
        assert_eq!(after.snapshot().refs[&byte_destination], source.merge);
        assert_eq!(
            tip(&destination, "refs/remotes/upstream/main"),
            Some(source.merge)
        );
        assert!(tip(&destination, "refs/heads/main").is_none());
        assert!(tip(&destination, "refs/heads/private").is_none());
        assert_eq!(after.snapshot().head_target, before.snapshot().head_target);
        assert_eq!(after.snapshot().outbox, before.snapshot().outbox);
        assert_eq!(
            after.basis().body().forge_position_root,
            before.basis().body().forge_position_root,
        );
        assert_native_transfer(&source.node, &destination, source.merge);
        assert_not_placed(&destination, &[source.private_tip, source.private_blob]);
        destination.shutdown().unwrap();
        source.node.shutdown().unwrap();
    }
}

#[test]
fn empty_incremental_pack_proves_original_ancestry_without_spending_uploaded_expansion() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let source = graph_fixture(&root, format);
        let full_path = root.0.join("full.bundle");
        write_export(&source.node, &full_path, &RefVisibility::new());
        let target = Scratch::new();
        let destination = empty_node(&target, format);
        committed(file_fetch(
            &destination,
            &full_path,
            &[
                mapping("refs/heads/base", "refs/remotes/upstream/main", None),
                mapping("refs/heads/topic", "refs/heads/original", None),
            ],
            "incremental-empty-seed",
            Default::default(),
        ));
        let path = root.0.join("empty-incremental.bundle");
        let bytes = write_incremental(&source.node, &path, &["refs/heads/topic"], &[source.child]);
        let parsed =
            FullBundleInput::parse_incremental(&bytes, FullBundleLimits::default(), &mut || true)
                .unwrap();
        let pack = fgit_pack::read_verified_pack(
            parsed.pack_bytes(),
            format,
            &Default::default(),
            &mut || true,
            &fgit_pack::NativeChecksumVerifier,
        )
        .unwrap();
        assert!(pack.entries().is_empty());
        let before = snapshot(&destination);
        let mut query = StreamIncrementalBundleImportQuery::default();
        query.bundle.limits.pack.max_total_expanded_bytes = 1;
        query.bundle.limits.graph.max_payload_bytes = 1;
        let updates = [
            mapping(
                "refs/heads/topic",
                "refs/remotes/upstream/main",
                Some(source.base),
            ),
            mapping("refs/heads/topic", "refs/tags/selected", None),
        ];
        committed(incremental_fetch(
            &destination,
            &path,
            &updates,
            "incremental-empty-advance",
            query.clone(),
            Default::default(),
        ));
        assert_eq!(
            tip(&destination, "refs/remotes/upstream/main"),
            Some(source.child)
        );
        assert_eq!(tip(&destination, "refs/tags/selected"), Some(source.child));
        assert_eq!(
            snapshot(&destination).selected_closure().closure(),
            before.selected_closure().closure(),
        );
        // A healthy prerequisite is still read and authenticated independently
        // of the empty upload, and a narrow original budget is not reset.
        let after = snapshot(&destination);
        query.max_original_bytes = 1;
        assert!(
            incremental_fetch(
                &destination,
                &path,
                &[mapping("refs/heads/topic", "refs/heads/budget", None)],
                "incremental-original-budget",
                query,
                Default::default(),
            )
            .is_err()
        );
        assert_eq!(snapshot(&destination).basis(), after.basis());
        assert_native_transfer(&source.node, &destination, source.child);
        assert_not_placed(
            &destination,
            &[source.merge, source.private_tip, source.private_blob],
        );
        destination.shutdown().unwrap();
        source.node.shutdown().unwrap();
    }
}

#[test]
fn incremental_fetch_refuses_nonancestors_tag_replacement_and_wrong_destination_kinds() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let source = graph_fixture(&root, format);
        let full_path = root.0.join("full.bundle");
        write_export(&source.node, &full_path, &RefVisibility::new());
        let target = Scratch::new();
        let destination = empty_node(&target, format);
        committed(file_fetch(
            &destination,
            &full_path,
            &[
                mapping("refs/heads/base", "refs/remotes/upstream/main", None),
                mapping("refs/heads/base", "refs/tags/stable", None),
            ],
            "incremental-refusal-seed",
            Default::default(),
        ));
        let path = root.0.join("typed-incremental.bundle");
        write_incremental(
            &source.node,
            &path,
            &[
                "refs/heads/base",
                "refs/heads/topic",
                "refs/heads/private",
                "refs/tags/blob",
            ],
            &[source.base],
        );
        let before = snapshot(&destination);
        for (key, bad, expected) in [
            (
                "unrelated-original",
                mapping(
                    "refs/heads/private",
                    "refs/remotes/upstream/main",
                    Some(source.base),
                ),
                RefusalCode::NonFastForwardRefused,
            ),
            (
                "blob-is-not-commit-ancestor",
                mapping(
                    "refs/heads/topic",
                    "refs/remotes/upstream/main",
                    Some(source.blob),
                ),
                RefusalCode::NonFastForwardRefused,
            ),
            (
                "tag-replacement",
                mapping("refs/heads/topic", "refs/tags/stable", Some(source.base)),
                RefusalCode::NonFastForwardRefused,
            ),
            (
                "blob-branch",
                mapping("refs/tags/blob", "refs/heads/blob", None),
                RefusalCode::EvidenceInvalid,
            ),
            (
                "blob-remote",
                mapping("refs/tags/blob", "refs/remotes/upstream/blob", None),
                RefusalCode::EvidenceInvalid,
            ),
        ] {
            let mappings = [
                bad,
                mapping("refs/heads/topic", "refs/heads/no-partial", None),
            ];
            let error = incremental_fetch(
                &destination,
                &path,
                &mappings,
                key,
                Default::default(),
                Default::default(),
            )
            .unwrap_err();
            assert_eq!(native_refusal(&error), Some(expected), "{error:?}");
            assert_eq!(snapshot(&destination).basis(), before.basis());
            assert_not_placed(
                &destination,
                &[source.child, source.private_tip, source.private_blob],
            );
        }
        // The same original history and blob are valid for their permitted
        // destination roles: commit fast-forward, tag reassertion and blob tag.
        committed(incremental_fetch(
            &destination,
            &path,
            &[
                mapping(
                    "refs/heads/topic",
                    "refs/remotes/upstream/main",
                    Some(source.base),
                ),
                mapping("refs/heads/base", "refs/tags/stable", Some(source.base)),
                mapping("refs/tags/blob", "refs/tags/blob", None),
            ],
            "incremental-typed-permitted",
            Default::default(),
            Default::default(),
        ));
        assert_eq!(
            tip(&destination, "refs/remotes/upstream/main"),
            Some(source.child)
        );
        assert_eq!(tip(&destination, "refs/tags/stable"), Some(source.base));
        assert_eq!(
            tip(&destination, "refs/tags/blob"),
            Some(source.private_blob)
        );
        assert_native_transfer(&source.node, &destination, source.private_blob);
        assert_not_placed(&destination, &[source.merge, source.private_tip]);
        destination.shutdown().unwrap();
        source.node.shutdown().unwrap();
    }
}

#[test]
fn cancellation_after_incremental_staging_drains_and_preserves_same_key_retry() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let source = graph_fixture(&root, format);
        let full_path = root.0.join("full.bundle");
        write_export(&source.node, &full_path, &RefVisibility::new());
        let target = Scratch::new();
        let destination = empty_node(&target, format);
        committed(file_fetch(
            &destination,
            &full_path,
            &[mapping(
                "refs/heads/base",
                "refs/remotes/upstream/main",
                None,
            )],
            "incremental-stop-seed",
            Default::default(),
        ));
        let path = root.0.join("cancellable-incremental.bundle");
        write_incremental(&source.node, &path, &["refs/heads/main"], &[source.base]);
        let mappings = [mapping(
            "refs/heads/main",
            "refs/remotes/upstream/main",
            Some(source.base),
        )];
        let before = snapshot(&destination);
        let staging = destination.storage_root().join("staging");
        let stopped = Cell::new(false);
        let mut live = || {
            if staged_candidate_present(&staging) {
                stopped.set(true);
            }
            !stopped.get()
        };
        let request = destination.import_request_context(None);
        let mut input = fs::File::open(&path).unwrap();
        let result = destination.runtime().block_on(
            destination.fetch_incremental_git_bundle_reader_controlled_in(
                &request,
                &session("incremental-stop-retry"),
                &mut input,
                &mappings,
                Default::default(),
                Default::default(),
                &mut live,
            ),
        );
        assert!(
            stopped.get(),
            "stop must observe a real synced candidate file"
        );
        assert!(result.is_err());
        assert_eq!(snapshot(&destination).basis(), before.basis());
        assert_not_placed(
            &destination,
            &[
                source.child,
                source.merge,
                source.other,
                source.private_tip,
                source.private_blob,
            ],
        );
        committed(incremental_fetch(
            &destination,
            &path,
            &mappings,
            "incremental-stop-retry",
            Default::default(),
            Default::default(),
        ));
        assert_native_transfer(&source.node, &destination, source.merge);
        assert_not_placed(&destination, &[source.private_tip, source.private_blob]);
        destination.shutdown().unwrap();
        source.node.shutdown().unwrap();
    }
}

#[test]
fn changed_authority_after_original_capture_cannot_rebase_mapped_incremental_evidence() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let source = graph_fixture(&root, format);
        let full_path = root.0.join("full.bundle");
        write_export(&source.node, &full_path, &RefVisibility::new());
        let target = Scratch::new();
        let destination = empty_node(&target, format);
        committed(file_fetch(
            &destination,
            &full_path,
            &[mapping(
                "refs/heads/base",
                "refs/remotes/upstream/main",
                None,
            )],
            "incremental-basis-seed",
            Default::default(),
        ));
        let mut concurrent = OneNode::open_existing(target.config(format)).unwrap();
        let current = concurrent
            .runtime()
            .block_on(concurrent.authenticate_authority_head())
            .unwrap();
        concurrent
            .bring_into_service(current.receipt().generation())
            .unwrap();
        let path = root.0.join("basis-bound-incremental.bundle");
        let bytes = write_incremental(&source.node, &path, &["refs/heads/topic"], &[source.base]);
        let mappings = [
            mapping(
                "refs/heads/topic",
                "refs/remotes/upstream/main",
                Some(source.base),
            ),
            mapping("refs/heads/topic", "refs/heads/no-partial", None),
        ];
        let staging = destination.storage_root().join("staging");
        let changed = Cell::new(false);
        let mut live = || {
            if !changed.get() && staged_candidate_present(&staging) {
                changed.set(true);
                accepted(apply(
                    &concurrent,
                    &[create("refs/heads/concurrent", source.base)],
                    "incremental-competing-publication",
                ));
            }
            true
        };
        let request = destination.import_request_context(None);
        let mut input = fs::File::open(&path).unwrap();
        let refused = destination
            .runtime()
            .block_on(
                destination.fetch_incremental_git_bundle_reader_controlled_in(
                    &request,
                    &session("incremental-stale-basis"),
                    &mut input,
                    &mappings,
                    Default::default(),
                    Default::default(),
                    &mut live,
                ),
            )
            .unwrap();
        assert!(
            changed.get(),
            "competing head must publish after real private staging"
        );
        assert!(refused.session.atomic);
        assert_eq!(refused.commands.len(), 2);
        assert!(refused.commands.iter().all(|command| matches!(
            command.terminal.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::AuthorityReceiptStale,
                ..
            },
        )));
        assert_eq!(
            tip(&destination, "refs/remotes/upstream/main"),
            Some(source.base)
        );
        assert_eq!(
            tip(&destination, "refs/heads/concurrent"),
            Some(source.base)
        );
        assert!(tip(&destination, "refs/heads/no-partial").is_none());
        assert_not_placed(
            &destination,
            &[source.child, source.merge, source.private_tip],
        );
        let after_refusal = snapshot(&destination);
        let header_end = bytes.windows(2).position(|pair| pair == b"\n\n").unwrap() + 2;
        fs::write(&path, &bytes[..header_end]).unwrap();
        let mut replay_only = StreamIncrementalBundleImportQuery::default();
        replay_only.max_original_bytes = 1;
        replay_only.bundle.limits.pack.max_object_bytes = 1;
        replay_only.bundle.limits.graph.max_object_bytes = 1;
        assert_eq!(
            incremental_fetch(
                &destination,
                &path,
                &mappings,
                "incremental-stale-basis",
                replay_only,
                Default::default()
            )
            .unwrap(),
            refused,
        );
        assert_eq!(snapshot(&destination).basis(), after_refusal.basis());
        assert_staging_empty(&destination);
        fs::write(&path, bytes).unwrap();
        committed(incremental_fetch(
            &destination,
            &path,
            &mappings,
            "incremental-fresh-basis",
            Default::default(),
            Default::default(),
        ));
        assert_eq!(
            tip(&destination, "refs/heads/no-partial"),
            Some(source.child)
        );
        assert_native_transfer(&source.node, &destination, source.child);
        assert_staging_empty(&destination);
        concurrent.shutdown().unwrap();
        destination.shutdown().unwrap();
        source.node.shutdown().unwrap();
    }
}

#[test]
fn incremental_fetch_preserves_authenticated_policy_evidence_and_refused_retry_identity() {
    use fgit_admission::evidence::PolicyDecisionRecord;
    use fgit_forge::ExpectedVersion;
    use fgit_forge::event::protection::{ProtectionCommand, ReviewProtection, compile_ref_policy};

    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let source = graph_fixture(&root, format);
        let full_path = root.0.join("full.bundle");
        let full = write_export(&source.node, &full_path, &RefVisibility::new());
        let target = Scratch::new();
        let destination = empty_node(&target, format);
        committed(file_fetch(
            &destination,
            &full_path,
            &[mapping(
                "refs/heads/base",
                "refs/remotes/upstream/main",
                None,
            )],
            "incremental-policy-seed",
            Default::default(),
        ));
        let request = destination.request_context();
        let current = destination
            .runtime()
            .block_on(destination.read_review_protection_in(&request))
            .unwrap();
        let command = ProtectionCommand {
            expected_version: current.version().map_or(ExpectedVersion::NewStream, ExpectedVersion::Exactly),
            expected_epoch: current.policy_epoch,
            protection: ReviewProtection {
                administrators: vec![principal()],
                branches: Vec::new(),
                ref_policy: Some(compile_ref_policy(
                    "policy authentication { rule credential { when actor.authentication >= single_factor then allow } default deny \"verified credential required\" }",
                ).unwrap()),
            },
        };
        let installed = destination
            .runtime()
            .block_on(destination.admit_review_protection_durable_in(
                &request,
                &session("incremental-policy-install"),
                &command,
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            installed.1.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let path = root.0.join("authenticated-incremental.bundle");
        write_incremental(&source.node, &path, &["refs/heads/topic"], &[source.base]);
        let mappings = [mapping(
            "refs/heads/topic",
            "refs/remotes/upstream/main",
            Some(source.base),
        )];
        let refused = incremental_fetch(
            &destination,
            &path,
            &mappings,
            "incremental-operator-refusal",
            Default::default(),
            Default::default(),
        )
        .unwrap();
        assert!(matches!(
            refused.commands[0].terminal.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::ProtectedRefTransitionDenied,
                ..
            },
        ));
        assert_eq!(
            tip(&destination, "refs/remotes/upstream/main"),
            Some(source.base)
        );
        assert_not_placed(
            &destination,
            &[source.child, source.merge, source.private_tip],
        );
        // A stronger credential on the same sealed request cannot replace its
        // prior refusal; a distinct exact key can begin a fresh authorized one.
        assert_eq!(
            incremental_fetch_as(
                &destination,
                &path,
                &mappings,
                authenticated_session("incremental-operator-refusal"),
                Default::default(),
                Default::default(),
            )
            .unwrap(),
            refused,
        );
        let accepted = committed(incremental_fetch_as(
            &destination,
            &path,
            &mappings,
            authenticated_session("incremental-credentialed"),
            Default::default(),
            Default::default(),
        ));
        assert_eq!(
            buffered_fetch(&destination, &full, &mappings, "incremental-credentialed").unwrap(),
            accepted,
        );
        let request = destination.request_context();
        let history = destination
            .runtime()
            .block_on(destination.snapshot_history_in(&request))
            .unwrap();
        let record = history
            .iter()
            .flat_map(|batch| &batch.batch.committed_rcrs)
            .find(|record| record.tx_id == accepted.session.tx_ids[0])
            .unwrap();
        let identity = record.principal_snapshot_id.as_internal_object_id();
        let principal_receipt = destination
            .runtime()
            .block_on(crate::read_principal_snapshot_in(
                &destination.authority,
                request.authority(),
                destination.repository_id,
                fgit_types::Digest::new(identity.algorithm(), *identity.digest()),
                &|| false,
            ))
            .unwrap();
        assert_eq!(
            principal_receipt.authentication(),
            Some(AdmissionAuthentication::HttpToken)
        );
        let policy = destination
            .runtime()
            .block_on(crate::read_policy_decision_in(
                &destination.authority,
                request.authority(),
                destination.repository_id,
                record.policy_decision_root,
                &|| false,
            ))
            .unwrap();
        assert!(matches!(
            policy,
            PolicyDecisionRecord::AuthenticationActivated(_)
        ));
        assert_eq!(
            policy.authentication(),
            Some(AdmissionAuthentication::HttpToken)
        );
        assert_eq!(
            tip(&destination, "refs/remotes/upstream/main"),
            Some(source.child)
        );
        assert_not_placed(
            &destination,
            &[source.merge, source.private_tip, source.private_blob],
        );
        destination.shutdown().unwrap();
        source.node.shutdown().unwrap();
    }
}
