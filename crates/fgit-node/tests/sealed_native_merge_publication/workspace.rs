//! Public workspace ownership over the real node, native objects and Fsqlite.
//! Caller-future interruption is observed at an actual async admission wait;
//! these tests do not claim control over the database worker's SQL schedule.

use super::*;
use fgit_node::{MergeWorkspaceReceipt, NodeWorkspaceRefusal, WorkspaceSessionRefusal};
use fgit_treefs::{
    EntryClass, ExportLimits, FileMode, IntentLog, TreeCapability, TreeEditIntent, TreePath,
    WorkspaceId,
};
use fgit_wire::visibility::RefVisibility;

fn capability(id: u8) -> TreeCapability {
    let paths = ["file.txt", "ours.txt", "theirs.txt"]
        .map(|name| TreePath::parse_default(name.as_bytes()).unwrap());
    TreeCapability::new(
        WorkspaceId::from_bytes([id; 16]),
        repository(),
        paths.to_vec(),
        vec![paths[2].clone()],
    )
    .with_fetch_budget(
        fgit_types::ByteCount::try_new("workspace fetch", 1_000_000, 1_000_000).unwrap(),
    )
    .with_file_budget(1_000)
}

fn edits(content: &[u8]) -> IntentLog {
    let mut log = IntentLog::new();
    log.push(TreeEditIntent::Write {
        path: TreePath::parse_default(b"theirs.txt").unwrap(),
        content: content.to_vec(),
        mode: FileMode::Regular,
        entry_class: EntryClass::Content,
    });
    log
}

fn open(node: &OneNode, owner: &LoopbackReceiveSession, id: u8) -> MergeWorkspaceReceipt {
    open_with_capability(node, owner, capability(id))
}

fn open_with_capability(
    node: &OneNode,
    owner: &LoopbackReceiveSession,
    capability: TreeCapability,
) -> MergeWorkspaceReceipt {
    let request = node.request_context();
    node.runtime()
        .block_on(node.open_merge_workspace_in(
            &request,
            owner,
            &main_ref(),
            &RefVisibility::new(),
            capability,
            0,
            ExportLimits {
                max_objects: 100,
                max_total_bytes: 1_000_000,
                max_tree_entries: 100,
            },
        ))
        .unwrap()
}

fn edit(
    node: &OneNode,
    owner: &LoopbackReceiveSession,
    receipt: &MergeWorkspaceReceipt,
    content: &[u8],
) -> Result<MergeWorkspaceReceipt, NodeWorkspaceRefusal> {
    edit_at(node, owner, receipt, content, 0)
}

fn edit_at(
    node: &OneNode,
    owner: &LoopbackReceiveSession,
    receipt: &MergeWorkspaceReceipt,
    content: &[u8],
    now: u64,
) -> Result<MergeWorkspaceReceipt, NodeWorkspaceRefusal> {
    let request = node.request_context();
    node.runtime().block_on(node.edit_merge_workspace_in(
        &request,
        owner,
        receipt,
        &edits(content),
        now,
    ))
}

fn close(node: &OneNode, owner: &LoopbackReceiveSession, receipt: &MergeWorkspaceReceipt) {
    let request = node.request_context();
    node.runtime()
        .block_on(node.close_merge_workspace_in(&request, owner, receipt))
        .unwrap();
}

fn workspace_package(
    node: &OneNode,
    fixture: &Fixture,
    context: &AdmissionContext,
    receipt: &MergeWorkspaceReceipt,
) -> Package {
    let offered = intent(fixture, 1, ExpectedVersion::NewStream);
    let closure = validate_merge_objects(
        &NodeObjects(node),
        offered.merge().unwrap(),
        MergeObjectLimits::default(),
        &mut || true,
    )
    .expect("the source fixture passes the production native object validator");
    package_with_workspace(
        node,
        fixture,
        context,
        closure,
        Some((
            receipt.snapshot_digest(),
            WorkspaceEpoch::from_u64(receipt.epochs().staged().get()),
        )),
    )
}

fn candidate_for_tree(node: &OneNode, original: &Fixture, tree: GitOid) -> Fixture {
    let mut candidate = original.clone();
    candidate.merged_tree = tree;
    candidate.candidate_body = commit(
        tree,
        &[original.target, original.source],
        "workspace merge\n",
    );
    candidate.candidate = node
        .put_git_object(GitObjectKind::Commit, candidate.candidate_body.clone())
        .unwrap()
        .identity();
    candidate
}

fn uppercase_tree_candidate(node: &OneNode, original: &Fixture) -> Fixture {
    let mut candidate = original.clone();
    let header_end = candidate
        .candidate_body
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap();
    assert!(candidate.candidate_body.starts_with(b"tree "));
    candidate.candidate_body[5..header_end].make_ascii_uppercase();
    assert_ne!(candidate.candidate_body, original.candidate_body);
    candidate.candidate = node
        .put_git_object(GitObjectKind::Commit, candidate.candidate_body.clone())
        .unwrap()
        .identity();
    assert_ne!(candidate.candidate, original.candidate);
    candidate
}

fn admit(
    node: &OneNode,
    owner: &LoopbackReceiveSession,
    receipt: &MergeWorkspaceReceipt,
    package: &Package,
) -> Result<TerminalOutcome, NodeWorkspaceRefusal> {
    let request = node.request_context();
    node.runtime()
        .block_on(node.admit_workspace_merge_durable_in(
            &request,
            owner,
            receipt,
            &package.sealed(),
            AdmissionLimits::default(),
            MergeObjectLimits::default(),
        ))
}

fn assert_one_merge(
    node: &OneNode,
    fixture: &Fixture,
    context: &AdmissionContext,
    receipt: &MergeWorkspaceReceipt,
    package: &Package,
    terminal: TerminalOutcome,
) {
    let DecisionOutcome::Committed {
        repository_commit_id,
    } = terminal.outcome
    else {
        panic!("permitted workspace must commit: {terminal:?}");
    };
    let selected = snapshot(node);
    assert_eq!(selected.snapshot().refs[&main_ref()], fixture.candidate);
    assert_eq!(selected.snapshot().refs[&topic_ref()], fixture.source);
    assert_eq!(selected.snapshot().forge_positions.len(), 1);
    assert_eq!(selected.snapshot().outbox.len(), 1);
    assert_eq!(
        selected.basis().body().latest_committed_rcr_id,
        Some(repository_commit_id)
    );
    let request = node.request_context();
    let history = node
        .runtime()
        .block_on(node.snapshot_history_in(&request))
        .unwrap();
    let events: Vec<_> = history
        .iter()
        .flat_map(|batch| &batch.forge_events)
        .collect();
    assert_eq!(events, vec![&package.effect.event]);
    let merge = history
        .iter()
        .find(|batch| !batch.forge_events.is_empty())
        .unwrap();
    assert_eq!(merge.batch.committed_rcrs.len(), 1);
    let record = &merge.batch.committed_rcrs[0];
    assert_eq!(record.resulting_ref_root, selected.basis().body().ref_root);
    assert_eq!(
        record.resulting_forge_position_root,
        selected.basis().body().forge_position_root
    );
    assert_eq!(
        merge.batch.resulting_outbox_root,
        selected.basis().body().outbox_root
    );
    let event_root = evidence_root(&ForgeEventBatch::of_one(package.effect.event.clone())).unwrap();
    assert_eq!(record.forge_event_batch_root, event_root);
    assert_eq!(
        selected
            .snapshot()
            .outbox
            .values()
            .copied()
            .collect::<Vec<_>>(),
        vec![event_root]
    );
    let original = fgit_admission::merge::native::workspace_seal_attempt_for(
        context,
        &package.sealed(),
        receipt.snapshot_digest(),
    )
    .unwrap();
    assert_eq!(merge.batch.decisions[0].tx_id, original.derive().unwrap().0);
}

#[test]
fn real_edit_exports_the_candidate_tree_and_original_terminal_retry_is_stable() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (mut node, _) = OneNode::init(config(&scratch.0, format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let fixture = fixture(&node, &scratch.0, format, true);
        let context = context(format, b"workspace-permitted");
        let owner = session(b"workspace-permitted");
        let before = snapshot(&node);
        let initial = open(&node, &owner, 0x91);
        assert_eq!(initial.base_commit(), fixture.target);
        assert_eq!(
            Some(initial.base_rcr()),
            before.basis().body().latest_committed_rcr_id
        );
        let exported = edit(&node, &owner, &initial, b"theirs\n").unwrap();
        assert_eq!(exported.tree(), fixture.merged_tree);
        assert_ne!(exported.snapshot_digest(), initial.snapshot_digest());
        assert_eq!(
            exported.epochs().staged().get(),
            initial.epochs().staged().get() + 1
        );
        assert_eq!(exported.epochs().visible(), exported.epochs().staged());
        assert_eq!(exported.epochs().durable().get(), 0);
        assert_eq!(
            snapshot(&node).basis(),
            before.basis(),
            "workspace staging cannot publish a repository head"
        );
        let package = workspace_package(&node, &fixture, &context, &exported);
        let terminal = admit(&node, &owner, &exported, &package).unwrap();
        assert_one_merge(&node, &fixture, &context, &exported, &package, terminal);
        let committed = snapshot(&node);
        assert_eq!(
            committed.basis().body().generation,
            before.basis().body().generation.next().unwrap()
        );
        assert_eq!(
            committed.basis().body().retention_root,
            before.basis().body().retention_root
        );
        assert_eq!(admit(&node, &owner, &exported, &package).unwrap(), terminal);
        assert_eq!(snapshot(&node).basis(), committed.basis());
        close(&node, &owner, &exported);
        node.shutdown().unwrap();
    }
}

#[test]
fn second_real_edit_refuses_the_old_snapshot_and_permits_the_latest_snapshot() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (mut node, _) = OneNode::init(config(&scratch.0, format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let fixture = fixture(&node, &scratch.0, format, true);
        let stale_context = context(format, b"workspace-stale");
        let stale_owner = session(b"workspace-stale");
        let initial = open(&node, &stale_owner, 0x92);
        let first = edit(&node, &stale_owner, &initial, b"theirs\n").unwrap();
        let stale_package = workspace_package(&node, &fixture, &stale_context, &first);
        let second = edit(&node, &stale_owner, &first, b"theirs updated\n").unwrap();
        assert_ne!(first.snapshot_digest(), second.snapshot_digest());
        assert_ne!(first.tree(), second.tree());
        assert_eq!(
            second.epochs().staged().get(),
            first.epochs().staged().get() + 1
        );
        let before = snapshot(&node);
        let refused = admit(&node, &stale_owner, &first, &stale_package).unwrap();
        assert_eq!(
            refused.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::EvidenceStale
            }
        );
        assert_unchanged_effects(&before, &snapshot(&node));
        assert_eq!(
            admit(&node, &stale_owner, &first, &stale_package).unwrap(),
            refused
        );
        let latest_fixture = candidate_for_tree(&node, &fixture, second.tree());
        let latest_context = context(format, b"workspace-latest");
        let latest_owner = session(b"workspace-latest");
        let latest_package = workspace_package(&node, &latest_fixture, &latest_context, &second);
        let accepted = admit(&node, &latest_owner, &second, &latest_package).unwrap();
        assert_one_merge(
            &node,
            &latest_fixture,
            &latest_context,
            &second,
            &latest_package,
            accepted,
        );
        let committed = snapshot(&node);
        assert_eq!(
            admit(&node, &stale_owner, &first, &stale_package).unwrap(),
            refused
        );
        assert_eq!(
            admit(&node, &latest_owner, &second, &latest_package).unwrap(),
            accepted
        );
        assert_eq!(snapshot(&node).basis(), committed.basis());
        close(&node, &latest_owner, &second);
        node.shutdown().unwrap();
    }
}

#[test]
fn native_candidate_tree_must_equal_the_owned_workspace_export() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (mut node, _) = OneNode::init(config(&scratch.0, format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let fixture = fixture(&node, &scratch.0, format, true);
        let owner = session(b"workspace-wrong-tree");
        let initial = open(&node, &owner, 0x93);
        let exported = edit(&node, &owner, &initial, b"theirs\n").unwrap();
        let empty = node
            .put_git_object(GitObjectKind::Tree, Vec::new())
            .unwrap()
            .identity();
        let wrong = candidate_for_tree(&node, &fixture, empty);
        let wrong_context = context(format, b"workspace-wrong-tree");
        let wrong_package = workspace_package(&node, &wrong, &wrong_context, &exported);
        let before = snapshot(&node);
        let refused = admit(&node, &owner, &exported, &wrong_package).unwrap();
        assert_eq!(
            refused.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::EvidenceStale
            }
        );
        assert_unchanged_effects(&before, &snapshot(&node));
        let permitted_context = context(format, b"workspace-right-tree");
        let permitted_owner = session(b"workspace-right-tree");
        // Native Git parsing accepts either hex case. The workspace binding
        // compares the parsed tree identity while committing these exact bytes.
        let uppercase = uppercase_tree_candidate(&node, &fixture);
        let permitted = workspace_package(&node, &uppercase, &permitted_context, &exported);
        let terminal = admit(&node, &permitted_owner, &exported, &permitted).unwrap();
        assert_one_merge(
            &node,
            &uppercase,
            &permitted_context,
            &exported,
            &permitted,
            terminal,
        );
        close(&node, &permitted_owner, &exported);
        node.shutdown().unwrap();
    }
}

#[test]
fn unsupported_symlink_payload_refuses_before_workspace_mutation() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (mut node, _) = OneNode::init(config(&scratch.0, format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let fixture = fixture(&node, &scratch.0, format, true);
        let owner = session(b"workspace-symlink");
        let initial = open(&node, &owner, 0x97);
        let before = snapshot(&node);
        let mut unsupported = IntentLog::new();
        unsupported.push(TreeEditIntent::CreateSymlink {
            path: TreePath::parse_default(b"theirs.txt").unwrap(),
            link_target: vec![b'x'; 4096],
        });
        let request = node.request_context();
        assert!(matches!(
            node.runtime().block_on(node.edit_merge_workspace_in(
                &request,
                &owner,
                &initial,
                &unsupported,
                0,
            )),
            Err(NodeWorkspaceRefusal::UnsupportedWorkspaceEdit)
        ));
        assert_eq!(snapshot(&node).basis(), before.basis());
        // Reusing the exact receipt and exporting the expected tree also checks
        // that the rejected intent did not enter the retained log or overlay.
        let exported = edit(&node, &owner, &initial, b"theirs\n").unwrap();
        assert_eq!(exported.tree(), fixture.merged_tree);
        assert_eq!(
            exported.epochs().staged().get(),
            initial.epochs().staged().get() + 1
        );
        assert_eq!(snapshot(&node).basis(), before.basis());
        close(&node, &owner, &exported);
        node.shutdown().unwrap();
    }
}

#[test]
fn retained_capability_expiry_refuses_new_merge_but_preserves_terminal_retry() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for commit_before_expiry in [false, true] {
            let scratch = Scratch::new();
            let (mut node, _) = OneNode::init(config(&scratch.0, format)).unwrap();
            node.bring_into_service(HeadGeneration::FIRST).unwrap();
            let fixture = fixture(&node, &scratch.0, format, true);
            let owner = session(b"workspace-expiry");
            let context = context(format, b"workspace-expiry");
            let initial =
                open_with_capability(&node, &owner, capability(0x98).with_expiry(u64::MAX - 1));
            let exported = edit(&node, &owner, &initial, b"theirs\n").unwrap();
            assert_eq!(exported.tree(), fixture.merged_tree);
            let package = workspace_package(&node, &fixture, &context, &exported);
            let before = snapshot(&node);
            let committed = commit_before_expiry.then(|| {
                let terminal = admit(&node, &owner, &exported, &package).unwrap();
                assert_one_merge(&node, &fixture, &context, &exported, &package, terminal);
                terminal
            });
            let selected = snapshot(&node);
            let expired_edit = edit_at(&node, &owner, &exported, b"later\n", u64::MAX);
            if let Some(terminal) = committed {
                assert!(matches!(
                    expired_edit,
                    Err(NodeWorkspaceRefusal::WorkspaceSession(
                        WorkspaceSessionRefusal::Retired
                    ))
                ));
                assert_eq!(admit(&node, &owner, &exported, &package).unwrap(), terminal);
                assert_eq!(snapshot(&node).basis(), selected.basis());
            } else {
                let assert_expired = |result| {
                    assert!(matches!(
                        result,
                        Err(NodeWorkspaceRefusal::Manifest(
                            fgit_treefs::SparseRefusal::Capability(
                                fgit_treefs::CapabilityRefusal::Expired {
                                    expires_at,
                                    observed: u64::MAX,
                                }
                            )
                        )) if expires_at == u64::MAX - 1
                    ));
                };
                assert_expired(expired_edit);
                // The rejected observation advanced the node-owned clock floor;
                // a later caller cannot restore authority by supplying zero.
                assert_expired(edit(&node, &owner, &exported, b"later\n"));
                assert_eq!(snapshot(&node).basis(), before.basis());
                let terminal = admit(&node, &owner, &exported, &package).unwrap();
                assert_eq!(
                    terminal.outcome,
                    DecisionOutcome::Refused {
                        code: RefusalCode::CapabilityExpired,
                    }
                );
                assert_unchanged_effects(&before, &snapshot(&node));
                let refused = snapshot(&node);
                assert_eq!(admit(&node, &owner, &exported, &package).unwrap(), terminal);
                assert_eq!(snapshot(&node).basis(), refused.basis());
            }
            close(&node, &owner, &exported);
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn owner_and_opaque_handle_are_checked_across_close_and_same_id_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (mut node, _) = OneNode::init(config(&scratch.0, format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let fixture = fixture(&node, &scratch.0, format, true);
        let owner = session(b"workspace-owner");
        let original = open(&node, &owner, 0x94);
        let other = LoopbackReceiveSession::authenticated(
            PrincipalId::from_bytes([0x95; 16]),
            IdempotencyKey::new(b"other-owner".to_vec()).unwrap(),
        );
        let before = snapshot(&node);
        assert!(matches!(
            edit(&node, &other, &original, b"theirs\n"),
            Err(NodeWorkspaceRefusal::WorkspaceOwnerMismatch)
        ));
        let permitted = edit(&node, &owner, &original, b"theirs\n").unwrap();
        assert_eq!(permitted.tree(), fixture.merged_tree);
        close(&node, &owner, &permitted);
        assert!(matches!(
            edit(&node, &owner, &permitted, b"theirs\n"),
            Err(NodeWorkspaceRefusal::WorkspaceHandleUnavailable)
        ));
        let reopened = open(&node, &owner, 0x94);
        assert_eq!(reopened.workspace_id(), original.workspace_id());
        assert_eq!(
            reopened.snapshot_digest(),
            original.snapshot_digest(),
            "identical initial state does not resurrect an old handle"
        );
        assert!(matches!(
            edit(&node, &owner, &original, b"theirs\n"),
            Err(NodeWorkspaceRefusal::WorkspaceHandleUnavailable)
        ));
        let new_export = edit(&node, &owner, &reopened, b"theirs\n").unwrap();
        assert_eq!(new_export.tree(), fixture.merged_tree);
        assert_eq!(snapshot(&node).basis(), before.basis());
        close(&node, &owner, &new_export);
        node.shutdown().unwrap();
    }
}

#[test]
fn dropped_real_admission_keeps_workspace_blocked_until_drain_and_reconciliation() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (mut node, _) = OneNode::init(config(&scratch.0, format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let fixture = fixture(&node, &scratch.0, format, true);
        let owner = session(b"workspace-drop");
        let context = context(format, b"workspace-drop");
        let initial = open(&node, &owner, 0x96);
        let exported = edit(&node, &owner, &initial, b"theirs\n").unwrap();
        let package = workspace_package(&node, &fixture, &context, &exported);
        let before = snapshot(&node);
        let tx_id = fgit_admission::merge::native::workspace_seal_attempt_for(
            &context,
            &package.sealed(),
            exported.snapshot_digest(),
        )
        .unwrap()
        .derive()
        .unwrap()
        .0;
        let inspection_cx = fsqlite_types::cx::Cx::new();
        inspection_cx.set_native_cx(
            node.runtime()
                .request_cx(fgit_runtime::meter::BudgetClass::Database),
        );
        let mut inspector = node
            .runtime()
            .block_on(fgit_authority_fsqlite::FsqliteAuthorityStore::open(
                &inspection_cx,
                scratch.0.join("node/authority.fsqlite").to_str().unwrap(),
                fgit_authority::StoreInstanceId::from_raw(1),
                fgit_authority::AuthorityLimits::default(),
            ))
            .unwrap();
        let request = node.request_context();
        let sealed = package.sealed();
        let mut admission = Box::pin(node.admit_workspace_merge_durable_in(
            &request,
            &owner,
            &exported,
            &sealed,
            AdmissionLimits::default(),
            MergeObjectLimits::default(),
        ));
        let new_probe = || {
            Box::pin(fgit_authority::read_seal_async(
                &inspector,
                &inspection_cx,
                context.tenant_id,
                context.repository_id,
                tx_id,
            ))
        };
        let mut probe = new_probe();
        let mut polls = 0;
        let mut admission_pending = false;
        node.runtime().block_on(poll_fn(|cx| {
            polls += 1;
            assert!(polls <= 4096, "bounded real seal observation exhausted");
            match probe.as_mut().poll(cx) {
                Poll::Ready(Ok(Some(seal))) => {
                    assert_eq!(seal.tx_id, tx_id);
                    assert!(admission_pending, "seal must be observed beside the pending real driver");
                    return Poll::Ready(());
                }
                Poll::Ready(Ok(None)) => probe = new_probe(),
                Poll::Ready(Err(error)) => panic!("real seal observation failed: {error:?}"),
                Poll::Pending => {}
            }
            match admission.as_mut().poll(cx) {
                Poll::Pending => admission_pending = true,
                Poll::Ready(outcome) => panic!("admission completed before the staged-seal interruption; this run cannot establish the drop boundary: {outcome:?}"),
            }
            Poll::Pending
        }));
        drop(probe);
        let close_cx = fsqlite_types::cx::Cx::new();
        close_cx.set_native_cx(
            node.runtime()
                .request_cx(fgit_runtime::meter::BudgetClass::Database),
        );
        node.runtime().block_on(inspector.close(&close_cx)).unwrap();
        assert!(matches!(
            edit(&node, &owner, &exported, b"after drop\n"),
            Err(NodeWorkspaceRefusal::WorkspaceBusy)
        ));
        let close_request = node.request_context();
        assert!(matches!(
            node.runtime().block_on(node.close_merge_workspace_in(
                &close_request,
                &owner,
                &exported
            )),
            Err(NodeWorkspaceRefusal::WorkspaceBusy)
        ));
        drop(admission);
        // This invokes the real same-store drain and authenticated outcome
        // recovery; dropping the response itself is never the success oracle.
        let edited = edit(&node, &owner, &exported, b"after drop\n");
        let recovered = snapshot(&node);
        match edited {
            Ok(next) => {
                assert_eq!(
                    recovered.basis(),
                    before.basis(),
                    "an editable recovery proved that the old admission did not commit"
                );
                assert_eq!(
                    next.epochs().staged().get(),
                    exported.epochs().staged().get() + 1
                );
                let refused = admit(&node, &owner, &exported, &package).unwrap();
                assert_eq!(
                    refused.outcome,
                    DecisionOutcome::Refused {
                        code: RefusalCode::EvidenceStale
                    }
                );
                assert_unchanged_effects(&before, &snapshot(&node));
                close(&node, &owner, &next);
            }
            Err(
                NodeWorkspaceRefusal::WorkspaceSession(WorkspaceSessionRefusal::Retired)
                | NodeWorkspaceRefusal::StaleWorkspaceBase,
            ) => {
                let terminal = admit(&node, &owner, &exported, &package).unwrap();
                assert_one_merge(&node, &fixture, &context, &exported, &package, terminal);
                assert_eq!(
                    snapshot(&node).basis(),
                    recovered.basis(),
                    "recovery cannot append another merge"
                );
                close(&node, &owner, &exported);
            }
            Err(error) => panic!(
                "same-store recovery must either resume the workspace or recover its committed retirement: {error:?}"
            ),
        }
        node.shutdown().unwrap();
    }
}
