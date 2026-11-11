//! Production patch/evaluation/export/bundle preparation reaches the existing
//! checked publication consumer. Only ECC/approval assertions use the explicitly
//! synthetic host fixtures from `evidence_tests`; no production evidence is
//! fabricated and no alternate overlay, exporter or pack writer is used here.

use super::*;
use crate::{AgentWorkspacePatchInput, AgentWorkspacePatchRefusal, PreparedAgentPatchCandidate};
use fgit_agent::{AgentPublicationRefusal, ProtocolRefusal};
use fgit_forge::{patch::PatchLimits, source_browse::SourceBrowseError};
use fgit_types::ByteCount;
use fgit_wire::visibility::RefVisibility;

const PATCH: &[u8] = b"diff --git a/lib.rs b/lib.rs\n--- a/lib.rs\n+++ b/lib.rs\n@@ -1 +1 @@\n-fn original() {}\n+fn checked_change() {}\n";
const OTHER_PATCH: &[u8] = b"diff --git a/lib.rs b/lib.rs\n--- a/lib.rs\n+++ b/lib.rs\n@@ -1 +1 @@\n-fn original() {}\n+fn other_change() {}\n";

fn scope() -> ClassSet {
    ClassSet::from_classes(&[
        OperationClass::ReadCanonicalObject,
        OperationClass::TreeFsWorkspace,
        OperationClass::CreateCandidateObject,
        OperationClass::PreparePublication,
        OperationClass::PublishRefTransaction,
    ])
}

fn authenticated_run(node: &OneNode, scope: ClassSet) -> (IntentRun, HeadReadReceipt) {
    let authenticated = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap();
    let receipt = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(10),
        [0x54; 32],
    )
    .unwrap();
    (
        IntentRun::new_authenticated(
            RunId::new(901),
            receipt,
            scope,
            budget(),
            LogicalTime::new(10_000),
        )
        .unwrap(),
        authenticated.receipt().clone(),
    )
}

fn capability(node: &OneNode) -> TreeCapability {
    let path = TreePath::parse_default(b"lib.rs").unwrap();
    TreeCapability::new(
        WorkspaceId::from_bytes([0x55; 16]),
        node.repository_id(),
        vec![path.clone()],
        vec![path],
    )
    .with_fetch_budget(ByteCount::try_new("test-read-bytes", 1 << 20, 1 << 20).unwrap())
    .with_file_budget(100)
    .with_expiry(10_000)
}

fn metadata() -> MergeMetadata {
    MergeMetadata {
        author: "Native Agent <agent@example.invalid>".into(),
        committer: "Native Agent <agent@example.invalid>".into(),
        timestamp: 18,
        message: b"retain the actual native agent change\n".to_vec(),
    }
}

fn prepare<A: GitHashAlgorithm, C: Fn() -> LogicalTime + Sync>(
    node: &OneNode,
    run: &IntentRun,
    base: fgit_types::GitOid,
    capability: &mut TreeCapability,
    patch: &[u8],
    now: &C,
) -> Result<PreparedAgentPatchCandidate<A>, AgentWorkspacePatchRefusal> {
    node.runtime()
        .block_on(node.prepare_agent_workspace_patch_in::<A, _>(
            &node.request_context(),
            AgentWorkspacePatchInput {
                run,
                reference: &reference(),
                expected_commit: base,
                visibility: &RefVisibility::new(),
                capability,
                patch_bytes: patch,
                metadata: &metadata(),
                limits: PatchLimits::default(),
            },
            now,
        ))
}

fn current(node: &OneNode) -> (fgit_types::GitOid, fgit_types::RepositoryAuthorityHeadId) {
    let selected = node
        .runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .unwrap();
    (
        selected.snapshot().refs[&reference()],
        selected.basis().id(),
    )
}

fn context(run: &IntentRun) -> ContextPacket {
    // This test deliberately supplies its own context fixture. The production
    // preparer accepts no sources and does not mint a ContextPacket.
    ContextPacket::build(
        run.authority_read_receipt().unwrap().clone(),
        ContextControl::new(
            [1; 32],
            ClassSet::from_classes(&[OperationClass::ReadCanonicalObject]),
            [2; 32],
            vec![],
            vec![],
        ),
        vec![
            ContextSource::new(
                [3; 32],
                RetrievalChannel::Exact,
                b"fn original() {}\n".to_vec(),
            )
            .unwrap(),
        ],
    )
    .unwrap()
}

fn native_candidate_reaches_publication<A: GitHashAlgorithm>() {
    let scratch = Scratch::new();
    let (node, source) = node(&scratch, A::OBJECT_FORMAT, true);
    let (run, original_read) = authenticated_run(&node, scope());
    let before = current(&node);
    let mut cap = capability(&node);
    let prepared = prepare::<A, _>(&node, &run, source.commit, &mut cap, PATCH, &|| {
        LogicalTime::new(11)
    })
    .unwrap();
    assert!(cap.fetched_bytes() > 0);
    assert_eq!(
        current(&node),
        before,
        "preparation has no canonical effect"
    );
    let snapshot = prepared.workspace().snapshot();
    assert_eq!(snapshot.base_commit_oid().erase(), source.commit);
    assert_eq!(snapshot.base_tree_oid().erase(), source.tree);
    assert_eq!(snapshot.overlay_root(), OverlayRoot::of(prepared.overlay()));
    assert_eq!(snapshot.epochs().staged().get(), 1);
    assert_eq!(snapshot.epochs().visible().get(), 1);
    assert_eq!(snapshot.epochs().durable().get(), 0);
    assert_eq!(prepared.workspace().run(), &run);
    assert_eq!(
        prepared.workspace().authority_read_receipt(),
        run.authority_read_receipt().unwrap(),
    );
    assert_eq!(
        prepared.proposal().receipt().touched_paths,
        prepared.overlay().touched_paths(),
    );
    assert_eq!(
        prepared.proposal().receipt().proposed_tree_oid,
        *prepared.export().root_tree(),
    );
    assert_eq!(
        prepared.proposal().ref_intents()[0].expected,
        ExpectedRef::Exactly {
            oid: A::parse_hex(&source.commit.to_string()).unwrap(),
        },
    );
    assert!(prepared.export().verify_all());
    let changed_blob = GitOid::<A>::of_object(GitObjectKind::Blob, b"fn checked_change() {}\n");
    assert_eq!(
        prepared.export().get(&changed_blob).unwrap().body(),
        b"fn checked_change() {}\n",
    );
    assert_eq!(
        prepared.proposal().ref_intents()[0].new.erase(),
        prepared.candidate().candidate_commit,
    );
    assert_eq!(
        GitOid::<A>::of_object(GitObjectKind::Commit, prepared.commit_body()).erase(),
        prepared.candidate().candidate_commit,
    );
    // The legacy patch surface shares exactly the same evaluator and packer.
    let ordinary = node
        .runtime()
        .block_on(node.prepare_workspace_patch_in::<A>(
            &node.request_context(),
            &reference(),
            source.commit,
            &RefVisibility::new(),
            &mut capability(&node),
            PATCH,
            11,
            &metadata(),
            PatchLimits::default(),
        ))
        .unwrap();
    assert_eq!(ordinary.bundle_bytes(), prepared.candidate().bundle_bytes());
    assert_eq!(ordinary.commit_body(), prepared.commit_body());

    let contexts = [context(&run)];
    let fixture_evidence = evidence::Evidence::new(
        prepared.workspace(),
        prepared.proposal(),
        &contexts,
        prepared.overlay(),
        prepared.export(),
    );
    assert_eq!(
        prepared
            .publication_subject(&contexts, &fixture_evidence.plan)
            .unwrap(),
        fixture_evidence.subject,
    );
    let transaction = prepared
        .prepare_ref_transaction(
            &contexts,
            fixture_evidence.input(prepared.overlay(), prepared.export()),
        )
        .unwrap();
    // Reuse the test host's durable broker plumbing, retaining only copies of
    // the real production outputs. No manual overlay or pack assembly remains.
    let change = Prepared {
        transaction,
        export: prepared.export().clone(),
        bundle: prepared.candidate().bundle_bytes().to_vec(),
        body: prepared.commit_body().to_vec(),
        original_read,
    };
    let approved = approval(&change, b"native-prepared-agent-change");
    let chain = chain(10_000, true);
    let mut broker = broker(&node, &change, &scratch.journal("prepared-journal"));
    let clock = node
        .trusted_local_agent_publication_clock(LogicalTime::new(20), Duration::from_secs(1))
        .unwrap();
    let result = node
        .runtime()
        .block_on(node.publish_agent_ref_transaction_trusted_local_in(
            &node.command_request_context(Some(
                crate::GitDaemonSessionTimeout::try_new(Duration::from_secs(30)).unwrap(),
            )),
            &mut broker,
            &clock,
            TrustedLocalAgentPublicationInput {
                transaction: &change.transaction,
                export: prepared.export(),
                bundle: prepared.candidate().bundle_bytes(),
                approval: &approved,
                chain: &chain,
            },
        ))
        .unwrap();
    let NativeAgentPublicationResult::Submitted(result) = result else {
        panic!("first native submission");
    };
    let admission = result.admission.unwrap();
    assert!(matches!(
        admission.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    let RefTransactionResolution::Decided(settled) = result.responsibility.unwrap() else {
        panic!("submission responsibility settled from canonical authority");
    };
    assert_eq!(
        settled.observation().terminal(),
        &admission.commands[0].terminal
    );
    let after = current(&node);
    assert_eq!(after.0, prepared.candidate().candidate_commit);
    assert_ne!(after.1, before.1);
    assert_eq!(broker.dispatch_authorizations().len(), 1);
    assert!(broker.close().is_quiescent());
    drop(clock);
    node.shutdown().unwrap();
}

#[test]
fn native_prepared_patch_reaches_checked_publication_in_both_formats() {
    native_candidate_reaches_publication::<Sha1>();
    native_candidate_reaches_publication::<Sha256>();
}

#[test]
fn another_candidate_cannot_reuse_the_first_candidates_evidence_subject() {
    let scratch = Scratch::new();
    let (node, source) = node(&scratch, Format::Sha1, true);
    let (run, _) = authenticated_run(&node, scope());
    let before = current(&node);
    let prepared = prepare::<Sha1, _>(
        &node,
        &run,
        source.commit,
        &mut capability(&node),
        PATCH,
        &|| LogicalTime::new(11),
    )
    .unwrap();
    let other = prepare::<Sha1, _>(
        &node,
        &run,
        source.commit,
        &mut capability(&node),
        OTHER_PATCH,
        &|| LogicalTime::new(11),
    )
    .unwrap();
    let contexts = [context(&run)];
    let fixture_evidence = evidence::Evidence::new(
        prepared.workspace(),
        prepared.proposal(),
        &contexts,
        prepared.overlay(),
        prepared.export(),
    );
    assert!(matches!(
        other.prepare_ref_transaction(
            &contexts,
            fixture_evidence.input(prepared.overlay(), prepared.export()),
        ),
        Err(ProtocolRefusal::Publication(
            AgentPublicationRefusal::EvidenceSubject
        ))
    ));
    assert_eq!(current(&node), before);
    node.shutdown().unwrap();
}

#[test]
fn run_expiry_clock_and_missing_scope_refuse_before_source_fetch() {
    let scratch = Scratch::new();
    let (node, source) = node(&scratch, Format::Sha1, false);
    let (run, _) = authenticated_run(&node, scope());
    let before = current(&node);
    for (tick, expired) in [(10_000, true), (9, false)] {
        let mut cap = capability(&node);
        let result = prepare::<Sha1, _>(&node, &run, source.commit, &mut cap, PATCH, &|| {
            LogicalTime::new(tick)
        });
        assert!(if expired {
            matches!(result, Err(AgentWorkspacePatchRefusal::RunExpired))
        } else {
            matches!(result, Err(AgentWorkspacePatchRefusal::ClockRegressed))
        });
        assert_eq!(cap.fetched_files(), 0);
    }
    for missing in [
        OperationClass::ReadCanonicalObject,
        OperationClass::TreeFsWorkspace,
        OperationClass::CreateCandidateObject,
        OperationClass::PreparePublication,
    ] {
        let classes = OperationClass::ALL
            .into_iter()
            .filter(|class| *class != missing)
            .collect::<Vec<_>>();
        let (narrow, _) = authenticated_run(&node, ClassSet::from_classes(&classes));
        let mut cap = capability(&node);
        assert!(matches!(
            prepare::<Sha1, _>(&node, &narrow, source.commit, &mut cap, PATCH, &|| LogicalTime::new(11)),
            Err(AgentWorkspacePatchRefusal::OperationOutsideRun(class)) if class == missing
        ));
        assert_eq!(cap.fetched_files(), 0);
    }
    let legacy = IntentRun::new(
        RunId::new(902),
        run.base_authority(),
        scope(),
        budget(),
        LogicalTime::new(10_000),
    )
    .unwrap();
    let mut cap = capability(&node);
    assert!(matches!(
        prepare::<Sha1, _>(&node, &legacy, source.commit, &mut cap, PATCH, &|| LogicalTime::new(11)),
        Err(AgentWorkspacePatchRefusal::Binding(error)) if matches!(error.as_ref(), ProtocolRefusal::RunAuthorityReceiptRequired)
    ));
    assert_eq!(cap.fetched_files(), 0);
    assert_eq!(current(&node), before);
    node.shutdown().unwrap();
}

#[test]
fn late_expiry_regression_and_capability_expiry_discard_the_complete_candidate() {
    let scratch = Scratch::new();
    let (node, source) = node(&scratch, Format::Sha1, false);
    let (run, _) = authenticated_run(&node, scope());
    let before = current(&node);
    for (late, expected_expiry) in [(10_000, true), (10, false)] {
        let reads = AtomicU64::new(0);
        let mut cap = capability(&node);
        let result = prepare::<Sha1, _>(&node, &run, source.commit, &mut cap, PATCH, &|| {
            LogicalTime::new(if reads.fetch_add(1, Ordering::Relaxed) < 2 {
                11
            } else {
                late
            })
        });
        assert!(cap.fetched_bytes() > 0, "exercise expiry after native work");
        assert!(if expected_expiry {
            matches!(result, Err(AgentWorkspacePatchRefusal::RunExpired))
        } else {
            matches!(result, Err(AgentWorkspacePatchRefusal::ClockRegressed))
        });
    }
    let reads = AtomicU64::new(0);
    let mut cap = capability(&node).with_expiry(12);
    let result = prepare::<Sha1, _>(&node, &run, source.commit, &mut cap, PATCH, &|| {
        LogicalTime::new(if reads.fetch_add(1, Ordering::Relaxed) < 2 {
            11
        } else {
            12
        })
    });
    assert!(matches!(
        result,
        Err(AgentWorkspacePatchRefusal::Workspace(error))
            if matches!(error.as_ref(), NodeWorkspaceRefusal::Manifest(fgit_treefs::SparseRefusal::Capability(fgit_treefs::CapabilityRefusal::Expired { .. })))
    ));
    assert_eq!(current(&node), before);
    node.shutdown().unwrap();
}

#[test]
fn stale_authority_and_commit_refuse_without_rebasing_or_fetching_source() {
    let scratch = Scratch::new();
    let (node, source) = node(&scratch, Format::Sha1, false);
    let (run, _) = authenticated_run(&node, scope());
    let mut cap = capability(&node);
    let wrong = fgit_crypto::git_object_id(Format::Sha1, GitObjectKind::Commit, b"unrelated");
    assert!(matches!(
        prepare::<Sha1, _>(&node, &run, wrong, &mut cap, PATCH, &|| LogicalTime::new(11)),
        Err(AgentWorkspacePatchRefusal::Workspace(error))
            if matches!(error.as_ref(), NodeWorkspaceRefusal::SourceBrowse(inner) if matches!(inner.as_ref(), SourceBrowseError::CommitMoved))
    ));
    assert_eq!(cap.fetched_files(), 0);
    source_on_branch(
        &node,
        &RefName::try_new(b"refs/heads/unrelated").unwrap(),
        b"move-authority-without-moving-base",
        b"diff --git a/other b/other\nnew file mode 100644\n--- /dev/null\n+++ b/other\n@@ -0,0 +1 @@\n+other\n",
    );
    let before = current(&node);
    assert_eq!(before.0, source.commit);
    assert!(matches!(
        prepare::<Sha1, _>(&node, &run, source.commit, &mut cap, PATCH, &|| LogicalTime::new(11)),
        Err(AgentWorkspacePatchRefusal::Workspace(error))
            if matches!(error.as_ref(), NodeWorkspaceRefusal::SourceBrowse(inner) if matches!(inner.as_ref(), SourceBrowseError::SnapshotMoved))
    ));
    assert_eq!(cap.fetched_files(), 0);
    assert_eq!(current(&node), before);
    node.shutdown().unwrap();
}

#[test]
fn foreign_run_capability_and_hidden_source_do_not_gain_disclosure() {
    let scratch = Scratch::new();
    let (node, source) = node(&scratch, Format::Sha1, false);
    let (run, _) = authenticated_run(&node, scope());
    let before = current(&node);
    let (mut foreign, _) = OneNode::init(
        NodeConfig::new(
            scratch.0.join("foreign"),
            node.tenant_id(),
            RepositoryId::from_bytes([0x96; 16]),
        )
        .with_worker_threads(2),
    )
    .unwrap();
    foreign.bring_into_service(HeadGeneration::FIRST).unwrap();
    let (foreign_run, _) = authenticated_run(&foreign, scope());
    let mut cap = capability(&node);
    assert!(matches!(
        prepare::<Sha1, _>(&node, &foreign_run, source.commit, &mut cap, PATCH, &|| LogicalTime::new(11)),
        Err(AgentWorkspacePatchRefusal::Workspace(error))
            if matches!(error.as_ref(), NodeWorkspaceRefusal::RepositoryMismatch)
    ));
    assert_eq!(cap.fetched_files(), 0);
    let mut foreign_cap = capability(&foreign);
    assert!(matches!(
        prepare::<Sha1, _>(&node, &run, source.commit, &mut foreign_cap, PATCH, &|| LogicalTime::new(11)),
        Err(AgentWorkspacePatchRefusal::Workspace(error))
            if matches!(error.as_ref(), NodeWorkspaceRefusal::RepositoryMismatch)
    ));
    assert_eq!(foreign_cap.fetched_files(), 0);
    assert!(matches!(
        prepare::<Sha256, _>(&node, &run, source.commit, &mut cap, PATCH, &|| LogicalTime::new(11)),
        Err(AgentWorkspacePatchRefusal::Workspace(error))
            if matches!(error.as_ref(), NodeWorkspaceRefusal::ObjectFormatMismatch)
    ));
    assert_eq!(cap.fetched_files(), 0);
    let mut hidden = RefVisibility::new();
    hidden
        .push_rule(b"refs/heads/main", &Default::default())
        .unwrap();
    let result = node
        .runtime()
        .block_on(node.prepare_agent_workspace_patch_in::<Sha1, _>(
            &node.request_context(),
            AgentWorkspacePatchInput {
                run: &run,
                reference: &reference(),
                expected_commit: source.commit,
                visibility: &hidden,
                capability: &mut cap,
                patch_bytes: PATCH,
                metadata: &metadata(),
                limits: PatchLimits::default(),
            },
            &|| LogicalTime::new(11),
        ));
    assert!(matches!(
        result,
        Err(AgentWorkspacePatchRefusal::Workspace(error))
            if matches!(error.as_ref(), NodeWorkspaceRefusal::RefUnavailable)
    ));
    assert_eq!(cap.fetched_files(), 0);
    let mut read_only = cap
        .attenuate(vec![TreePath::parse_default(b"lib.rs").unwrap()], vec![])
        .unwrap();
    assert!(matches!(
        prepare::<Sha1, _>(&node, &run, source.commit, &mut read_only, PATCH, &|| LogicalTime::new(11)),
        Err(AgentWorkspacePatchRefusal::Workspace(error))
            if matches!(error.as_ref(), NodeWorkspaceRefusal::Manifest(fgit_treefs::SparseRefusal::Capability(fgit_treefs::CapabilityRefusal::WriteOutsideScope { .. })))
    ));
    assert_eq!(read_only.fetched_files(), 0);
    assert_eq!(current(&node), before);
    foreign.shutdown().unwrap();
    node.shutdown().unwrap();
}

#[test]
fn cancelled_and_no_net_change_requests_never_release_prepared_candidates() {
    let scratch = Scratch::new();
    let (node, source) = node(&scratch, Format::Sha1, false);
    let (run, _) = authenticated_run(&node, scope());
    let before = current(&node);
    let request = node.request_context();
    request.cancel();
    let mut cap = capability(&node);
    let result = node
        .runtime()
        .block_on(node.prepare_agent_workspace_patch_in::<Sha1, _>(
            &request,
            AgentWorkspacePatchInput {
                run: &run,
                reference: &reference(),
                expected_commit: source.commit,
                visibility: &RefVisibility::new(),
                capability: &mut cap,
                patch_bytes: PATCH,
                metadata: &metadata(),
                limits: PatchLimits::default(),
            },
            &|| LogicalTime::new(11),
        ));
    assert!(matches!(
        result,
        Err(AgentWorkspacePatchRefusal::Workspace(error))
            if matches!(error.as_ref(), NodeWorkspaceRefusal::Cancelled { .. })
    ));
    assert_eq!(cap.fetched_files(), 0);
    let no_change = b"diff --git a/lib.rs b/lib.rs\n--- a/lib.rs\n+++ b/lib.rs\n@@ -1 +1 @@\n-fn original() {}\n+fn original() {}\n";
    assert!(matches!(
        prepare::<Sha1, _>(&node, &run, source.commit, &mut cap, no_change, &|| LogicalTime::new(11)),
        Err(AgentWorkspacePatchRefusal::Workspace(error))
            if matches!(error.as_ref(), NodeWorkspaceRefusal::InvalidWorkspaceCandidate("patch has no net tree change; no candidate was created"))
    ));
    assert_eq!(current(&node), before);
    node.shutdown().unwrap();
}
