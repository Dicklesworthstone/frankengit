//! Real scoped publication through quarantine, native delta proof and authority.
use super::*;
use crate::{NodeWorkspaceRefusal, WorkspacePatchCandidate};
use fgit_admission::AdmissionResult;
use fgit_forge::event::protection::ProtectedBranch;
use fgit_forge::preparation::MergeMetadata;
use fgit_identity::agent::{SOURCE_PUBLISH, SourcePublicationScope};
use fgit_types::{GitOid, RefName};

const INITIAL: &[u8] = b"diff --git a/src/file b/src/file\nnew file mode 100644\n--- /dev/null\n+++ b/src/file\n@@ -0,0 +1 @@\n+before\ndiff --git a/src-other/file b/src-other/file\nnew file mode 100644\n--- /dev/null\n+++ b/src-other/file\n@@ -0,0 +1 @@\n+outside\n";
pub(super) const PATCH: &[u8] = b"diff --git a/src/file b/src/file\n--- a/src/file\n+++ b/src/file\n@@ -1 +1 @@\n-before\n+after\n";
const OUTSIDE: &[u8] = b"diff --git a/src-other/file b/src-other/file\n--- a/src-other/file\n+++ b/src-other/file\n@@ -1 +1 @@\n-outside\n+changed\n";
const DELETE_OUTSIDE: &[u8] = b"diff --git a/src-other/file b/src-other/file\ndeleted file mode 100644\n--- a/src-other/file\n+++ /dev/null\n@@ -1 +0,0 @@\n-outside\n";

pub(super) fn reference() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}

fn metadata() -> MergeMetadata {
    MergeMetadata {
        author: "A <a@example.invalid>".into(),
        committer: "C <c@example.invalid>".into(),
        timestamp: 1,
        message: b"scoped source candidate\n".to_vec(),
    }
}

pub(super) fn seed(node: &OneNode) -> GitOid {
    let request = node.command_request_context(None);
    let (_, plan, bundle) = node
        .runtime()
        .block_on(node.prepare_trusted_initial_patch_in(
            &request,
            &reference(),
            INITIAL,
            &metadata(),
            Default::default(),
            None,
        ))
        .unwrap();
    let result = node
        .runtime()
        .block_on(node.apply_initial_patch_bundle_durable_in(
            &request,
            &operator(actor(1), "source-seed"),
            &reference(),
            plan.commit,
            bundle.bytes(),
            Default::default(),
        ))
        .unwrap();
    assert_committed(&result);
    plan.commit
}

pub(super) fn candidate(node: &OneNode, base: GitOid, patch: &[u8]) -> WorkspacePatchCandidate {
    node.runtime()
        .block_on(node.prepare_trusted_patch_in(
            &node.command_request_context(None),
            &reference(),
            base,
            [9; 16],
            patch,
            &metadata(),
            Default::default(),
        ))
        .unwrap()
}

pub(super) fn scope(reference: &RefName, prefixes: &[&[u8]]) -> SourcePublicationScope {
    let hex: String = reference
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    SourcePublicationScope::new(
        &format!("exact:{hex}"),
        prefixes.iter().map(|prefix| prefix.to_vec()).collect(),
    )
    .unwrap()
}

fn issue_source(
    node: &OneNode,
    token: &str,
    retry: &str,
    scope: SourcePublicationScope,
) -> AgentCredentialCommand {
    let command = AgentCredentialCommand {
        id: agent_credential_id(token.as_bytes()).unwrap(),
        expected_version: ExpectedVersion::NewStream,
        action: AgentCredentialAction::issuance(
            AgentCredentialGrant {
                operations: SOURCE_PUBLISH | SOURCE_CANDIDATES | OUTCOMES_READ,
                ..grant(node)
            },
            Some(scope),
        ),
    };
    committed(credential(node, &command, actor(1), retry));
    command
}

fn apply(
    node: &OneNode,
    run: &AgentRequest,
    candidate: &WorkspacePatchCandidate,
    bytes: &[u8],
) -> Result<AdmissionResult, NodeWorkspaceRefusal> {
    let publication = run.source_publication(node).unwrap();
    node.runtime()
        .block_on(node.apply_agent_workspace_bundle_in(
            &run.context(node),
            &publication,
            &reference(),
            candidate.source_commit,
            candidate.candidate_commit,
            bytes,
        ))
}

pub(super) fn assert_committed(result: &AdmissionResult) {
    assert!(result.session.atomic);
    assert_eq!(result.commands.len(), 1);
    assert!(
        matches!(
            result.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ),
        "{result:?}"
    );
}

pub(super) fn assert_refused(result: &AdmissionResult, code: RefusalCode) {
    assert_eq!(result.commands.len(), 1);
    assert!(
        matches!(result.commands[0].terminal.outcome, DecisionOutcome::Refused { code: actual, .. } if actual == code),
        "{result:?}"
    );
}

fn tip(node: &OneNode) -> GitOid {
    node.runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .unwrap()
        .snapshot()
        .refs[&reference()]
}

#[test]
fn scoped_source_publish_recovers_original_agent_witness_after_rotation_and_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = scratch.node(format);
        let base = seed(&node);
        let candidate = candidate(&node, base, PATCH);
        let token = bearer('a');
        issue_source(
            &node,
            &token,
            "source-issue",
            scope(&reference(), &[b"src"]),
        );
        let run = authentication(&node, &token, "source-publish", SOURCE_PUBLISH);
        assert!(
            run.run
                .allowed_operation_classes()
                .contains(OperationClass::PublishRefTransaction)
        );
        let published = apply(&node, &run, &candidate, candidate.bundle_bytes()).unwrap();
        assert_committed(&published);
        assert_eq!(tip(&node), candidate.candidate_commit);
        let original = provenance(&node, actor(2), "source-publish");
        assert_eq!(original.agent_provenance(), Some(&run.authentication));

        // A terminal retry confirms the original sealed command and witness,
        // not the integrity of replacement transport bytes or today's grant.
        let mut different_encoding = candidate.bundle_bytes().to_vec();
        *different_encoding.last_mut().unwrap() ^= 1;
        let replacement = bearer('b');
        issue_source(
            &node,
            &replacement,
            "source-replacement",
            scope(&reference(), &[b"src-other"]),
        );
        let replacement_run = authentication(&node, &replacement, "source-publish", SOURCE_PUBLISH);
        let recovered = apply(&node, &replacement_run, &candidate, &different_encoding).unwrap();
        assert_eq!(recovered.commands, published.commands);
        assert_eq!(provenance(&node, actor(2), "source-publish"), original);
        node.shutdown().unwrap();

        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        let retry = authentication(&reopened, &replacement, "source-publish", SOURCE_PUBLISH);
        let recovered = apply(&reopened, &retry, &candidate, &different_encoding).unwrap();
        assert_eq!(recovered.commands, published.commands);
        assert_eq!(provenance(&reopened, actor(2), "source-publish"), original);
        assert_eq!(tip(&reopened), candidate.candidate_commit);
        reopened.shutdown().unwrap();
    }
}

#[test]
fn source_scope_checks_complete_native_path_changes_and_exact_ref_ceiling() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = scratch.node(format);
        let base = seed(&node);
        let token = bearer('a');
        issue_source(&node, &token, "scope-issue", scope(&reference(), &[b"src"]));
        for (retry, patch) in [
            ("outside-edit", OUTSIDE),
            ("outside-delete", DELETE_OUTSIDE),
        ] {
            let candidate = candidate(&node, base, patch);
            let run = authentication(&node, &token, retry, SOURCE_PUBLISH);
            let refused = apply(&node, &run, &candidate, candidate.bundle_bytes()).unwrap();
            assert_refused(&refused, RefusalCode::CapabilityScopeViolation);
            assert_eq!(tip(&node), base);
        }

        let different_ref = RefName::try_new(b"refs/heads/agent/topic").unwrap();
        let wrong_ref_token = bearer('b');
        issue_source(
            &node,
            &wrong_ref_token,
            "wrong-ref-issue",
            scope(&different_ref, &[b""]),
        );
        let allowed = candidate(&node, base, PATCH);
        let wrong_ref = authentication(&node, &wrong_ref_token, "wrong-ref", SOURCE_PUBLISH);
        let refused = apply(&node, &wrong_ref, &allowed, allowed.bundle_bytes()).unwrap();
        assert_refused(&refused, RefusalCode::CapabilityScopeViolation);
        assert_eq!(tip(&node), base);

        // Granting candidate preparation alone cannot mint publication; nor
        // can a real source grant enable the generic source-write entrypoint.
        let prepare = authentication(&node, &token, "candidate-only", SOURCE_CANDIDATES);
        assert!(prepare.source_publication(&node).is_err());
        let run = authentication(&node, &token, "generic-publication", SOURCE_PUBLISH);
        let generic = node
            .runtime()
            .block_on(node.apply_workspace_bundle_with_authentication_in(
                &run.context(&node),
                actor(2),
                b"generic-publication",
                &reference(),
                base,
                allowed.candidate_commit,
                allowed.bundle_bytes(),
                AdmissionAuthentication::AgentCredential(run.authentication),
            ))
            .unwrap();
        assert_refused(&generic, RefusalCode::CapabilityScopeViolation);
        let asserted = node
            .runtime()
            .block_on(node.apply_workspace_bundle_durable_in(
                &node.request_context(),
                actor(2),
                b"asserted-agent-publication",
                &reference(),
                base,
                allowed.candidate_commit,
                allowed.bundle_bytes(),
            ))
            .unwrap();
        assert_refused(&asserted, RefusalCode::CapabilityScopeViolation);
        let valid = authentication(&node, &token, "scope-valid", SOURCE_PUBLISH);
        assert_committed(&apply(&node, &valid, &allowed, allowed.bundle_bytes()).unwrap());
        node.shutdown().unwrap();
    }
}

#[test]
fn source_publication_reloads_inflight_revocation_and_preserves_normal_protection() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = scratch.node(format);
        let base = seed(&node);
        let candidate = candidate(&node, base, PATCH);
        let token = bearer('a');
        let issued = issue_source(
            &node,
            &token,
            "revoke-issue",
            scope(&reference(), &[b"src"]),
        );
        let inflight = authentication(&node, &token, "source-inflight", SOURCE_PUBLISH);
        let selected = node
            .runtime()
            .block_on(node.read_agent_credential_in(&node.request_context(), issued.id))
            .unwrap()
            .unwrap();
        let revoke = AgentCredentialCommand {
            id: issued.id,
            expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
            action: AgentCredentialAction::revocation(selected.grant, selected.source_scope),
        };
        committed(credential(&node, &revoke, actor(1), "source-revoke"));
        let refused = apply(&node, &inflight, &candidate, candidate.bundle_bytes()).unwrap();
        assert_refused(&refused, RefusalCode::CapabilityScopeViolation);
        let retry = apply(&node, &inflight, &candidate, candidate.bundle_bytes()).unwrap();
        assert_eq!(retry.commands, refused.commands);
        assert_eq!(
            provenance(&node, actor(2), "source-inflight").agent_provenance(),
            Some(&inflight.authentication)
        );

        let replacement = bearer('b');
        issue_source(
            &node,
            &replacement,
            "protected-issue",
            scope(&reference(), &[b"src"]),
        );
        let current = node
            .runtime()
            .block_on(node.read_review_protection_in(&node.request_context()))
            .unwrap();
        let protection = ProtectionCommand {
            expected_version: ExpectedVersion::NewStream,
            expected_epoch: current.policy_epoch,
            protection: ReviewProtection {
                administrators: vec![actor(1)],
                branches: vec![ProtectedBranch {
                    name: reference(),
                    reviewers: vec![actor(3)],
                    required_approvals: 1,
                    required_checks: Vec::new(),
                    required_candidate_checks: Vec::new(),
                    require_merge_queue: false,
                    path_reviews: Vec::new(),
                }],
                ref_policy: None,
            },
        };
        committed(
            node.runtime()
                .block_on(node.admit_review_protection_durable_in(
                    &node.request_context(),
                    &operator(actor(1), "source-protection"),
                    &protection,
                    Default::default(),
                ))
                .unwrap(),
        );
        let run = authentication(&node, &replacement, "protected-source", SOURCE_PUBLISH);
        let refused = apply(&node, &run, &candidate, candidate.bundle_bytes()).unwrap();
        assert!(
            matches!(
                refused.commands[0].terminal.outcome,
                DecisionOutcome::Refused { .. }
            ),
            "{refused:?}"
        );
        assert_eq!(tip(&node), base);
        node.shutdown().unwrap();
    }
}

#[test]
fn source_publication_retains_original_context_and_cannot_refresh_expired_request() {
    let scratch = Scratch::new();
    let node = scratch.node(GitHashAlgorithm::Sha1);
    let base = seed(&node);
    let candidate = candidate(&node, base, PATCH);
    let token = bearer('a');
    issue_source(
        &node,
        &token,
        "bounded-issue",
        scope(&reference(), &[b"src"]),
    );
    let mut run = authentication(&node, &token, "bounded-source", SOURCE_PUBLISH);
    let original = node.command_request_context(None);
    original.cancel();
    let proof = run.source_publication(&node).unwrap();
    let cancelled = node
        .runtime()
        .block_on(node.apply_agent_workspace_bundle_in(
            &original,
            &proof,
            &reference(),
            base,
            candidate.candidate_commit,
            candidate.bundle_bytes(),
        ))
        .unwrap_err();
    assert!(
        matches!(
            cancelled,
            NodeWorkspaceRefusal::Cancelled { exhaustion: None }
        ),
        "{cancelled:?}"
    );
    drop(proof);
    run.constrain_deadline(Instant::now());
    assert!(run.source_publication(&node).is_err());
    assert_eq!(tip(&node), base);
    node.shutdown().unwrap();
}

#[test]
fn source_deadline_cancels_and_drains_pending_work_in_the_original_longer_context() {
    use std::cell::Cell;
    use std::future::Future;
    use std::task::{Context, Waker};
    use std::time::Duration;

    let scratch = Scratch::new();
    let node = scratch.node(GitHashAlgorithm::Sha1);
    let base = seed(&node);
    let candidate = candidate(&node, base, PATCH);
    let token = bearer('a');
    issue_source(
        &node,
        &token,
        "awaited-expiry-issue",
        scope(&reference(), &[b"src"]),
    );
    let mut run = authentication(&node, &token, "awaited-expiry", SOURCE_PUBLISH);
    // The caller deliberately supplies a longer-lived context. Establish that
    // its awaited phase is pending before the owner's deadline timer runs.
    let original = node.command_request_context(None);
    let mut pending = Box::pin(original.authority().wait_for_local_cancel_request());
    assert!(
        pending
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    run.constrain_deadline(Instant::now() + Duration::from_millis(100));
    let proof = run.source_publication(&node).unwrap();
    let drained = Cell::new(false);
    let outcome = node
        .runtime()
        .block_on(proof.drive_in(&node, &original, async {
            pending.await;
            drained.set(true);
            // A valid ordinary publication cannot escape this exact cancelled
            // context when the awaited phase resumes; the future is not dropped.
            node.apply_workspace_bundle_durable_in(
                &original,
                actor(1),
                b"after-pending-expiry",
                &reference(),
                base,
                candidate.candidate_commit,
                candidate.bundle_bytes(),
            )
            .await
        }));
    assert!(drained.get(), "the pending operation must be drained");
    assert!(original.authority().is_cancel_requested());
    assert!(outcome.is_err(), "{outcome:?}");
    assert_eq!(tip(&node), base);
    let fresh = authentication(&node, &token, "after-expiry-success", SOURCE_PUBLISH);
    assert_committed(&apply(&node, &fresh, &candidate, candidate.bundle_bytes()).unwrap());
    node.shutdown().unwrap();
}
