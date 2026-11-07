//! Real canonical hidden-ref policy reaches fresh and retained PR inbox reads.
use super::*;
use crate::treefs_workspace::{NotificationInboxPage, NotificationReadRefusal};
use fgit_authority::{
    PublicationOutcome, authority_head_identity, collect_cumulative_outcomes_async,
    publish_decisions_async, read_repository_incarnation_configuration_async,
    stage_hidden_ref_policy_async, stage_latest_repository_incarnation_configuration_async,
};
use fgit_chronicle::{PublicationBasis, PublicationPlan, ResultingRoots};
use fgit_codec::{
    CryptoBodyIdentity, DecodeLimits, HiddenRefPolicyBody, RepositoryAuthorityHeadBody,
    RepositoryIncarnationConfigurationBodyV2_1, decode_body,
};
use fgit_forge::IssueNumber;
use fgit_forge::event::issue::{IssueAction, IssueCommand};
use fgit_forge::event::notification::{NotificationTarget, NotificationTargetKind};

fn inbox(
    node: &OneNode,
    expected: Option<RepositoryAuthorityHeadId>,
    single: bool,
) -> Result<NotificationInboxPage, NotificationReadRefusal> {
    let request = node.request_context();
    let reader = session("notification-read");
    if single {
        node.runtime().block_on(node.read_notification_target_in(
            &request,
            &reader,
            NotificationTarget::PullRequest(PullRequestNumber::FIRST),
            expected,
        ))
    } else {
        node.runtime()
            .block_on(node.read_notification_inbox_for_kind_in(
                &request,
                &reader,
                NotificationTargetKind::PullRequest,
                0,
                100,
                expected,
                false,
                false,
            ))
    }
}

/// Like hidden_ref_policy_end_to_end, stage actual canonical bodies and select
/// the configuration with an authenticated CAS over a refusal-only batch.
/// All existing committed roots are carried forward unchanged.
fn hide(node: &OneNode, reference: &RefName) -> RepositoryAuthorityHeadId {
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
        let policy_root = stage_hidden_ref_policy_async(
            &node.authority,
            request.authority(),
            &HiddenRefPolicyBody {
                rules: vec![reference.as_bytes().to_vec()],
            },
        )
        .await
        .unwrap();
        let configuration_root = stage_latest_repository_incarnation_configuration_async(
            &node.authority,
            request.authority(),
            &RepositoryIncarnationConfigurationBodyV2_1 {
                root_layout: original.root_layout,
                object_format: original.object_format,
                repository_incarnation_id: original.repository_incarnation_id,
                policy_root: Some(policy_root),
            },
        )
        .await
        .unwrap();
        let basis = PublicationBasis::new(authority_head_identity(&prior).unwrap(), prior);
        let roots = ResultingRoots::carried_forward(&basis);
        let mut plan = PublicationPlan::open(basis).unwrap();
        plan.refuse(
            fgit_codec::harness::tx_id(),
            fgit_types::RefusalCode::QuotaExceeded,
            fgit_codec::harness::refusal_record_id(),
        );
        let outcomes =
            collect_cumulative_outcomes_async(&node.authority, request.authority(), &node.head_key)
                .await
                .unwrap();
        let publication = plan
            .seal(&CryptoBodyIdentity, roots, &outcomes, receipt.token())
            .unwrap();
        let mut head = publication.head().clone();
        head.configuration_root = configuration_root;
        assert!(matches!(
            publish_decisions_async(
                &node.authority,
                request.authority(),
                &node.head_key,
                receipt.token(),
                publication.batch(),
                &head,
                node.tenant_id,
            )
            .await
            .unwrap(),
            PublicationOutcome::Published(_)
        ));
        let selected = node.materialize_admission_in(&request).await.unwrap();
        assert!(selected.snapshot().hidden_refs.hides(reference.as_bytes()));
        selected.basis().id()
    })
}

fn advance_with_issue(node: &OneNode) {
    let request = node.request_context();
    accepted(node.runtime().block_on(node.admit_issue_durable_in(
        &request,
        &session("advance-hidden-inbox"),
        &IssueCommand {
            number: IssueNumber::FIRST,
            expected_version: ExpectedVersion::NewStream,
            action: IssueAction::Open {
                title: "Independent visible issue".into(),
                body: String::new(),
                labels: Vec::new(),
            },
        },
        AdmissionLimits::default(),
    )));
}

fn assert_hidden(
    node: &OneNode,
    visible_head: RepositoryAuthorityHeadId,
    retained_hidden_head: RepositoryAuthorityHeadId,
) {
    let before = snapshot(node);
    for single in [false, true] {
        let fresh = inbox(node, None, single).unwrap();
        assert!(fresh.threads.is_empty());
        assert_eq!(fresh.next_after, None);
        assert_eq!(fresh.binding.authority_head, before.basis().id());
        let retained = inbox(node, Some(retained_hidden_head), single).unwrap();
        assert!(retained.threads.is_empty());
        assert_eq!(retained.next_after, None);
        assert_eq!(retained.binding.authority_head, retained_hidden_head);
        assert!(matches!(
            inbox(node, Some(visible_head), single),
            Err(NotificationReadRefusal::SnapshotMoved)
        ));
    }
    assert_eq!(
        snapshot(node).basis(),
        before.basis(),
        "reads cannot publish"
    );
}

#[test]
fn current_source_or_target_policy_hides_fresh_and_retained_pull_request_notifications() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for hidden in [source_ref(), target()] {
            let scratch = Scratch::new();
            let node = node(&scratch, format);
            let fixture = fixture(&node, &scratch, format);
            accepted(apply(&node, &command(&fixture, 1), "open-inbox-subject"));
            let visible = inbox(&node, None, false).unwrap();
            assert_eq!(visible.threads.len(), 1, "visible positive twin");
            assert_eq!(visible.threads[0].title, fixture.data.title);
            assert_eq!(inbox(&node, None, true).unwrap().threads.len(), 1);
            let original = snapshot(&node);
            let hidden_head = hide(&node, &hidden);
            assert_ne!(hidden_head, visible.binding.authority_head);
            let hidden_snapshot = snapshot(&node);
            assert_eq!(hidden_snapshot.snapshot().refs, original.snapshot().refs);
            assert_eq!(
                hidden_snapshot.basis().body().forge_position_root,
                original.basis().body().forge_position_root,
                "the PR still exists at exactly its original frontier"
            );
            assert_hidden(&node, visible.binding.authority_head, hidden_head);
            advance_with_issue(&node);
            let current = snapshot(&node).basis().id();
            assert_ne!(current, hidden_head);
            assert_hidden(&node, visible.binding.authority_head, hidden_head);
            node.shutdown().unwrap();

            let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
            let head = reopened
                .runtime()
                .block_on(reopened.authenticate_authority_head())
                .unwrap();
            reopened
                .bring_into_service(head.receipt().generation())
                .unwrap();
            assert_hidden(&reopened, visible.binding.authority_head, hidden_head);
            assert_eq!(snapshot(&reopened).basis().id(), current);
            reopened.shutdown().unwrap();
        }
    }
}
