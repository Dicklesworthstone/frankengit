//! Label publication and pinned filtering over real imported native objects.
use super::*;
use fgit_forge::event::pull_request_labels::PullRequestLabelsCommand;

fn labels(number: u64, previous: u64, values: &[&str]) -> PullRequestLabelsCommand {
    PullRequestLabelsCommand {
        number: PullRequestNumber::try_new(number).unwrap(),
        expected_version: AggregateVersion::try_new(previous)
            .map_or(ExpectedVersion::NewStream, ExpectedVersion::Exactly),
        labels: values.iter().map(|value| (*value).into()).collect(),
    }
}
fn set(
    node: &OneNode,
    command: &PullRequestLabelsCommand,
    key: &str,
) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
    node.runtime()
        .block_on(node.admit_pull_request_labels_durable_in(
            &node.request_context(),
            &session(key),
            command,
            AdmissionLimits::default(),
        ))
}
fn filtered(
    node: &OneNode,
    after: u64,
    head: Option<RepositoryAuthorityHeadId>,
    labels: &[&str],
) -> PullRequestPage {
    let labels: Vec<String> = labels.iter().map(|value| (*value).into()).collect();
    node.runtime()
        .block_on(node.read_pull_requests_filtered_in(
            &node.request_context(),
            &RefVisibility::new(),
            after,
            1,
            head,
            &labels,
        ))
        .unwrap()
}

#[test]
fn exact_labels_filter_before_paging_and_remain_pinned_across_clear_and_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        let fixture = fixture(&node, &scratch, format);
        for number in 1..=3 {
            accepted(apply(
                &node,
                &command(&fixture, number),
                &format!("open-{number}"),
            ));
        }
        let original = page(&node, 0, 100, None).unwrap();
        let before = snapshot(&node);
        let command_two = labels(2, 0, &["bug"]);
        let committed_two = accepted(set(&node, &command_two, "labels-two"));
        accepted(set(
            &node,
            &labels(3, 0, &["bug", "urgent"]),
            "labels-three",
        ));
        let current = page(&node, 0, 100, None).unwrap();
        unchanged_code(&before, &snapshot(&node));
        for (old, new) in original.pull_requests.iter().zip(&current.pull_requests) {
            assert_eq!(old.event, new.event);
            assert_eq!(old.data, new.data);
            assert_eq!(old.opened_by, new.opened_by);
            assert_eq!(old.last_metadata_actor, new.last_metadata_actor);
        }
        assert_eq!(
            current.pull_requests[1].labels_version,
            Some(AggregateVersion::FIRST)
        );
        let first = filtered(&node, 0, None, &["bug"]);
        assert_eq!(first.pull_requests[0].number.get(), 2);
        assert_eq!(first.next_after, Some(2));
        let both = filtered(&node, 0, Some(first.source_head), &["bug", "urgent"]);
        assert_eq!(both.pull_requests[0].number.get(), 3);
        assert_eq!(both.next_after, None);
        accepted(set(&node, &labels(3, 1, &[]), "labels-three-clear"));
        let continuation = filtered(&node, 2, Some(first.source_head), &["bug"]);
        assert_eq!(continuation.pull_requests[0].number.get(), 3);
        assert_eq!(continuation.pull_requests[0].labels, vec!["bug", "urgent"]);
        assert_eq!(continuation.next_after, None);
        assert!(filtered(&node, 2, None, &["bug"]).pull_requests.is_empty());
        assert_eq!(
            set(&node, &command_two, "labels-two").unwrap(),
            committed_two
        );
        let clear = page(&node, 2, 1, None).unwrap().pull_requests.remove(0);
        assert!(clear.labels.is_empty());
        assert_eq!(clear.labels_version.unwrap().get(), 2);
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        assert_eq!(
            set(&reopened, &command_two, "labels-two").unwrap(),
            committed_two
        );
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        let restored = filtered(&reopened, 0, None, &["bug"]);
        assert_eq!(restored.pull_requests[0].number.get(), 2);
        assert_eq!(restored.next_after, None);
        reopened.shutdown().unwrap();
    }
}

#[test]
fn labels_keep_native_visibility_scope_cancellation_and_historical_outcomes() {
    use crate::AuthenticatedReceiveSession;
    use fgit_admission::evidence::AdmissionAuthentication;
    for hidden in [source_ref(), target()] {
        let scratch = Scratch::new();
        let mut node = node(&scratch, GitHashAlgorithm::Sha256);
        let fixture = fixture(&node, &scratch, GitHashAlgorithm::Sha256);
        let mut lifecycle = command(&fixture, 1);
        accepted(apply(&node, &lifecycle, "labels-open"));
        lifecycle.action = PullRequestAction::Close;
        lifecycle.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
        accepted(apply(&node, &lifecycle, "labels-close"));
        let actor = PrincipalId::from_bytes([0xd3; 16]);
        let writer = LoopbackReceiveSession::Authenticated(
            AuthenticatedReceiveSession::new(
                actor,
                IdempotencyKey::new(b"labels-other-writer".to_vec()).unwrap(),
            )
            .with_authentication(AdmissionAuthentication::HttpToken)
            .with_ref_write_scope(
                fgit_types::ref_write_scope::RefWriteScope::parse("none")
                    .unwrap()
                    .map(std::sync::Arc::new),
            ),
        );
        let command = labels(1, 0, &["triage"]);
        let cancelled = node.request_context();
        cancelled.cancel();
        let before = snapshot(&node);
        assert!(
            node.runtime()
                .block_on(node.admit_pull_request_labels_durable_in(
                    &cancelled,
                    &writer,
                    &command,
                    AdmissionLimits::default()
                ))
                .is_err()
        );
        assert_eq!(snapshot(&node).basis(), before.basis());
        let result = accepted(
            node.runtime()
                .block_on(node.admit_pull_request_labels_durable_in(
                    &node.request_context(),
                    &writer,
                    &command,
                    AdmissionLimits::default(),
                )),
        );
        let row = page(&node, 0, 1, None).unwrap().pull_requests.remove(0);
        assert_eq!(row.labels_actor, Some(actor));
        assert_eq!(row.opened_by, Some(principal()));
        assert_eq!(row.event.version.get(), 2);
        assert!(
            matches!(&row.event.payload, ForgeEventPayload::PullRequestChangedNative(change)
            if change.action == PullRequestAction::Close)
        );
        super::notifications::hide(&node, &hidden);
        assert!(
            filtered(&node, 0, None, &["triage"])
                .pull_requests
                .is_empty()
        );
        let refusal = set(&node, &labels(1, 1, &[]), "labels-hidden").unwrap();
        assert!(matches!(
            refusal.1.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::HiddenRefUnauthorized,
                ..
            }
        ));
        node.push_quota.limit.max_events = 0;
        let after = snapshot(&node);
        assert_eq!(
            node.runtime()
                .block_on(node.admit_pull_request_labels_durable_in(
                    &node.request_context(),
                    &writer,
                    &command,
                    AdmissionLimits::default()
                ))
                .unwrap(),
            result
        );
        assert_eq!(snapshot(&node).basis(), after.basis());
        node.shutdown().unwrap();
    }
}
