use super::*;
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::{AggregateVersion, PullRequestNumber};
use fgit_types::{GitHashAlgorithm, GitOid, RefName};

fn row() -> PullRequestView {
    let format = GitHashAlgorithm::Sha256;
    let actor = PrincipalId::from_bytes([7; 16]);
    let command = PullRequestCommand {
        number: PullRequestNumber::FIRST,
        expected_version: ExpectedVersion::NewStream,
        action: PullRequestAction::Open,
        data: PullRequestData {
            source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
            target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
            source_tip: GitOid::from_hex(format, &"a".repeat(64)).unwrap(),
            target_tip: GitOid::from_hex(format, &"b".repeat(64)).unwrap(),
            title: "Native PR".into(),
            body: String::new(),
        },
    };
    PullRequestView {
        number: command.number,
        event: command.proposed_event(actor, format).unwrap(),
        data: Some(command.data),
        opened_by: Some(actor),
        last_metadata_actor: Some(actor),
        labels: Vec::new(),
        labels_version: None,
        labels_actor: None,
    }
}

#[test]
fn untouched_and_cleared_label_sets_keep_distinct_versions_and_literal_text() {
    let mut value = row();
    let content = value.event.clone();
    assert_eq!(
        fields(&value).unwrap(),
        "\"labels\":[],\"labels_version\":0,\"labels_actor\":null"
    );
    value.labels = vec!["<script>\"untrusted\"".into(), "é🦀".into()];
    value.labels_version = Some(AggregateVersion::try_new(23).unwrap());
    value.labels_actor = Some(PrincipalId::from_bytes([8; 16]));
    let body = fields(&value).unwrap();
    assert!(body.contains("\"labels_version\":23"));
    assert!(body.contains("<script>\\\"untrusted\\\""));
    assert!(body.contains("é🦀"));
    assert_eq!(value.event, content);
    value.labels.clear();
    assert!(
        fields(&value)
            .unwrap()
            .contains("\"labels\":[],\"labels_version\":23")
    );
}

#[test]
fn inconsistent_label_state_is_refused_instead_of_fabricating_an_untouched_set() {
    let original = row();
    let mut bad = original.clone();
    bad.labels = vec!["bug".into()];
    assert!(fields(&bad).is_err());
    bad = original.clone();
    bad.labels_version = Some(AggregateVersion::FIRST);
    assert!(fields(&bad).is_err());
    bad.labels_actor = Some(PrincipalId::from_bytes([8; 16]));
    bad.data = None;
    assert!(fields(&bad).is_err());
    bad = original;
    bad.labels_actor = Some(PrincipalId::from_bytes([8; 16]));
    assert!(fields(&bad).is_err());
}

#[test]
fn additive_receipts_echo_only_the_sealed_additions_and_never_fabricate_versions() {
    use fgit_codec::harness::{commit_id, refusal_record_id, tx_id};
    use fgit_types::{DecisionSequence, RefusalCode};
    let labels = vec!["<script>\"untrusted\"".into(), "é🦀".into()];
    for outcome in [
        DecisionOutcome::Committed {
            repository_commit_id: commit_id(),
        },
        DecisionOutcome::Refused {
            code: RefusalCode::ResourceBudgetExceeded,
            refusal_record_id: refusal_record_id(),
        },
    ] {
        let terminal = TerminalOutcome {
            decision_sequence: DecisionSequence::FIRST,
            outcome,
        };
        let encoded = publication_fields(
            "\"principal_id\":\"original\"",
            PullRequestNumber::FIRST,
            &labels,
            None,
            tx_id(),
            terminal,
        )
        .unwrap();
        for field in [
            "\"action\":\"add-labels\"",
            "\"command_profile\":\"pull-request.add-labels.v1\"",
            "\"expected_version\":null",
            "\"labels_version\":null",
            "\"refs_changed\":false",
            "\"pull_request_version_changed\":false",
            "\"delivery_acknowledged\":null",
        ] {
            assert!(encoded.contains(field), "{encoded}");
        }
        assert!(encoded.contains("<script>\\\"untrusted\\\""));
        assert!(encoded.contains("é🦀"));
        assert!(encoded.contains(&format!("\"labels\":{}", array(&labels))));
        assert_eq!(
            publication_fields(
                "\"principal_id\":\"original\"",
                PullRequestNumber::FIRST,
                &labels,
                None,
                tx_id(),
                terminal
            )
            .unwrap(),
            encoded
        );
        if matches!(outcome, DecisionOutcome::Refused { .. }) {
            assert!(encoded.contains("\"outcome\":\"refused\""));
            assert!(encoded.contains("\"repository_commit_id\":null"));
            assert!(encoded.contains("\"refusal_code\":\"ResourceBudgetExceeded\""));
        } else {
            assert!(encoded.contains("\"outcome\":\"committed\""));
            assert!(encoded.contains("\"refusal_code\":null"));
        }
        let exact = publication_fields(
            "\"principal_id\":\"original\"",
            PullRequestNumber::FIRST,
            &labels,
            Some(7),
            tx_id(),
            terminal,
        )
        .unwrap();
        assert!(exact.contains("\"action\":\"set-labels\""));
        assert!(exact.contains("\"expected_version\":7"));
        assert!(!exact.contains("command_profile"));
        if matches!(outcome, DecisionOutcome::Committed { .. }) {
            assert!(exact.contains("\"labels_version\":8"));
        }
    }
}
