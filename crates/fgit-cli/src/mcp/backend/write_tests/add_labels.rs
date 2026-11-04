//! Real MCP label intents preserve independent edits and original recovery.
use super::*;

fn addition(key: &str, labels: &[&str]) -> Value {
    object([
        ("number", text("7")),
        ("idempotency_key", text(key)),
        (
            "labels",
            Value::Array(labels.iter().map(|label| text(*label)).collect()),
        ),
    ])
}

#[test]
fn label_additions_recover_without_readding_labels_removed_by_later_replacement() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let mut backend = NodeTools::open(fixture.options(true, true, true, 0xa3)).unwrap();
        let mut server = initialized(&mut backend);
        assert!(!failed(&invoke(
            &mut server,
            &mut backend,
            2,
            "frankengit_issue_open",
            opening()
        )));
        let original = addition("labels-original", &["triage", "bug"]);
        assert!(!failed(&invoke(
            &mut server,
            &mut backend,
            3,
            "frankengit_issue_edit",
            command(
                "7",
                "1",
                "independent-edit",
                &[("title", text("Independent title"))]
            )
        )));
        let added = invoke(
            &mut server,
            &mut backend,
            4,
            "frankengit_issue_add_labels",
            original.clone(),
        );
        assert!(!failed(&added), "{added:?}");
        assert_eq!(structured(&added)["outcome"].text(), Some("committed"));
        assert_eq!(structured(&added)["action"].text(), Some("add-labels"));
        assert_eq!(
            structured(&added)["command_profile"].text(),
            Some("issue.add-labels.v1")
        );
        assert_eq!(structured(&added)["expected_version"], Value::Null);
        assert_eq!(structured(&added)["refs_changed"], Value::Bool(false));
        let stale = invoke(
            &mut server,
            &mut backend,
            5,
            "frankengit_issue_edit",
            command(
                "7",
                "1",
                "strict-stale",
                &[("labels", Value::Array(vec![text("replacement")]))],
            ),
        );
        assert!(failed(&stale));
        assert_eq!(structured(&stale)["outcome"].text(), Some("refused"));
        assert!(!failed(&invoke(
            &mut server,
            &mut backend,
            6,
            "frankengit_issue_add_labels",
            addition("labels-independent", &["triage", "urgent"])
        )));
        assert!(!failed(&invoke(
            &mut server,
            &mut backend,
            7,
            "frankengit_issue_edit",
            command(
                "7",
                "4",
                "replace-later",
                &[("labels", Value::Array(vec![text("retained")]))]
            )
        )));
        let held = current_head(&backend);
        let replay = invoke(
            &mut server,
            &mut backend,
            8,
            "frankengit_issue_add_labels",
            addition("labels-original", &["bug", "triage"]),
        );
        assert_eq!(structured(&replay), structured(&added));
        assert_eq!(current_head(&backend), held);
        let changed = invoke(
            &mut server,
            &mut backend,
            9,
            "frankengit_issue_add_labels",
            addition("labels-original", &["different"]),
        );
        assert!(failed(&changed));
        assert_eq!(structured(&changed)["outcome_unknown"], Value::Bool(true));
        assert_eq!(current_head(&backend), held);
        backend.close().unwrap();

        let mut stopped = NodeTools {
            agent: None,
            maintenance: None,
            node: OneNode::open_existing(fixture.config()).unwrap(),
            options: fixture.options(true, true, true, 0xa3),
        };
        let recovered = stopped
            .call("frankengit_issue_add_labels", original.object().unwrap())
            .unwrap();
        assert_eq!(recovered.object().unwrap(), structured(&added));
        let fresh = addition("new-stopped", &["different"]);
        assert!(
            !stopped
                .call("frankengit_issue_add_labels", fresh.object().unwrap())
                .unwrap_err()
                .invalid
        );
        stopped.close().unwrap();

        let mut backend = NodeTools::open(fixture.options(true, true, true, 0xa3)).unwrap();
        let mut server = initialized(&mut backend);
        let outcome = recover(&mut server, &mut backend, 2, "labels-original");
        assert_eq!(structured(&outcome)["tx_id"], structured(&added)["tx_id"]);
        let shown = invoke(
            &mut server,
            &mut backend,
            3,
            "frankengit_issue_show",
            object([("number", text("7"))]),
        );
        assert!(!failed(&shown));
        let issue = structured(&shown)["issue"].object().unwrap();
        assert_eq!(issue["title"].text(), Some("Independent title"));
        assert_eq!(issue["version"].text(), Some("5"));
        assert_eq!(issue["labels"], Value::Array(vec![text("retained")]));
        assert_eq!(current_head(&backend), held);
        backend.close().unwrap();
    }
}
