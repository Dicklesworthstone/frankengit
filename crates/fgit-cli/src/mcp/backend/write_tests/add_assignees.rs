//! Real native admission and fresh-node retry for explicitly additive metadata.
use super::*;

fn addition(key: &str, ids: &[u8]) -> Value {
    object([
        ("number", text("7")),
        ("idempotency_key", text(key)),
        (
            "assignees",
            Value::Array(
                ids.iter()
                    .map(|id| text(format!("{id:02x}").repeat(16)))
                    .collect(),
            ),
        ),
    ])
}

#[test]
fn additions_preserve_independent_changes_and_recover_without_readding_removed_assignments() {
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
        let original = addition("add-original", &[0x44, 0x22]);
        // The intent was formed before an independent edit; there is no stale
        // issue-version field to refresh before submitting it.
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
            ),
        )));
        let added = invoke(
            &mut server,
            &mut backend,
            4,
            "frankengit_issue_add_assignees",
            original.clone(),
        );
        assert!(!failed(&added), "{added:?}");
        assert_eq!(structured(&added)["outcome"].text(), Some("committed"));
        assert_eq!(structured(&added)["action"].text(), Some("add-assignees"));
        assert_eq!(
            structured(&added)["command_profile"].text(),
            Some("issue.add-assignees.v1")
        );
        assert_eq!(structured(&added)["expected_version"], Value::Null);
        assert_eq!(structured(&added)["refs_changed"], Value::Bool(false));
        let stale = invoke(
            &mut server,
            &mut backend,
            5,
            "frankengit_issue_assign",
            command(
                "7",
                "1",
                "strict-stale",
                &[("assignees", Value::Array(vec![text("66".repeat(16))]))],
            ),
        );
        assert!(failed(&stale));
        assert_eq!(structured(&stale)["outcome"].text(), Some("refused"));
        // Partial overlap adds the missing member while retaining both earlier
        // assignments. Its key owns a separate canonical decision.
        assert!(!failed(&invoke(
            &mut server,
            &mut backend,
            6,
            "frankengit_issue_add_assignees",
            addition("add-independent", &[0x44, 0x55]),
        )));
        assert!(!failed(&invoke(
            &mut server,
            &mut backend,
            7,
            "frankengit_issue_unassign",
            command(
                "7",
                "4",
                "remove-first",
                &[("assignees", Value::Array(vec![text("22".repeat(16))]))]
            ),
        )));
        let held = current_head(&backend);
        let replay = invoke(
            &mut server,
            &mut backend,
            8,
            "frankengit_issue_add_assignees",
            original.clone(),
        );
        assert_eq!(structured(&replay), structured(&added));
        assert_eq!(current_head(&backend), held);
        let changed = invoke(
            &mut server,
            &mut backend,
            9,
            "frankengit_issue_add_assignees",
            addition("add-original", &[0x66]),
        );
        assert!(failed(&changed));
        assert_eq!(structured(&changed)["outcome_unknown"], Value::Bool(true));
        assert_eq!(current_head(&backend), held);
        backend.close().unwrap();

        // Historical recovery still precedes current service-intake eligibility.
        let mut stopped = NodeTools {
            agent: None,
            maintenance: None,
            node: OneNode::open_existing(fixture.config()).unwrap(),
            options: fixture.options(true, true, true, 0xa3),
        };
        let recovered = stopped
            .call("frankengit_issue_add_assignees", original.object().unwrap())
            .unwrap();
        assert_eq!(recovered.object().unwrap(), structured(&added));
        let fresh = addition("new-stopped", &[0x66]);
        assert!(
            !stopped
                .call("frankengit_issue_add_assignees", fresh.object().unwrap())
                .unwrap_err()
                .invalid
        );
        stopped.close().unwrap();

        let mut backend = NodeTools::open(fixture.options(true, true, true, 0xa3)).unwrap();
        let mut server = initialized(&mut backend);
        let outcome = recover(&mut server, &mut backend, 2, "add-original");
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
        assert_eq!(
            issue["assignees"],
            Value::Array(vec![text("44".repeat(16)), text("55".repeat(16))])
        );
        assert_eq!(current_head(&backend), held);
        backend.close().unwrap();
    }
}
