//! Canonical PR-write scope is revalidated for every reopen and retry.
use super::super::super::pull_writes::{CLOSE, OPEN, REOPEN};
use super::*;

fn command(fixture: &Fixture, version: &str, key: &str) -> Object {
    let mut args = pull_opening(fixture, 7, key);
    args.insert("expected_version".into(), text(version));
    args
}

#[test]
fn sponsored_reopen_needs_both_the_pull_write_scope_and_launch_ceiling_and_recovers_its_original_actor()
 {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let mut administrator = NodeTools::open(fixture.options.clone()).unwrap();
        committed(
            &administrator
                .call(OPEN, &command(&fixture, "0", "sponsored-open"))
                .unwrap(),
        );
        committed(
            &administrator
                .call(CLOSE, &command(&fixture, "1", "sponsored-close"))
                .unwrap(),
        );
        let writer_id = issue(
            &administrator.node,
            &token(0x61),
            grant(&administrator.node, PULLS_WRITE),
            "issue-reopen-writer",
        );
        issue(
            &administrator.node,
            &token(0x62),
            grant(&administrator.node, PULLS_READ),
            "issue-reopen-reader",
        );
        administrator.close().unwrap();

        let mut reopening = command(&fixture, "2", "sponsored-reopen");
        reopening.insert("title".into(), text("Agent resumes review"));
        reopening.insert(
            "body".into(),
            text("Revised literal content; this is not an approval."),
        );
        let mut reader = NodeTools::open(fixture.replacement(0x62)).unwrap();
        assert!(reader.tools().iter().any(|tool| tool.name == REOPEN));
        assert_eq!(
            reader.call(REOPEN, &reopening).unwrap_err().code,
            "agent_operation_not_granted"
        );
        assert!(reader.agent.as_ref().unwrap().request.is_none());
        reader.close().unwrap();

        let mut narrow = fixture.options.clone();
        narrow.writes.pulls = false;
        let mut no_ceiling = NodeTools::open(narrow).unwrap();
        assert!(!no_ceiling.tools().iter().any(|tool| tool.name == REOPEN));
        assert_eq!(
            no_ceiling.call(REOPEN, &reopening).unwrap_err().code,
            "tool_not_granted"
        );
        no_ceiling.close().unwrap();

        let mut writer_options = fixture.replacement(0x61);
        writer_options.issues = false;
        writer_options.discussions = false;
        writer_options.pulls = false;
        writer_options.outcomes = false;
        writer_options.writes.issues = false;
        writer_options.writes.discussions = false;
        let mut writer = NodeTools::open(writer_options).unwrap();
        assert_eq!(writer.tools().len(), 6);
        assert!(
            writer
                .tools()
                .iter()
                .all(|tool| writer.is_mutation(tool.name))
        );
        let mut injected = reopening.clone();
        injected.insert("principal".into(), text(SPONSOR.to_string()));
        assert_eq!(
            writer.call(REOPEN, &injected).unwrap_err().code,
            "unknown_argument"
        );
        let first = writer.call(REOPEN, &reopening).unwrap();
        committed(&first);
        assert_eq!(first.object().unwrap()["action"].text(), Some("reopen"));
        assert_eq!(first.object().unwrap()["refs_changed"], Value::Bool(false));
        assert_eq!(writer.call(REOPEN, &reopening).unwrap(), first);
        let original = provenance(&writer, "sponsored-reopen");
        assert_eq!(original.principal_id(), AGENT);
        assert_eq!(
            original.agent_provenance().unwrap().credential_id(),
            writer_id
        );
        assert!(writer.agent.as_ref().unwrap().request.is_none());
        assert_eq!(
            writer
                .call("frankengit_pull_show", &Object::new())
                .unwrap_err()
                .code,
            "tool_not_granted"
        );
        assert_eq!(
            writer
                .call("frankengit_pull_merge", &reopening)
                .unwrap_err()
                .code,
            "tool_not_granted"
        );

        // Revocation gates even a terminal retry. Rotation retains the original
        // authenticated author and sponsor evidence instead of replacing it.
        revoke(&writer.node, writer_id, "revoke-reopen-writer");
        assert_eq!(
            writer.call(REOPEN, &reopening).unwrap_err().code,
            "agent_credential_unavailable"
        );
        let replacement_id = issue(
            &writer.node,
            &token(0x63),
            grant(&writer.node, PULLS_WRITE),
            "issue-reopen-replacement",
        );
        writer.close().unwrap();
        let mut replacement = NodeTools::open(fixture.replacement(0x63)).unwrap();
        assert_eq!(replacement.call(REOPEN, &reopening).unwrap(), first);
        assert_eq!(provenance(&replacement, "sponsored-reopen"), original);
        assert_ne!(
            original.agent_provenance().unwrap().credential_id(),
            replacement_id
        );
        // Selecting a read ceiling does not add reads to this write-only grant.
        assert_eq!(
            replacement
                .call(
                    "frankengit_pull_show",
                    object([("number", text("7"))]).object().unwrap()
                )
                .unwrap_err()
                .code,
            "agent_operation_not_granted"
        );
        replacement.close().unwrap();
    }
}
