//! Retarget uses the existing sponsored PR-write grant and principal binding.
use super::super::super::pull_writes::{OPEN, RETARGET};
use super::*;
use fgit_authority::{ExpectedOld, ProposedNew, RefCommand};
use fgit_types::RefName;

#[test]
fn sponsored_retarget_requires_write_scope_and_keeps_original_authenticated_actor() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let mut administrator = NodeTools::open(fixture.options.clone()).unwrap();
        let node = &administrator.node;
        let result = node
            .runtime()
            .block_on(node.admit_branch_updates_durable_in(
                &node.request_context(),
                &operator(SPONSOR, "retarget-release"),
                &[RefCommand {
                    name: RefName::try_new(b"refs/heads/release").unwrap(),
                    expected_old: ExpectedOld::Absent,
                    proposed_new: ProposedNew::Update(fixture.tip),
                    force: false,
                }],
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            result.commands[0].terminal.outcome,
            fgit_types::DecisionOutcome::Committed { .. }
        ));
        let writer = issue(
            node,
            &token(0x65),
            grant(node, PULLS_WRITE),
            "retarget-writer",
        );
        issue(
            node,
            &token(0x66),
            grant(node, PULLS_READ),
            "retarget-reader",
        );
        committed(
            &administrator
                .call(OPEN, &pull_opening(&fixture, 7, "retarget-open"))
                .unwrap(),
        );
        administrator.close().unwrap();
        let mut input = pull_opening(&fixture, 7, "retarget-original");
        input.insert("expected_version".into(), text("1"));
        input.insert("target_reference".into(), text("refs/heads/release"));
        let mut reader = NodeTools::open(fixture.replacement(0x66)).unwrap();
        assert_eq!(
            reader.call(RETARGET, &input).unwrap_err().code,
            "agent_operation_not_granted"
        );
        reader.close().unwrap();
        let mut no_write = fixture.replacement(0x65);
        no_write.writes.pulls = false;
        let mut no_write = NodeTools::open(no_write).unwrap();
        assert_eq!(
            no_write.call(RETARGET, &input).unwrap_err().code,
            "tool_not_granted"
        );
        no_write.close().unwrap();
        let mut agent = NodeTools::open(fixture.replacement(0x65)).unwrap();
        let first = agent.call(RETARGET, &input).unwrap();
        committed(&first);
        assert_eq!(first.object().unwrap()["action"].text(), Some("retarget"));
        assert_eq!(agent.call(RETARGET, &input).unwrap(), first);
        let original = provenance(&agent, "retarget-original");
        assert_eq!(original.principal_id(), AGENT);
        assert_eq!(original.agent_provenance().unwrap().credential_id(), writer);
        agent.close().unwrap();
    }
}
