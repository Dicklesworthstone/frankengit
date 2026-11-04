//! Real persisted history, native bundles and publication through MCP dispatch.
//! These fixtures exercise the source lease separately from the onto prerequisite.
mod support;

use super::super::super::super::protocol::ReadTools;
use super::*;
use support::*;

#[test]
fn complete_series_publishes_with_write_only_grant_and_recovers_after_movement_and_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut fixture = Fixture::new(format);
        assert!(!fixture.backend().options.source);
        assert!(
            fixture
                .backend()
                .tools()
                .iter()
                .any(|tool| tool.name == NAME)
        );
        assert!(fixture.backend().is_mutation(NAME));
        let prepared = fixture.prepare(false);
        assert_eq!(prepared.rewritten.len(), 2);
        for commit in &prepared.rewritten {
            fixture.assert_private(*commit);
        }
        let original = fixture.args(prepared.candidate, &prepared.bundle, "publish-series");
        let before = fixture.state();
        let reply = fixture.protocol_call(original.clone());
        let receipt = content(&reply, false);
        assert_eq!(receipt["type"].text(), Some("source_publication"));
        assert_eq!(receipt["action"].text(), Some("publish_rebase"));
        assert_eq!(
            receipt["publication_profile"].text(),
            Some("linear-rebase-v1")
        );
        assert_eq!(receipt["outcome"].text(), Some("committed"));
        assert_eq!(receipt["terminal"], Value::Bool(true));
        assert_eq!(receipt["command_committed"], Value::Bool(true));
        assert_eq!(receipt["ref_transaction_committed"], Value::Bool(true));
        assert_eq!(receipt["atomic"], Value::Bool(true));
        assert_eq!(receipt["complete"], Value::Bool(true));
        assert_eq!(receipt["historical_outcome"], Value::Bool(true));
        assert_eq!(receipt["current_refs_asserted"], Value::Bool(false));
        assert_eq!(receipt["outcome_unknown"], Value::Bool(false));
        assert_eq!(receipt["bundle_validation_receipt"], Value::Null);
        assert_eq!(receipt["replay_equivalence_verified"], Value::Bool(false));
        assert_eq!(
            receipt["submitted_onto"].text(),
            Some(fixture.onto.to_string().as_str())
        );
        assert_eq!(
            receipt["principal_id"].text(),
            Some(actor().to_string().as_str())
        );
        assert_eq!(receipt["object_format"].text(), Some(format.as_str()));
        assert_eq!(
            receipt["submitted_commands"],
            Value::Array(vec![object([
                ("reference_hex", text(hex(fixture.source_ref.as_bytes()))),
                ("expected_old", text(fixture.source.to_string())),
                ("proposed_new", text(prepared.candidate.to_string())),
                ("force", Value::Bool(false)),
            ])])
        );
        let committed = fixture.state();
        assert_ne!(committed.head, before.head);
        let mut expected_refs = before.refs;
        expected_refs.insert(fixture.source_ref.clone(), prepared.candidate);
        assert_eq!(committed.refs, expected_refs);
        for commit in &prepared.rewritten {
            fixture.backend().node.read_git_object(*commit).unwrap();
        }
        assert_eq!(fixture.protocol_call(original.clone()), reply);
        assert_eq!(fixture.state(), committed);

        // A later successful publication makes every original source pin stale.
        // The original key must still recover exactly the original terminal fact.
        let advanced = fixture.advance(prepared.candidate, "after.txt", b"after-publication");
        let moved = fixture.state();
        assert_eq!(moved.refs[&fixture.source_ref], advanced);
        assert_ne!(moved.head, committed.head);
        let options = fixture.backend().options.clone();
        fixture.reopen(options);
        assert_eq!(fixture.protocol_call(original.clone()), reply);
        assert_eq!(fixture.state(), moved);
        let mut new_attempt = original;
        new_attempt.insert("idempotency_key".into(), text("new-key-stale-source"));
        let refused = fixture.protocol_call(new_attempt);
        let refused = content(&refused, true);
        assert_eq!(
            refused["refusal_code"].text(),
            Some("ExpectedOldRefMismatch")
        );
        assert_ne!(refused["tx_id"], receipt["tx_id"]);
        assert_eq!(fixture.state().refs, moved.refs);
        fixture.assert_staging_empty();
    }
}

#[test]
fn stale_source_lease_has_one_recoverable_refusal_and_does_not_place_the_candidate() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut fixture = Fixture::new(format);
        let prepared = fixture.prepare(false);
        let stale = fixture.args(prepared.candidate, &prepared.bundle, "stale-source");
        let advanced = fixture.advance(fixture.source, "advanced.txt", b"advance-source");
        let moved = fixture.state();
        let reply = fixture.protocol_call(stale.clone());
        let receipt = content(&reply, true);
        assert_eq!(receipt["outcome"].text(), Some("refused"));
        assert_eq!(
            receipt["refusal_code"].text(),
            Some("ExpectedOldRefMismatch")
        );
        assert_eq!(receipt["terminal"], Value::Bool(true));
        assert_eq!(receipt["command_committed"], Value::Bool(false));
        assert_eq!(receipt["ref_transaction_committed"], Value::Bool(false));
        assert_eq!(receipt["outcome_unknown"], Value::Bool(false));
        assert_eq!(fixture.state().refs, moved.refs);
        let refused = fixture.state();
        assert_eq!(fixture.protocol_call(stale), reply);
        assert_eq!(fixture.state(), refused);
        for commit in &prepared.rewritten {
            fixture.assert_private(*commit);
        }
        fixture.assert_staging_empty();

        // Re-selecting the actual source with a fresh complete native series is
        // the permitted twin. A fresh key alone must not fix an obsolete lease.
        fixture.source = advanced;
        let fresh = fixture.prepare(false);
        assert_eq!(fresh.rewritten.len(), 3);
        let args = fixture.args(fresh.candidate, &fresh.bundle, "current-source");
        let accepted = fixture.protocol_call(args);
        assert_eq!(
            content(&accepted, false)["outcome"].text(),
            Some("committed")
        );
        assert_eq!(fixture.state().refs[&fixture.source_ref], fresh.candidate);
    }
}

#[test]
fn malformed_bindings_corrupt_bytes_and_non_linear_history_publish_nothing() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut fixture = Fixture::new(format);
        let prepared = fixture.prepare(false);
        let before = fixture.state();
        let mut corrupted = prepared.bundle.clone();
        *corrupted.last_mut().unwrap() ^= 1;
        let mut cases = vec![fixture.args(prepared.candidate, &corrupted, "bad-checksum")];
        let mut wrong_candidate =
            fixture.args(prepared.candidate, &prepared.bundle, "bad-candidate");
        wrong_candidate.insert(
            "expected_candidate".into(),
            text(fixture.source.to_string()),
        );
        cases.push(wrong_candidate);
        let mut wrong_onto = fixture.args(prepared.candidate, &prepared.bundle, "bad-onto");
        wrong_onto.insert("onto".into(), text(fixture.base.to_string()));
        cases.push(wrong_onto);
        let mut wrong_branch = fixture.args(prepared.candidate, &prepared.bundle, "bad-branch");
        wrong_branch.remove("reference");
        wrong_branch.insert(
            "reference_hex".into(),
            text(hex(fixture.onto_ref.as_bytes())),
        );
        cases.push(wrong_branch);
        for args in cases {
            let error = fixture.backend_mut().call(NAME, &args).unwrap_err();
            assert_eq!(error.code, "source_mutation_outcome_unknown");
            assert!(!error.invalid);
            assert_eq!(fixture.state(), before);
            fixture.assert_staging_empty();
        }

        let (nonlinear, bundle) = fixture.non_linear_bundle();
        let node = &fixture.backend().node;
        let error = node
            .runtime()
            .block_on(node.apply_rebase_bundle_durable_in(
                &node.request_context(),
                actor(),
                b"native-nonlinear-check",
                &fixture.source_ref,
                fixture.source,
                fixture.onto,
                nonlinear,
                &bundle,
            ))
            .unwrap_err();
        assert!(matches!(
            error,
            fgit_node::NodeWorkspaceRefusal::InvalidWorkspaceCandidate(
                "rebase publication accepts only a single-parent series"
            )
        ));
        let args = fixture.args(nonlinear, &bundle, "nonlinear-mcp");
        let error = fixture.backend_mut().call(NAME, &args).unwrap_err();
        assert_eq!(error.code, "source_mutation_outcome_unknown");
        assert_eq!(fixture.state(), before);
        fixture.assert_private(nonlinear);
        for commit in &prepared.rewritten {
            fixture.assert_private(*commit);
        }
        fixture.assert_staging_empty();

        // The same native node and ordinary source-write grant accept the
        // complete linear artifact after all hostile envelopes were discarded.
        let args = fixture.args(prepared.candidate, &prepared.bundle, "linear-twin");
        let accepted = fixture.protocol_call(args);
        assert_eq!(
            content(&accepted, false)["outcome"].text(),
            Some("committed")
        );
        assert_eq!(
            fixture.state().refs[&fixture.source_ref],
            prepared.candidate
        );
        fixture.assert_private(nonlinear);
    }
}

#[test]
fn zero_commit_rebase_can_publish_onto_without_relaxing_the_single_commit_publisher() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut fixture = Fixture::new(format);
        let prepared = fixture.prepare(true);
        assert!(prepared.rewritten.is_empty());
        assert_eq!(prepared.candidate, fixture.onto);
        assert_ne!(prepared.candidate, fixture.source);
        let before = fixture.state();
        let mut legacy = fixture.args(prepared.candidate, &prepared.bundle, "wrong-profile");
        legacy.remove("expected_source");
        legacy.remove("onto");
        legacy.insert("expected_base".into(), text(fixture.source.to_string()));
        assert_eq!(
            fixture
                .backend_mut()
                .call(super::super::PUBLISH, &legacy)
                .unwrap_err()
                .code,
            "source_mutation_outcome_unknown"
        );
        assert_eq!(fixture.state(), before);
        let args = fixture.args(prepared.candidate, &prepared.bundle, "zero-series");
        let reply = fixture.protocol_call(args.clone());
        assert_eq!(content(&reply, false)["outcome"].text(), Some("committed"));
        let published = fixture.state();
        let mut expected_refs = before.refs;
        expected_refs.insert(fixture.source_ref.clone(), fixture.onto);
        assert_eq!(published.refs, expected_refs);
        assert_eq!(fixture.protocol_call(args), reply);
        assert_eq!(fixture.state(), published);
        fixture.assert_staging_empty();
    }
}

#[test]
fn read_only_and_sponsored_profiles_cannot_reach_operator_rebase_publication() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut fixture = Fixture::new(format);
        let prepared = fixture.prepare(false);
        let args = fixture.args(prepared.candidate, &prepared.bundle, "grant-twin");
        let original = fixture.backend().options.clone();
        let before = fixture.state();
        let hostile = Object::new();
        fixture.backend_mut().options.source = true;
        fixture.backend_mut().options.writes.source = false;
        fixture.backend_mut().options.principal = None;
        assert!(
            fixture
                .backend()
                .tools()
                .iter()
                .all(|tool| tool.name != NAME)
        );
        assert_eq!(
            fixture.backend_mut().call(NAME, &hostile).unwrap_err().code,
            "tool_not_granted"
        );
        assert_eq!(
            super::call(fixture.backend(), &hostile).unwrap_err().code,
            "tool_not_granted"
        );
        fixture.backend_mut().options.writes.source = true;
        fixture.backend_mut().options.principal = Some(actor());
        fixture.backend_mut().options.agent_token_file =
            Some(std::path::PathBuf::from("must-not-open"));
        assert!(
            fixture
                .backend()
                .tools()
                .iter()
                .all(|tool| tool.name != NAME)
        );
        assert_eq!(
            fixture.backend_mut().call(NAME, &hostile).unwrap_err().code,
            "tool_not_granted"
        );
        assert_eq!(
            super::call(fixture.backend(), &hostile).unwrap_err().code,
            "tool_not_granted"
        );
        assert_eq!(fixture.state(), before);
        fixture.backend_mut().options = original;
        let reply = fixture.protocol_call(args);
        assert_eq!(content(&reply, false)["outcome"].text(), Some("committed"));
        assert_eq!(
            fixture.state().refs[&fixture.source_ref],
            prepared.candidate
        );
    }
}
