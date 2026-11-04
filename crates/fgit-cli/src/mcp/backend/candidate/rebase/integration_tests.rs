//! Whole-series MCP preparation, explicit resolution and independent inspection
//! over actual persisted native histories in both object formats.
use super::*;
mod support;
use support::*;

fn rows<'a>(value: &'a Object, name: &str) -> &'a [Value] {
    let Value::Array(rows) = &value[name] else {
        panic!("array required: {name}")
    };
    rows
}
fn stopped(value: &Object, state: &str) {
    assert_eq!(value["state"].text(), Some(state));
    for name in [
        "complete",
        "series_complete",
        "candidate_available",
        "objects_staged",
        "transaction_created",
        "published",
    ] {
        assert_eq!(value[name], Value::Bool(false), "{name}");
    }
    for name in [
        "candidate_commit",
        "root_tree",
        "bundle_sha256",
        "inspection_arguments",
        "publication_arguments",
    ] {
        assert_eq!(value[name], Value::Null, "{name}");
    }
    assert_eq!(value["provisional_steps"], Value::Bool(true));
    assert_eq!(value["bundle_bytes"].text(), Some("0"));
    assert_eq!(value["pack_objects"].text(), Some("0"));
}

#[test]
fn whole_native_series_has_exact_review_handoff_without_staging_or_authority_change() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut fixture = Fixture::new(format, History::Clean);
        let before = fixture.head();
        let args = fixture.args();
        let response = fixture.protocol_call(args.clone());
        let prepared = content(&response);
        assert_eq!(prepared["state"].text(), Some("clean"));
        assert_eq!(prepared["complete"], Value::Bool(true));
        assert_eq!(prepared["step_count"].text(), Some("2"));
        assert_eq!(
            prepared["reference_hex"].text(),
            Some(hex(b"refs/heads/topic-\xff").as_str())
        );
        assert_eq!(
            prepared["snapshot_token"].text(),
            Some(head_token(before.0).as_str())
        );
        assert_eq!(
            prepared["expected_source"].text(),
            Some(raw_oid(fixture.source_tip).as_str())
        );
        let mappings = rows(prepared, "steps");
        assert_eq!(
            mappings[0].object().unwrap()["original"].text(),
            Some(raw_oid(fixture.first).as_str())
        );
        assert_eq!(
            mappings[1].object().unwrap()["original"].text(),
            Some(raw_oid(fixture.source_tip).as_str())
        );
        for name in [
            "objects_staged",
            "transaction_created",
            "published",
            "approval_granted",
            "inspection_performed",
            "publication_authorized",
        ] {
            assert_eq!(prepared[name], Value::Bool(false), "{name}");
        }
        assert_eq!(fixture.call(&args).unwrap().object().unwrap(), prepared);
        let inspection = prepared["inspection_arguments"].object().unwrap().clone();
        let inspected_response = fixture.protocol_call(inspection.clone());
        let inspected = content(&inspected_response);
        assert_eq!(inspected["type"].text(), Some("source_rebase_inspection"));
        assert_eq!(inspected["bundle_sha256"], prepared["bundle_sha256"]);
        assert_eq!(inspected["commit_count"].text(), Some("2"));
        assert_eq!(inspected["replay_equivalence_verified"], Value::Bool(false));
        assert_eq!(
            inspected["completion_scope"].text(),
            Some("entire_rebase_series_and_net_tree")
        );
        let mut parent = raw_oid(fixture.onto_tip);
        for (index, commit) in rows(inspected, "commits").iter().enumerate() {
            let commit = commit.object().unwrap();
            assert_eq!(commit["parent"].text(), Some(parent.as_str()));
            let body = unhex(commit["body_hex"].text().unwrap(), 128 * 1024).unwrap();
            let body = std::str::from_utf8(&body).unwrap();
            assert!(body.contains("\nauthor Original <original@example.invalid> 1 +0000\n"));
            assert!(body.contains("\ncommitter Rebaser <rebaser@example.invalid> 2 +0000\n"));
            assert!(body.ends_with(if index == 0 {
                "first original\r\n"
            } else {
                "second original\n"
            }));
            let diff = commit["diff"].object().unwrap();
            assert_eq!(diff["entry_count"].text(), Some("1"));
            let expected_path: &[u8] = if index == 0 {
                b"first-file"
            } else {
                b"second-file"
            };
            assert_eq!(
                rows(diff, "entries")[0].object().unwrap()["path_hex"].text(),
                Some(hex(expected_path).as_str())
            );
            let id = GitOid::from_hex(format, commit["commit"].text().unwrap()).unwrap();
            assert!(
                fixture.backend().node.read_git_object(id).is_err(),
                "inspection must not stage commits"
            );
            parent = raw_oid(id);
        }
        assert_eq!(Some(parent.as_str()), prepared["candidate_commit"].text());
        let net = inspected["net_change"].object().unwrap();
        assert_eq!(net["entry_count"].text(), Some("1"));
        assert_eq!(
            rows(net, "entries")[0].object().unwrap()["path_hex"].text(),
            Some(hex(b"onto-only").as_str())
        );
        let publication = prepared["publication_arguments"].object().unwrap();
        assert_eq!(prepared["publication_tool"].text(), Some(PUBLICATION_TOOL));
        assert_eq!(
            inspected["publication_arguments"].object().unwrap(),
            publication
        );
        assert_eq!(publication["expected_source"], prepared["expected_source"]);
        assert_eq!(publication["onto"], prepared["onto"]);
        assert!(!publication.contains_key("idempotency_key"));
        assert!(!publication.contains_key("expected_head"));
        assert_eq!(fixture.head(), before);
    }
}

#[test]
fn inspected_mcp_handoff_publishes_and_original_key_recovers_after_later_source_advance() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut fixture = Fixture::new(format, History::Clean);
        let before = fixture.head();
        let initial_refs = fixture.refs();
        let args = fixture.args();
        let prepared = fixture.protocol_call(args);
        let prepared = content(&prepared);
        assert_eq!(prepared["state"].text(), Some("clean"));
        let candidate =
            GitOid::from_hex(format, prepared["candidate_commit"].text().unwrap()).unwrap();
        let inspection_args = prepared["inspection_arguments"].object().unwrap().clone();
        let inspected = fixture.protocol_call(inspection_args.clone());
        let inspected = content(&inspected);
        assert_eq!(inspected["complete"], Value::Bool(true));
        assert_eq!(inspected["commit_count"].text(), Some("2"));
        assert_eq!(inspected["bundle_sha256"], prepared["bundle_sha256"]);
        assert_eq!(
            inspected["publication_arguments"],
            prepared["publication_arguments"]
        );
        let mut publication = inspected["publication_arguments"].object().unwrap().clone();
        assert!(!publication.contains_key("expected_head"));
        assert!(!publication.contains_key("idempotency_key"));
        publication.insert(
            "idempotency_key".into(),
            text("original-inspected-rebase-publication"),
        );
        assert_eq!(
            fixture
                .call_tool(PUBLICATION_TOOL, &publication)
                .unwrap_err()
                .code,
            "tool_not_granted"
        );
        assert_eq!(fixture.head(), before);
        assert_eq!(fixture.refs(), initial_refs);

        fixture.allow_publication();
        let committed = fixture.protocol_tool_call(PUBLICATION_TOOL, publication.clone());
        let committed = content(&committed).clone();
        assert_eq!(committed["type"].text(), Some("source_publication"));
        assert_eq!(committed["action"].text(), Some("publish_rebase"));
        assert_eq!(
            committed["publication_profile"].text(),
            Some("linear-rebase-v1")
        );
        assert_eq!(committed["outcome"].text(), Some("committed"));
        assert_eq!(committed["terminal"], Value::Bool(true));
        assert_eq!(committed["ref_transaction_committed"], Value::Bool(true));
        assert_eq!(committed["bundle_validation_receipt"], Value::Null);
        assert_eq!(
            committed["submitted_onto"].text(),
            Some(raw_oid(fixture.onto_tip).as_str())
        );
        let mut expected_refs = initial_refs;
        expected_refs.insert(fixture.source.clone(), candidate);
        assert_eq!(
            fixture.refs(),
            expected_refs,
            "only the leased source branch may move"
        );
        for row in rows(inspected, "commits") {
            let id =
                GitOid::from_hex(format, row.object().unwrap()["commit"].text().unwrap()).unwrap();
            fixture.backend().node.read_git_object(id).unwrap();
        }

        // Advance through the existing MCP patch/publish handoff. The original
        // rebase command then has obsolete source and snapshot coordinates.
        let later = fixture.protocol_call(fields([
            ("operation", text("prepare_patch")),
            ("reference_hex", text(hex(fixture.source.as_bytes()))),
            ("expected_base", text(raw_oid(candidate))),
            ("patch", text("diff --git a/after-rebase b/after-rebase\nnew file mode 100644\n--- /dev/null\n+++ b/after-rebase\n@@ -0,0 +1 @@\n+must survive historical retry\n")),
            ("author", text("Later <later@example.invalid>")),
            ("committer", text("Later <later@example.invalid>")),
            ("timestamp", text("3")), ("message_hex", text(hex(b"later source work\n"))),
        ]));
        let later = content(&later);
        let later_tip =
            GitOid::from_hex(format, later["candidate_commit"].text().unwrap()).unwrap();
        let mut later_publication = later["publication_arguments"].object().unwrap().clone();
        later_publication.insert("idempotency_key".into(), text("later-source-after-rebase"));
        let advanced = fixture.protocol_tool_call("frankengit_source_publish", later_publication);
        assert_eq!(content(&advanced)["outcome"].text(), Some("committed"));
        expected_refs.insert(fixture.source.clone(), later_tip);
        assert_eq!(fixture.refs(), expected_refs);
        let advanced_head = fixture.head();
        let options = fixture.backend().options.clone();
        fixture.reopen(options);
        let recovered = fixture.protocol_tool_call(PUBLICATION_TOOL, publication);
        assert_eq!(
            content(&recovered),
            &committed,
            "recover the exact original terminal receipt"
        );
        assert_eq!(fixture.head(), advanced_head);
        assert_eq!(
            fixture.refs(),
            expected_refs,
            "historical retry must preserve later source work"
        );
        fixture.backend().node.read_git_object(later_tip).unwrap();
        assert_eq!(
            fixture.call(&inspection_args).unwrap_err().code,
            "source_snapshot_moved"
        );
    }
}

#[test]
fn original_bound_decisions_reconstruct_every_step_and_never_publish_a_successful_prefix() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut fixture = Fixture::new(format, History::Conflicted);
        let before = fixture.head();
        let mut args = fixture.args();
        let stop_prepared = fixture.call(&args).unwrap();
        let stop_prepared = stop_prepared.object().unwrap();
        stopped(stop_prepared, "conflicted");
        let stop_resolution = fixture.resolve(stop_prepared, vec![recipe(fixture.first, "ours")]);
        let empty = fixture.call(&stop_resolution).unwrap();
        let empty = empty.object().unwrap();
        stopped(empty, "became_empty");
        assert_eq!(
            empty["stopped_commit"].text(),
            Some(raw_oid(fixture.first).as_str())
        );
        assert_eq!(empty["step_count"].text(), Some("0"));
        assert!(rows(empty, "steps").is_empty());
        assert_eq!(empty["resolution_consumed_commits"].text(), Some("1"));
        let receipt = rows(empty, "resolutions")[0].object().unwrap();
        assert_eq!(
            receipt["original"].text(),
            Some(raw_oid(fixture.first).as_str())
        );
        let path = rows(receipt, "paths")[0].object().unwrap();
        assert_eq!(path["choice"].text(), Some("ours"));
        assert_eq!(path["conflict"], rows(stop_prepared, "conflicts")[0]);
        assert_eq!(path["result"], path["conflict"].object().unwrap()["ours"]);
        assert_eq!(fixture.head(), before);

        args.insert("empty".into(), text("keep"));
        let prepared = fixture.call(&args).unwrap();
        let prepared = prepared.object().unwrap();
        stopped(prepared, "conflicted");
        assert_eq!(
            prepared["stopped_commit"].text(),
            Some(raw_oid(fixture.first).as_str())
        );
        assert_eq!(
            rows(prepared, "conflicts")[0].object().unwrap()["path_hex"].text(),
            Some(hex(b"README").as_str())
        );

        let first = fixture.resolve(prepared, vec![recipe(fixture.first, "ours")]);
        let partial = fixture.call(&first).unwrap();
        let partial = partial.object().unwrap();
        stopped(partial, "conflicted");
        assert_eq!(
            partial["stopped_commit"].text(),
            Some(raw_oid(fixture.source_tip).as_str())
        );
        assert_eq!(partial["step_count"].text(), Some("1"));
        assert_eq!(partial["resolution_consumed_commits"].text(), Some("1"));
        let temporary = GitOid::from_hex(
            format,
            rows(partial, "steps")[0].object().unwrap()["rewritten"]
                .text()
                .unwrap(),
        )
        .unwrap();
        assert!(fixture.backend().node.read_git_object(temporary).is_err());

        // Input order is immaterial; decisions are keyed by original identities
        // and their receipts follow the actual chronological reconstruction.
        let complete = fixture.resolve(
            prepared,
            vec![
                recipe(fixture.source_tip, "theirs"),
                recipe(fixture.first, "ours"),
            ],
        );
        let resolved = fixture.call(&complete).unwrap();
        let resolved = resolved.object().unwrap();
        assert_eq!(resolved["state"].text(), Some("clean"));
        assert_eq!(resolved["series_complete"], Value::Bool(true));
        assert_eq!(resolved["step_count"].text(), Some("2"));
        assert_eq!(resolved["resolution_consumed_commits"].text(), Some("2"));
        assert_eq!(
            rows(resolved, "resolutions")[0].object().unwrap()["original"].text(),
            Some(raw_oid(fixture.first).as_str())
        );
        let inspect = resolved["inspection_arguments"].object().unwrap().clone();
        let inspected = fixture.call(&inspect).unwrap();
        assert_eq!(
            inspected.object().unwrap()["commit_count"].text(),
            Some("2")
        );
        let bad = fixture.resolve(prepared, vec![recipe(temporary, "theirs")]);
        assert_eq!(
            fixture.call(&bad).unwrap_err().code,
            "resolution_outside_suffix"
        );
        let mut stale = complete;
        stale.insert("expected_head".into(), text(head_token(fixture.genesis)));
        assert_eq!(
            fixture.call(&stale).unwrap_err().code,
            "source_snapshot_moved"
        );
        assert_eq!(fixture.head(), before);
    }
}

#[test]
fn explicit_empty_policy_distinguishes_stop_drop_keep_and_empty_suffix() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut fixture = Fixture::new(format, History::BecomesEmpty);
        let before = fixture.head();
        let mut args = fixture.args();
        let result = fixture.call(&args).unwrap();
        stopped(result.object().unwrap(), "became_empty");
        for (policy, count) in [("drop", "0"), ("keep", "1")] {
            args.insert("empty".into(), text(policy));
            let result = fixture.call(&args).unwrap();
            let result = result.object().unwrap();
            assert_eq!(result["state"].text(), Some("clean"));
            let inspection = result["inspection_arguments"].object().unwrap().clone();
            let inspected = fixture.call(&inspection).unwrap();
            assert_eq!(
                inspected.object().unwrap()["commit_count"].text(),
                Some(count)
            );
            if policy == "drop" {
                assert_eq!(
                    result["candidate_commit"].text(),
                    Some(raw_oid(fixture.onto_tip).as_str())
                );
                assert_eq!(
                    rows(result, "steps")[0].object().unwrap()["kind"].text(),
                    Some("dropped_empty")
                );
                assert_eq!(result["pack_objects"].text(), Some("0"));
            }
        }
        args.insert("upstream".into(), text(raw_oid(fixture.source_tip)));
        let result = fixture.call(&args).unwrap();
        let result = result.object().unwrap();
        assert_eq!(result["step_count"].text(), Some("0"));
        let inspection = result["inspection_arguments"].object().unwrap().clone();
        let inspected = fixture.call(&inspection).unwrap();
        assert_eq!(
            inspected.object().unwrap()["commit_count"].text(),
            Some("0")
        );
        assert_eq!(fixture.head(), before);
    }
}

#[test]
fn snapshot_tip_budget_integrity_and_capability_refusals_leave_source_unchanged() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut fixture = Fixture::new(format, History::Clean);
        let before = fixture.head();
        let args = fixture.args();
        for (name, value, code) in [
            (
                "expected_head",
                text(head_token(fixture.genesis)),
                "source_snapshot_moved",
            ),
            (
                "expected_source",
                text(raw_oid(fixture.base)),
                "rebase_tip_moved",
            ),
            (
                "expected_onto",
                text(raw_oid(fixture.base)),
                "rebase_tip_moved",
            ),
            (
                "upstream",
                text(raw_oid(fixture.onto_tip)),
                "upstream_outside_linear_history",
            ),
            ("max_commits", json::number(1), "resource_limit"),
        ] {
            let mut bad = args.clone();
            bad.insert(name.into(), value);
            assert_eq!(fixture.call(&bad).unwrap_err().code, code, "{name}");
        }
        let prepared = fixture.call(&args).unwrap();
        let inspection = prepared.object().unwrap()["inspection_arguments"]
            .object()
            .unwrap()
            .clone();
        let mut bad = inspection.clone();
        bad.insert("expected_bundle_sha256".into(), text("00".repeat(32)));
        assert_eq!(
            fixture.call(&bad).unwrap_err().code,
            "bundle_digest_mismatch"
        );
        let mut bad = inspection.clone();
        bad.insert("max_changes".into(), json::number(1));
        assert_eq!(fixture.call(&bad).unwrap_err().code, "resource_limit");
        let mut bad = inspection.clone();
        bad.insert("expected_candidate".into(), text(raw_oid(fixture.base)));
        assert_eq!(
            fixture.call(&bad).unwrap_err().code,
            "invalid_rebase_candidate"
        );
        let mut bad = inspection;
        let mut bytes = chunks(&bad, "bundle_hex_chunks").unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        bad.insert("bundle_hex_chunks".into(), encoded_chunks(&bytes).unwrap());
        bad.remove("expected_bundle_sha256");
        assert!(fixture.call(&bad).is_err());
        fixture.backend_mut().options.source = false;
        assert_eq!(
            super::call(fixture.backend(), &args).unwrap_err().code,
            "tool_not_granted"
        );
        fixture.backend_mut().options.source = true;
        fixture.backend_mut().options.agent_token_file =
            Some(std::path::PathBuf::from("must-not-be-read"));
        assert_eq!(
            super::call(fixture.backend(), &args).unwrap_err().code,
            "tool_not_granted"
        );
        fixture.backend_mut().options.agent_token_file = None;
        assert_eq!(fixture.head(), before);
    }
}
