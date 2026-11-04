//! End-to-end MCP calls over real persisted native object and authority stores.
use super::*;
mod support;
use support::*;

#[test]
fn historical_pick_inspect_publish_reopen_and_original_key_retry_preserve_later_work() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, false);
        let before = f.head();
        let args = f.prepare_args();
        let response = f.protocol_call(NAME, args.clone());
        let prepared = content(&response);
        assert_eq!(prepared["state"].text(), Some("prepared"));
        assert_eq!(prepared["selected_commit"].text(), Some(raw_oid(f.selected).as_str()));
        assert_ne!(f.selected, f.source_tip, "fixture must exercise historical selection");
        assert_eq!(prepared["selected_parent"].text(), Some(raw_oid(f.base).as_str()));
        assert_eq!(prepared["selected_mainline"].unsigned(), Some(1));
        assert_eq!(prepared["source_reference_hex"].text(), Some(hex(b"refs/heads/topic-\xff").as_str()));
        assert!(prepared["borrowed_objects"].text().unwrap().parse::<usize>().unwrap() > 0);
        assert_eq!(prepared["parents"], Value::Array(vec![text(raw_oid(f.target))]));
        for name in ["published", "approval_granted", "objects_staged", "transaction_created"] {
            assert_eq!(prepared[name], Value::Bool(false));
        }
        assert_eq!(prepared["snapshot_token"].text(), Some(head_token(before.0).as_str()));
        let candidate = GitOid::from_hex(format, prepared["candidate_commit"].text().unwrap()).unwrap();
        assert!(f.backend().node.read_git_object(candidate).is_err());
        let body = prepared["candidate_commit_text_utf8"].text().unwrap();
        assert_eq!(body.lines().filter(|line| line.starts_with("parent ")).count(), 1);
        assert!(body.contains(&format!("\nparent {}\n", f.target)));
        assert!(body.ends_with("one selected historical change\r\n"));
        assert_eq!(f.call(NAME, &args).unwrap().object().unwrap(), prepared);
        let inspection = prepared["inspection_arguments"].object().unwrap().clone();
        let inspected = f.call(NAME, &inspection).unwrap();
        assert_eq!(inspected.object().unwrap()["bundle_sha256"], prepared["bundle_sha256"]);
        let review = inspected.object().unwrap()["review"].object().unwrap();
        assert_eq!(review["entry_count"].text(), Some("1"));
        assert_eq!(review["completion_scope"].text(), Some("entire_candidate_tree"));
        let Value::Array(entries) = &review["entries"] else { unreachable!() };
        assert_eq!(entries[0].object().unwrap()["path_hex"].text(), Some(hex(b"selected-file").as_str()));
        assert_eq!(f.head(), before);
        let mut publication = prepared["publication_arguments"].object().unwrap().clone();
        publication.insert("idempotency_key".into(), text("replay-original-publication"));
        assert_eq!(f.call("frankengit_source_publish", &publication).unwrap_err().code, "tool_not_granted");

        f.allow_publication();
        let committed = f.protocol_call("frankengit_source_publish", publication.clone());
        let committed = content(&committed).clone();
        assert_eq!(committed["outcome"].text(), Some("committed"));
        assert_eq!(f.blob(b"selected-file").unwrap().object().unwrap()["bytes_hex"].text(), Some(hex(b"selected\n").as_str()));
        assert_eq!(f.blob(b"target-only").unwrap().object().unwrap()["bytes_hex"].text(), Some(hex(b"target\n").as_str()));
        assert_eq!(f.blob(b"sibling").unwrap().object().unwrap()["bytes_hex"].text(), Some(hex(b"untouched\n").as_str()));
        assert!(f.blob(b"later-file").is_err(), "later source changes must not be replayed");
        let after = f.head();
        let options = f.options();
        f.reopen(options);
        let retry = f.protocol_call("frankengit_source_publish", publication.clone());
        assert_eq!(content(&retry), &committed);
        assert_eq!(f.head(), after);

        // Advance the destination after the original decision, then retry the
        // same command and key. Recovery must not reconstruct or roll back a ref.
        let advanced = f.call(NAME, &fields([
            ("operation", text("prepare_patch")),
            ("reference_hex", text(hex(f.reference.as_bytes()))),
            ("expected_base", text(raw_oid(candidate))),
            ("patch", text("diff --git a/README b/README\n--- a/README\n+++ b/README\n@@ -1 +1 @@\n-base\n+later target\n")),
            ("author", text("Later <later@example.invalid>")),
            ("committer", text("Later <later@example.invalid>")),
            ("timestamp", text("3")), ("message_hex", text(hex(b"later target\n"))),
        ])).unwrap();
        let mut later = advanced.object().unwrap()["publication_arguments"].object().unwrap().clone();
        later.insert("idempotency_key".into(), text("later-target-publication"));
        assert_eq!(f.call("frankengit_source_publish", &later).unwrap().object().unwrap()["outcome"].text(), Some("committed"));
        let newer = f.head();
        let options = f.options();
        f.reopen(options);
        assert_eq!(f.call("frankengit_source_publish", &publication).unwrap().object().unwrap(), &committed);
        assert_eq!(f.head(), newer);
        assert_eq!(f.blob(b"README").unwrap().object().unwrap()["bytes_hex"].text(), Some(hex(b"later target\n").as_str()));
        assert!(f.call(NAME, &inspection).is_err(), "old snapshot cannot inspect against a moved target");
    }
}

#[test]
fn exact_conflict_resolution_supports_binary_files_no_change_and_stale_snapshot_refusal() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, true);
        let before = f.head();
        let args = f.prepare_args();
        let prepared = f.call(NAME, &args).unwrap();
        let prepared = prepared.object().unwrap();
        assert_eq!(prepared["state"].text(), Some("conflicted"));
        assert_eq!(prepared["candidate_commit"], Value::Null);
        assert_eq!(prepared["publication_arguments"], Value::Null);
        let Value::Array(conflicts) = &prepared["conflicts"] else { unreachable!() };
        assert_eq!(conflicts.len(), 1);
        let conflict = conflicts[0].object().unwrap();
        assert_eq!(conflict["path_hex"].text(), Some(hex(b"README").as_str()));
        assert_ne!(conflict["ours"], conflict["theirs"]);

        let ours = f.resolve_args(prepared, vec![side(b"README", "ours")]);
        let same = f.call(NAME, &ours).unwrap();
        let same = same.object().unwrap();
        assert_eq!(same["state"].text(), Some("no_change"));
        assert_eq!(same["candidate_available"], Value::Bool(false));
        for name in ["candidate_commit", "root_tree", "inspection_arguments", "publication_arguments"] {
            assert_eq!(same[name], Value::Null);
        }
        let Value::Array(paths) = &same["resolved_paths"] else { unreachable!() };
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].object().unwrap()["choice"].text(), Some("ours"));
        assert_eq!(paths[0].object().unwrap()["conflict"], conflicts[0]);
        assert_eq!(f.head(), before);
        let mut stale = ours.clone();
        stale.insert("expected_head".into(), text(head_token(f.genesis)));
        assert_eq!(f.call(NAME, &stale).unwrap_err().code, "source_snapshot_moved");
        let mut absent = ours.clone();
        absent.remove("expected_head");
        assert_eq!(f.call(NAME, &absent).unwrap_err().code, "resolution_snapshot_required");
        let extra = f.resolve_args(prepared, vec![side(b"README", "ours"), side(b"sibling", "theirs")]);
        assert_eq!(f.call(NAME, &extra).unwrap_err().code, "resolution_path_is_not_a_conflict");

        let bytes = b"resolved\0\xff\r\n";
        let file = object([
            ("path_hex", text(hex(b"README"))), ("choice", text("file")),
            ("mode", text("100755")), ("bytes_hex_chunks", Value::Array(vec![text(hex(bytes))])),
        ]);
        let choices = f.resolve_args(prepared, vec![file]);
        let response = f.protocol_call(NAME, choices);
        let resolved = content(&response);
        assert_eq!(resolved["state"].text(), Some("resolved"));
        let inspected = f.call(NAME, resolved["inspection_arguments"].object().unwrap()).unwrap();
        assert_eq!(inspected.object().unwrap()["bundle_sha256"], resolved["bundle_sha256"]);
        assert_eq!(f.head(), before);
        f.allow_publication();
        let mut publication = resolved["publication_arguments"].object().unwrap().clone();
        publication.insert("idempotency_key".into(), text("binary-resolution"));
        assert_eq!(f.call("frankengit_source_publish", &publication).unwrap().object().unwrap()["outcome"].text(), Some("committed"));
        assert_eq!(f.blob(b"README").unwrap().object().unwrap()["bytes_hex"].text(), Some(hex(bytes).as_str()));
        assert_eq!(f.blob(b"sibling").unwrap().object().unwrap()["bytes_hex"].text(), Some(hex(b"untouched\n").as_str()));
        assert!(f.blob(b"later-file").is_err());
        assert_eq!(f.call(NAME, &ours).unwrap_err().code, "source_snapshot_moved");
    }
}

#[test]
fn same_branch_revert_appends_inverse_history_and_root_and_mainline_rules_remain_native() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, false);
        let before = f.head();
        let args = f.prepare_args();
        let mut root = args.clone();
        root.insert("selected_commit".into(), text(raw_oid(f.base)));
        let unchanged = f.call(NAME, &root).unwrap();
        assert_eq!(unchanged.object().unwrap()["state"].text(), Some("no_change"));
        assert_eq!(unchanged.object().unwrap()["selected_parent"], Value::Null);
        assert_eq!(unchanged.object().unwrap()["selected_mainline"], Value::Null);
        root.insert("mainline".into(), json::number(1));
        assert_eq!(f.call(NAME, &root).unwrap_err().code, "invalid_mainline");
        let mut invalid_parent = args.clone();
        invalid_parent.insert("mainline".into(), json::number(2));
        assert_eq!(f.call(NAME, &invalid_parent).unwrap_err().code, "invalid_mainline");
        let mut first_parent = args.clone();
        first_parent.insert("mainline".into(), json::number(1));
        assert_eq!(f.call(NAME, &first_parent).unwrap().object().unwrap()["selected_mainline"].unsigned(), Some(1));
        assert_eq!(f.head(), before);

        f.allow_publication();
        let prepared = f.call(NAME, &args).unwrap();
        let candidate = prepared.object().unwrap()["candidate_commit"].clone();
        let mut publication = prepared.object().unwrap()["publication_arguments"].object().unwrap().clone();
        publication.insert("idempotency_key".into(), text("pick-before-same-branch-revert"));
        assert_eq!(f.call("frankengit_source_publish", &publication).unwrap().object().unwrap()["outcome"].text(), Some("committed"));
        let mut revert = args;
        revert.insert("direction".into(), text("revert"));
        revert.insert("source_reference_hex".into(), text(hex(f.reference.as_bytes())));
        revert.insert("expected_base".into(), candidate.clone());
        revert.insert("expected_source".into(), candidate.clone());
        revert.insert("selected_commit".into(), candidate.clone());
        revert.insert("expected_head".into(), text(head_token(f.head().0)));
        revert.insert("timestamp".into(), text("3"));
        revert.insert("message_hex".into(), text(hex(b"undo without rewriting\n")));
        let reversed = f.call(NAME, &revert).unwrap();
        let reversed = reversed.object().unwrap();
        assert_eq!(reversed["state"].text(), Some("prepared"));
        assert_eq!(reversed["direction"].text(), Some("revert"));
        assert_eq!(reversed["parents"], Value::Array(vec![candidate]));
        assert_eq!(reversed["selected_parent"].text(), Some(raw_oid(f.target).as_str()));
        let inspection = reversed["inspection_arguments"].object().unwrap();
        assert!(f.call(NAME, inspection).is_ok());
        let mut publication = reversed["publication_arguments"].object().unwrap().clone();
        publication.insert("idempotency_key".into(), text("same-branch-revert"));
        assert_eq!(f.call("frankengit_source_publish", &publication).unwrap().object().unwrap()["outcome"].text(), Some("committed"));
        assert!(f.blob(b"selected-file").is_err());
        assert_eq!(f.blob(b"target-only").unwrap().object().unwrap()["bytes_hex"].text(), Some(hex(b"target\n").as_str()));
    }
}

#[test]
fn stale_or_outside_history_inputs_budget_exhaustion_and_absent_refs_never_return_candidates() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, false);
        let before = f.head();
        let args = f.prepare_args();
        for (name, value, code) in [
            ("expected_base", text(raw_oid(f.base)), "replay_tip_moved"),
            ("expected_source", text(raw_oid(f.selected)), "replay_tip_moved"),
            ("selected_commit", text(raw_oid(f.target)), "reference_unavailable"),
            ("source_reference_hex", text(hex(b"refs/heads/absent")), "reference_unavailable"),
            ("expected_head", text(head_token(f.genesis)), "source_snapshot_moved"),
            ("max_commits", json::number(1), "resource_limit"),
            ("max_preparation_bytes", json::number(1), "resource_limit"),
        ] {
            let mut bad = args.clone();
            bad.insert(name.into(), value);
            assert_eq!(f.call(NAME, &bad).unwrap_err().code, code, "{name}");
            assert_eq!(f.head(), before);
        }
        let prepared = f.call(NAME, &args).unwrap();
        let clean = f.resolve_args(prepared.object().unwrap(), vec![side(b"README", "ours")]);
        assert_eq!(f.call(NAME, &clean).unwrap_err().code, "no_conflicts_to_resolve");
        assert_eq!(f.head(), before);
    }
}

#[test]
fn direct_replay_handlers_require_source_read_and_keep_sponsored_agents_excluded() {
    let mut f = Fixture::new(GitHashAlgorithm::Sha1, false);
    let before = f.head();
    let hostile = fields([("operation", text(PREPARE))]);
    f.backend_mut().options.source = false;
    f.backend_mut().options.writes.source = true;
    assert_eq!(super::call(f.backend(), &hostile).unwrap_err().code, "tool_not_granted");
    f.backend_mut().options.source = true;
    f.backend_mut().options.agent_token_file = Some(std::path::PathBuf::from("must-not-open"));
    assert_eq!(super::call(f.backend(), &hostile).unwrap_err().code, "tool_not_granted");
    f.backend_mut().options.agent_token_file = None;
    f.backend_mut().options.writes.source = false;
    assert_eq!(f.head(), before);
}
