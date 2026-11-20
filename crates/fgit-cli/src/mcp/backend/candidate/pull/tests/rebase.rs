//! Real JSON-RPC PR rebase preparation, full-series inspection, independent
//! review, atomic landing and restart recovery in both native hash formats.
use super::*;

fn preparation(f: &Fixture) -> Object {
    let mut args = subject_fields(&f.subject);
    args.extend([
        ("operation".into(), text(REBASE_PREPARE)),
        ("profile".into(), text("path-v1")),
        ("expected_head".into(), text(head_token(f.head().0))),
        ("upstream".into(), text(raw_oid(f.base))),
        ("empty".into(), text("stop")),
        (
            "committer".into(),
            text("Rebaser <rebaser@example.invalid>"),
        ),
        ("timestamp".into(), text("2")),
    ]);
    args
}

#[test]
fn rebase_series_survives_independent_review_atomic_merge_and_restart_through_real_mcp() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::fast_forward(format);
        let before = f.head();
        let prepare = preparation(&f);
        let response = f.protocol_call(NAME, prepare.clone());
        let prepared = content(&response);
        assert_eq!(prepared["state"].text(), Some("clean"));
        assert_eq!(prepared["method"].text(), Some("rebase"));
        assert_eq!(prepared["step_count"].text(), Some("2"));
        assert_eq!(prepared["objects_staged"], Value::Bool(false));
        assert_eq!(prepared["approval_granted"], Value::Bool(false));
        assert_eq!(f.call(NAME, &prepare).unwrap().object().unwrap(), prepared);
        let mut approval = prepared["candidate_arguments"].object().unwrap().clone();
        let (subject, candidate) = reviews::subject(&approval, format).unwrap();
        assert_eq!(subject, f.subject);
        assert_eq!(candidate.merge_base, f.base);
        assert_ne!(candidate.commit, subject.source_tip);
        assert!(f.backend().node.read_git_object(candidate.commit).is_err());
        assert_eq!(approval["method"].text(), Some("rebase"));
        let inspection = prepared["inspection_arguments"].object().unwrap().clone();
        assert_eq!(inspection["operation"].text(), Some(REBASE_INSPECT));
        let inspected_response = f.protocol_call(NAME, inspection);
        let inspected = content(&inspected_response);
        assert_eq!(inspected["complete"], Value::Bool(true));
        assert_eq!(inspected["commit_count"].text(), Some("2"));
        assert_eq!(
            inspected["completion_scope"].text(),
            Some("entire_rebase_series_and_net_tree")
        );
        assert_eq!(
            inspected["candidate_arguments"],
            prepared["candidate_arguments"]
        );
        assert_eq!(
            inspected["publication_arguments"],
            prepared["publication_arguments"]
        );
        let Value::Array(commits) = &inspected["commits"] else {
            panic!("whole series required")
        };
        let mut parent = subject.target_tip;
        for row in commits {
            let row = row.object().unwrap();
            assert_eq!(row["parent"].text(), Some(raw_oid(parent).as_str()));
            let body = unhex(row["body_hex"].text().unwrap(), 128 * 1024).unwrap();
            let commit =
                fgit_crypto::git_object_id(format, fgit_crypto::GitObjectKind::Commit, &body);
            assert_eq!(row["commit"].text(), Some(raw_oid(commit).as_str()));
            let body = std::str::from_utf8(&body).unwrap();
            assert!(body.contains("\nauthor Author <author@example.invalid> 1 +0000\n"));
            assert!(body.contains("\ncommitter Rebaser <rebaser@example.invalid> 2 +0000\n"));
            assert!(body.ends_with("seed\n"));
            assert_eq!(row["diff"].object().unwrap()["complete"], Value::Bool(true));
            parent = commit;
        }
        assert_eq!(parent, candidate.commit);
        assert_eq!(f.head(), before);

        approval.extend([
            ("idempotency_key".into(), text("approve-pr-rebase")),
            ("review_version".into(), text("0")),
            ("decision".into(), text("approve")),
        ]);
        assert_eq!(
            f.call(reviews::NAME, &approval).unwrap_err().code,
            "tool_not_granted"
        );
        let mut reviewer = f.options();
        reviewer.source = false;
        reviewer.pulls = false;
        reviewer.writes.reviews = true;
        reviewer.principal = Some(actor(2));
        f.reopen(reviewer);
        // The generic single-commit validator must not silently accept a series.
        let mut downgrade = approval.clone();
        downgrade.remove("method");
        downgrade.insert("idempotency_key".into(), text("wrong-review-profile"));
        let rejected = f.call(reviews::NAME, &downgrade).unwrap();
        assert_ne!(
            rejected.object().unwrap()["outcome"].text(),
            Some("committed")
        );
        let approved_response = f.protocol_call(reviews::NAME, approval.clone());
        let approved = content(&approved_response);
        assert_eq!(approved["outcome"].text(), Some("committed"));
        assert_eq!(approved["method"].text(), Some("rebase"));
        assert_eq!(
            f.call(reviews::NAME, &approval).unwrap().object().unwrap(),
            approved
        );

        let mut merger = f.options();
        merger.writes = Default::default();
        merger.writes.merges = true;
        merger.principal = Some(actor(3));
        f.reopen(merger.clone());
        let mut publication = prepared["publication_arguments"].object().unwrap().clone();
        publication.extend([
            ("idempotency_key".into(), text("publish-pr-rebase")),
            (
                "required_reviewers".into(),
                Value::Array(vec![text(actor(2).to_string())]),
            ),
        ]);
        let published_response =
            f.protocol_call("frankengit_pull_merge_reviewed", publication.clone());
        let published = content(&published_response);
        assert_eq!(published["outcome"].text(), Some("committed"));
        assert_eq!(published["method"].text(), Some("rebase"));
        assert_eq!(published["coupled_pr_and_ref"], Value::Bool(true));
        let node = &f.backend().node;
        let selected = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(
            selected.snapshot().refs[&subject.source_ref],
            subject.source_tip
        );
        assert_eq!(
            selected.snapshot().refs[&subject.target_ref],
            candidate.commit
        );
        let page = node
            .runtime()
            .block_on(node.read_pull_requests_in(
                &node.request_context(),
                &Default::default(),
                0,
                1,
                None,
            ))
            .unwrap();
        assert!(matches!(
            page.pull_requests[0].event.payload,
            fgit_forge::ForgeEventPayload::MergeCommittedNative(_)
        ));
        let after = f.head();
        f.reopen(merger);
        // Original stale coordinates recover before parsing a discarded bundle.
        publication.insert("bundle_hex_chunks".into(), Value::Array(vec![text("00")]));
        assert_eq!(
            f.call("frankengit_pull_merge_reviewed", &publication)
                .unwrap()
                .object()
                .unwrap(),
            published
        );
        assert_eq!(f.head(), after);
        publication.insert("method".into(), text("squash"));
        assert!(
            f.call("frankengit_pull_merge_reviewed", &publication)
                .is_err()
        );
        assert_eq!(f.head(), after);
    }
}

#[test]
fn rebase_preparation_and_inspection_refuse_stale_inputs_limits_and_missing_read_grants() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::fast_forward(format);
        let before = f.head();
        let args = preparation(&f);
        for (field, value) in [
            ("expected_version", text("2")),
            ("policy_epoch", text("2")),
            ("expected_source", text(raw_oid(f.base))),
            ("expected_head", text(head_token(f.genesis))),
            ("max_commits", json::number(1)),
            ("max_preparation_bytes", json::number(1)),
        ] {
            let mut bad = args.clone();
            bad.insert(field.into(), value);
            assert!(f.call(NAME, &bad).is_err(), "{field}");
            assert_eq!(f.head(), before);
        }
        let result = f.call(NAME, &args).unwrap();
        let inspected = result.object().unwrap()["inspection_arguments"]
            .object()
            .unwrap()
            .clone();
        for (field, value) in [
            ("paths_hex", Value::Array(vec![text(hex(b"README"))])),
            ("comparison", text("merge-base")),
            ("expected_bundle_sha256", text("00".repeat(32))),
            ("expected_head", text(head_token(f.genesis))),
            ("max_changes", json::number(1)),
            ("method", text("squash")),
        ] {
            let mut bad = inspected.clone();
            bad.insert(field.into(), value);
            assert!(f.call(NAME, &bad).is_err(), "{field}");
            assert_eq!(f.head(), before);
        }
        assert_eq!(
            f.call(NAME, &inspected).unwrap().object().unwrap()["complete"],
            Value::Bool(true)
        );
        for (source, pulls) in [(true, false), (false, true), (false, false)] {
            let mut options = f.options();
            options.source = source;
            options.pulls = pulls;
            options.writes.merges = true;
            options.principal = Some(actor(3));
            f.reopen(options);
            for operation in [REBASE_PREPARE, REBASE_INSPECT] {
                let malformed = fields([("operation", text(operation))]);
                assert_eq!(
                    f.call(NAME, &malformed).unwrap_err().code,
                    "tool_not_granted"
                );
                assert_eq!(
                    super::super::rebase::call(f.backend(), &malformed)
                        .unwrap_err()
                        .code,
                    "tool_not_granted"
                );
            }
            assert_eq!(f.head(), before);
        }
    }
}

#[test]
fn a_conflicted_pr_rebase_returns_no_partial_review_or_publication_handoff() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, true);
        let before = f.head();
        let args = preparation(&f);
        let result = f.call(NAME, &args).unwrap();
        let result = result.object().unwrap();
        assert_eq!(result["state"].text(), Some("conflicted"));
        assert_eq!(result["complete"], Value::Bool(false));
        assert_eq!(result["candidate_available"], Value::Bool(false));
        for field in [
            "candidate_commit",
            "root_tree",
            "bundle_sha256",
            "candidate_arguments",
            "inspection_arguments",
            "publication_arguments",
        ] {
            assert_eq!(result[field], Value::Null, "{field}");
        }
        let Value::Array(conflicts) = &result["conflicts"] else {
            panic!("exact conflicts required")
        };
        assert_eq!(
            conflicts[0].object().unwrap()["path_hex"].text(),
            Some(hex(b"README").as_str())
        );
        assert_eq!(f.head(), before);
    }
}
