//! Real native conflict resolution -> complete inspection -> independent
//! review -> coupled merge, with durable original-key retries and reopen.
use super::*;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_types::GitOid;

fn side(choice: &str) -> Value {
    object([("path_hex", text(hex(b"README"))), ("choice", text(choice))])
}
fn file(bytes: &[u8]) -> Value {
    object([
        ("path_hex", text(hex(b"README"))), ("choice", text("file")), ("mode", text("100755")),
        ("bytes_hex_chunks", Value::Array(bytes.chunks(CHUNK_BYTES).map(|part| text(hex(part))).collect())),
    ])
}
fn arguments(f: &Fixture, row: Value) -> Object {
    let mut args = f.prepare_args();
    args.insert("operation".into(), text(RESOLVE));
    args.insert("merge_base".into(), text(raw_oid(f.base)));
    args.insert("resolutions".into(), Value::Array(vec![row]));
    args
}
fn tips(f: &Fixture) -> (GitOid, GitOid) {
    let node = &f.backend().node;
    let request = node.request_context();
    let selected = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
    (selected.snapshot().refs[&f.subject.target_ref], selected.snapshot().refs[&f.subject.source_ref])
}
fn inspection(result: &Object) -> Object {
    let mut args = result["candidate_arguments"].object().unwrap().clone();
    args.insert("operation".into(), text(INSPECT));
    args.insert("expected_head".into(), result["snapshot_token"].clone());
    args.insert("expected_bundle_sha256".into(), result["bundle_sha256"].clone());
    args
}

#[test]
fn exact_conflict_choices_are_inspected_without_staging_and_empty_is_not_delete() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, true);
        let before = f.head();
        for (row, expected, choice, mode) in [
            (side("base"), Some(b"base\n".as_slice()), "base", "100644"),
            (side("ours"), Some(b"main\n".as_slice()), "ours", "100644"),
            (side("theirs"), Some(b"topic\n".as_slice()), "theirs", "100644"),
            (side("delete"), None, "delete", "100644"),
            (file(b""), Some(b"".as_slice()), "file", "100755"),
            (file(b"\0\xff\r\n"), Some(b"\0\xff\r\n".as_slice()), "file", "100755"),
        ] {
            let args = arguments(&f, row);
            let response = f.protocol_call(NAME, args.clone());
            let result = content(&response);
            assert_eq!(result["operation"].text(), Some(RESOLVE));
            assert_eq!(result["snapshot_token"].text(), Some(head_token(before.0).as_str()));
            assert_eq!(result["inspection_performed"], Value::Bool(true));
            assert_eq!(result["resolution_count"].text(), Some("1"));
            for field in ["published", "approval_granted", "repository_changed"] {
                assert_eq!(result[field], Value::Bool(false));
            }
            let Value::Array(receipts) = &result["resolved_paths"] else { unreachable!() };
            assert_eq!(receipts.len(), 1);
            let receipt = receipts[0].object().unwrap();
            assert_eq!(receipt["path_hex"].text(), Some(hex(b"README").as_str()));
            assert_eq!(receipt["choice"].text(), Some(choice));
            if let Some(bytes) = expected {
                let entry = receipt["result"].object().unwrap();
                assert_eq!(entry["oid"].text(), Some(raw_oid(git_object_id(format, GitObjectKind::Blob, bytes)).as_str()));
                assert_eq!(entry["mode"].text(), Some(mode));
            } else { assert_eq!(receipt["result"], Value::Null); }
            let review = result["review"].object().unwrap();
            assert_eq!(review["completion_scope"].text(), Some("entire_candidate_tree"));
            if choice == "ours" { assert_eq!(review["entry_count"].text(), Some("0")); }
            let candidate = oid(result["candidate_arguments"].object().unwrap(), "candidate_commit", format).unwrap();
            assert!(f.backend().node.read_git_object(candidate).is_err());
            assert_eq!(f.call(NAME, &args).unwrap().object().unwrap(), result);
            assert_eq!(f.head(), before);
        }
    }
}

#[test]
fn nonconflicts_wrong_bases_stale_subjects_and_phase_exhaustion_never_return_candidates() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, true);
        let before = f.head();
        let args = arguments(&f, file(b"resolved\n"));
        for (field, value) in [
            ("expected_version", text("2")), ("policy_epoch", text("2")),
            ("expected_head", text(head_token(f.genesis))),
            ("merge_base", text(raw_oid(f.subject.target_tip))),
            ("expected_source", text(raw_oid(f.base))),
            ("max_commits", json::number(1)), ("max_preparation_bytes", json::number(32)),
            ("max_review_bytes", json::number(1)),
            ("resolutions", Value::Array(vec![object([("path_hex", text(hex(b"sibling"))), ("choice", text("ours"))])])),
            ("resolutions", Value::Array(Vec::new())),
        ] {
            let mut bad = args.clone(); bad.insert(field.into(), value);
            assert!(f.call(NAME, &bad).is_err(), "{field}");
            assert_eq!(f.head(), before);
        }
        let result = f.call(NAME, &args).unwrap();
        assert_eq!(result.object().unwrap()["inspection_performed"], Value::Bool(true));
        assert_eq!(f.head(), before);
        let mut clean = Fixture::new(format, false);
        let before = clean.head();
        let args = arguments(&clean, side("ours"));
        assert!(clean.call(NAME, &args).is_err(), "a resolution cannot edit an unconflicted path");
        assert_eq!(clean.head(), before);
    }
}

#[test]
fn resolution_and_nested_inspection_never_reset_the_request_or_infer_read_grants() {
    let mut f = Fixture::new(GitHashAlgorithm::Sha256, true);
    let before = f.head();
    let args = arguments(&f, file(b"resolved\n"));
    let result = f.call(NAME, &args).unwrap();
    let inspection = inspection(result.object().unwrap());
    let request = f.backend().node.request_context();
    request.authority().cancel();
    assert!(inspect::call_in(f.backend(), &inspection, &request).is_err());
    assert!(f.call(NAME, &inspection).is_ok(), "only a genuinely new request owns a fresh budget");
    for (source, pulls) in [(true, false), (false, true), (false, false)] {
        let mut options = f.options();
        options.source = source; options.pulls = pulls;
        options.writes.reviews = true; options.writes.merges = true;
        options.principal = Some(actor(2));
        f.reopen(options);
        let hostile = fields([("operation", text(RESOLVE))]);
        assert_eq!(f.call(NAME, &hostile).unwrap_err().code, "tool_not_granted");
        assert_eq!(call(f.backend(), &hostile).unwrap_err().code, "tool_not_granted");
        assert_eq!(resolve::call(f.backend(), &hostile).unwrap_err().code, "tool_not_granted");
        assert_eq!(f.head(), before);
    }
}

#[test]
fn resolved_candidate_crosses_independent_review_and_merge_grants_then_recovers_after_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, true);
        let before = f.head();
        let args = arguments(&f, file(b"resolved\n"));
        let result = f.call(NAME, &args).unwrap();
        let result = result.object().unwrap();
        let mut publication = result["candidate_arguments"].object().unwrap().clone();
        let candidate = oid(&publication, "candidate_commit", format).unwrap();
        let mut review = publication.clone();
        review.insert("idempotency_key".into(), text("review-resolved"));
        review.insert("review_version".into(), text("0"));
        review.insert("decision".into(), text("approve"));
        assert_eq!(f.call(reviews::NAME, &review).unwrap_err().code, "tool_not_granted");
        publication.insert("required_reviewers".into(), Value::Array(vec![text(hex(actor(2).as_bytes()))]));
        publication.insert("idempotency_key".into(), text("unapproved-merge"));
        assert_eq!(f.call("frankengit_pull_merge_reviewed", &publication).unwrap_err().code, "tool_not_granted");
        assert_eq!(f.head(), before);

        // A distinct launch identity owns merge authority, not the resolver.
        let mut merger = f.options();
        merger.source = false; merger.pulls = false;
        merger.writes.merges = true; merger.principal = Some(actor(3));
        f.reopen(merger.clone());
        let unapproved = f.call("frankengit_pull_merge_reviewed", &publication);
        if let Ok(value) = unapproved {
            assert_ne!(value.object().unwrap()["outcome"].text(), Some("committed"));
        }
        assert_eq!(tips(&f), (f.subject.target_tip, f.subject.source_tip));

        // Neither the PR opener (1) nor merge submitter (3) supplies the vote.
        let mut reviewer = merger.clone();
        reviewer.writes = Default::default(); reviewer.writes.reviews = true;
        reviewer.principal = Some(actor(2));
        f.reopen(reviewer);
        let approved = f.call(reviews::NAME, &review).unwrap();
        assert_eq!(approved.object().unwrap()["outcome"].text(), Some("committed"));
        let after_review = f.head();
        assert_ne!(after_review, before);
        assert_eq!(f.call(reviews::NAME, &review).unwrap(), approved);
        assert_eq!(f.head(), after_review);
        assert_eq!(tips(&f), (f.subject.target_tip, f.subject.source_tip));

        f.reopen(merger.clone());
        // This is a NEW post-approval operation, not a retry of the refused key.
        publication.insert("idempotency_key".into(), text("approved-resolved-merge"));
        let response = f.protocol_call("frankengit_pull_merge_reviewed", publication.clone());
        let committed = content(&response);
        assert_eq!(committed["outcome"].text(), Some("committed"));
        assert_eq!(committed["coupled_pr_and_ref"], Value::Bool(true));
        let after = f.head();
        assert_eq!(tips(&f), (candidate, f.subject.source_tip));
        assert_eq!(f.call("frankengit_pull_merge_reviewed", &publication).unwrap().object().unwrap(), committed);
        assert_eq!(f.head(), after);
        f.reopen(merger.clone());
        assert_eq!(f.call("frankengit_pull_merge_reviewed", &publication).unwrap().object().unwrap(), committed);
        assert_eq!(f.head(), after);

        let mut reader = merger;
        reader.writes = Default::default(); reader.principal = None;
        reader.source = true; reader.pulls = true;
        f.reopen(reader);
        for (path, expected) in [(b"README".as_slice(), b"resolved\n".as_slice()), (b"sibling", b"unchanged\n")] {
            let blob = f.call("frankengit_source_blob", &fields([
                ("reference", text("refs/heads/main")), ("path_hex", text(hex(path))),
            ])).unwrap();
            assert_eq!(blob.object().unwrap()["bytes_hex"].text(), Some(hex(expected).as_str()));
        }
        assert!(f.call(NAME, &args).is_err(), "merged PRs and old pins cannot refresh themselves");
        assert_eq!(f.head(), after);
    }
}
