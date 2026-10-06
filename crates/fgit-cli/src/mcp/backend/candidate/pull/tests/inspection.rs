//! Protocol calls over real persisted SHA-1/SHA-256 nodes. The existing fixture
//! constructs divergent native branches and a real open PR, without Git or mocks.
use super::*;
use fgit_forge::review::{ComparisonMode, ReviewOptions, SourceReview};

fn inspection(prepared: &Object) -> Object {
    let mut args = prepared["candidate_arguments"].object().unwrap().clone();
    args.insert("operation".into(), text(INSPECT));
    args.insert("expected_bundle_sha256".into(), prepared["bundle_sha256"].clone());
    args.insert("expected_head".into(), prepared["snapshot_token"].clone());
    args
}

#[test]
fn actual_target_to_uploaded_result_is_complete_pinned_and_unstaged_over_mcp() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, false);
        let before = f.head();
        let args = f.prepare_args();
        let prepared = f.call(NAME, &args).unwrap();
        let prepared = prepared.object().unwrap();
        let args = inspection(prepared);
        let response = f.protocol_call(NAME, args.clone());
        let result = content(&response);
        assert_eq!(result["operation"].text(), Some(INSPECT));
        assert_eq!(result["snapshot_token"], prepared["snapshot_token"]);
        assert_eq!(result["candidate_arguments"], prepared["candidate_arguments"]);
        assert_eq!(result["bundle_sha256"], prepared["bundle_sha256"]);
        assert_eq!(result["candidate_commit_body_hex"], prepared["candidate_commit_body_hex"]);
        assert_eq!(result["parents"], prepared["parents"]);
        for field in ["published", "approval_granted", "repository_changed", "merge_algorithm_verified"] {
            assert_eq!(result[field], Value::Bool(false), "{field}");
        }
        let review = result["review"].object().unwrap();
        assert_eq!(review["complete"], Value::Bool(true));
        assert_eq!(review["completion_scope"].text(), Some("entire_candidate_tree"));
        assert_eq!(review["comparison_subject"].text(), Some("target_before_to_uploaded_candidate"));
        assert_eq!(review["requested_before"].text(), Some(f.subject.target_tip.to_string().as_str()));
        assert_eq!(review["requested_after"], result["candidate_commit"]);
        assert_eq!(review["pull_request"].object().unwrap()["version"].text(), Some("1"));
        let Value::Array(entries) = &review["entries"] else { unreachable!() };
        assert_eq!(entries.len(), 1);
        // The source branch lacks main-only. Comparing source -> candidate would
        // show the wrong side's addition instead of the actual landed change.
        assert_eq!(entries[0].object().unwrap()["path_hex"].text(), Some(hex(b"topic-only").as_str()));
        let candidate = oid(&args, "candidate_commit", format).unwrap();
        assert!(f.backend().node.read_git_object(candidate).is_err());
        assert_eq!(f.call(NAME, &args).unwrap().object().unwrap(), result);
        for tool in [reviews::NAME, "frankengit_pull_merge_reviewed", "frankengit_source_publish"] {
            assert_eq!(f.call(tool, result["candidate_arguments"].object().unwrap()).unwrap_err().code, "tool_not_granted");
        }
        assert_eq!(f.head(), before);
        let options = f.options();
        f.reopen(options);
        assert_eq!(f.call(NAME, &args).unwrap().object().unwrap(), result);
        assert_eq!(f.head(), before);
    }
}

#[test]
fn corrupt_uploads_moved_pins_and_exhausted_reviews_return_no_successful_prefix() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, false);
        let before = f.head();
        let prepare = f.prepare_args();
        let prepared = f.call(NAME, &prepare).unwrap();
        let args = inspection(prepared.object().unwrap());
        for (name, value) in [
            ("expected_version", text("2")), ("policy_epoch", text("2")),
            ("expected_source", text(raw_oid(f.base))), ("expected_target", text(raw_oid(f.base))),
            ("candidate_commit", text("ee".repeat(format.digest_len()))),
            ("merge_base", text("dd".repeat(format.digest_len()))),
            ("expected_head", text(head_token(f.genesis))),
            ("max_output_bytes", json::number(1)), ("max_blob_bytes", json::number(1)),
        ] {
            let mut bad = args.clone(); bad.insert(name.into(), value);
            assert!(f.call(NAME, &bad).is_err(), "{name}");
            assert_eq!(f.head(), before);
        }
        let mut corrupt = args.clone();
        let mut bytes = chunks(&corrupt, "bundle_hex_chunks").unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        corrupt.remove("expected_bundle_sha256");
        corrupt.insert("bundle_hex_chunks".into(), encoded_chunks(&bytes).unwrap());
        assert_eq!(f.call(NAME, &corrupt).unwrap_err().code, "pull_candidate_inspection_failed");
        bytes.truncate(bytes.len() - 4);
        corrupt.insert("bundle_hex_chunks".into(), encoded_chunks(&bytes).unwrap());
        assert!(f.call(NAME, &corrupt).is_err());
        assert!(f.call(NAME, &args).is_ok(), "a failed inspection cannot poison the next read");
        assert_eq!(f.head(), before);
    }
}

#[test]
fn independent_read_grants_precede_parsing_despite_review_and_merge_write_grants() {
    let mut f = Fixture::new(GitHashAlgorithm::Sha256, false);
    let before = f.head();
    for (source, pulls) in [(true, false), (false, true), (false, false)] {
        let mut options = f.options();
        options.source = source; options.pulls = pulls;
        options.writes.reviews = true; options.writes.merges = true;
        options.principal = Some(actor(2));
        f.reopen(options);
        let hostile = fields([("operation", text(INSPECT))]);
        assert_eq!(f.call(NAME, &hostile).unwrap_err().code, "tool_not_granted");
        assert_eq!(call(f.backend(), &hostile).unwrap_err().code, "tool_not_granted");
        assert_eq!(inspect::call(f.backend(), &hostile).unwrap_err().code, "tool_not_granted");
        assert_eq!(f.head(), before);
    }
}

#[test]
fn shared_renderer_rejects_pr_ref_commit_head_and_path_misbinding() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, false);
        let args = f.prepare_args();
        let prepared = f.call(NAME, &args).unwrap();
        let args = inspection(prepared.object().unwrap());
        let (subject, candidate) = reviews::subject(&args, format).unwrap();
        let bytes = chunks(&args, "bundle_hex_chunks").unwrap();
        let node = &f.backend().node;
        let request = node.request_context();
        let mut report = node.runtime().block_on(node.inspect_pull_request_bundle_in(
            &request, &subject, candidate, &bytes, &Default::default(), &ReviewOptions::default(),
        )).unwrap().review;
        let selected = f.head().0;
        let render = |report: &SourceReview, options: ReviewOptions| {
            super::super::super::super::review::render_pull_candidate(
                f.backend(), &subject, candidate, Some(selected), options, report,
            )
        };
        assert!(render(&report, ReviewOptions::default()).is_ok());
        report.pull_request = None;
        assert!(render(&report, ReviewOptions::default()).is_err());
        report.pull_request = Some((subject.pull_request, subject.pull_request_version));
        report.after_reference = subject.source_ref.clone();
        assert!(render(&report, ReviewOptions::default()).is_err());
        report.after_reference = subject.target_ref.clone();
        report.before_reference = subject.source_ref.clone();
        assert!(render(&report, ReviewOptions::default()).is_err());
        report.before_reference = subject.target_ref.clone();
        report.comparison.requested_after = subject.source_tip;
        assert!(render(&report, ReviewOptions::default()).is_err());
        report.comparison.requested_after = candidate.commit;
        report.source_head = f.genesis;
        assert!(render(&report, ReviewOptions::default()).is_err());
        report.source_head = selected;
        let path = std::mem::take(&mut report.comparison.entries[0].path);
        assert!(render(&report, ReviewOptions::default()).is_err());
        report.comparison.entries[0].path = path;
        let mut filtered = ReviewOptions::default();
        filtered.paths.push(b"topic-only".to_vec());
        assert!(render(&report, filtered).is_err());
        let wrong_mode = ReviewOptions { mode: ComparisonMode::MergeBase, ..ReviewOptions::default() };
        assert!(render(&report, wrong_mode).is_err());
        assert!(render(&report, ReviewOptions::default()).is_ok());
        request.cancel();
        assert!(node.runtime().block_on(node.inspect_pull_request_bundle_in(
            &request, &subject, candidate, &bytes, &Default::default(), &ReviewOptions::default(),
        )).is_err());
    }
}
