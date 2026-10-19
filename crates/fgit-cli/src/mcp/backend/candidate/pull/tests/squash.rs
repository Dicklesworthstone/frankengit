//! Real MCP preparation, full candidate inspection, exact approval and coupled
//! squash publication across independent grants in both native hash formats.
use super::*;

#[test]
fn squash_candidates_keep_their_method_through_inspection_review_publication_and_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, false);
        let before = f.head();
        let mut prepare = f.prepare_args();
        prepare.insert("method".into(), text("squash"));
        let response = f.protocol_call(NAME, prepare.clone());
        let prepared = content(&response);
        assert_eq!(prepared["state"].text(), Some("clean"));
        assert_eq!(prepared["method"].text(), Some("squash"));
        assert_eq!(
            prepared["parents"],
            Value::Array(vec![text(raw_oid(f.subject.target_tip))])
        );
        let review_arguments = prepared["candidate_arguments"].object().unwrap().clone();
        let publication_arguments = prepared["publication_arguments"].object().unwrap().clone();
        let inspection_arguments = prepared["inspection_arguments"].object().unwrap().clone();
        assert!(!review_arguments.contains_key("method"));
        assert_eq!(publication_arguments["method"].text(), Some("squash"));
        assert_eq!(inspection_arguments["method"].text(), Some("squash"));
        assert_eq!(inspection_arguments["operation"].text(), Some(INSPECT));
        assert_eq!(
            inspection_arguments["expected_head"],
            prepared["snapshot_token"]
        );
        let (subject, candidate) = reviews::subject(&review_arguments, format).unwrap();
        assert_eq!(subject, f.subject);
        assert_ne!(candidate.commit, subject.source_tip);
        assert!(f.backend().node.read_git_object(candidate.commit).is_err());
        assert_eq!(f.call(NAME, &prepare).unwrap().object().unwrap(), prepared);
        let inspection_response = f.protocol_call(NAME, inspection_arguments);
        let inspected = content(&inspection_response);
        assert_eq!(inspected["method"].text(), Some("squash"));
        assert_eq!(inspected["parents"], prepared["parents"]);
        assert_eq!(
            inspected["candidate_commit_body_hex"],
            prepared["candidate_commit_body_hex"]
        );
        assert_eq!(
            inspected["candidate_arguments"],
            prepared["candidate_arguments"]
        );
        assert_eq!(
            inspected["publication_arguments"],
            prepared["publication_arguments"]
        );
        assert_eq!(
            inspected["publication_tool"].text(),
            Some("frankengit_pull_merge_reviewed")
        );
        assert_eq!(
            inspected["review"].object().unwrap()["complete"],
            Value::Bool(true)
        );
        assert_eq!(
            f.head(),
            before,
            "preparation and inspection cannot approve or publish"
        );

        let mut approval = review_arguments;
        approval.insert("idempotency_key".into(), text("approve-squash"));
        approval.insert("review_version".into(), text("0"));
        approval.insert("decision".into(), text("approve"));
        assert_eq!(
            f.call(reviews::NAME, &approval).unwrap_err().code,
            "tool_not_granted"
        );
        let mut reviewer = f.options();
        reviewer.source = false;
        reviewer.pulls = false;
        reviewer.writes = Default::default();
        reviewer.writes.reviews = true;
        reviewer.principal = Some(actor(2));
        f.reopen(reviewer);
        let mut inappropriate = approval.clone();
        inappropriate.insert("method".into(), text("squash"));
        assert_eq!(
            f.call(reviews::NAME, &inappropriate).unwrap_err().code,
            "unknown_argument"
        );
        let approved_response = f.protocol_call(reviews::NAME, approval.clone());
        let approved = content(&approved_response);
        assert_eq!(approved["outcome"].text(), Some("committed"));
        let after_review = f.head();
        assert_eq!(
            f.call(reviews::NAME, &approval).unwrap().object().unwrap(),
            approved
        );
        assert_eq!(f.head(), after_review);

        let mut merger = f.options();
        merger.writes = Default::default();
        merger.writes.merges = true;
        merger.principal = Some(actor(3));
        f.reopen(merger.clone());
        let mut publication = publication_arguments;
        publication.insert("idempotency_key".into(), text("publish-squash"));
        publication.insert(
            "required_reviewers".into(),
            Value::Array(vec![text(actor(2).to_string())]),
        );
        let published_response =
            f.protocol_call("frankengit_pull_merge_reviewed", publication.clone());
        let published = content(&published_response);
        assert_eq!(published["outcome"].text(), Some("committed"));
        assert_eq!(published["method"].text(), Some("squash"));
        assert_eq!(published["coupled_pr_and_ref"], Value::Bool(true));
        let node = &f.backend().node;
        let selected = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(
            selected.snapshot().refs[&subject.target_ref],
            candidate.commit
        );
        assert_eq!(
            selected.snapshot().refs[&subject.source_ref],
            subject.source_tip
        );
        let stored = node.read_git_object(candidate.commit).unwrap();
        assert_eq!(
            fgit_crypto::git_object_id(
                format,
                fgit_crypto::GitObjectKind::Commit,
                stored.payload()
            ),
            candidate.commit
        );
        let commit = std::str::from_utf8(stored.payload()).unwrap();
        let parents: Vec<_> = commit
            .lines()
            .filter_map(|line| line.strip_prefix("parent "))
            .collect();
        let target = subject.target_tip.to_string();
        assert_eq!(parents, [target.as_str()]);
        let after = f.head();
        f.reopen(merger);
        assert_eq!(
            f.call("frankengit_pull_merge_reviewed", &publication)
                .unwrap()
                .object()
                .unwrap(),
            published
        );
        assert_eq!(f.head(), after);
    }
}
