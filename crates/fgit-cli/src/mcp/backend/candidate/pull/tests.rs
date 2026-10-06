use super::*;
mod support;
use support::*;

#[test]
fn native_pr_preparation_is_pinned_reproducible_and_never_stages_or_approves() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, false);
        let before = f.head();
        let args = f.prepare_args();
        let response = f.protocol_call(NAME, args.clone());
        let prepared = content(&response);
        assert_eq!(prepared["state"].text(), Some("clean"));
        assert_eq!(prepared["snapshot_token"].text(), Some(head_token(before.0).as_str()));
        assert_eq!(prepared["approval_granted"], Value::Bool(false));
        assert_eq!(prepared["published"], Value::Bool(false));
        assert_eq!(prepared["candidate_available"], Value::Bool(true));
        assert_eq!(prepared["merge_base"].text(), Some(raw_oid(f.base).as_str()));
        let arguments = prepared["candidate_arguments"].object().unwrap();
        let (subject, candidate) = reviews::subject(arguments, format).unwrap();
        assert_eq!(subject, f.subject);
        let bytes = reviews::bundle(arguments).unwrap();
        assert_eq!(prepared["bundle_sha256"].text(), Some(hex(&fgit_crypto::sha256_digest(&bytes)).as_str()));
        assert!(f.backend().node.read_git_object(candidate.commit).is_err());
        let commit = prepared["candidate_commit_text_utf8"].text().unwrap();
        assert!(commit.contains(&format!("\nparent {}\nparent {}\n", f.subject.target_tip, f.subject.source_tip)));
        assert!(commit.ends_with("review this actual merge\n"));
        assert_eq!(f.call(NAME, &args).unwrap().object().unwrap(), prepared);
        let mut renamed = args.clone();
        renamed.insert("merge_profile".into(), text("exact-renames-v1"));
        let explicit = f.call(NAME, &renamed).unwrap();
        assert_eq!(explicit.object().unwrap()["candidate_arguments"], prepared["candidate_arguments"]);
        for tool in [reviews::NAME, "frankengit_pull_merge_reviewed", "frankengit_source_publish"] {
            assert_eq!(f.call(tool, arguments).unwrap_err().code, "tool_not_granted");
        }
        assert_eq!(f.head(), before);
    }
}

#[test]
fn stale_subjects_pins_and_work_exhaustion_never_refresh_or_return_a_partial_candidate() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, false);
        let before = f.head();
        let args = f.prepare_args();
        for (field, value) in [
            ("expected_version", text("2")), ("policy_epoch", text("2")),
            ("expected_source", text(raw_oid(f.base))), ("expected_target", text(raw_oid(f.base))),
            ("expected_head", text(head_token(f.genesis))), ("max_commits", json::number(1)),
            ("max_output_bytes", json::number(1)),
        ] {
            let mut bad = args.clone(); bad.insert(field.into(), value);
            assert!(f.call(NAME, &bad).is_err(), "{field}");
            assert_eq!(f.head(), before);
        }
        assert_eq!(f.call(NAME, &args).unwrap().object().unwrap()["state"].text(), Some("clean"));
        for (source, pulls) in [(true, false), (false, true), (false, false)] {
            let mut options = f.options();
            options.source = source; options.pulls = pulls;
            options.writes.merges = true; options.writes.reviews = true;
            options.principal = Some(actor(2));
            f.reopen(options);
            // Even an invalid payload must be refused by the grant check first.
            let hostile = fields([("operation", text(PREPARE))]);
            assert_eq!(f.call(NAME, &hostile).unwrap_err().code, "tool_not_granted");
            assert_eq!(call(f.backend(), &hostile).unwrap_err().code, "tool_not_granted");
            assert_eq!(prepare::call(f.backend(), &hostile).unwrap_err().code, "tool_not_granted");
            assert_eq!(f.head(), before);
        }
    }
}

#[test]
fn real_conflicts_return_exact_coordinates_without_a_commit_bundle_or_approval() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, true);
        let before = f.head();
        let args = f.prepare_args();
        let result = f.call(NAME, &args).unwrap();
        let result = result.object().unwrap();
        assert_eq!(result["state"].text(), Some("conflicted"));
        assert_eq!(result["candidate_available"], Value::Bool(false));
        for field in ["candidate_commit", "candidate_arguments", "parents", "bundle_sha256", "root_tree"] {
            assert_eq!(result[field], Value::Null);
        }
        let Value::Array(conflicts) = &result["conflicts"] else { unreachable!() };
        assert_eq!(conflicts.len(), 1);
        let conflict = conflicts[0].object().unwrap();
        assert_eq!(conflict["path_hex"].text(), Some(hex(b"README").as_str()));
        assert_eq!(conflict["kind"].text(), Some("content"));
        assert_ne!(conflict["ours"], conflict["theirs"]);
        assert_eq!(f.call(NAME, &args).unwrap().object().unwrap(), result);
        assert_eq!(f.head(), before);
    }
}
