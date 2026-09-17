#![forbid(unsafe_code)]
#[path = "source_rebase_http/support.rs"]
mod support;
use support::*;
use fgit_types::{GitHashAlgorithm, GitOid};

#[test]
fn multi_commit_rebase_is_read_only_until_explicit_atomic_apply_and_recovers_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let (node, history) = fixture(&root, format, 0);
        let credentials = root.0.join("credentials"); configure(&node, &credentials);
        let before = generation(&node); let form = prepare_form(&history);
        let server = SourceServer::start(node, &credentials, 3);
        let first = post_form(&server.client, "rebase/prepare", 'a', &form, false);
        let (metadata, bundle) = extract_candidate(&first);
        assert_eq!(numeric(&metadata, "step_count"), 2);
        assert!(numeric(&metadata, "borrowed_objects") >= 2);
        assert!(metadata.contains("\"series_complete\":true"));
        assert!(metadata.contains(&format!("\"original\":\"{}\"", history.first)));
        assert!(metadata.contains(&format!("\"original\":\"{}\"", history.source)));
        let candidate = GitOid::from_hex(format, field(&metadata, "candidate_commit")).unwrap();
        let intermediate = GitOid::from_hex(format, field(&metadata, "rewritten")).unwrap();
        let second = post_form(&server.client, "rebase/prepare", 'a', &form, true);
        assert_eq!(first, second, "framing cannot change the generated candidate");
        status(&post_form(&server.client, "rebase/prepare", 'b', &form, false), 403);
        server.finish();
        let node = reopen(&root.config(format));
        assert_eq!(generation(&node), before);
        assert_eq!(tip(&node, b"refs/heads/topic"), history.source);
        assert!(node.read_git_object(candidate).is_err());
        assert!(node.read_git_object(intermediate).is_err());
        let command = apply_form(&history, candidate);
        let server = SourceServer::start(node, &credentials, 3);
        status(&multipart(&server.client, "rebase/apply", 'a', &command, &bundle, Some("rebase-series")), 403);
        let applied = multipart(&server.client, "rebase/apply", 'b', &command, &bundle, Some("rebase-series"));
        status(&applied, 200); assert!(json(&applied).contains("\"outcome\":\"committed\""));
        let tx = field(json(&applied), "tx_id").to_owned();
        assert_eq!(applied, multipart(&server.client, "rebase/apply", 'b', &command, &bundle, Some("rebase-series")));
        server.finish();
        let node = reopen(&root.config(format));
        assert_eq!(tip(&node, b"refs/heads/topic"), candidate);
        assert_eq!(tip(&node, b"refs/heads/main"), history.onto);
        assert_eq!(generation(&node), before + 1);
        for (id, parent, message) in [(intermediate, history.onto, "first original message"),
            (candidate, intermediate, "second original message")]
        {
            let object = node.read_git_object(id).unwrap();
            let body = std::str::from_utf8(object.payload()).unwrap();
            assert!(body.contains(&format!("parent {parent}\n")));
            assert!(body.contains("author Original <original@example.invalid> 5 -0330\n"));
            assert!(body.contains("committer Rebaser <rebaser@example.invalid> 9 +0000\n"));
            assert!(body.ends_with(&format!("\n\n{message}\n")));
        }
        let server = SourceServer::start(node, &credentials, 3);
        assert_eq!(applied, multipart(&server.client, "rebase/apply", 'b', &command, &bundle, Some("rebase-series")));
        let lookup = binary_exchange(&server.client, &request(&server.client, "POST", "/api/v1/outcomes", 'b',
            "Content-Length: 0\r\nIdempotency-Key: rebase-series\r\n", &[]), true);
        status(&lookup, 200); assert!(json(&lookup).contains(&tx));
        let stale = post_form(&server.client, "rebase/prepare", 'a', &form, false);
        status(&stale, 409); assert!(json(&stale).contains("rebase_tip_moved"));
        server.finish();
        let node = reopen(&root.config(format)); assert_eq!(generation(&node), before + 1); node.shutdown().unwrap();
    }
}

#[test]
fn stopped_series_resource_and_read_key_refusals_never_publish_or_claim_completion() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let (node, history) = fixture(&root, format, 1);
        let credentials = root.0.join("credentials"); let grants = configure(&node, &credentials);
        let before = generation(&node); let form = prepare_form(&history);
        let server = SourceServer::start(node, &credentials, 6);
        let stop = post_form(&server.client, "rebase/prepare", 'a', &form, false);
        status(&stop, 409);
        assert_eq!(field(json(&stop), "state"), "conflicted");
        assert_eq!(field(json(&stop), "stopped_commit"), history.first.to_string());
        assert!(json(&stop).contains("\"bundle\":null") && json(&stop).contains("\"candidate_commit\":null"));
        assert!(json(&stop).contains("\"series_complete\":false") && json(&stop).contains("\"path_hex\":\"61ff\""));
        status(&post_form(&server.client, "rebase/prepare", 'a', &(form.clone()+"&max_commits=1"), false), 413);
        let unrelated = form.replace(&format!("upstream={}", history.upstream), &format!("upstream={}", history.onto));
        let refused = post_form(&server.client, "rebase/prepare", 'a', &unrelated, true);
        status(&refused, 409); assert!(json(&refused).contains("upstream_outside_linear_history"));
        let read_key = binary_exchange(&server.client, &request(&server.client, "POST", "/api/v1/source/rebase/prepare", 'a',
            &format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: never-rebase\r\n", form.len()), form.as_bytes()), true);
        status(&read_key, 400); assert!(json(&read_key).contains("source_read_has_no_transaction_key"));
        replace(&credentials, &(grants + &row('b', OWNER, "receive,outcomes-read") + &row('c', OWNER, "read,outcomes-read")));
        status(&post_form(&server.client, "rebase/prepare", 'a', &form, false), 401);
        let again = post_form(&server.client, "rebase/prepare", 'c', &form, false);
        assert_eq!(stop, again, "credential rotation does not change the pinned comparison");
        server.finish();
        let node = reopen(&root.config(format)); assert_eq!(generation(&node), before);
        assert_eq!(tip(&node, b"refs/heads/topic"), history.source); node.shutdown().unwrap();
    }
}

#[test]
fn empty_commit_policy_stop_drop_and_keep_has_an_executable_zero_commit_result() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let (node, history) = fixture(&root, format, 2);
        let credentials = root.0.join("credentials"); configure(&node, &credentials);
        let before = generation(&node); let form = prepare_form(&history);
        let server = SourceServer::start(node, &credentials, 4);
        let stopped = post_form(&server.client, "rebase/prepare", 'a', &form, false);
        status(&stopped, 409); assert_eq!(field(json(&stopped), "state"), "became_empty");
        let dropped = post_form(&server.client, "rebase/prepare", 'a', &form.replace("empty=stop", "empty=drop"), true);
        let (metadata, bundle) = extract_candidate(&dropped);
        assert_eq!(numeric(&metadata, "step_count"), 2);
        assert_eq!(numeric(&metadata, "pack_objects"), 0);
        assert_eq!(field(&metadata, "candidate_commit"), history.onto.to_string());
        assert_eq!(metadata.matches("\"kind\":\"dropped_empty\"").count(), 2);
        let kept = post_form(&server.client, "rebase/prepare", 'a', &form.replace("empty=stop", "empty=keep"), false);
        let (kept, _) = extract_candidate(&kept);
        assert_ne!(field(&kept, "candidate_commit"), history.onto.to_string());
        assert_eq!(kept.matches("\"kind\":\"replayed\"").count(), 2);
        let applied = multipart(&server.client, "rebase/apply", 'b', &apply_form(&history, history.onto), &bundle, Some("drop-whole-suffix"));
        status(&applied, 200); assert!(json(&applied).contains("\"outcome\":\"committed\""));
        server.finish();
        let node = reopen(&root.config(format)); assert_eq!(generation(&node), before + 1);
        assert_eq!(tip(&node, b"refs/heads/topic"), history.onto); node.shutdown().unwrap();
    }
}
