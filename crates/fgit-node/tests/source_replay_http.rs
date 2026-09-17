#![forbid(unsafe_code)]
//! Real HTTP replay -> native bundle -> independent inspection -> sealed apply.
mod source_replay_http {
    pub mod support;
}
use source_replay_http::support::*;
use fgit_types::{GitHashAlgorithm, GitOid};

#[test]
fn native_cherry_pick_and_inverse_are_reproducible_read_only_and_target_complete() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, data) = non_clean_fixture(&root, format, false);
        let before = generation(&node); let path = root.0.join("credentials"); configure(&node, &path);
        let server = SourceServer::start(node, &path, 8);
        // topic is the root/base; main adds a new blob absent from topic history.
        let pick = form(&data.source_ref, &data.target_ref, data.source_tip, data.target_tip, data.target_tip);
        let first = post_form(&server.client, "cherry-pick/prepare", 'a', &pick, false); // 1
        let (metadata, bundle) = extract_candidate(&first);
        assert_eq!(field(&metadata, "direction"), "cherry-pick");
        assert_eq!(field(&metadata, "selected_parent"), data.source_tip.to_string());
        assert!(numeric(&metadata, "borrowed_objects") > 0);
        assert!(bundle.windows(data.source_tip.to_string().len()).any(|part| part == data.source_tip.to_string().as_bytes()));
        assert_eq!(post_form(&server.client, "cherry-pick/prepare", 'a', &pick, true), first); // 2
        let inverse = form(&data.target_ref, &data.target_ref, data.target_tip, data.target_tip, data.target_tip);
        let (reverted, _) = extract_candidate(&post_form(&server.client, "revert/prepare", 'a', &inverse, true)); // 3
        assert_eq!(field(&reverted, "direction"), "revert");
        assert_ne!(field(&reverted, "candidate_commit"), field(&metadata, "candidate_commit"));
        let unchanged = post_form(&server.client, "cherry-pick/prepare", 'a', &inverse, false); // 4
        status(&unchanged, 200); assert_eq!(field(json(&unchanged), "state"), "no_change");
        assert!(json(&unchanged).contains("\"bundle\":null"));
        let root_mainline = pick.replace(&format!("commit={}", data.target_tip), &format!("commit={}", data.source_tip)) + "&mainline=1";
        status(&post_form(&server.client, "cherry-pick/prepare", 'a', &root_mainline, false), 400); // 5
        let outside = form(&data.target_ref, &data.source_ref, data.target_tip, data.source_tip, data.target_tip);
        status(&post_form(&server.client, "cherry-pick/prepare", 'a', &outside, false), 404); // 6
        status(&post_form(&server.client, "cherry-pick/prepare", 'a', &(pick + "&max_objects=1"), false), 413); // 7
        let absent = binary_exchange(&server.client, &request(&server.client, "POST", "/api/v1/outcomes", 'a',
            "Content-Length: 0\r\nIdempotency-Key: read-only-source-query\r\n", &[]), true); // 8
        status(&absent, 200); assert!(json(&absent).contains("key_not_observed"));
        assert_eq!(server.finish().accepted_sessions(), 8);
        let node = reopen(&config); assert_eq!(generation(&node), before); node.shutdown().unwrap();
    }
}

#[test]
fn replay_artifact_is_inspected_and_published_only_by_explicit_recoverable_write() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, data) = non_clean_fixture(&root, format, false); let before = generation(&node);
        let path = root.0.join("credentials"); configure(&node, &path);
        let server = SourceServer::start(node, &path, 5);
        let pick = form(&data.source_ref, &data.target_ref, data.source_tip, data.target_tip, data.target_tip);
        let (metadata, bundle) = extract_candidate(&post_form(&server.client, "cherry-pick/prepare", 'a', &pick, false)); // 1
        let candidate = GitOid::from_hex(format, field(&metadata, "candidate_commit")).unwrap();
        let command = format!("object_format={}&ref={}&expected_commit={}&candidate_commit={candidate}",
            format.as_str(), encode(data.source_ref.as_bytes()), data.source_tip);
        let inspection = multipart(&server.client, "inspect", 'a', &command, &bundle, None); // 2
        status(&inspection, 200); assert!(json(&inspection).contains("source_inspection"));
        status(&multipart(&server.client, "apply", 'a', &command, &bundle, Some("remote-replay")), 403); // 3
        let published = multipart(&server.client, "apply", 'b', &command, &bundle, Some("remote-replay")); // 4
        status(&published, 200); assert!(json(&published).contains("\"outcome\":\"committed\""));
        assert_eq!(multipart(&server.client, "apply", 'b', &command, &bundle, Some("remote-replay")), published); // 5
        assert_eq!(server.finish().accepted_sessions(), 5);
        let node = reopen(&config); assert_eq!(generation(&node), before + 1);
        let server = SourceServer::start(node, &path, 3);
        assert_eq!(multipart(&server.client, "apply", 'b', &command, &bundle, Some("remote-replay")), published); // 1
        status(&post_form(&server.client, "cherry-pick/prepare", 'a', &pick, false), 409); // 2
        let query = format!("object_format={}&ref={}&path_hex={}", format.as_str(),
            encode(data.source_ref.as_bytes()), hex(b"file\xff.txt"));
        let file = post_form(&server.client, "blob", 'a', &query, false); // 3
        status(&file, 200); assert_eq!(field(json(&file), "content_hex"), hex(b"left\n"));
        assert_eq!(server.finish().accepted_sessions(), 3);
        let node = reopen(&config); assert_eq!(generation(&node), before + 1); node.shutdown().unwrap();
    }
}

#[test]
fn conflicts_pins_scopes_and_rotation_never_publish_or_consume_unauthorized_bodies() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, data) = non_clean_fixture(&root, format, true); let before = generation(&node);
        let path = root.0.join("credentials"); let header = configure(&node, &path);
        let server = SourceServer::start(node, &path, 9);
        let pick = form(&data.target_ref, &data.source_ref, data.target_tip, data.source_tip, data.source_tip);
        for action in ["cherry-pick/prepare", "revert/prepare"] { // 1, 2
            let conflict = post_form(&server.client, action, 'a', &pick, true);
            status(&conflict, 409);
            assert_eq!(field(json(&conflict), "state"), "conflicted");
            assert!(json(&conflict).contains(&hex(b"file\xff.txt")));
            assert!(json(&conflict).contains("\"candidate_commit\":null"));
        }
        let stale = pick.replace(&format!("expected_target={}", data.target_tip), &format!("expected_target={}", data.source_tip));
        status(&post_form(&server.client, "cherry-pick/prepare", 'a', &stale, false), 409); // 3
        status(&post_form(&server.client, "cherry-pick/prepare", 'a',
            &(pick.clone() + "&expected_head=alg:1:" + &"ab".repeat(32)), false), 409); // 4
        for (token, key, expected) in [('b', "", 403), ('a', "Idempotency-Key: forbidden-read-key\r\n", 400)] { // 5, 6
            let denied = binary_exchange(&server.client, &request(&server.client, "POST", "/api/v1/source/cherry-pick/prepare", token,
                &format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nExpect: 100-continue\r\n{key}", pick.len()), &[]), false);
            status(&denied, expected); assert!(!denied.head.contains("100 Continue"));
        }
        status(&post_form(&server.client, "cherry-pick/prepare", 'a', &(pick.clone() + "&force=true"), false), 400); // 7
        replace(&path, &(header + &row('9', OWNER, "read")));
        status(&post_form(&server.client, "cherry-pick/prepare", 'a', &pick, false), 401); // 8
        status(&post_form(&server.client, "cherry-pick/prepare", '9', &pick, false), 409); // 9
        assert_eq!(server.finish().accepted_sessions(), 9);
        let node = reopen(&config); assert_eq!(generation(&node), before); node.shutdown().unwrap();
    }
}
