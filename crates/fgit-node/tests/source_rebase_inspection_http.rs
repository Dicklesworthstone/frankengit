#![forbid(unsafe_code)]
//! Real listener -> native untrusted bundle inspector -> existing source JSON.
#[path = "source_rebase_http/support.rs"]
mod support;
use support::*;
use fgit_types::{GitHashAlgorithm, GitOid};

fn inspection_form(history: &History, candidate: GitOid) -> String {
    format!("profile=linear-v1&object_format={}&source_ref_hex={}&onto_ref_hex={}&expected_source={}&expected_onto={}&candidate_commit={candidate}",
        candidate.algorithm().as_str(), hex(b"refs/heads/topic"), hex(b"refs/heads/main"), history.source, history.onto)
}

#[test]
fn full_series_inspection_survives_restart_then_explicit_apply_retains_its_own_lease() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let (node, history) = fixture(&root, format, 0);
        let credentials = root.0.join("credentials"); configure(&node, &credentials);
        let before = generation(&node);
        let server = SourceServer::start(node, &credentials, 2);
        let prepared = post_form(&server.client, "rebase/prepare", 'a', &prepare_form(&history), false);
        let (metadata, bundle) = extract_candidate(&prepared);
        let candidate = GitOid::from_hex(format, field(&metadata, "candidate_commit")).unwrap();
        let intermediate = GitOid::from_hex(format, field(&metadata, "rewritten")).unwrap();
        let command = inspection_form(&history, candidate);
        let inspected = multipart(&server.client, "rebase/inspect", 'a', &command, &bundle, None);
        status(&inspected, 200);
        assert_eq!(numeric(json(&inspected), "commit_count"), 2);
        assert_eq!(json(&inspected).matches("\"type\":\"source_diff\"").count(), 3);
        assert!(json(&inspected).contains("\"net_change\":{\"type\":\"source_diff\""));
        for flag in ["\"objects_staged\":false", "\"transaction_created\":false", "\"published\":false",
            "\"publication_authorized\":false", "\"replay_equivalence_verified\":false",
            "\"all_rewritten_commits\":true", "\"all_changed_paths\":true"]
        { assert!(json(&inspected).contains(flag)); }
        for raw in [b"a\xff".as_slice(), b"b", b"onto"] {
            assert!(json(&inspected).contains(&format!("\"path_hex\":\"{}\"", hex(raw))));
        }
        assert!(json(&inspected).contains(&hex(b"author Original <original@example.invalid> 5 -0330\n")));
        assert_eq!(field(json(&inspected), "sha256"), field(&metadata, "sha256"));
        let head = field(json(&inspected), "snapshot_token").to_owned();
        server.finish();
        let node = reopen(&root.config(format));
        assert_eq!(generation(&node), before);
        assert!(node.read_git_object(candidate).is_err());
        assert!(node.read_git_object(intermediate).is_err());
        let server = SourceServer::start(node, &credentials, 4);
        let pinned = command.clone() + &format!("&expected_head={head}");
        let again = multipart(&server.client, "rebase/inspect", 'a', &pinned, &bundle, None);
        assert_eq!(again, inspected);
        let applied = multipart(&server.client, "rebase/apply", 'b', &apply_form(&history, candidate), &bundle, Some("inspected-rebase"));
        status(&applied, 200); assert!(json(&applied).contains("\"outcome\":\"committed\""));
        let stale = multipart(&server.client, "rebase/inspect", 'a', &pinned, &bundle, None);
        status(&stale, 409); assert!(json(&stale).contains("source_snapshot_moved"));
        let retried = multipart(&server.client, "rebase/apply", 'b', &apply_form(&history, candidate), &bundle, Some("inspected-rebase"));
        assert_eq!(retried, applied, "inspection freshness must not change terminal retry semantics");
        server.finish();
        let node = reopen(&root.config(format));
        assert_eq!(generation(&node), before + 1);
        assert_eq!(tip(&node, b"refs/heads/topic"), candidate);
        node.shutdown().unwrap();
    }
}

#[test]
fn scope_keys_limits_and_corruption_fail_closed_and_rotation_does_not_change_content() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let (node, history) = fixture(&root, format, 0);
        let credentials = root.0.join("credentials"); let grants = configure(&node, &credentials);
        let before = generation(&node);
        let server = SourceServer::start(node, &credentials, 10);
        let prepared = post_form(&server.client, "rebase/prepare", 'a', &prepare_form(&history), false);
        let (metadata, bundle) = extract_candidate(&prepared);
        let candidate = GitOid::from_hex(format, field(&metadata, "candidate_commit")).unwrap();
        let command = inspection_form(&history, candidate);
        let permitted = multipart(&server.client, "rebase/inspect", 'a', &command, &bundle, None);
        status(&permitted, 200);
        // Send no body: denial must precede 100-continue or waiting for payload.
        let denied = binary_exchange(&server.client, &request(&server.client, "POST", "/api/v1/source/rebase/inspect", 'b',
            "Content-Type: multipart/form-data; boundary=x\r\nContent-Length: 1\r\nExpect: 100-continue\r\n", &[]), false);
        status(&denied, 403); assert!(!denied.head.contains("100 Continue"));
        let key = binary_exchange(&server.client, &request(&server.client, "POST", "/api/v1/source/rebase/inspect", 'a',
            "Content-Type: multipart/form-data; boundary=x\r\nContent-Length: 1\r\nIdempotency-Key: not-an-inspection-transaction\r\n", &[]), false);
        status(&key, 400); assert!(json(&key).contains("source_read_has_no_transaction_key"));
        status(&multipart(&server.client, "rebase/inspect", 'a', &(command.clone()+"&max_changes=1"), &bundle, None), 413);
        let stale = command.replace(&format!("expected_source={}", history.source), &format!("expected_source={}", history.first));
        status(&multipart(&server.client, "rebase/inspect", 'a', &stale, &bundle, None), 409);
        let mut corrupt = bundle.clone(); *corrupt.last_mut().unwrap() ^= 1;
        let corrupt = multipart(&server.client, "rebase/inspect", 'a', &command, &corrupt, None);
        assert_ne!(corrupt.status, 200); assert!(!json(&corrupt).contains("\"complete\":true"));
        status(&multipart(&server.client, "rebase/inspect", 'a', &(command.clone()+"&path_prefix_hex=61"), &bundle, None), 400);
        replace(&credentials, &(grants + &row('b', OWNER, "receive,outcomes-read") + &row('c', OWNER, "read,outcomes-read")));
        status(&multipart(&server.client, "rebase/inspect", 'a', &command, &bundle, None), 401);
        assert_eq!(multipart(&server.client, "rebase/inspect", 'c', &command, &bundle, None), permitted);
        server.finish();
        let node = reopen(&root.config(format));
        assert_eq!(generation(&node), before);
        assert!(node.read_git_object(candidate).is_err());
        node.shutdown().unwrap();
    }
}

fn chunked_inspect(endpoint: &Endpoint, command: &str, bundle: &[u8], complete: bool) -> BinaryReply {
    let boundary = "inspect-series-fixture";
    assert!(!bundle.windows(boundary.len()).any(|p| p == boundary.as_bytes()));
    // Reverse MIME part order; ignored filenames must never select host files.
    let mut body = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"bundle\"; filename=\"../../never-open\"\r\nContent-Type: application/x-git-bundle\r\n\r\n").into_bytes();
    body.extend_from_slice(bundle);
    body.extend_from_slice(format!("\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"command\"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n{command}\r\n--{boundary}--\r\n").as_bytes());
    if !complete { body.truncate(body.len() - boundary.len() - 8); }
    let mut wire = Vec::new();
    for part in body.chunks(31) {
        wire.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
        wire.extend_from_slice(part); wire.extend_from_slice(b"\r\n");
    }
    wire.extend_from_slice(b"0\r\n\r\n");
    binary_exchange(endpoint, &request(endpoint, "POST", "/api/v1/source/rebase/inspect", 'a',
        &format!("Content-Type: multipart/form-data; boundary={boundary}\r\nTransfer-Encoding: chunked\r\n"), &wire), true)
}

#[test]
fn zero_commit_series_still_inspects_the_result_and_requires_complete_multipart_framing() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let (node, history) = fixture(&root, format, 2);
        let credentials = root.0.join("credentials"); configure(&node, &credentials);
        let before = generation(&node);
        let server = SourceServer::start(node, &credentials, 4);
        let prepared = post_form(&server.client, "rebase/prepare", 'a', &prepare_form(&history).replace("empty=stop", "empty=drop"), false);
        let (_, bundle) = extract_candidate(&prepared);
        let command = inspection_form(&history, history.onto);
        let inspected = multipart(&server.client, "rebase/inspect", 'a', &command, &bundle, None);
        status(&inspected, 200);
        assert_eq!(numeric(json(&inspected), "commit_count"), 0);
        assert_eq!(numeric(json(&inspected), "pack_objects"), 0);
        assert!(json(&inspected).contains("\"commits\":[]"));
        assert!(json(&inspected).contains(&format!("\"path_hex\":\"{}\"", hex(b"onto"))));
        assert_eq!(chunked_inspect(&server.client, &command, &bundle, true), inspected);
        status(&chunked_inspect(&server.client, &command, &bundle, false), 400);
        server.finish();
        let node = reopen(&root.config(format)); assert_eq!(generation(&node), before);
        assert_eq!(tip(&node, b"refs/heads/topic"), history.source); node.shutdown().unwrap();
    }
}
