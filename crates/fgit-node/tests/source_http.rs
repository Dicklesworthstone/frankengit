#![forbid(unsafe_code)]
//! Real HTTP -> native TreeFS/search -> embedded authority -> reopen. Byte
//! offsets, snapshot pins and explicit partial results are checked independently.
#[path = "source_http/support.rs"]
mod support;
use support::*;

use fgit_authority::{IdempotencyKey, key_recovery::RequestRecovery};
use fgit_forge::source_browse::SourceBrowseError;
use fgit_forge::source_search::{SearchCase, SearchCompletion, SearchLimits, SourceQuery};
use fgit_node::{LoopbackReceiveSession, NodeWorkspaceRefusal};
use fgit_types::{GitHashAlgorithm, GitOid, RefName};

#[test]
fn tree_and_file_pages_preserve_raw_bytes_modes_and_pins_after_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, main) = fixture(&root, format); let before = generation(&node);
        let path = root.0.join("credentials"); credentials(&node, &path);
        let server = Server::start(node, &path, 14, true, false);
        let query = common(format);
        let first = post(&server.client, "tree", 'a', &(query.clone() + "&limit=2"), false); // 1
        status(&first, 200);
        assert!(first.body.contains("\"type\":\"source_tree\""));
        assert_eq!(text(&first.body, "source_commit"), main.to_string());
        assert_eq!(text(&first.body, "next_after_hex"), hex(BINARY_PATH));
        let pin = token(&first);
        let next = post(&server.client, "tree", 'a', &format!("{query}&limit=2&after_hex={}&expected_head={pin}", hex(BINARY_PATH)), true); // 2
        status(&next, 200); assert_eq!(token(&next), pin);
        assert!(next.body.contains("\"name_hex\":\"646972\""));
        assert!(next.body.contains("\"name_hex\":\"656d707479\""));
        let binary_query = format!("{query}&path_hex={}", hex(BINARY_PATH));
        let binary = post(&server.client, "blob", 'a', &binary_query, true); // 3
        status(&binary, 200); assert_eq!(text(&binary.body, "content_hex"), hex(BINARY));
        assert!(binary.body.contains("\"next_offset\":null"));
        let slice = post(&server.client, "blob", 'a', &(binary_query.clone() + "&limit=3"), false); // 4
        status(&slice, 200); assert_eq!(text(&slice.body, "content_hex"), hex(&BINARY[..3]));
        assert_eq!(number(&slice.body, "next_offset"), 3);
        let slice = post(&server.client, "blob", 'a', &format!("{binary_query}&offset=3&limit=3&expected_head={pin}"), true); // 5
        status(&slice, 200); assert_eq!(text(&slice.body, "content_hex"), hex(&BINARY[3..6]));
        let eof = post(&server.client, "blob", 'a', &format!("{binary_query}&offset={}&limit=1&expected_head={pin}", BINARY.len()), false); // 6
        status(&eof, 200); assert_eq!(number(&eof.body, "returned_bytes"), 0);
        assert_eq!(text(&eof.body, "content_hex"), "");
        status(&post(&server.client, "blob", 'a', &format!("{binary_query}&offset={}&expected_head={pin}", BINARY.len() + 1), false), 400); // 7
        let empty = post(&server.client, "blob", 'a', &(query.clone() + "&path_hex=656d707479"), false); // 8
        status(&empty, 200); assert_eq!(number(&empty.body, "total_bytes"), 0);
        let link = post(&server.client, "blob", 'a', &(query.clone() + "&path_hex=6c696e6b"), false); // 9
        status(&link, 200); assert_eq!(text(&link.body, "content_hex"), hex(LINK));
        assert_eq!(text(&link.body, "kind"), "symlink");
        let traversal = post(&server.client, "blob", 'a', &(query.clone() + "&path_hex=" + &hex(b"link/secret")), false); // 10
        status(&traversal, 409); assert!(traversal.body.contains("symlink_not_followed"));
        let nested = post(&server.client, "tree", 'a', &(query.clone() + "&path_hex=646972"), false); // 11
        status(&nested, 200); assert!(nested.body.contains(&hex(b"nested.txt")));
        let executable = post(&server.client, "blob", 'a', &(query.clone() + "&path_hex=72756e"), false); // 12
        status(&executable, 200); assert_eq!(text(&executable.body, "kind"), "executable");
        status(&post(&server.client, "blob", 'a', &(query.clone() + "&path_hex=6d6f64756c65"), false), 409); // 13
        status(&post(&server.client, "blob", 'a', &(query.clone() + "&path_hex=616273656e74"), false), 404); // 14
        assert_eq!(server.finish().accepted_sessions(), 14);
        let node = reopen(&config); assert_eq!(generation(&node), before);
        let session = LoopbackReceiveSession::authenticated(OWNER, IdempotencyKey::new(b"read-only-source-query".to_vec()).unwrap());
        assert!(matches!(node.runtime().block_on(node.recover_transaction_in(&node.request_context(), &session)).unwrap(), RequestRecovery::KeyNotObserved));
        let server = Server::start(node, &path, 2, true, false);
        assert_eq!(post(&server.client, "tree", 'a', &(query + "&limit=2"), false), first);
        assert_eq!(post(&server.client, "blob", 'a', &binary_query, false), binary);
        assert_eq!(server.finish().accepted_sessions(), 2);
        let node = reopen(&config); assert_eq!(generation(&node), before); node.shutdown().unwrap();
    }
}

#[test]
fn literal_search_reports_overlap_binary_content_component_prefixes_and_real_truncation() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, _) = fixture(&root, format); let before = generation(&node);
        let path = root.0.join("credentials"); credentials(&node, &path);
        let server = Server::start(node, &path, 10, true, false);
        let query = common(format);
        let needle = format!("{query}&needle_hex={}", hex(b"needle"));
        let complete = post(&server.client, "search", 'a', &needle, false); // 1
        status(&complete, 200); assert_eq!(number(&complete.body, "returned_matches"), 4);
        assert_eq!(text(&complete.body, "completion"), "complete");
        assert_eq!(number(&complete.body, "files_selected"), 5);
        assert_eq!(number(&complete.body, "non_regular_entries"), 2);
        assert!(complete.body.contains(&hex(BINARY_PATH)));
        let limited = post(&server.client, "search", 'a', &(needle.clone() + "&max_matches=1"), true); // 2
        status(&limited, 200); assert_eq!(number(&limited.body, "returned_matches"), 1);
        assert!(limited.body.contains("\"completion\":\"match_limit\",\"complete\":false"));
        let exact_bound = post(&server.client, "search", 'a', &(needle.clone() + "&max_matches=4"), false); // 3
        status(&exact_bound, 200); assert_eq!(text(&exact_bound.body, "completion"), "complete");
        let folded = post(&server.client, "search", 'a', &(needle.clone() + "&case=ascii-insensitive"), false); // 4
        status(&folded, 200); assert_eq!(number(&folded.body, "returned_matches"), 5);
        let overlap = post(&server.client, "search", 'a', &format!("{query}&needle_hex=616261"), false); // 5
        status(&overlap, 200); assert_eq!(number(&overlap.body, "returned_matches"), 2);
        assert!(overlap.body.contains("\"byte_offset\":15,\"line\":2,\"byte_column\":1"));
        assert!(overlap.body.contains("\"byte_offset\":17,\"line\":2,\"byte_column\":3"));
        let binary = post(&server.client, "search", 'a', &format!("{query}&needle_hex=00ff"), true); // 6
        status(&binary, 200); assert_eq!(number(&binary.body, "returned_matches"), 1);
        // Excerpts stop before the terminating LF; CR and all prior binary
        // bytes remain exact. Blob reads above include the complete CRLF.
        assert_eq!(text(&binary.body, "excerpt_hex"), hex(&BINARY[..BINARY.len() - 1]));
        assert!(text(&binary.body, "excerpt_hex").ends_with("0d"));
        let prefix = post(&server.client, "search", 'a', &(needle.clone() + "&path_prefix_hex=646972"), false); // 7
        status(&prefix, 200); assert_eq!(number(&prefix.body, "returned_matches"), 1);
        assert_eq!(text(&prefix.body, "path_hex"), hex(b"dir/nested.txt"));
        let not_component = post(&server.client, "search", 'a', &(needle.clone() + "&path_prefix_hex=6469"), false); // 8
        status(&not_component, 200); assert_eq!(number(&not_component.body, "returned_matches"), 0);
        assert_eq!(text(&not_component.body, "completion"), "complete");
        let no_link_following = post(&server.client, "search", 'a', &format!("{query}&needle_hex={}", hex(LINK)), false); // 9
        status(&no_link_following, 200); assert_eq!(number(&no_link_following.body, "returned_matches"), 0);
        let exhausted = post(&server.client, "search", 'a', &(needle + "&max_bytes=1"), false); // 10
        status(&exhausted, 413); assert!(exhausted.body.contains("\"type\":\"source_error\""));
        assert!(!exhausted.body.contains("\"matches\":[]"));
        assert_eq!(server.finish().accepted_sessions(), 10);
        let node = reopen(&config); assert_eq!(generation(&node), before); node.shutdown().unwrap();
    }
}

fn issue(client: &Endpoint) -> Reply {
    let body = b"expected_version=0&title=Intervening+write&body=";
    exchange(client, &request(client, "/api/v1/issues/1/open", 'b',
        &format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: unrelated-issue\r\n", body.len()), body), true)
}
fn recover_read_sentinel(client: &Endpoint) -> Reply {
    exchange(client, &request(client, "/api/v1/outcomes", 'c',
        "Content-Length: 0\r\nIdempotency-Key: read-only-source-query\r\n", &[]), true)
}
#[test]
fn current_head_pins_refuse_intervening_writes_and_read_credentials_rotate_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, main) = fixture(&root, format); let before = generation(&node);
        let path = root.0.join("credentials"); let header = credentials(&node, &path);
        let server = Server::start(node, &path, 10, true, true);
        let query = common(format);
        let first = post(&server.client, "tree", 'a', &(query.clone() + "&limit=1"), false); // 1
        status(&first, 200); let old = token(&first);
        let search = format!("{query}&needle_hex={}", hex(b"needle"));
        let old_search = post(&server.client, "search", 'a', &format!("{search}&expected_head={old}"), false); // 2
        status(&old_search, 200); assert_eq!(token(&old_search), old);
        let blob = format!("{query}&path_hex={}", hex(BINARY_PATH));
        status(&post(&server.client, "blob", 'a', &format!("{blob}&limit=2&expected_head={old}"), false), 200); // 3
        let written = issue(&server.client); // 4
        status(&written, 200); assert!(written.body.contains("\"outcome\":\"committed\""));
        for (operation, command) in [
            ("tree", format!("{query}&after_hex=616c7068612e747874&expected_head={old}")),
            ("search", format!("{search}&expected_head={old}")),
            ("blob", format!("{blob}&offset=2&expected_head={old}")),
        ] { // 5, 6, 7
            let stale = post(&server.client, operation, 'a', &command, false);
            status(&stale, 409); assert!(stale.body.contains("source_snapshot_moved"));
            assert!(!stale.body.contains("\"published\":true"));
        }
        let current_query = format!("{search}&expected_commit={main}");
        let current = post(&server.client, "search", 'a', &current_query, true); // 8
        status(&current, 200); assert_ne!(token(&current), old);
        assert_eq!(number(&current.body, "returned_matches"), 4);
        let current_blob_query = format!("{blob}&expected_head={}", token(&current));
        let current_blob = post(&server.client, "blob", 'a', &current_blob_query, false); // 9
        status(&current_blob, 200); assert_eq!(text(&current_blob.body, "content_hex"), hex(BINARY));
        let absent = recover_read_sentinel(&server.client); // 10
        status(&absent, 200); assert!(absent.body.contains("\"state\":\"key_not_observed\""));
        server.finish();
        let node = reopen(&config); assert_eq!(generation(&node), before + 1);
        replace(&path, &(header.clone() + &row('9', OWNER, "read") + &row('c', OWNER, "outcomes-read")));
        let server = Server::start(node, &path, 5, true, false);
        status(&post(&server.client, "search", 'a', &current_query, false), 401); // 1
        assert_eq!(post(&server.client, "search", '9', &current_query, false), current); // 2
        replace(&path, "malformed\n");
        let unavailable = post(&server.client, "search", '9', &current_query, false); // 3
        status(&unavailable, 503); assert!(unavailable.body.contains("\"outcome_unknown\":false"));
        replace(&path, &(header + &row('9', OWNER, "read") + &row('c', OWNER, "outcomes-read")));
        assert_eq!(post(&server.client, "blob", '9', &current_blob_query, true), current_blob); // 4
        assert_eq!(recover_read_sentinel(&server.client), absent); // 5
        assert_eq!(server.finish().accepted_sessions(), 5);
        let node = reopen(&config); assert_eq!(generation(&node), before + 1); node.shutdown().unwrap();
    }
}

fn withheld(client: &Endpoint, token: char, extra: &str, length: usize) -> Reply {
    let reply = exchange(client, &request(client, "/api/v1/source/tree", token,
        &format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {length}\r\nExpect: 100-continue\r\n{extra}"), &[]), false);
    assert!(!reply.raw.contains("100 Continue")); reply
}
#[test]
fn deployment_credentials_and_complete_envelopes_gate_every_source_read() {
    let format = GitHashAlgorithm::Sha256;
    let root = Scratch::new(); let config = root.config(format);
    let (node, _) = fixture(&root, format); let before = generation(&node);
    let path = root.0.join("credentials"); credentials(&node, &path);
    let query = common(format);
    let disabled = Server::start(node, &path, 2, false, false);
    status(&post(&disabled.client, "tree", 'a', &query, false), 403);
    status(&withheld(&disabled.client, 'a', "", 100), 403);
    assert_eq!(disabled.finish().refused_sessions(), 2);
    let node = reopen(&config);
    let enabled = Server::start(node, &path, 12, true, true);
    status(&withheld(&enabled.client, 'b', "", 100), 403); // 1: all write/metadata scopes, no read.
    status(&withheld(&enabled.client, 'a', "Idempotency-Key: not-a-mutation\r\n", 100), 400); // 2
    status(&withheld(&enabled.client, 'a', "", 256 * 1024 + 1), 413); // 3
    let forged = format!("POST {}/api/v1/source/tree HTTP/1.1\r\nHost: local\r\nX-Forwarded-User: owner\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\r\nExpect: 100-continue\r\n\r\n", enabled.client.route);
    let denied = exchange(&enabled.client, forged.as_bytes(), false); // 4
    status(&denied, 401); assert!(!denied.raw.contains("100 Continue"));
    status(&post(&enabled.client, "tree", 'a', &(query.clone() + "&ref=refs/heads/other"), false), 400); // 5
    status(&post(&enabled.client, "tree", 'a', &query.replace("sha256", "sha1"), false), 400); // 6
    status(&post(&enabled.client, "blob", 'a', &(query.clone() + "&path_hex=" + &hex(b"../outside-secret")), false), 400); // 7
    let incomplete = request(&enabled.client, "/api/v1/source/tree", 'a',
        &format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n", query.len() + 1), query.as_bytes());
    status(&exchange(&enabled.client, &incomplete, true), 400); // 8
    let chunks = format!("{:x}\r\n{query}\r\n0\r\n", query.len());
    status(&exchange(&enabled.client, &request(&enabled.client, "/api/v1/source/tree", 'a',
        "Content-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\n", chunks.as_bytes()), true), 400); // 9
    status(&post(&enabled.client, "tree", 'a', &(query.clone() + "&object_id=" + &"a".repeat(64)), false), 400); // 10
    let body = b"expected_version=0&title=No+issue+grant&body=";
    status(&exchange(&enabled.client, &request(&enabled.client, "/api/v1/issues/2/open", 'a',
        &format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: forbidden-issue\r\n", body.len()), body), true), 403); // 11
    status(&post(&enabled.client, "tree", 'a', &query, false), 200); // 12
    assert_eq!(enabled.finish().accepted_sessions(), 12);
    let node = reopen(&config); assert_eq!(generation(&node), before); node.shutdown().unwrap();
}

#[test]
fn native_search_binds_preconditions_and_refuses_cancelled_or_wrong_domain_reads() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let (node, main) = fixture(&root, format);
        let before = generation(&node); let reference = RefName::try_new(b"refs/heads/main").unwrap();
        let query = SourceQuery::new(b"needle", SearchCase::Exact, &[]).unwrap();
        let request = node.request_context();
        let (head, report) = node.runtime().block_on(node.search_source_snapshot_local_in(
            &request, &reference, None, Some(main), &query, SearchLimits::default())).unwrap();
        assert_eq!(report.source_commit, main); assert_eq!(report.completion, SearchCompletion::Complete);
        assert_eq!(report.matches.len(), 4);
        assert_eq!(node.runtime().block_on(node.search_source_snapshot_local_in(
            &request, &reference, Some(head), Some(main), &query, SearchLimits::default())).unwrap(), (head, report));
        let other = GitOid::from_hex(format, &"e".repeat(format.digest_len() * 2)).unwrap();
        let failure = node.runtime().block_on(node.search_source_snapshot_local_in(
            &request, &reference, Some(head), Some(other), &query, SearchLimits::default())).unwrap_err();
        assert!(matches!(failure, NodeWorkspaceRefusal::SourceBrowse(error) if matches!(*error, SourceBrowseError::CommitMoved)));
        let foreign = match format { GitHashAlgorithm::Sha1 => GitHashAlgorithm::Sha256, GitHashAlgorithm::Sha256 => GitHashAlgorithm::Sha1 };
        let foreign = GitOid::from_hex(foreign, &"a".repeat(foreign.digest_len() * 2)).unwrap();
        assert!(node.runtime().block_on(node.search_source_snapshot_local_in(
            &request, &reference, None, Some(foreign), &query, SearchLimits::default())).is_err());
        let cancelled = node.request_context(); cancelled.cancel();
        assert!(node.runtime().block_on(node.search_source_snapshot_local_in(
            &cancelled, &reference, None, None, &query, SearchLimits::default())).is_err());
        assert_eq!(generation(&node), before); node.shutdown().unwrap();
    }
}
