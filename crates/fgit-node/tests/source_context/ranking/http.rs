//! Opt-in fusion through the actual source gateway and native index stores.
use super::*;
use fgit_node::source_retrieval::context::ranked::PROFILE;

fn form(format: GitHashAlgorithm) -> String {
    format!("object_format={}&ref=refs/heads/main&term_hex=5468696e67&symbol_name_hex=5468696e67&symbol_match=prefix", format.as_str())
}
#[test]
fn authenticated_ranked_context_preserves_legacy_selection_and_exposes_exact_score_receipts() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, _) = rank_corpus(&root, format, true); let canonical = generation(&node);
        let report = initial(&node, b"Thing", true, &[]);
        let pin = report.generations().symbols.as_ref().unwrap();
        let id = pin.generation_id.as_internal_object_id();
        let higher = format!("&minimum_symbol_token=alg:{}:{}&minimum_symbol_number={}",
            id.algorithm().code_point(), hex(id.digest().as_bytes()), pin.authority_generation.get()+1);
        let path = root.0.join("credentials"); credentials(&node, &path);
        let server = Server::start(node, &path, 12, true, false);
        let raw_form = form(format)+"&context_max_files=1";
        let raw = post(&server.client, "context-initial", 'a', &raw_form, false); status(&raw, 200);
        assert!(raw.body.contains(&format!("\"files\":[{{\"path_hex\":\"{}\"", hex(b"00.txt"))));
        assert!(!raw.body.contains("\"ranking\":"));
        let explicit = post(&server.client, "context-initial", 'a', &(raw_form.clone()+"&context_selection=raw-path-prefix"), true);
        status(&explicit, 200); assert_eq!(explicit.body, raw.body);
        let ranked_form = raw_form+"&context_selection="+PROFILE;
        let selected = post(&server.client, "context-initial", 'a', &ranked_form, false); status(&selected, 200);
        assert!(selected.body.contains(&format!("\"selection\":\"{PROFILE}\"")));
        assert!(selected.body.contains(&format!("\"files\":[{{\"path_hex\":\"{}\"", hex(b"a/Thing.rs"))));
        assert_eq!(number(&selected.body, "source_blobs_read"), 1);
        assert_eq!(number(&selected.body, "source_bytes_read") as usize, A.len());
        assert_eq!(number(&selected.body, "score_q16"), 4279);
        assert_eq!(number(&selected.body, "omitted_files"), 4);
        assert!(selected.body.contains("\"input_order\":\"raw-path-distinct-documents\""));
        assert!(selected.body.contains("\"channel\":\"symbol\",\"document_rank\":1,\"weight\":2,\"score_q16\":2148"));
        assert!(selected.body.contains(&hex(A)));
        let chunked = post(&server.client, "context-initial", 'a', &ranked_form, true);
        status(&chunked, 200); assert_eq!(chunked.body, selected.body);
        let scoped = post(&server.client, "context-initial", 'a', &(ranked_form.clone()+"&path_prefix_hex=62"), false);
        status(&scoped, 200); assert_eq!(number(&scoped.body, "candidate_files"), 1);
        assert!(scoped.body.contains(&format!("\"files\":[{{\"path_hex\":\"{}\"", hex(b"b/Thing.txt"))));
        for (endpoint, token, body, expected) in [
            ("context-initial", 'a', ranked_form.clone()+"&context_selection=raw-path-prefix", 400),
            ("context-initial", 'a', ranked_form.replace(PROFILE, "semantic"), 400),
            ("search-initial", 'a', form(format)+"&context_selection="+PROFILE, 400),
            ("context-initial", 'a', ranked_form.clone()+&format!("&context_max_excerpt_bytes={}", A.len()-1), 413),
            ("context-initial", 'b', ranked_form.clone(), 403),
            ("context-initial", 'a', ranked_form.clone()+&higher, 409),
        ] {
            let refused = post(&server.client, endpoint, token, &body, false);
            status(&refused, expected); assert!(!refused.body.contains("\"ranking\":"));
        }
        let headers = format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: no-ranking-transaction\r\n", ranked_form.len());
        let request = request(&server.client, "/api/v1/source/context-initial", 'a', &headers, ranked_form.as_bytes());
        status(&exchange(&server.client, &request, true), 400);
        assert_eq!(server.finish().accepted_sessions(), 12);
        let node = reopen(&config); assert_eq!(generation(&node), canonical);
        let current = initial(&node, b"Thing", true, &[]);
        assert_eq!(current.generations(), report.generations()); node.shutdown().unwrap();
    }
}

#[test]
fn optional_channels_empty_rankings_revocation_and_disabled_source_are_not_bypassed() {
    let format = GitHashAlgorithm::Sha256; let root = Scratch::new(); let config = root.config(format);
    let (node, _) = rank_corpus(&root, format, false); let canonical = generation(&node);
    let path = root.0.join("credentials"); let header = credentials(&node, &path);
    let server = Server::start(node, &path, 3, true, false);
    let input = form(format)+"&context_selection="+PROFILE;
    let partial = post(&server.client, "context-initial", 'a', &input, false); status(&partial, 200);
    assert!(partial.body.contains("\"state\":\"unavailable\",\"reason\":\"uninitialized\""));
    assert!(!partial.body.contains("\"channel\":\"symbol\",\"document_rank\""));
    assert!(partial.body.split_once("\"complete\":").unwrap().1.starts_with("false"));
    let empty = format!("object_format={}&ref=refs/heads/main&term_hex={}&context_selection={PROFILE}", format.as_str(), hex(b"NoSuchToken"));
    let empty = post(&server.client, "context-initial", 'a', &empty, true); status(&empty, 200);
    assert_eq!(number(&empty.body, "source_blobs_read"), 0);
    assert!(empty.body.contains("\"selected\":[]"));
    replace(&path, &(header+&row('c', OWNER, "outcomes-read")));
    status(&post(&server.client, "context-initial", 'a', &input, false), 401);
    server.finish();
    let node = reopen(&config); assert_eq!(generation(&node), canonical); credentials(&node, &path);
    let server = Server::start(node, &path, 1, false, false);
    status(&post(&server.client, "context-initial", 'a', &input, false), 403);
    server.finish();
}
