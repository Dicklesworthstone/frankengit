use super::*;
const BASE: &str = "object_format=sha1&ref=refs/heads/main&term_hex=5468696e67";

#[test]
fn context_limits_are_separate_from_retrieval_and_validated_before_io() {
    let input = format!("{BASE}&context_max_files=2&context_radius_bytes=0&context_max_source_bytes=30&context_max_excerpt_bytes=10");
    let parsed = command(input.as_bytes(), GitHashAlgorithm::Sha1).unwrap();
    assert_eq!(parsed.limits, ContextLimits { max_files: 2, radius_bytes: 0, max_source_bytes: 30, max_excerpt_bytes: 10 });
    assert_eq!(parsed.initial.query.content().terms(), &[b"thing".to_vec()]);
    assert_eq!(parsed.initial.limits, InitialLimits::default());
    // The old read remains an index-only query; it cannot silently acquire
    // context/file-read semantics because an extra parameter was supplied.
    assert!(super::super::command(input.as_bytes(), GitHashAlgorithm::Sha1).is_err());
    for suffix in ["&context_max_files=0", "&context_max_files=33", "&context_radius_bytes=4097",
        "&context_radius_bytes=-1", "&context_max_source_bytes=67108865", "&context_max_excerpt_bytes=1048577",
        "&context_max_excerpt_bytes=0", "&context_max_files=1&context_max_files=2", "&force=true", "&after=1"] {
        assert!(command((BASE.to_owned()+suffix).as_bytes(), GitHashAlgorithm::Sha1).is_err());
    }
}

#[test]
fn scope_symbols_and_checkpoint_pairs_use_the_original_closed_grammar() {
    let input = format!("{BASE}&path_prefix_hex=737263&symbol_name_hex=5468696e67&symbol_match=prefix&symbol_policy=required\
        &minimum_symbol_token=alg:2:{}&minimum_symbol_number=3", "a".repeat(64));
    let parsed = command(input.as_bytes(), GitHashAlgorithm::Sha1).unwrap();
    assert_eq!(parsed.initial.query.path().prefixes(), &[b"src".to_vec()]);
    assert_eq!(parsed.initial.query.symbols().unwrap().0.name(), b"Thing");
    assert_eq!(parsed.initial.checkpoints.symbols.unwrap().authority_generation.get(), 3);
    for suffix in ["&path_prefix_hex=2e2e2f70726976617465", "&symbol_policy=required",
        "&minimum_symbol_number=3", "&term_hex=612e2a", "&expected_commit=00", "&object_format=sha1"] {
        assert!(command((BASE.to_owned()+suffix).as_bytes(), GitHashAlgorithm::Sha1).is_err());
    }
}

#[test]
fn source_gateway_recognizes_context_as_a_read_and_preserves_envelope_refusals() {
    for operation in ["context-initial", "search-initial"] {
        let text = format!("POST /r.git/api/v1/source/{operation} HTTP/1.1\r\nHost: local\r\n\
            Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n\r\n");
        let head = fgit_wire::smart_http::head::parse(text.as_bytes(), HttpLimits::default()).unwrap().unwrap();
        let request = super::super::Request::parse(&head).unwrap().unwrap();
        assert_eq!(request.hydrate, operation == "context-initial");
        assert_eq!(request.repository_route, "/r.git");
        assert!(!super::super::super::Request::parse(&head).unwrap().is_mutation());
        for bad in [text.replacen("POST", "GET", 1), text.replace("context-initial HTTP", "context-initial?force=1 HTTP")
            .replace("search-initial HTTP", "search-initial?force=1 HTTP"),
            text.replace("Content-Length: 1", "Content-Length: 0"),
            text.replace("application/x-www-form-urlencoded", "application/json")] {
            let head = fgit_wire::smart_http::head::parse(bad.as_bytes(), HttpLimits::default()).unwrap().unwrap();
            assert!(super::super::Request::parse(&head).is_err());
        }
    }
}

#[test]
fn raw_hex_output_has_exact_limits_and_checks_cancellation_during_large_excerpts() {
    let mut output = String::new();
    append_hex(&mut output, b"\0\xff\r\n", 8, &mut || true).unwrap();
    assert_eq!(output, "00ff0d0a");
    let mut output = String::new();
    assert!(append_hex(&mut output, b"\0\xff\r\n", 7, &mut || true).is_err());
    assert!(output.is_empty());
    let bytes = vec![b'x'; 8193];
    let mut probes = 0;
    assert!(append_hex(&mut output, &bytes, 20000, &mut || { probes += 1; probes < 3 }).is_err());
    assert!(output.len() < bytes.len()*2);
    assert!(append_hex(&mut output, b"", 20000, &mut || false).is_err());
}

#[test]
fn invalid_hydration_evidence_is_not_success_or_client_syntax_failure() {
    assert_eq!(failure(RetrievalError::Invalid("context anchor/source mismatch")).status, Status::Unavailable);
    assert_eq!(failure(RetrievalError::MixedSource).status, Status::Conflict);
    assert_eq!(failure(RetrievalError::Limit("context excerpt bytes")).status, Status::TooLarge);
}
