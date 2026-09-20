use super::*;
use fgit_graph::lexical::{LexicalHit, LexicalNamespace, LexicalReport, LexicalSource, LexicalSpan};
use fgit_types::{RepositoryAuthorityHeadId, RepositoryCommitId, RepositoryId, RepositoryIncarnationId, SchemaFamily, SchemaId, TenantId};
fn form() -> String { "object_format=sha1&ref=refs/heads/main&term_hex=4e4545444c45".to_owned() }
fn id_text() -> String {
    format!("alg:{}:{}", fgit_crypto::internal_algorithm_id(fgit_crypto::IdentityDomain::Generation).code_point(), "a".repeat(64))
}
fn report() -> IndexedLexicalReport {
    use fgit_crypto::{IdentityDomain, internal_object_id};
    let internal = |domain, family| internal_object_id(domain,
        SchemaId::new(SchemaFamily::from_static(family), 1, 0), CANONICAL_CODEC_VERSION, b"indexed-http-test");
    let head = internal(IdentityDomain::RepositoryAuthorityHead, "repository-authority-head");
    let source = LexicalSource {
        namespace: LexicalNamespace { tenant: TenantId::from_bytes([1;16]), repository: RepositoryId::from_bytes([2;16]),
            incarnation: RepositoryIncarnationId::from_bytes([3;16]), object_format: GitHashAlgorithm::Sha1 },
        reference: RefName::try_new(b"refs/heads/main").unwrap(),
        source_head: RepositoryAuthorityHeadId::from_internal_object_id(head).unwrap(),
        source_rcr: RepositoryCommitId::from_internal_object_id(internal(IdentityDomain::RepositoryCommitRecord, "repository-commit-record")).unwrap(),
        forge_position_root: fgit_types::Digest::new(head.algorithm(), *head.digest()),
        commit: GitOid::from_hex(GitHashAlgorithm::Sha1, &"b".repeat(40)).unwrap(),
        tree: GitOid::from_hex(GitHashAlgorithm::Sha1, &"c".repeat(40)).unwrap(),
    };
    let activation = GenerationActivation { generation_id: generation_id(&id_text()).unwrap(), authority_generation: HeadGeneration::FIRST };
    IndexedLexicalReport { source, generation: activation.clone(), selected_generation_head: activation,
        query: command(form().as_bytes(), GitHashAlgorithm::Sha1).unwrap().query,
        results: LexicalReport { hits: vec![LexicalHit { document_id: 1, path: b"file.txt".to_vec(),
            blob: GitOid::from_hex(GitHashAlgorithm::Sha1, &"d".repeat(40)).unwrap(), content_bytes: 6,
            spans: vec![LexicalSpan { query_index: 0, byte_offset: 0, byte_length: 6 }] }],
            complete: true, next_after: None, work_units: 10 },
        indexed_documents: 1, indexed_source_bytes: 6, non_regular_entries: 0, segments_read: 1,
        payload_bytes_read: 100, generation_bytes_read: 100 }
}
#[test]
fn terms_are_conjoined_normalized_and_not_interpreted_as_patterns_or_authority() {
    let c = command((form() + "&term_hex=6e6565646c65&path_prefix_hex=737263&path_prefix_hex=737263").as_bytes(), GitHashAlgorithm::Sha1).unwrap();
    assert_eq!(c.query.terms(), &[b"needle".to_vec()]); assert_eq!(c.query.prefixes(), &[b"src".to_vec()]);
    for suffix in ["&term_hex=61ff", "&term_hex=612062", "&term_hex=61%2a", "&channel=semantic",
        "&ref=refs/heads/other", "&principal=admin", "&build=true", "&limit=0", "&max_work=0",
        "&max_payload_bytes=33554433", "&path_prefix_hex=2e2e2f78", "&path_prefix_hex=2e676974"] {
        assert!(command((form() + suffix).as_bytes(), GitHashAlgorithm::Sha1).is_err(), "{suffix}");
    }
    assert!(command((form() + &"&term_hex=61".repeat(32)).as_bytes(), GitHashAlgorithm::Sha1).is_err());
    assert!(command(form().as_bytes(), GitHashAlgorithm::Sha256).is_err());
}
#[test]
fn index_identity_position_pairs_and_source_pins_are_independent_and_complete() {
    let binding = report().source;
    let extra = format!("&index_token={}&index_number=1&expected_head={}&expected_commit={}&after=1",
        id_text(), token(binding.source_head.as_internal_object_id()), binding.commit);
    let c = command((form() + &extra).as_bytes(), GitHashAlgorithm::Sha1).unwrap(); assert_eq!(c.after, Some(1));
    for suffix in [format!("&index_token={}", id_text()), "&index_number=1".to_owned(),
        "&minimum_index_number=2".to_owned(), "&after=0".to_owned(), "&after=1".to_owned(),
        format!("&index_token={}&index_number=0", id_text()),
        format!("&index_token={}&index_number=01", id_text())] {
        assert!(command((form() + &suffix).as_bytes(), GitHashAlgorithm::Sha1).is_err());
    }
    for value in [format!("alg:1:{}", "a".repeat(40)), format!("alg:2:{}", "0".repeat(64)),
        id_text() + "a", id_text().to_ascii_uppercase(), format!("alg:02:{}", "a".repeat(64))] {
        assert!(generation_id(&value).is_err());
    }
    assert!(command((form() + &format!("&minimum_index_token={}&minimum_index_number=1", id_text())).as_bytes(), GitHashAlgorithm::Sha1).is_ok());
}
#[test]
fn route_cannot_accept_builds_queries_other_media_or_protocol_options() {
    for (method, target, extra, length, media) in [
        ("GET", "/r.git/api/v1/source/search-index", "", 1, "application/x-www-form-urlencoded"),
        ("POST", "/r.git/api/v1/source/search-index?q=a", "", 1, "application/x-www-form-urlencoded"),
        ("POST", "/../r.git/api/v1/source/search-index", "", 1, "application/x-www-form-urlencoded"),
        ("POST", "/r.git/api/v1/source/search-index", "Git-Protocol: version=2\r\n", 1, "application/x-www-form-urlencoded"),
        ("POST", "/r.git/api/v1/source/search-index", "", 0, "application/x-www-form-urlencoded"),
        ("POST", "/r.git/api/v1/source/search-index", "", 1, "application/json"),
    ] {
        let bytes = format!("{method} {target} HTTP/1.1\r\nHost: local\r\nContent-Type: {media}\r\nContent-Length: {length}\r\n{extra}\r\n");
        let head = fgit_wire::smart_http::head::parse(bytes.as_bytes(), HttpLimits::default()).unwrap().unwrap();
        assert!(Request::parse(&head).is_err());
    }
    for action in ["search-index/build", "index/build", "search-regex"] {
        let bytes = format!("POST /r.git/api/v1/source/{action} HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n\r\n");
        let head = fgit_wire::smart_http::head::parse(bytes.as_bytes(), HttpLimits::default()).unwrap().unwrap();
        assert!(Request::parse(&head).unwrap().is_none());
    }
}
#[test]
fn result_rows_refuse_wrong_coordinates_order_counts_format_and_scope() {
    let c = command(form().as_bytes(), GitHashAlgorithm::Sha1).unwrap();
    let original = report(); assert!(rows(&c, &original, usize::MAX, &mut || true).is_ok());
    for change in 0..9 {
        let mut r = original.clone();
        match change {
            0 => r.results.hits[0].spans[0].byte_offset = 1,
            1 => r.results.hits[0].spans[0].query_index = 1,
            2 => r.results.hits[0].document_id = 0,
            3 => r.results.hits[0].blob = GitOid::from_hex(GitHashAlgorithm::Sha256, &"a".repeat(64)).unwrap(),
            4 => r.results.hits[0].path = b"../file".to_vec(),
            5 => r.results.next_after = Some(1),
            6 => r.results.hits.push(r.results.hits[0].clone()),
            7 => r.results.work_units = MAX_WORK + 1,
            _ => r.payload_bytes_read = c.reads.max_payload_bytes + 1,
        }
        assert!(rows(&c, &r, usize::MAX, &mut || true).is_err(), "case {change}");
    }
    let c = command((form() + "&path_prefix_hex=737263").as_bytes(), GitHashAlgorithm::Sha1).unwrap();
    let mut r = original; r.query = c.query.clone();
    assert!(rows(&c, &r, usize::MAX, &mut || true).is_err());
    r.results.hits[0].path = b"src/file".to_vec();
    assert!(rows(&c, &r, usize::MAX, &mut || true).is_ok());
}
#[test]
fn exact_row_limit_does_not_imply_truncation_and_response_bounds_are_exact() {
    let c = command((form() + "&limit=1").as_bytes(), GitHashAlgorithm::Sha1).unwrap();
    let mut r = report();
    let body = rows(&c, &r, usize::MAX, &mut || true).unwrap();
    assert_eq!(rows(&c, &r, body.len(), &mut || true).unwrap(), body);
    assert!(rows(&c, &r, body.len() - 1, &mut || true).is_err());
    assert!(rows(&c, &r, usize::MAX, &mut || false).is_err());
    r.results.complete = false; assert!(rows(&c, &r, usize::MAX, &mut || true).is_err());
    r.results.next_after = Some(1); assert!(rows(&c, &r, usize::MAX, &mut || true).is_ok());
}
#[test]
fn failed_reads_do_not_fabricate_empty_results_or_canonical_write_decisions() {
    for error in [NodeWorkspaceRefusal::SourceIndexStale,
        NodeWorkspaceRefusal::SourceIndex(Box::new(IndexError::Uninitialized)),
        NodeWorkspaceRefusal::SourceIndex(Box::new(IndexError::Lexical(LexicalError::CommitmentMismatch))),
        NodeWorkspaceRefusal::SourceIndex(Box::new(IndexError::Generation(GenerationAuthorityError::CheckpointUnresolved)))] {
        let error = failure(error); assert!(!error.outcome_unknown);
        let mut bytes = Vec::new(); error.send_named(&mut bytes, fgit_wire::smart_http::HttpVersion::Http11, "source_error").unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains("\"hits\":[]") && !text.contains("\"outcome\":\"refused\""));
    }
}
