//! Parser, byte-boundary and provenance regression tests. Persisted native
//! behavior is exercised separately through the MCP protocol.
use super::*;
use fgit_crypto::{GitObjectKind, IdentityDomain, git_object_id, internal_object_id};
use fgit_types::{
    Digest, RepositoryCommitId, RepositoryIncarnationId, SchemaFamily, SchemaId, TenantId,
};

fn args() -> Object {
    let Value::Object(args) = object([
        ("reference", text("refs/heads/main")),
        ("name", text("alpha")),
        ("source_mode", text("indexed-current")),
    ]) else {
        unreachable!()
    };
    args
}
fn generation() -> InternalObjectId {
    internal_object_id(
        IdentityDomain::Generation,
        SchemaId::new(SchemaFamily::from_static("graph-generation"), 1, 0),
        CANONICAL_CODEC_VERSION,
        b"first",
    )
}
fn source(format: GitHashAlgorithm, label: &[u8]) -> data::Source {
    let id = |domain, family| {
        internal_object_id(
            domain,
            SchemaId::new(SchemaFamily::from_static(family), 1, 0),
            CANONICAL_CODEC_VERSION,
            label,
        )
    };
    let forge = id(IdentityDomain::MerkleLeaf, "test-forge");
    data::Source {
        tenant: TenantId::from_bytes([1; 16]),
        repository: RepositoryId::from_bytes([2; 16]),
        incarnation: RepositoryIncarnationId::from_bytes([3; 16]),
        format,
        reference: RefName::try_new(b"refs/heads/main").unwrap(),
        head: RepositoryAuthorityHeadId::from_internal_object_id(id(
            IdentityDomain::RepositoryAuthorityHead,
            "repository-authority-head",
        ))
        .unwrap(),
        rcr: RepositoryCommitId::from_internal_object_id(id(
            IdentityDomain::RepositoryCommitRecord,
            "repository-commit-record",
        ))
        .unwrap(),
        forge: Digest::new(forge.algorithm(), *forge.digest()),
        commit: git_object_id(format, GitObjectKind::Commit, b"commit"),
        tree: git_object_id(format, GitObjectKind::Tree, b"tree"),
    }
}
fn report(format: GitHashAlgorithm) -> data::Report {
    let bytes = b"fn alpha() {}";
    data::Report {
        source: source(format, b"indexed"),
        matches: vec![SymbolMatch {
            name: b"alpha".to_vec(),
            kind: SymbolKind::Function,
            raw_identifier: false,
            location: SourceMatch {
                path: b"src/lib.rs".to_vec(),
                blob: git_object_id(format, GitObjectKind::Blob, bytes),
                byte_offset: 3,
                line: 1,
                byte_column: 4,
                match_length: 5,
                excerpt_offset: 0,
                excerpt: bytes.to_vec(),
            },
        }],
        complete: true,
        coverage_complete: true,
        omissions: vec![],
        generation: generation(),
        generation_number: 9_007_199_254_740_993,
        indexed_files: 1,
        indexed_declarations: 1,
        indexed_source_bytes: bytes.len(),
        unsupported_language_files: 0,
        non_regular_entries: 0,
        tables_read: 1,
        payload_bytes_read: 400,
        work_units: 100,
    }
}
fn render(
    input: &Input,
    current: &data::Source,
    report: &data::Report,
) -> Result<Object, ToolError> {
    output::render(
        Object::new(),
        &output::Scope {
            tenant: report.source.tenant,
            repository: report.source.repository,
            incarnation: report.source.incarnation,
            format: report.source.format,
        },
        input,
        current,
        report,
        &mut || true,
    )
}

#[test]
fn mode_specific_arguments_refuse_fallback_exact_selection_and_invented_cursors() {
    let mut query = args();
    assert_eq!(
        input::parse(&query, GitHashAlgorithm::Sha1).unwrap().mode,
        Mode::Current
    );
    for mode in [
        None,
        Some("scan"),
        Some("current"),
        Some("indexed"),
        Some("revalidated"),
    ] {
        query.remove("source_mode");
        if let Some(mode) = mode {
            query.insert("source_mode".into(), text(mode));
        }
        assert_eq!(
            input::parse(&query, GitHashAlgorithm::Sha1)
                .err()
                .unwrap()
                .code,
            "invalid_symbol_source_mode"
        );
    }
    for field in [
        "after",
        "index_token",
        "index_number",
        "build",
        "refresh",
        "ignore_ascii_case",
    ] {
        let mut query = args();
        query.insert(field.into(), text("1"));
        assert_eq!(
            input::parse(&query, GitHashAlgorithm::Sha1)
                .err()
                .unwrap()
                .code,
            "unknown_argument"
        );
    }
    let mut scan = args();
    scan.insert("source_mode".into(), text("scan"));
    assert!(super::super::parse(&scan, GitHashAlgorithm::Sha1).is_ok());
    for field in [
        "minimum_index_token",
        "minimum_index_number",
        "max_payload_bytes",
    ] {
        let mut query = scan.clone();
        query.insert(field.into(), text("1"));
        assert_eq!(
            super::super::parse(&query, GitHashAlgorithm::Sha1)
                .err()
                .unwrap()
                .code,
            "unknown_argument"
        );
    }
    for value in [
        json::number(0),
        json::number(data::MAX_INDEX_BYTES as u64 + 1),
        text("1"),
    ] {
        let mut query = args();
        query.insert("max_payload_bytes".into(), value);
        assert_eq!(
            input::parse(&query, GitHashAlgorithm::Sha1)
                .err()
                .unwrap()
                .code,
            "invalid_limit"
        );
    }
}

#[test]
fn generation_floor_requires_one_canonical_pair_without_loss_of_u64_precision() {
    let mut query = args();
    query.insert("minimum_index_token".into(), text(token(&generation())));
    assert_eq!(
        input::parse(&query, GitHashAlgorithm::Sha1)
            .err()
            .unwrap()
            .code,
        "incomplete_index_generation"
    );
    query.insert("minimum_index_number".into(), text(u64::MAX.to_string()));
    assert_eq!(
        input::parse(&query, GitHashAlgorithm::Sha1)
            .unwrap()
            .minimum
            .unwrap()
            .authority_generation
            .get(),
        u64::MAX
    );
    for value in ["0", "01", "+1", "-1", " 1", "18446744073709551616", ""] {
        let mut bad = query.clone();
        bad.insert("minimum_index_number".into(), text(value));
        assert_eq!(
            input::parse(&bad, GitHashAlgorithm::Sha1)
                .err()
                .unwrap()
                .code,
            "invalid_index_generation",
            "{value}"
        );
    }
    for value in [
        format!("alg:1:{}", "a".repeat(40)),
        format!("alg:2:{}", "0".repeat(64)),
        format!("alg:2:{}", "A".repeat(64)),
        format!("alg:02:{}", "a".repeat(64)),
        format!("alg:2:{}", "a".repeat(62)),
        generation().to_string(),
    ] {
        let mut bad = query.clone();
        bad.insert("minimum_index_token".into(), text(value));
        assert_eq!(
            input::parse(&bad, GitHashAlgorithm::Sha1)
                .err()
                .unwrap()
                .code,
            "invalid_index_generation"
        );
    }
}

#[test]
fn complete_query_never_claims_complete_corpus_coverage_or_rewrites_provenance() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let input = input::parse(&args(), format).unwrap();
        let mut report = report(format);
        report.coverage_complete = false;
        report.omissions.push(data::Omission {
            path: b"outside/bad.rs".to_vec(),
            blob: git_object_id(format, GitObjectKind::Blob, b"fn bad("),
            source_bytes: 7,
            reason: data::OmissionReason::UnbalancedDelimiter,
            byte_offset: Some(6),
            limit: None,
        });
        let current = source(format, b"current");
        let fields = render(&input, &current, &report).unwrap();
        assert_eq!(fields["complete"], Value::Bool(true));
        assert_eq!(fields["coverage_complete"], Value::Bool(false));
        assert_eq!(fields["distinct_provenance"], Value::Bool(true));
        assert_eq!(fields["index_number"].text(), Some("9007199254740993"));
        assert_eq!(fields["omitted_source_bytes"].text(), Some("7"));
        assert_eq!(fields["pagination_supported"], Value::Bool(false));
        assert_eq!(
            fields["current_source"].object().unwrap()["snapshot_token"],
            text(head_token(current.head))
        );
        assert_eq!(
            fields["indexed_source"].object().unwrap()["snapshot_token"],
            text(head_token(report.source.head))
        );
        for field in [
            "max_matches",
            "tables_read",
            "source_blobs_read",
            "payload_bytes_read",
            "work_units",
        ] {
            assert!(fields[field].text().is_some(), "{field}");
        }
        for field in ["after", "next_after", "declarations_examined"] {
            assert!(!fields.contains_key(field));
        }
        let mut exact = args();
        exact.insert("source_mode".into(), text("indexed-exact"));
        let exact = input::parse(&exact, format).unwrap();
        assert_eq!(
            render(&exact, &current, &report).unwrap_err().code,
            "invalid_symbol_index_report"
        );
        assert!(render(&exact, &report.source, &report).is_ok());
    }
}

#[test]
fn tampered_native_reports_fail_before_returning_bytes_or_completeness() {
    let format = GitHashAlgorithm::Sha1;
    let input = input::parse(&args(), format).unwrap();
    let good = report(format);
    let mut changed = Vec::new();
    let mut r = good.clone();
    r.source.repository = RepositoryId::from_bytes([9; 16]);
    changed.push(r);
    let mut r = good.clone();
    r.source.tree = git_object_id(format, GitObjectKind::Tree, b"other");
    changed.push(r);
    let mut r = good.clone();
    r.source.head = good.source.head;
    r.source.rcr = source(format, b"other").rcr;
    changed.push(r);
    let mut r = good.clone();
    r.generation_number = 0;
    changed.push(r);
    let mut r = good.clone();
    r.generation = good.source.head.into_internal_object_id();
    changed.push(r);
    let mut r = good.clone();
    r.complete = false;
    changed.push(r);
    let mut r = good.clone();
    r.coverage_complete = false;
    changed.push(r);
    let mut r = good.clone();
    r.tables_read = 2;
    changed.push(r);
    let mut r = good.clone();
    r.payload_bytes_read = input.maximum_payload_bytes + 1;
    changed.push(r);
    let mut r = good.clone();
    r.work_units = input.query.maximum_work() + 1;
    changed.push(r);
    let mut r = good.clone();
    r.matches[0].location.excerpt[3] = b'X';
    changed.push(r);
    let mut r = good.clone();
    r.matches[0].location.path = b"../outside.rs".to_vec();
    changed.push(r);
    let mut r = good.clone();
    r.matches[0].name = b"other".to_vec();
    changed.push(r);
    for report in changed {
        assert!(render(&input, &good.source, &report).is_err(), "{report:?}");
    }
    let mut minimum = args();
    minimum.insert("minimum_index_token".into(), text(token(&good.generation)));
    minimum.insert(
        "minimum_index_number".into(),
        text((good.generation_number + 1).to_string()),
    );
    assert!(
        render(
            &input::parse(&minimum, format).unwrap(),
            &good.source,
            &good
        )
        .is_err()
    );
}

#[test]
fn rendering_keeps_cancellation_and_retained_bytes_bounded() {
    let format = GitHashAlgorithm::Sha1;
    let input = input::parse(&args(), format).unwrap();
    let mut report = report(format);
    let scope = output::Scope {
        tenant: report.source.tenant,
        repository: report.source.repository,
        incarnation: report.source.incarnation,
        format,
    };
    assert_eq!(
        output::render(
            Object::new(),
            &scope,
            &input,
            &report.source,
            &report,
            &mut || false
        )
        .unwrap_err()
        .code,
        "read_cancelled"
    );
    let mut remaining = 2;
    assert_eq!(
        output::render(
            Object::new(),
            &scope,
            &input,
            &report.source,
            &report,
            &mut || {
                remaining -= 1;
                remaining >= 0
            }
        )
        .unwrap_err()
        .code,
        "read_cancelled"
    );
    report.matches[0]
        .location
        .excerpt
        .resize(MAX_RETAINED_BYTES, b'x');
    assert_eq!(
        render(&input, &report.source, &report).unwrap_err().code,
        "resource_limit"
    );
}

#[test]
fn discovery_exposes_a_closed_mode_union_and_no_pagination_contract() {
    let schema = super::super::input_schema();
    let schema = schema.object().unwrap();
    let properties = schema["properties"].object().unwrap();
    for name in [
        "source_mode",
        "minimum_index_token",
        "minimum_index_number",
        "max_payload_bytes",
    ] {
        assert!(properties.contains_key(name), "{name}");
    }
    for name in ["after", "index_token", "index_number"] {
        assert!(!properties.contains_key(name));
    }
    let Value::Array(variants) = &schema["oneOf"] else {
        panic!("closed mode union")
    };
    assert_eq!(variants.len(), 2);
    for variant in variants {
        assert_eq!(
            variant.object().unwrap()["additionalProperties"],
            Value::Bool(false)
        );
    }
    assert!(
        !variants[0].object().unwrap()["properties"]
            .object()
            .unwrap()
            .contains_key("max_payload_bytes")
    );
    assert!(
        variants[1]
            .object()
            .unwrap()
            .contains_key("dependentRequired")
    );
}
