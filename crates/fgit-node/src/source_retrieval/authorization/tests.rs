//! Response-binding contract tests, not evidence of host authentication or live
//! source selection. Persisted-node HTTP/MCP coverage exercises those owners.
use super::*;
use crate::source_retrieval::{GenerationVector, InitialQuery};
use fgit_crypto::{GitObjectKind, IdentityDomain, git_object_id, internal_object_id};
use fgit_forge::source_search::SourceMatch;
use fgit_forge::source_symbols::{SymbolKind, index as symbols};
use fgit_graph::lexical::{IndexedLexicalReport, LexicalReport, LexicalSpan};
use fgit_graph::{GenerationActivation, GraphGenerationId};
use fgit_types::{
    CodecVersion, Digest, GitHashAlgorithm, HeadGeneration, RefName, RepositoryAuthorityHeadId,
    RepositoryCommitId, RepositoryId, RepositoryIncarnationId, SchemaFamily, SchemaId, TenantId,
};

fn cancelled() -> Result<(), RetrievalError> {
    Err(RetrievalError::Source(
        crate::NodeWorkspaceRefusal::Cancelled { exhaustion: None },
    ))
}
fn bind(
    context: &SourceReadContext,
    report: &mut InitialReport,
    maximum: usize,
    live: &mut impl FnMut() -> Result<(), RetrievalError>,
) -> Result<InitialAuthorization, RetrievalError> {
    InitialAuthorization::bind(
        context,
        InitialLabelInput::exact(
            &report.content,
            &report.path,
            &report.symbols,
            &report.vector,
        ),
        &mut report.result_bytes,
        maximum,
        live,
    )
}

fn fixture(format: GitHashAlgorithm) -> (SourceReadContext, InitialReport) {
    let id = |domain, family, body: &[u8]| {
        internal_object_id(
            domain,
            SchemaId::new(SchemaFamily::from_static(family), 1, 0),
            CodecVersion::new(1, 0),
            body,
        )
    };
    let namespace = LexicalNamespace {
        tenant: TenantId::from_bytes([1; 16]),
        repository: RepositoryId::from_bytes([2; 16]),
        incarnation: RepositoryIncarnationId::from_bytes([3; 16]),
        object_format: format,
    };
    let context = SourceReadContext {
        namespace,
        host: Host::TrustedLocalMcp,
    };
    let forge = id(IdentityDomain::MerkleLeaf, "test", b"forge");
    let source = LexicalSource {
        namespace,
        reference: RefName::try_new(b"refs/heads/main").unwrap(),
        source_head: RepositoryAuthorityHeadId::from_internal_object_id(id(
            IdentityDomain::RepositoryAuthorityHead,
            "repository-authority-head",
            b"head",
        ))
        .unwrap(),
        source_rcr: RepositoryCommitId::from_internal_object_id(id(
            IdentityDomain::RepositoryCommitRecord,
            "repository-commit-record",
            b"rcr",
        ))
        .unwrap(),
        forge_position_root: Digest::new(forge.algorithm(), *forge.digest()),
        commit: git_object_id(format, GitObjectKind::Commit, b"commit"),
        tree: git_object_id(format, GitObjectKind::Tree, b"tree"),
    };
    let generation = |body| GenerationActivation {
        generation_id: GraphGenerationId::from_internal_object_id(id(
            IdentityDomain::Generation,
            "graph-generation",
            body,
        ))
        .unwrap(),
        authority_generation: HeadGeneration::FIRST,
    };
    let lexical = generation(b"lexical");
    let symbol = generation(b"symbol");
    let query = InitialQuery::new(&[b"Thing".to_vec()], &[b"src".to_vec()]).unwrap();
    let blob = git_object_id(format, GitObjectKind::Blob, b"struct Thing;");
    let content = IndexedLexicalReport {
        source: source.clone(),
        generation: lexical.clone(),
        selected_generation_head: lexical.clone(),
        query: query.content().clone(),
        results: LexicalReport {
            hits: vec![LexicalHit {
                document_id: 1,
                path: b"src/Thing.rs".to_vec(),
                blob,
                content_bytes: 13,
                spans: vec![LexicalSpan {
                    query_index: 0,
                    byte_offset: 7,
                    byte_length: 5,
                }],
            }],
            complete: true,
            next_after: None,
            work_units: 1,
        },
        indexed_documents: 1,
        indexed_source_bytes: 13,
        coverage_complete: true,
        omissions: vec![],
        non_regular_entries: 0,
        segments_read: 1,
        payload_bytes_read: 128,
        generation_bytes_read: 128,
    };
    let mut path = content.clone();
    path.query = query.path().clone();
    path.results.hits[0].spans[0].byte_offset = 4;
    let symbols = symbols::Report {
        source: symbols::Source {
            tenant: namespace.tenant,
            repository: namespace.repository,
            incarnation: namespace.incarnation,
            format,
            reference: source.reference.clone(),
            head: source.source_head,
            rcr: source.source_rcr,
            forge: source.forge_position_root,
            commit: source.commit,
            tree: source.tree,
        },
        matches: vec![SymbolMatch {
            name: b"Thing".to_vec(),
            kind: SymbolKind::Struct,
            raw_identifier: false,
            location: SourceMatch {
                path: b"src/Thing.rs".to_vec(),
                blob,
                byte_offset: 7,
                line: 1,
                byte_column: 8,
                excerpt: b"struct Thing;".to_vec(),
                excerpt_offset: 0,
                match_length: 5,
            },
        }],
        complete: true,
        coverage_complete: true,
        omissions: vec![],
        generation: *symbol.generation_id.as_internal_object_id(),
        generation_number: 1,
        indexed_files: 1,
        indexed_declarations: 1,
        indexed_source_bytes: 13,
        unsupported_language_files: 0,
        non_regular_entries: 0,
        tables_read: 1,
        payload_bytes_read: 128,
        work_units: 1,
    };
    let vector = GenerationVector {
        lexical,
        symbols: Some(symbol),
    };
    let report = InitialReport::from_channels(
        &context,
        content,
        path,
        SymbolChannel::Available(Box::new(symbols)),
        vector,
        400,
        super::super::MAX_RESULT_BYTES,
        &mut || Ok(()),
    )
    .unwrap();
    (context, report)
}
#[test]
fn labels_are_deterministic_and_keep_position_domains_and_host_grants_distinct() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (context, mut report) = fixture(format);
        let labels = bind(&context, &mut report, 4096, &mut || Ok(())).unwrap();
        labels.validate(&context, &report, &mut || Ok(())).unwrap();
        let (same, mut other) = fixture(format);
        let repeated = bind(&same, &mut other, 4096, &mut || Ok(())).unwrap();
        assert_eq!(labels.binding, repeated.binding);
        assert_eq!(labels.content, repeated.content);
        assert_eq!(labels.path, repeated.path);
        assert_eq!(labels.symbols, repeated.symbols);
        assert_ne!(labels.content[0], labels.path[0]);
        assert_ne!(labels.content[0], labels.symbols[0]);
        let mut cli = context.clone();
        cli.host = Host::TrustedLocalCli;
        assert!(labels.validate(&cli, &report, &mut || Ok(())).is_err());
        let mut principal = context.clone();
        principal.host = Host::HttpCredential(PrincipalId::from_bytes([9; 16]));
        assert!(
            labels
                .validate(&principal, &report, &mut || Ok(()))
                .is_err()
        );
        // The original grant remains permitted; changing a rejected host cannot
        // mutate the immutable retained original binding.
        labels.validate(&context, &report, &mut || Ok(())).unwrap();
    }
}
#[test]
fn substituted_rows_source_generations_and_labels_refuse_beside_originals() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (context, mut report) = fixture(format);
        let labels = bind(&context, &mut report, 4096, &mut || Ok(())).unwrap();
        let mut changed = report.clone();
        changed.content.results.hits[0].path = b"src/Other.rs".to_vec();
        assert!(labels.validate(&context, &changed, &mut || Ok(())).is_err());
        let mut changed = report.clone();
        changed.content.results.hits[0].spans[0].byte_offset += 1;
        assert!(labels.validate(&context, &changed, &mut || Ok(())).is_err());
        let mut changed = report.clone();
        changed.content.source.reference = RefName::try_new(b"refs/heads/other").unwrap();
        assert!(labels.validate(&context, &changed, &mut || Ok(())).is_err());
        let mut changed = report.clone();
        changed.path.source.namespace.tenant = TenantId::from_bytes([8; 16]);
        assert!(labels.validate(&context, &changed, &mut || Ok(())).is_err());
        let mut changed = report.clone();
        changed.path.generation.authority_generation = HeadGeneration::try_new(2).unwrap();
        assert!(labels.validate(&context, &changed, &mut || Ok(())).is_err());
        let mut changed = report.clone();
        changed.vector.lexical.authority_generation = HeadGeneration::try_new(2).unwrap();
        assert!(labels.validate(&context, &changed, &mut || Ok(())).is_err());
        let mut changed = report.clone();
        if let SymbolChannel::Available(s) = &mut changed.symbols {
            s.matches[0].location.path = b"src/Other.rs".to_vec();
        }
        assert!(labels.validate(&context, &changed, &mut || Ok(())).is_err());
        let mut changed = labels.clone();
        changed.content[0] = changed.path[0];
        assert!(changed.validate(&context, &report, &mut || Ok(())).is_err());
        labels.validate(&context, &report, &mut || Ok(())).unwrap();
    }
}
#[test]
fn labels_charge_the_existing_result_budget_before_vector_allocation() {
    let (context, report) = fixture(GitHashAlgorithm::Sha256);
    let charge = DESCRIPTOR_BYTES + report.source().reference.as_bytes().len() + 3 * ROW_BYTES;
    let exact = report.result_bytes() + charge;
    let mut allowed = report.clone();
    bind(&context, &mut allowed, exact, &mut || Ok(())).unwrap();
    assert_eq!(allowed.result_bytes(), exact);
    let mut short = report.clone();
    assert!(matches!(
        bind(&context, &mut short, exact - 1, &mut || Ok(())),
        Err(RetrievalError::Limit(_))
    ));
    assert_eq!(short.result_bytes(), report.result_bytes());
    let mut stopped = report.clone();
    assert!(bind(&context, &mut stopped, exact, &mut cancelled).is_err());
    assert_eq!(stopped.result_bytes(), report.result_bytes());
    let labels = bind(&context, &mut stopped, exact, &mut || Ok(())).unwrap();
    assert!(labels.validate(&context, &stopped, &mut cancelled).is_err());
    labels.validate(&context, &stopped, &mut || Ok(())).unwrap();
}

#[test]
fn same_http_host_principal_substitution_refuses_beside_original() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut read, report) = fixture(format);
        read.host = Host::HttpCredential(PrincipalId::from_bytes([7; 16]));
        let mut original = report.clone();
        let labels = bind(&read, &mut original, 4096, &mut || Ok(())).unwrap();
        let mut other = read.clone();
        other.host = Host::HttpCredential(PrincipalId::from_bytes([8; 16]));
        let mut same_rows = report.clone();
        let other_labels = bind(&other, &mut same_rows, 4096, &mut || Ok(())).unwrap();
        assert_ne!(labels.binding(), other_labels.binding());
        assert_ne!(labels.content, other_labels.content);
        assert!(labels.validate(&other, &original, &mut || Ok(())).is_err());
        labels.validate(&read, &original, &mut || Ok(())).unwrap();
    }
}
#[test]
fn non_power_of_two_rows_do_not_retain_uncharged_digest_slots() {
    let (read, mut report) = fixture(GitHashAlgorithm::Sha256);
    if let SymbolChannel::Available(symbols) = &mut report.symbols {
        let row = symbols.matches[0].clone();
        symbols.matches.resize(513, row);
    }
    let labels = bind(
        &read,
        &mut report,
        super::super::MAX_RESULT_BYTES,
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(labels.symbols.len(), 513);
    assert_eq!(labels.symbols.capacity(), labels.symbols.len());
    assert_eq!(labels.content.capacity(), labels.content.len());
    assert_eq!(labels.path.capacity(), labels.path.len());
    labels.validate(&read, &report, &mut || Ok(())).unwrap();
    assert!(matches!(
        labels.validate(&read, &report, &mut || Err(RetrievalError::Limit(
            "label budget"
        ))),
        Err(RetrievalError::Limit("label budget"))
    ));
}
#[test]
fn revalidated_labels_keep_current_and_each_original_source_distinct() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (read, report) = fixture(format);
        let mut current = report.source().clone();
        current.source_head =
            RepositoryAuthorityHeadId::from_internal_object_id(internal_object_id(
                IdentityDomain::RepositoryAuthorityHead,
                SchemaId::new(SchemaFamily::from_static("repository-authority-head"), 1, 0),
                CodecVersion::new(1, 0),
                b"current",
            ))
            .unwrap();
        let mut symbols = report.symbols.clone();
        if let SymbolChannel::Available(s) = &mut symbols {
            s.source.head = RepositoryAuthorityHeadId::from_internal_object_id(internal_object_id(
                IdentityDomain::RepositoryAuthorityHead,
                SchemaId::new(SchemaFamily::from_static("repository-authority-head"), 1, 0),
                CodecVersion::new(1, 0),
                b"symbol-original",
            ))
            .unwrap();
        }
        let input = || {
            InitialLabelInput::revalidated(
                &current,
                &report.content,
                &report.path,
                &symbols,
                &report.vector,
            )
        };
        let mut retained = report.result_bytes;
        let labels =
            InitialAuthorization::bind(&read, input(), &mut retained, 4096, &mut || Ok(()))
                .unwrap();
        labels
            .validate_input(&read, input(), &mut || Ok(()))
            .unwrap();
        assert_ne!(labels.binding(), report.authorization().binding());
        assert!(labels.validate(&read, &report, &mut || Ok(())).is_err());
        let mut changed_current = current.clone();
        changed_current.reference = RefName::try_new(b"refs/heads/other").unwrap();
        assert!(
            labels
                .validate_input(
                    &read,
                    InitialLabelInput::revalidated(
                        &changed_current,
                        &report.content,
                        &report.path,
                        &symbols,
                        &report.vector
                    ),
                    &mut || Ok(())
                )
                .is_err()
        );
        let mut changed_symbols = symbols.clone();
        if let SymbolChannel::Available(s) = &mut changed_symbols {
            s.source.head = current.source_head;
        }
        assert!(
            labels
                .validate_input(
                    &read,
                    InitialLabelInput::revalidated(
                        &current,
                        &report.content,
                        &report.path,
                        &changed_symbols,
                        &report.vector
                    ),
                    &mut || Ok(())
                )
                .is_err()
        );
        labels
            .validate_input(&read, input(), &mut || Ok(()))
            .unwrap();
    }
}
