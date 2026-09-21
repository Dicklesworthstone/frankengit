//! Pure query/budget/join invariants. Real node/storage tests are separate.
use super::*;
use fgit_crypto::{IdentityDomain, GitObjectKind, git_object_id, internal_algorithm_id,
    internal_digest_value, internal_object_id};
use fgit_types::{CodecVersion, Digest, GitHashAlgorithm, RepositoryCommitId, RepositoryId,
    RepositoryIncarnationId, SchemaFamily, SchemaId, TenantId};

fn source() -> symbols::Source {
    let schema = |family| SchemaId::new(SchemaFamily::from_static(family), 1, 0);
    let id = |domain, family| internal_object_id(domain, schema(family), CodecVersion::new(1, 0), b"initial");
    symbols::Source {
        tenant: TenantId::from_bytes([1;16]), repository: RepositoryId::from_bytes([2;16]),
        incarnation: RepositoryIncarnationId::from_bytes([3;16]), format: GitHashAlgorithm::Sha1,
        reference: RefName::try_new(b"refs/heads/main").unwrap(),
        head: RepositoryAuthorityHeadId::from_internal_object_id(
            id(IdentityDomain::RepositoryAuthorityHead, "repository-authority-head")).unwrap(),
        rcr: RepositoryCommitId::from_internal_object_id(
            id(IdentityDomain::RepositoryCommitRecord, "repository-commit-record")).unwrap(),
        forge: Digest::new(internal_algorithm_id(IdentityDomain::MerkleLeaf),
            internal_digest_value(IdentityDomain::MerkleLeaf, schema("test"), b"forge")),
        commit: git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Commit, b"commit"),
        tree: git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Tree, b"tree"),
    }
}
fn lexical_source(source: &symbols::Source) -> LexicalSource {
    LexicalSource { namespace: lexical::LexicalNamespace { tenant: source.tenant, repository: source.repository,
        incarnation: source.incarnation, object_format: source.format }, reference: source.reference.clone(),
        source_head: source.head, source_rcr: source.rcr, forge_position_root: source.forge,
        commit: source.commit, tree: source.tree }
}
fn generation(bytes: &[u8], number: u64) -> GenerationActivation {
    GenerationActivation { generation_id: GraphGenerationId::from_internal_object_id(internal_object_id(
        IdentityDomain::Generation, SchemaId::new(SchemaFamily::from_static("graph-generation"), 1, 0),
        CodecVersion::new(1, 0), bytes)).unwrap(), authority_generation: HeadGeneration::try_new(number).unwrap() }
}
fn query() -> InitialQuery { InitialQuery::new(&[b"Thing".to_vec()], &[b"src".to_vec()]).unwrap() }
fn report() -> IndexedLexicalReport {
    let generation = generation(b"first", 1);
    IndexedLexicalReport { source: lexical_source(&source()), generation: generation.clone(),
        selected_generation_head: generation, query: query().content,
        results: lexical::LexicalReport { hits: vec![], complete: true, next_after: None, work_units: 0 },
        indexed_documents: 0, indexed_source_bytes: 0, non_regular_entries: 0,
        segments_read: 0, payload_bytes_read: 0, generation_bytes_read: 0 }
}

#[test]
fn query_keeps_case_sensitive_symbols_and_one_component_bounded_scope() {
    let query = InitialQuery::new(&[b"THING".to_vec(), b"thing".to_vec()],
        &[b"src".to_vec(), b"src".to_vec()]).unwrap()
        .with_symbols(b"Thing", SymbolMatchMode::Exact, &[SymbolKind::Function], SymbolPolicy::Optional).unwrap();
    assert_eq!(query.content().terms(), &[b"thing".to_vec()]);
    assert_eq!(query.path().terms(), query.content().terms());
    assert_eq!(query.content().prefixes(), query.path().prefixes());
    let (symbol, policy) = query.symbols().unwrap();
    assert_eq!(policy, SymbolPolicy::Optional);
    assert_eq!(symbol.name(), b"Thing");
    assert_eq!(symbol.source_scope().prefixes().len(), 1);
    assert_eq!(symbol.source_scope().prefixes()[0].as_bytes(), b"src");
    assert!(InitialQuery::new(&[], &[]).is_err());
    assert!(InitialQuery::new(&[b"a.*".to_vec()], &[]).is_err());
    assert!(InitialQuery::new(&[b"word".to_vec()], &[b"../private".to_vec()]).is_err());
    assert!(query.clone().with_symbols(b"r#type", SymbolMatchMode::Exact, &[], SymbolPolicy::Required).is_err());
}

#[test]
fn fixed_allowances_cover_failed_channels_without_renewing_or_exceeding_the_request() {
    for count in [2,3] {
        for total in [count as u64, count as u64 + 1, 1024, lexical::MAX_WORK, MAX_PAYLOAD_BYTES as u64] {
            let parts: Vec<_> = (0..count).map(|i| share(total, count, i)).collect();
            assert_eq!(parts.iter().sum::<u64>(), total);
            assert!(parts.iter().all(|n| *n > 0));
            assert!(parts.windows(2).all(|p| p[0] >= p[1] && p[0] - p[1] <= 1));
        }
    }
    for q in [query(), query().with_symbols(b"Thing", SymbolMatchMode::Prefix, &[], SymbolPolicy::Optional).unwrap()] {
        assert!(InitialLimits::default().validate(&q).is_ok());
        for limits in [InitialLimits { max_work: 1, ..Default::default() },
            InitialLimits { max_payload_bytes: 1, ..Default::default() },
            InitialLimits { max_results_per_channel: 0, ..Default::default() },
            InitialLimits { max_results_per_channel: 1025, ..Default::default() },
            InitialLimits { max_result_bytes: MAX_RESULT_BYTES + 1, ..Default::default() }] {
            assert!(limits.validate(&q).is_err());
        }
    }
}

#[test]
fn same_source_cannot_hide_a_different_lexical_generation_or_checkpoint_position() {
    let content = report();
    let mut path = content.clone();
    assert!(check_lexical_join(&content, &path).is_ok());
    // A later selected head is acceptable when the actual queried generation
    // remains the original one. No result was computed from this newer head.
    path.selected_generation_head = generation(b"later", 2);
    assert!(check_lexical_join(&content, &path).is_ok());
    path.generation = generation(b"different", 1);
    assert!(matches!(check_lexical_join(&content, &path), Err(RetrievalError::MixedGeneration)));
    path = content.clone(); path.generation.authority_generation = HeadGeneration::try_new(2).unwrap();
    assert!(matches!(check_lexical_join(&content, &path), Err(RetrievalError::MixedGeneration)));
    path = content.clone(); path.source.tree = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Tree, b"other");
    assert!(matches!(check_lexical_join(&content, &path), Err(RetrievalError::MixedSource)));
}

#[test]
fn symbol_join_checks_all_source_and_namespace_coordinates_not_just_commit() {
    let original = source(); let lexical = lexical_source(&original);
    assert!(check_symbol_join(&lexical, &original).is_ok());
    for field in 0..9 {
        let mut changed = original.clone();
        match field {
            0 => changed.tenant = TenantId::from_bytes([9;16]),
            1 => changed.repository = RepositoryId::from_bytes([9;16]),
            2 => changed.incarnation = RepositoryIncarnationId::from_bytes([9;16]),
            3 => changed.format = GitHashAlgorithm::Sha256,
            4 => changed.reference = RefName::try_new(b"refs/heads/other").unwrap(),
            5 => changed.head = RepositoryAuthorityHeadId::from_internal_object_id(internal_object_id(
                IdentityDomain::RepositoryAuthorityHead, SchemaId::new(SchemaFamily::from_static("repository-authority-head"),1,0),
                CodecVersion::new(1,0), b"other")).unwrap(),
            6 => changed.rcr = RepositoryCommitId::from_internal_object_id(internal_object_id(
                IdentityDomain::RepositoryCommitRecord, SchemaId::new(SchemaFamily::from_static("repository-commit-record"),1,0),
                CodecVersion::new(1,0), b"other")).unwrap(),
            7 => changed.forge = Digest::new(internal_algorithm_id(IdentityDomain::MerkleLeaf),
                internal_digest_value(IdentityDomain::MerkleLeaf, SchemaId::new(SchemaFamily::from_static("test"),1,0), b"other")),
            _ => changed.tree = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Tree, b"other"),
        }
        assert!(matches!(check_symbol_join(&lexical, &changed), Err(RetrievalError::MixedSource)));
    }
    let mut changed = original; changed.commit = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Commit, b"other");
    assert!(matches!(check_symbol_join(&lexical, &changed), Err(RetrievalError::MixedSource)));
}

#[test]
fn optional_symbols_never_swallow_integrity_cancellation_or_retained_checkpoints() {
    assert_eq!(symbol_unavailable(SymbolError::Uninitialized, SymbolPolicy::Optional, false).unwrap(), SymbolUnavailable::Uninitialized);
    assert_eq!(symbol_unavailable(SymbolError::Stale, SymbolPolicy::Optional, false).unwrap(), SymbolUnavailable::Stale);
    for policy in [SymbolPolicy::Optional, SymbolPolicy::Required] {
        assert!(symbol_unavailable(SymbolError::Uninitialized, policy, true).is_err());
        assert!(symbol_unavailable(SymbolError::Stale, policy, true).is_err());
        for error in [SymbolError::Index(symbols::Error::CommitmentMismatch),
            SymbolError::Index(symbols::Error::Cancelled),
            SymbolError::Index(symbols::Error::Limit("index bytes")),
            SymbolError::Generation(GenerationAuthorityError::CheckpointUnresolved),
            SymbolError::Source(NodeWorkspaceRefusal::RefUnavailable)] {
            assert!(symbol_unavailable(error, policy, false).is_err());
        }
    }
    assert!(symbol_unavailable(SymbolError::Uninitialized, SymbolPolicy::Required, false).is_err());
    assert!(symbol_unavailable(SymbolError::Stale, SymbolPolicy::Required, false).is_err());
}

#[test]
fn optional_unavailability_is_incomplete_and_retained_bytes_are_shared() {
    let content = report(); let path = content.clone();
    let mut report = InitialReport { vector: GenerationVector { lexical: content.generation.clone(), symbols: None },
        content, path, symbols: SymbolChannel::NotRequested, result_bytes: 0 };
    assert!(report.complete());
    report.symbols = SymbolChannel::Unavailable(SymbolUnavailable::Stale);
    assert!(!report.complete());
    report.symbols = SymbolChannel::NotRequested;
    report.path.results.complete = false;
    assert!(!report.complete());
    let mut total = 0;
    add_result(&mut total, 7, 10).unwrap(); add_result(&mut total, 3, 10).unwrap();
    assert!(add_result(&mut total, 1, 10).is_err()); assert_eq!(total, 10);
    total = usize::MAX; assert!(add_result(&mut total, 1, usize::MAX).is_err());
}
