//! Ranking cannot replace the sealed current/index proof or renew its budget.
use super::*;
use crate::source_retrieval::context::ranked::RevalidatedRankedContext;

fn ranked(
    fixture: &Fixture,
    report: RevalidatedInitialReport,
    limits: ContextLimits,
) -> Result<RevalidatedRankedContext, RetrievalError> {
    let node = fixture.node();
    node.runtime()
        .block_on(node.hydrate_source_initial_revalidated_ranked_local_in(
            &node.request_context(),
            &SourceReadContext::trusted_local_native(node),
            report,
            limits,
        ))
}

#[test]
fn ranking_revalidated_rows_preserves_labels_and_refuses_proof_substitution() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format);
        let indexed = f.build_lexical();
        f.unrelated("before-ranked-symbols");
        f.build_symbols();
        f.unrelated("before-ranked-context");
        let report = f
            .query(
                &query(Some(SymbolPolicy::Required)),
                &Checkpoints::default(),
                InitialLimits::default(),
            )
            .unwrap();
        let before = f.head();
        let limits = ContextLimits {
            max_files: 1,
            ..Default::default()
        };
        let joined = ranked(&f, report.clone(), limits).unwrap();
        let (context, ranking) = joined.into_parts();
        assert_eq!(ranking.candidate_files(), 3);
        assert_eq!(ranking.selected().len(), 1);
        assert_eq!(context.candidate_files(), ranking.candidate_files());
        assert_eq!(context.omitted_files(), 2);
        assert_eq!(context.source_blobs_read(), 1);
        assert!(!context.complete());
        assert_eq!(context.retrieval().content().source, indexed);
        assert_ne!(indexed.source_head, report.current_source().source_head);
        assert_eq!(
            context.retrieval().current_source(),
            report.current_source()
        );
        assert_eq!(context.retrieval().generations(), report.generations());
        assert_eq!(
            context.retrieval().authorization().binding(),
            report.authorization().binding()
        );
        let file = &context.files()[0];
        assert_eq!(file.path(), ranking.selected()[0].path());
        assert_eq!(file.blob(), ranking.selected()[0].blob());
        assert_eq!(file.excerpts()[0].untrusted_bytes(), SOURCE);
        file.validate_revalidated_lineage(&report, &mut || Ok(()))
            .unwrap();

        let mut changed_generation = report.clone();
        changed_generation.content.generation.authority_generation = changed_generation
            .content
            .generation
            .authority_generation
            .next()
            .unwrap();
        assert!(matches!(
            ranked(&f, changed_generation, limits),
            Err(RetrievalError::MixedGeneration)
        ));
        let mut changed_row = report.clone();
        changed_row.content.results.hits[0].spans[0].byte_offset += 1;
        assert!(matches!(
            ranked(&f, changed_row, limits),
            Err(RetrievalError::Invalid("result authorization label"))
        ));
        let node = f.node();
        assert!(matches!(
            node.runtime()
                .block_on(node.hydrate_source_initial_revalidated_ranked_local_in(
                    &node.request_context(),
                    &SourceReadContext::trusted_local_mcp(node),
                    report.clone(),
                    limits,
                )),
            Err(RetrievalError::Invalid("result authorization binding"))
        ));
        assert!(ranked(&f, report, limits).is_ok());
        assert_eq!(f.head(), before);
    }
}

#[test]
fn ranked_lineage_reserves_the_original_allowance_before_current_source_io() {
    let mut f = Fixture::new(GitHashAlgorithm::Sha256);
    f.build_lexical();
    f.unrelated("ranked-original-allowance");
    let query = query(None);
    let context_limits = ContextLimits {
        max_files: 1,
        ..Default::default()
    };
    let report = f
        .query(&query, &Checkpoints::default(), InitialLimits::default())
        .unwrap();
    let baseline = ranked(&f, report, context_limits).unwrap();
    let required =
        baseline.context().retrieval().result_bytes() + baseline.context().lineage_metadata_bytes();
    let limits = InitialLimits {
        max_result_bytes: required,
        ..Default::default()
    };
    let exact = f.query(&query, &Checkpoints::default(), limits).unwrap();
    assert!(ranked(&f, exact.clone(), context_limits).is_ok());
    let under = f
        .query(
            &query,
            &Checkpoints::default(),
            InitialLimits {
                max_result_bytes: required - 1,
                ..limits
            },
        )
        .unwrap();
    assert!(matches!(
        ranked(&f, under.clone(), context_limits),
        Err(RetrievalError::Limit("retained result bytes"))
    ));

    // The exact report now fails its saved current-source pin. The exhausted
    // report must still refuse its original budget before native selection.
    f.unrelated("after-ranked-retrieval");
    let before = f.head();
    assert!(matches!(
        ranked(&f, under, context_limits),
        Err(RetrievalError::Limit("retained result bytes"))
    ));
    assert!(matches!(
        ranked(&f, exact, context_limits),
        Err(RetrievalError::Source(NodeWorkspaceRefusal::SourceBrowse(error)))
            if matches!(*error, fgit_forge::source_browse::SourceBrowseError::SnapshotMoved)
    ));
    assert_eq!(f.head(), before);
}
