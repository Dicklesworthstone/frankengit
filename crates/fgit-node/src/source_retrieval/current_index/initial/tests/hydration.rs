//! Revalidated retrieval must still prove native bytes and preserve its labels.
use super::*;
use crate::NodeWorkspaceRefusal;
use crate::source_retrieval::context::{ContextChannel, ContextLimits, RevalidatedInitialContext};

mod visibility;

const SOURCE: &[u8] = b"pub fn Thing() {}\n";

fn hydrate(
    fixture: &Fixture,
    report: RevalidatedInitialReport,
    limits: ContextLimits,
) -> Result<RevalidatedInitialContext, RetrievalError> {
    let node = fixture.node();
    node.runtime()
        .block_on(node.hydrate_source_initial_revalidated_local_in(
            &node.request_context(),
            &SourceReadContext::trusted_local_native(node),
            report,
            limits,
        ))
}

#[test]
fn metadata_only_reuse_hydrates_native_bytes_with_each_original_index_and_label() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format);
        let indexed = f.build_lexical();
        f.unrelated("before-symbols");
        f.build_symbols();
        f.unrelated("before-context");
        let floors = Checkpoints {
            lexical: f.lexical.clone(),
            symbols: f.symbols.clone(),
        };
        let query = query(Some(SymbolPolicy::Required));
        let report = f.query(&query, &floors, InitialLimits::default()).unwrap();
        let before = f.head();
        let context = hydrate(&f, report.clone(), ContextLimits::default()).unwrap();
        assert!(context.complete());
        assert_eq!(context.candidate_files(), 3);
        assert_eq!(context.omitted_files(), 0);
        assert_eq!(context.source_blobs_read(), 3);
        assert_eq!(context.source_bytes_read(), SOURCE.len() * 3);
        assert_eq!(context.excerpt_bytes(), SOURCE.len() * 3);
        assert_eq!(context.source_file_limit(), 8 * 1024 * 1024);
        assert_eq!(
            context.retrieval().current_source(),
            report.current_source()
        );
        assert_ne!(
            context.retrieval().current_source().source_head,
            indexed.source_head
        );
        assert_eq!(context.retrieval().content().source, indexed);
        assert_eq!(context.retrieval().path().source, indexed);
        assert_eq!(context.retrieval().generations(), report.generations());
        assert_eq!(context.retrieval().result_bytes(), report.result_bytes());
        assert_eq!(
            context.retrieval().authorization().binding(),
            report.authorization().binding()
        );
        let SymbolChannel::Available(symbols) = context.retrieval().symbols() else {
            panic!("required symbol index")
        };
        assert_ne!(symbols.source.head, indexed.source_head);
        assert_ne!(symbols.source.head, report.current_source().source_head);
        assert_eq!(
            context
                .files()
                .iter()
                .map(|file| file.path())
                .collect::<Vec<_>>(),
            vec![
                b"src/Thing-extra.rs".as_slice(),
                b"src/Thing.rs",
                b"src/other.rs"
            ]
        );
        for file in context.files() {
            assert_eq!(file.source_bytes(), SOURCE.len());
            assert_eq!(file.excerpts().len(), 1);
            assert_eq!(file.excerpts()[0].offset(), 0);
            assert_eq!(file.excerpts()[0].untrusted_bytes(), SOURCE);
            assert!(
                file.anchors()
                    .iter()
                    .any(|anchor| anchor.channel == ContextChannel::Content)
            );
            assert!(
                file.anchors()
                    .iter()
                    .any(|anchor| anchor.channel == ContextChannel::Symbol)
            );
            assert_eq!(
                file.anchors().len(),
                file.anchor_authorization_labels().len()
            );
            file.validate_revalidated_lineage(&report, &mut || Ok(()))
                .unwrap();
            let mut origins = Vec::new();
            for (channel, results) in [
                (LexicalChannel::Content, report.content()),
                (LexicalChannel::Path, report.path()),
            ] {
                for (row, label) in results
                    .results
                    .hits
                    .iter()
                    .zip(report.authorization().lexical(channel))
                {
                    if row.path == file.path() && !origins.contains(label) {
                        origins.push(*label);
                    }
                }
            }
            for (row, label) in symbols.matches.iter().zip(report.authorization().symbols()) {
                if row.location.path == file.path() && !origins.contains(label) {
                    origins.push(*label);
                }
            }
            assert_eq!(file.authorization_labels(), origins);
            assert!(
                file.anchor_authorization_labels()
                    .iter()
                    .all(|label| origins.contains(label))
            );
        }
        assert!(context.lineage_metadata_bytes() > 0);
        assert_eq!(f.head(), before);

        f.reopen();
        let reopened = hydrate(&f, report, ContextLimits::default()).unwrap();
        assert_eq!(reopened.files(), context.files());
        assert_eq!(
            reopened.retrieval().current_source(),
            context.retrieval().current_source()
        );
        assert_eq!(f.head(), before);
    }
}

#[test]
fn native_hydration_keeps_fixed_byte_shares_omissions_and_optional_channel_status() {
    let mut f = Fixture::new(GitHashAlgorithm::Sha256);
    f.build_lexical();
    f.unrelated("bounded-context");
    let report = f
        .query(
            &query(None),
            &Checkpoints::default(),
            InitialLimits::default(),
        )
        .unwrap();
    let before = f.head();
    let limits = ContextLimits {
        max_source_bytes: SOURCE.len() * 3,
        max_excerpt_bytes: SOURCE.len() * 3,
        ..Default::default()
    };
    let exact = hydrate(&f, report.clone(), limits).unwrap();
    assert!(exact.complete());
    assert_eq!(exact.source_file_limit(), SOURCE.len());
    assert_eq!(exact.source_bytes_read(), limits.max_source_bytes);
    assert_eq!(exact.excerpt_bytes(), limits.max_excerpt_bytes);
    for limits in [
        ContextLimits {
            max_source_bytes: limits.max_source_bytes - 1,
            ..limits
        },
        ContextLimits {
            max_excerpt_bytes: limits.max_excerpt_bytes - 1,
            ..limits
        },
    ] {
        assert!(hydrate(&f, report.clone(), limits).is_err());
        assert_eq!(f.head(), before);
    }
    let omitted = hydrate(
        &f,
        report,
        ContextLimits {
            max_files: 1,
            max_source_bytes: SOURCE.len(),
            max_excerpt_bytes: SOURCE.len(),
            ..limits
        },
    )
    .unwrap();
    assert_eq!(omitted.candidate_files(), 3);
    assert_eq!(omitted.source_blobs_read(), 1);
    assert_eq!(omitted.omitted_files(), 2);
    assert!(!omitted.complete());
    assert_eq!(omitted.files()[0].path(), b"src/Thing-extra.rs");

    let optional = f
        .query(
            &query(Some(SymbolPolicy::Optional)),
            &Checkpoints::default(),
            InitialLimits::default(),
        )
        .unwrap();
    let optional = hydrate(&f, optional, limits).unwrap();
    assert_eq!(optional.omitted_files(), 0);
    assert!(!optional.complete());
    assert!(matches!(
        optional.retrieval().symbols(),
        SymbolChannel::Unavailable(SymbolUnavailable::Uninitialized)
    ));
    assert_eq!(f.head(), before);
}

#[test]
fn original_result_budget_reserves_lineage_before_native_source_selection() {
    let mut f = Fixture::new(GitHashAlgorithm::Sha1);
    f.build_lexical();
    f.unrelated("original-allowance");
    let query = query(None);
    let report = f
        .query(&query, &Checkpoints::default(), InitialLimits::default())
        .unwrap();
    let baseline = hydrate(&f, report, ContextLimits::default()).unwrap();
    let combined = baseline.retrieval().result_bytes() + baseline.lineage_metadata_bytes();
    let limits = InitialLimits {
        max_result_bytes: combined,
        ..Default::default()
    };
    let exact = f.query(&query, &Checkpoints::default(), limits).unwrap();
    assert!(hydrate(&f, exact.clone(), ContextLimits::default()).is_ok());
    let under = f
        .query(
            &query,
            &Checkpoints::default(),
            InitialLimits {
                max_result_bytes: combined - 1,
                ..limits
            },
        )
        .unwrap();
    assert!(matches!(
        hydrate(&f, under.clone(), ContextLimits::default()),
        Err(RetrievalError::Limit("retained result bytes"))
    ));

    // If native selection ran first, both saved reports would now fail their
    // source pin. Only the exhausted metadata reservation must win beforehand.
    f.unrelated("after-retrieval");
    let before = f.head();
    assert!(matches!(
        hydrate(&f, under, ContextLimits::default()),
        Err(RetrievalError::Limit("retained result bytes"))
    ));
    assert!(matches!(hydrate(&f, exact, ContextLimits::default()),
        Err(RetrievalError::Source(NodeWorkspaceRefusal::SourceBrowse(error)))
            if matches!(*error, fgit_forge::source_browse::SourceBrowseError::SnapshotMoved)));
    assert_eq!(f.head(), before);
}

#[test]
fn head_code_and_generation_substitution_never_reselect_or_remint_lineage() {
    let mut f = Fixture::new(GitHashAlgorithm::Sha256);
    f.build_lexical();
    f.build_symbols();
    f.unrelated("selected-source");
    let query = query(Some(SymbolPolicy::Required));
    let report = f
        .query(&query, &Checkpoints::default(), InitialLimits::default())
        .unwrap();
    let context = hydrate(&f, report.clone(), ContextLimits::default()).unwrap();

    let mut altered_generation = report.clone();
    altered_generation.content.generation.authority_generation = altered_generation
        .content
        .generation
        .authority_generation
        .next()
        .unwrap();
    assert!(matches!(
        hydrate(&f, altered_generation, ContextLimits::default()),
        Err(RetrievalError::MixedGeneration)
    ));
    let mut altered_row = report.clone();
    altered_row.content.results.hits[0].spans[0].byte_offset += 1;
    assert!(matches!(
        hydrate(&f, altered_row, ContextLimits::default()),
        Err(RetrievalError::Invalid("result authorization label"))
    ));

    f.unrelated("new-current-selection");
    assert!(hydrate(&f, report.clone(), ContextLimits::default()).is_err());
    let fresh = f
        .query(&query, &Checkpoints::default(), InitialLimits::default())
        .unwrap();
    assert_eq!(fresh.content().source, report.content().source);
    assert_ne!(
        fresh.authorization().binding(),
        report.authorization().binding()
    );
    for file in context.files() {
        file.validate_revalidated_lineage(&report, &mut || Ok(()))
            .unwrap();
        assert!(matches!(
            file.validate_revalidated_lineage(&fresh, &mut || Ok(())),
            Err(RetrievalError::Invalid("context original label membership"))
        ));
    }
    assert!(hydrate(&f, fresh.clone(), ContextLimits::default()).is_ok());

    f.change_code();
    let before = f.head();
    assert!(hydrate(&f, fresh, ContextLimits::default()).is_err());
    assert!(matches!(
        f.query(&query, &Checkpoints::default(), InitialLimits::default()),
        Err(RetrievalError::Source(
            NodeWorkspaceRefusal::SourceIndexStale
        ))
    ));
    assert_eq!(f.head(), before);
}

#[test]
fn revalidated_hydration_requires_the_same_live_read_grant_and_request() {
    let mut f = Fixture::new(GitHashAlgorithm::Sha1);
    f.build_lexical();
    f.unrelated("grant-bound-context");
    let report = f
        .query(
            &query(None),
            &Checkpoints::default(),
            InitialLimits::default(),
        )
        .unwrap();
    let before = f.head();
    let node = f.node();
    let cancelled = node.request_context();
    cancelled.authority().cancel();
    assert!(matches!(
        node.runtime()
            .block_on(node.hydrate_source_initial_revalidated_local_in(
                &cancelled,
                &SourceReadContext::trusted_local_native(node),
                report.clone(),
                ContextLimits::default(),
            )),
        Err(RetrievalError::Source(
            NodeWorkspaceRefusal::Cancelled { .. }
        ))
    ));
    assert!(matches!(
        node.runtime()
            .block_on(node.hydrate_source_initial_revalidated_local_in(
                &node.request_context(),
                &SourceReadContext::trusted_local_mcp(node),
                report.clone(),
                ContextLimits::default(),
            )),
        Err(RetrievalError::Invalid("result authorization binding"))
    ));
    assert!(hydrate(&f, report, ContextLimits::default()).is_ok());
    assert_eq!(f.head(), before);
}
