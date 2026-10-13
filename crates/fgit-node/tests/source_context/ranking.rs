//! Production index/TreeFS selection, including an alphabetical distraction.
use super::*;
use fgit_node::source_retrieval::context::ranked::{RankedContext, channel_weight, SCORE_SCALE, RANK_CONSTANT};

fn ranked(node: &OneNode, report: InitialReport, limits: ContextLimits) -> Result<RankedContext, RetrievalError> {
    node.runtime().block_on(node.hydrate_source_initial_ranked_local_in(&node.outbox_delivery_context(), report, limits))
}
fn rank_corpus(root: &Scratch, format: GitHashAlgorithm, symbols: bool) -> (OneNode, GitOid) {
    let (node, base) = fixture(root, format);
    let mut inputs = vec![(b"00.txt".as_slice(), b"Thing is only mentioned here.\n".as_slice())];
    inputs.extend_from_slice(INPUTS);
    let commit = add(&node, base, &inputs, b"ranked-context-fixture");
    node.runtime().block_on(node.build_source_index_local_in(&node.outbox_delivery_context(), &reference(),
        None, Some(commit), None, Default::default())).unwrap();
    if symbols {
        node.runtime().block_on(node.build_source_symbol_index_local_in(&node.outbox_delivery_context(), &reference(),
            None, Some(commit), None, Default::default())).unwrap();
    }
    (node, commit)
}

#[test]
fn fusion_selects_corroborated_code_instead_of_alphabetical_distraction_and_survives_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, _) = rank_corpus(&root, format, true); let canonical = generation(&node);
        let report = initial(&node, b"Thing", true, &[]);
        let limits = ContextLimits { max_files: 1, ..Default::default() };
        let old = hydrate(&node, report.clone(), limits).unwrap();
        assert_eq!(old.files()[0].path(), b"00.txt");
        let selected = ranked(&node, report.clone(), limits).unwrap();
        assert_eq!(selected.context().files()[0].path(), b"a/Thing.rs");
        assert_eq!(selected.context().source_blobs_read(), 1);
        assert_eq!(selected.context().source_bytes_read(), A.len());
        assert_eq!(selected.context().files()[0].excerpts()[0].untrusted_bytes(), A);
        assert_eq!(selected.context().candidate_files(), 5);
        assert_eq!(selected.context().omitted_files(), 4); assert!(!selected.context().complete());
        assert_eq!(selected.context().retrieval().generations(), report.generations());
        let evidence = &selected.ranking().selected()[0];
        assert_eq!(evidence.path(), selected.context().files()[0].path());
        assert_eq!(evidence.blob(), selected.context().files()[0].blob());
        assert_eq!(evidence.contributions().len(), 3);
        let score: u32 = evidence.contributions().iter().map(|r|
            channel_weight(r.channel()) * SCORE_SCALE / (RANK_CONSTANT + r.document_rank())).sum();
        assert_eq!(evidence.score_q16(), score);
        assert_eq!(score, 4279);
        let two = ranked(&node, report.clone(), ContextLimits { max_files: 2, ..limits }).unwrap();
        assert_eq!(two.ranking().selected()[0], *evidence);
        assert_eq!(two.ranking().selected()[1].path(), b"raw\xff.rs");
        assert!(two.context().files().windows(2).all(|p| p[0].path() < p[1].path()));
        assert_eq!(generation(&node), canonical); node.shutdown().unwrap();
        let node = reopen(&config);
        let again = ranked(&node, report, limits).unwrap();
        assert_eq!(again.ranking(), selected.ranking());
        assert_eq!(again.context().files(), selected.context().files());
        assert_eq!(generation(&node), canonical); node.shutdown().unwrap();
    }
}

#[test]
fn ranked_selection_never_replaces_an_over_budget_winner_with_a_cheaper_file() {
    let root = Scratch::new(); let (node, _) = rank_corpus(&root, GitHashAlgorithm::Sha256, true);
    let report = initial(&node, b"Thing", true, &[]);
    let limits = ContextLimits { max_files: 1, max_source_bytes: A.len(), max_excerpt_bytes: A.len(), ..Default::default() };
    let exact = ranked(&node, report.clone(), limits).unwrap();
    assert_eq!(exact.context().source_file_limit(), A.len());
    for limits in [ContextLimits { max_source_bytes: A.len()-1, ..limits },
        ContextLimits { max_excerpt_bytes: A.len()-1, ..limits }] {
        assert!(ranked(&node, report.clone(), limits).is_err());
    }
    let scoped = ranked(&node, initial(&node, b"Thing", true, &[b"b".to_vec()]), Default::default()).unwrap();
    assert_eq!(scoped.context().files()[0].path(), b"b/Thing.txt");
    assert_eq!(scoped.ranking().selected()[0].contributions().len(), 1);
    assert_eq!(scoped.ranking().selected()[0].contributions()[0].channel(), ContextChannel::Path);
    node.shutdown().unwrap();
}

#[test]
fn optional_absence_and_empty_answers_are_not_upgraded_by_ranking() {
    let root = Scratch::new(); let (node, _) = rank_corpus(&root, GitHashAlgorithm::Sha1, false);
    let selected = ranked(&node, initial(&node, b"Thing", true, &[]), Default::default()).unwrap();
    assert!(!selected.context().complete());
    assert!(matches!(selected.context().retrieval().symbols(), SymbolChannel::Unavailable(_)));
    assert!(selected.ranking().selected().iter().all(|file|
        file.contributions().iter().all(|r| r.channel() != ContextChannel::Symbol)));
    let empty = ranked(&node, initial(&node, b"NoSuchToken", false, &[]), Default::default()).unwrap();
    assert_eq!(empty.ranking().candidate_files(), 0); assert!(empty.ranking().selected().is_empty());
    assert_eq!(empty.context().source_blobs_read(), 0);
    node.shutdown().unwrap();
}

#[test]
fn ranked_source_pins_cancellation_and_unpolled_reads_preserve_existing_state() {
    let root = Scratch::new(); let (node, commit) = rank_corpus(&root, GitHashAlgorithm::Sha1, true);
    let report = initial(&node, b"Thing", true, &[]); let before = generation(&node);
    let request = node.outbox_delivery_context();
    drop(node.hydrate_source_initial_ranked_local_in(&request, report.clone(), Default::default()));
    request.cancel();
    assert!(node.runtime().block_on(node.hydrate_source_initial_ranked_local_in(&request,
        report.clone(), Default::default())).is_err());
    assert_eq!(generation(&node), before);
    let source = ranked(&node, report.clone(), Default::default()).unwrap();
    assert_eq!(source.context().retrieval().generations(), report.generations());
    add(&node, commit, &[(b"new.txt", b"unrelated\n")], b"ranked-source-moved");
    let after = generation(&node);
    assert!(ranked(&node, report, Default::default()).is_err());
    assert_eq!(generation(&node), after); node.shutdown().unwrap();
}

mod http;
