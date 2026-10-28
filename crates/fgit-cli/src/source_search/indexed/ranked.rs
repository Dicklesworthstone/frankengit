//! Explicit ranked ANY-term reads through the ordinary current-source boundary.
use super::*;
use fgit_node::source_retrieval::current_index::RevalidatedRankedIndexReport;

const RANKED_USAGE: &str = "usage: fg search --ranked --indexed-current <storage-root> <tenant-id> <repository-id> <full-ref>
  --trusted-local --term <complete-ASCII-word> [--term <word>]...
  [--channel content|path] [--path <prefix> | --path-hex <bytes>]...
  [--object-format sha1|sha256] [--max-results <1..4096>]
  [--max-work <1..16777216>] [--max-index-bytes <1..33554432>]
  [--expected-head <snapshot-token>] [--expected-commit <native-oid>]
  [--generation <token> --generation-number <number>]
  [--minimum-generation <token> --minimum-number <number>]

Match ANY normalized term in one persisted immutable lexical generation.
Rank by number of distinct matched terms, then inverse-frequency weight,
then ascending raw path. source-lexical-coverage-rarity-v1 uses the exact
integer formula sum(floor((N+1)*65536/(df+1))) over matched terms: N and df
count the complete indexed corpus inside the requested path scope. This is
keyword retrieval, not BM25, embeddings, or semantic dependency analysis.

All selected segments are authenticated before a bounded top-k is returned.
Late corruption, missing data, cancellation or a budget refusal yields no
successful prefix. Existing index omissions are retained explicitly.
Scores and normalized query-index spans explain each selected result.
No document-ID cursor is supported; --after refuses. Increase --max-results
to request more results, retaining the source and generation pins for replay.
Exit 0: every indexed match returned with full coverage; 3: top-k truncation
or omitted files; 2: refusal. No source, index or repository state changes.";

pub(in crate::source_search) fn run(args: &[String]) -> Result<u8, String> {
    if args == ["--help"] {
        write_report(&mut std::io::stdout().lock(), RANKED_USAGE)?;
        return Ok(0);
    }
    let options = options::parse(args)?;
    if options.after.is_some() {
        return Err("ranked search does not support --after; repeat pinned query with a larger --max-results".into());
    }
    let mut node = OneNode::open_existing(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format),
    )
    .map_err(|error| error.to_string())?;
    let operation = (|| {
        let authenticated = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .map_err(|error| error.to_string())?;
        node.bring_into_service(authenticated.receipt().generation())
            .map_err(|error| error.to_string())?;
        let request = fgit_cli::command_request_context(&node);
        node.runtime()
            .block_on(
                node.search_source_index_ranked_revalidated_local_in(&request, options.request()),
            )
            .map_err(|error| error.to_string())
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    finish(&mut std::io::stdout().lock(), operation, cleanup)
}

fn finish(
    output: &mut impl Write,
    operation: Result<RevalidatedRankedIndexReport, String>,
    cleanup: Option<String>,
) -> Result<u8, String> {
    let report = match (operation, cleanup) {
        (Ok(report), None) => report,
        (Err(error), None) => return Err(error),
        (Ok(_), Some(error)) => return Err(format!("ranked search node shutdown failed: {error}")),
        (Err(error), Some(cleanup)) => {
            return Err(format!("{error}; node shutdown also failed: {cleanup}"));
        }
    };
    let ranking = report.ranking();
    let rendered = render_profile(report.current_source(), &ranking.index, Some(ranking))?;
    write_report(output, &rendered)?;
    Ok(
        if ranking.index.results.complete && ranking.index.coverage_complete {
            0
        } else {
            3
        },
    )
}

pub(super) fn metadata(report: &RankedLexicalReport) -> Result<String, String> {
    let query = &report.index.query;
    if report.scores.len() != report.index.results.hits.len()
        || report.term_document_frequencies.len() != query.terms().len()
        || report.scoped_documents > report.index.indexed_documents
        || report.matched_documents > report.scoped_documents
        || report.index.results.hits.len() > report.matched_documents
        || report.index.results.next_after.is_some()
        || report.index.results.complete
            != (report.matched_documents == report.index.results.hits.len())
        || report
            .term_document_frequencies
            .iter()
            .any(|df| *df > report.scoped_documents)
    {
        return Err("invalid ranked lexical evidence".into());
    }
    for (hit, score) in report.index.results.hits.iter().zip(&report.scores) {
        if hit.spans.is_empty()
            || score.matched_terms != hit.spans.len()
            || hit
                .spans
                .windows(2)
                .any(|pair| pair[0].query_index >= pair[1].query_index)
        {
            return Err("invalid ranked match coverage".into());
        }
        let mut expected = 0u64;
        for span in &hit.spans {
            let df = *report
                .term_document_frequencies
                .get(span.query_index)
                .filter(|df| **df != 0)
                .ok_or("invalid ranked term frequency")?;
            expected += (report.scoped_documents as u64 + 1) * RARITY_SCALE / (df as u64 + 1);
        }
        if score.rarity_q16 != expected {
            return Err("invalid ranked rarity score".into());
        }
    }
    Ok(format!(
        concat!(
            "\"query_mode\":\"any\",\"candidate_scan_complete\":true,",
            "\"ranking_order\":[\"matched_terms_desc\",\"rarity_q16_desc\",\"raw_path_asc\"],",
            "\"rarity_scale\":{},\"scoped_documents\":{},\"matched_documents\":{},",
            "\"term_document_frequencies\":[{}],"
        ),
        RARITY_SCALE,
        report.scoped_documents,
        report.matched_documents,
        report
            .term_document_frequencies
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(","),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ranked_dispatch_is_explicit_and_has_no_document_cursor() {
        assert!(crate::source_search::run(&["--ranked".into(), "--help".into()]).is_err());
        assert_eq!(
            crate::source_search::run(&[
                "--ranked".into(),
                "--indexed-current".into(),
                "--help".into()
            ])
            .unwrap(),
            0
        );
        assert_eq!(
            crate::source_search::run(&[
                "--indexed-current".into(),
                "--ranked".into(),
                "--help".into()
            ])
            .unwrap(),
            0
        );
        let error = run(&super::super::tests::pinned()).unwrap_err();
        assert!(error.contains("does not support --after"));
    }
}
