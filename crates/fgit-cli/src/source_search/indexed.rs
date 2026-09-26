//! Explicit persisted-index reads; never an implicit fallback from literal search.
mod options;
#[cfg(test)]
mod tests;

use super::{hex, quote, write_report};
use fgit_node::source_retrieval::current_index::{
    GenerationActivation, IndexedLexicalReport, LexicalChannel, LexicalQuery, LexicalQueryLimits,
    LexicalReadLimits, LexicalSource, PROFILE, RevalidatedIndexReport, RevalidatedIndexRequest,
};
use fgit_node::{NodeConfig, OneNode};
use fgit_types::{GenerationId, GitHashAlgorithm, GitOid, RefName, RepositoryAuthorityHeadId, RepositoryId, TenantId};
use std::io::Write;
use std::path::PathBuf;

const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const USAGE: &str = "usage: fg search --indexed-current <storage-root> <tenant-id> <repository-id> <full-ref>
  --trusted-local --term <complete-ASCII-word> [--term <word>]...
  [--channel content|path] [--path <prefix> | --path-hex <bytes>]...
  [--object-format sha1|sha256] [--max-results <1..4096>]
  [--max-work <1..16777216>] [--max-index-bytes <1..33554432>]
  [--expected-head <snapshot-token>] [--expected-commit <native-oid>]
  [--generation <token> --generation-number <number>]
  [--minimum-generation <token> --minimum-number <number>]
  [--after <document-id>]

Query a previously built lexical index; this command NEVER builds or refreshes it.
Terms are ANDed complete ASCII alphanumeric/underscore words of at most 128 bytes,
with ASCII case folding. This is NOT the default literal/substring search profile.
Content and path are separate channels. Paths in results are exact hexadecimal.

Unrelated issue/PR/ref metadata may change without invalidating these postings
when the same currently visible ref still selects the exact indexed commit/tree.
current_source names this read's verified authority basis; indexed_source retains
the original generation's provenance. Neither may be relabelled as the other.
Changed code, hidden/missing refs, corrupt/missing index data and exhausted budgets
are errors, never empty successful results or triggers for an automatic rebuild.

To continue, repeat the same terms/channel/path scope, pass next_after as --after,
current_source.snapshot_token as --expected-head, current_source.commit as
--expected-commit, and generation.token/number as --generation/--generation-number.
All four pins are required. A head change between pages refuses; start a new query.
Retain selected_generation_head as an independent minimum checkpoint when needed.
Document IDs and generation numbers are decimal JSON strings, preserving u64 values.
Exit 0: complete answer (including no matches); 3: result prefix with continuation;
2: argument, read, shutdown or output error. No canonical or index publication.";

pub(super) fn run(args: &[String]) -> Result<u8, String> {
    if args == ["--help"] {
        write_report(&mut std::io::stdout().lock(), USAGE)?;
        return Ok(0);
    }
    let options = options::parse(args)?;
    let mut node = OneNode::open_existing(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format),
    ).map_err(|error| error.to_string())?;
    let operation = (|| {
        let authenticated = node.runtime().block_on(node.authenticate_authority_head())
            .map_err(|error| error.to_string())?;
        node.bring_into_service(authenticated.receipt().generation())
            .map_err(|error| error.to_string())?;
        let request = node.request_context();
        node.runtime().block_on(node.search_source_index_revalidated_local_in(
            &request, options.request(),
        )).map_err(|error| error.to_string())
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    finish(&mut std::io::stdout().lock(), operation, cleanup)
}

fn finish(
    output: &mut impl Write,
    operation: Result<RevalidatedIndexReport, String>,
    cleanup: Option<String>,
) -> Result<u8, String> {
    let report = match (operation, cleanup) {
        (Ok(report), None) => report,
        (Err(error), None) => return Err(error),
        (Ok(_), Some(error)) => return Err(format!("indexed search node shutdown failed: {error}")),
        (Err(error), Some(cleanup)) => {
            return Err(format!("{error}; node shutdown also failed: {cleanup}"));
        }
    };
    let rendered = render(report.current_source(), report.index())?;
    write_report(output, &rendered)?;
    Ok(if report.index().results.complete { 0 } else { 3 })
}

fn head_token(head: RepositoryAuthorityHeadId) -> String {
    let id = head.as_internal_object_id();
    format!("alg:{}:{}", id.algorithm().code_point(), hex(id.digest().as_bytes()))
}
fn generation_token(generation: GenerationId) -> String {
    let id = generation.as_internal_object_id();
    format!("alg:{}:{}", id.algorithm().code_point(), hex(id.digest().as_bytes()))
}
fn activation_json(activation: &GenerationActivation) -> String {
    format!("{{\"token\":{},\"number\":{}}}",
        quote(&generation_token(activation.generation_id)),
        quote(&activation.authority_generation.get().to_string()))
}
fn source_json(source: &LexicalSource) -> String {
    let rcr = source.source_rcr.as_internal_object_id();
    format!(concat!(
        "{{\"tenant_id\":{},\"repository_id\":{},\"incarnation_id\":{},",
        "\"object_format\":{},\"reference_hex\":{},\"source_head\":{},\"snapshot_token\":{},",
        "\"source_rcr\":{},\"rcr_algorithm\":{},\"forge_position_root\":{},\"forge_algorithm\":{},",
        "\"commit\":{},\"tree\":{}}}"),
        quote(&source.namespace.tenant.to_string()),
        quote(&source.namespace.repository.to_string()),
        quote(&source.namespace.incarnation.to_string()),
        quote(source.namespace.object_format.as_str()),
        quote(&hex(source.reference.as_bytes())),
        quote(&source.source_head.to_string()), quote(&head_token(source.source_head)),
        quote(&source.source_rcr.to_string()), rcr.algorithm().code_point(),
        quote(&hex(source.forge_position_root.bytes().as_bytes())),
        source.forge_position_root.algorithm().code_point(),
        quote(&source.commit.to_string()), quote(&source.tree.to_string()),
    )
}
fn byte_list(values: &[Vec<u8>]) -> String {
    values.iter().map(|v| quote(&hex(v))).collect::<Vec<_>>().join(",")
}

// Production receives both arguments only from the node's private-constructor
// receipt. This pure renderer does not authenticate caller-supplied snapshots.
fn render(current: &LexicalSource, index: &IndexedLexicalReport) -> Result<String, String> {
    let channel = match index.query.channel() {
        LexicalChannel::Content => "content",
        LexicalChannel::Path => "path",
    };
    let next = index.results.next_after.map_or_else(
        || "null".into(), |id| quote(&id.to_string()),
    );
    let mut out = format!(concat!(
        "{{\"type\":\"source_index_search\",\"schema_version\":1,\"profile\":{},",
        "\"current_source\":{},\"indexed_source\":{},\"distinct_index_provenance\":{},",
        "\"generation\":{},\"selected_generation_head\":{},\"channel\":{},",
        "\"terms_hex\":[{}],\"path_prefixes_hex\":[{}],\"complete\":{},\"next_after\":{},",
        "\"indexed_documents\":{},\"indexed_source_bytes\":{},\"non_regular_entries\":{},",
        "\"segments_read\":{},\"payload_bytes_read\":{},\"generation_bytes_read\":{},",
        "\"work_units\":{},\"node_closed\":true,\"repository_changed\":false,",
        "\"index_changed\":false,\"hits\":["),
        quote(PROFILE), source_json(current), source_json(&index.source), current != &index.source,
        activation_json(&index.generation), activation_json(&index.selected_generation_head), quote(channel),
        byte_list(index.query.terms()), byte_list(index.query.prefixes()), index.results.complete, next,
        index.indexed_documents, index.indexed_source_bytes, index.non_regular_entries,
        index.segments_read, index.payload_bytes_read, index.generation_bytes_read, index.results.work_units,
    );
    for (ordinal, hit) in index.results.hits.iter().enumerate() {
        if ordinal != 0 { out.push(','); }
        let spans = hit.spans.iter().map(|span| format!(
            "{{\"query_index\":{},\"byte_offset\":{},\"byte_length\":{}}}",
            span.query_index, span.byte_offset, span.byte_length,
        )).collect::<Vec<_>>().join(",");
        out.push_str(&format!(
            "{{\"document_id\":{},\"path_hex\":{},\"blob\":{},\"content_bytes\":{},\"spans\":[{}]}}",
            quote(&hit.document_id.to_string()), quote(&hex(&hit.path)),
            quote(&hit.blob.to_string()), hit.content_bytes, spans,
        ));
        if out.len() > MAX_OUTPUT_BYTES {
            return Err("indexed search JSON exceeds its output budget".into());
        }
    }
    out.push_str("]}");
    if out.len() > MAX_OUTPUT_BYTES {
        return Err("indexed search JSON exceeds its output budget".into());
    }
    Ok(out)
}
