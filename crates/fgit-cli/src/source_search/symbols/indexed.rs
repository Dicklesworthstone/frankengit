//! Explicit current-source reads of persisted declaration tables, never a scan fallback.
use super::*;
use fgit_forge::source_symbols::index as data;
use fgit_node::source_retrieval::current_index::GenerationActivation;
use fgit_types::{CANONICAL_CODEC_VERSION, GenerationId, HeadGeneration, InternalObjectId};
use std::collections::BTreeMap;

#[cfg(test)]
mod tests;

const USAGE: &str = "usage: fg search --symbols --indexed-current <storage-root> <tenant-id> <repository-id> <full-ref>
  --trusted-local --name <ASCII-identifier> [--match exact|prefix]
  [--kind function|struct|enum|trait|type|module|union|macro]...
  [--path <prefix> | --path-hex <bytes>]... [--object-format sha1|sha256]
  [--expected-head <snapshot-token>] [--expected-commit <native-oid>]
  [--minimum-generation <token> --minimum-number <number>]
  [--max-index-bytes <1..33554432>] [--max-matches <1..4096>]
  [--max-work <1..67108864>] [--max-bytes <1..67108864>]
  [--max-file-bytes <1..8388608>] [--max-files <1..20000>]

Read an existing persisted Rust declaration index without scanning source blobs.
Current repository authority and native commit/tree are checked independently.
Unrelated issue/PR/ref metadata changes can reuse the same native source, but
current_source and indexed_source remain distinct: provenance is NOT rewritten.
The old generation is not a read grant. Whole-repository local trust is required.

No index is built or refreshed, and unavailable/stale/corrupt index data never
falls back to scanning or becomes an empty successful answer. Index payload and
query work budgets are independent. Source-byte/file limits constrain referenced
index documents, not a source scan. Minimum generation is an ancestry floor,
not exact selection, a retention pin, or a pagination token. Match truncation
requires narrowing the query or increasing its bounded result limit; no --after.
Exit 0: complete result (including no matches); 3: truncated match prefix;
2: argument, read, shutdown or output error. No canonical/index publication.";

#[derive(Debug)]
struct Options {
    query: options::Options,
    maximum_payload_bytes: usize,
    minimum: Option<GenerationActivation>,
}

fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 4 || args.len() > 320
        || args.iter().any(|arg| arg.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 128 * 1024
    {
        return Err(USAGE.into());
    }
    let mut common = args[..4].to_vec();
    let mut flags = BTreeMap::new();
    let mut cursor = 4;
    while cursor < args.len() {
        let flag = args[cursor].as_str();
        cursor += 1;
        if flag == "--trusted-local" {
            common.push(flag.into());
            continue;
        }
        let value = args.get(cursor).ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        if matches!(flag, "--max-index-bytes" | "--minimum-generation" | "--minimum-number") {
            if flags.insert(flag, value.as_str()).is_some() {
                return Err(format!("duplicate {flag}"));
            }
        } else {
            common.extend([flag.to_owned(), value.clone()]);
        }
    }
    let query = options::parse(&common)?;
    let maximum_payload_bytes = flags.get("--max-index-bytes")
        .map(|text| super::super::decimal(text)).transpose()?.unwrap_or(data::MAX_INDEX_BYTES);
    if maximum_payload_bytes > data::MAX_INDEX_BYTES {
        return Err("index byte limit exceeds the bounded profile".into());
    }
    let minimum = match (flags.get("--minimum-generation"), flags.get("--minimum-number")) {
        (None, None) => None,
        (Some(token), Some(number)) => {
            let (algorithm, digest) = options::parse_id(token)?;
            Some(GenerationActivation {
                generation_id: GenerationId::from_digest(algorithm, CANONICAL_CODEC_VERSION, digest),
                authority_generation: HeadGeneration::try_new(options::positive_u64(number)?)
                    .map_err(|error| error.to_string())?,
            })
        }
        _ => return Err("--minimum-generation and --minimum-number must be supplied together".into()),
    };
    Ok(Options { query, maximum_payload_bytes, minimum })
}

pub(super) fn run(args: &[String]) -> Result<u8, String> {
    if args == ["--help"] {
        write_report(&mut std::io::stdout().lock(), USAGE)?;
        return Ok(0);
    }
    let options = parse(args)?;
    let query = &options.query;
    let mut node = OneNode::open_existing(
        NodeConfig::new(query.storage.clone(), query.tenant, query.repository)
            .with_object_format(query.format),
    ).map_err(|error| error.to_string())?;
    let operation = (|| {
        let authenticated = node.runtime().block_on(node.authenticate_authority_head())
            .map_err(|error| error.to_string())?;
        node.bring_into_service(authenticated.receipt().generation())
            .map_err(|error| error.to_string())?;
        let request = node.request_context();
        node.runtime().block_on(node.search_source_symbols_index_revalidated_local_in(
            &request, &query.reference, query.expected_head, query.expected_commit,
            options.minimum.as_ref(), &query.query, query.limits, options.maximum_payload_bytes,
        )).map_err(|error| error.to_string())
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    finish(&mut std::io::stdout().lock(), &options, operation, cleanup)
}

fn finish(
    output: &mut impl Write,
    options: &Options,
    operation: Result<(data::Source, data::Report), String>,
    cleanup: Option<String>,
) -> Result<u8, String> {
    let (current, report) = match (operation, cleanup) {
        (Ok(report), None) => report,
        (Err(error), None) => return Err(error),
        (Ok(_), Some(error)) => return Err(format!("indexed symbol node shutdown failed: {error}")),
        (Err(error), Some(cleanup)) => {
            return Err(format!("{error}; node shutdown also failed: {cleanup}"));
        }
    };
    let text = render(options, &current, &report)?;
    write_report(output, &text)?;
    Ok(if report.complete { 0 } else { 3 })
}

fn token(id: &InternalObjectId) -> String {
    format!("alg:{}:{}", id.algorithm().code_point(), hex(id.digest().as_bytes()))
}
fn source_json(source: &data::Source) -> String {
    format!(concat!(
        "{{\"tenant_id\":{},\"repository_id\":{},\"incarnation_id\":{},\"object_format\":{},",
        "\"reference_hex\":{},\"source_head\":{},\"snapshot_token\":{},\"source_rcr\":{},",
        "\"rcr_token\":{},\"forge_position_root\":{},\"forge_algorithm\":{},\"commit\":{},\"tree\":{}}}"),
        quote(&source.tenant.to_string()), quote(&source.repository.to_string()),
        quote(&source.incarnation.to_string()), quote(source.format.as_str()),
        quote(&hex(source.reference.as_bytes())), quote(&source.head.to_string()),
        quote(&head_token(source.head)), quote(&source.rcr.to_string()),
        quote(&token(&source.rcr.as_internal_object_id())), quote(&hex(source.forge.bytes().as_bytes())),
        source.forge.algorithm().code_point(), quote(&source.commit.to_string()), quote(&source.tree.to_string()),
    )
}

// Production calls this only with the node's revalidated current-source tuple.
// Rendering does not authenticate caller-created Source/Report values.
fn render(options: &Options, current: &data::Source, report: &data::Report) -> Result<String, String> {
    let query = &options.query.query;
    let mode = match query.mode() { SymbolMatchMode::Exact => "exact", SymbolMatchMode::Prefix => "prefix" };
    let kinds = query.kinds().iter().map(|kind| quote(kind.as_str())).collect::<Vec<_>>().join(",");
    let paths = query.source_scope().prefixes().iter()
        .map(|path| quote(&hex(path.as_bytes()))).collect::<Vec<_>>().join(",");
    let mut out = format!(concat!(
        "{{\"type\":\"source_symbol_index_search\",\"schema_version\":1,",
        "\"profile\":\"source-symbols-revalidated-v1\",\"index_profile\":{},\"declaration_profile\":{},",
        "\"current_source\":{},\"indexed_source\":{},\"distinct_index_provenance\":{},",
        "\"generation\":{{\"token\":{},\"number\":{}}},\"name_hex\":{},\"match_mode\":{},",
        "\"kinds\":[{}],\"path_prefixes_hex\":[{}],\"complete\":{},\"truncated_reason\":{},",
        "\"match_count\":{},\"max_matches\":{},\"indexed_files\":{},\"indexed_declarations\":{},",
        "\"indexed_source_bytes\":{},\"unsupported_language_files\":{},\"non_regular_entries\":{},",
        "\"tables_read\":{},\"payload_bytes_read\":{},\"work_units\":{},\"node_closed\":true,",
        "\"repository_changed\":false,\"index_changed\":false,\"matches\":["),
        quote(data::INDEX_PROFILE), quote(PROFILE), source_json(current), source_json(&report.source),
        current != &report.source, quote(&token(&report.generation)), quote(&report.generation_number.to_string()),
        quote(&hex(query.name())), quote(mode), kinds, paths, report.complete,
        if report.complete { "null" } else { "\"match_limit\"" }, report.matches.len(), options.query.limits.max_matches,
        report.indexed_files, report.indexed_declarations, report.indexed_source_bytes,
        report.unsupported_language_files, report.non_regular_entries, report.tables_read,
        report.payload_bytes_read, quote(&report.work_units.to_string()),
    );
    append_matches(&mut out, &report.matches)?;
    out.push_str("]}");
    if out.len() > MAX_OUTPUT_BYTES { return Err("indexed symbol JSON exceeds its output budget".into()); }
    Ok(out)
}
