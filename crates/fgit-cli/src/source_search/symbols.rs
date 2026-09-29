//! Explicit Rust declaration retrieval through the native snapshot reader.
//! No compiler, macro expansion, index build or repository mutation is performed.
mod indexed;
mod options;
#[cfg(test)]
mod tests;

use super::{hex, quote, write_report};
use fgit_forge::source_search::{SearchCompletion, SearchLimits};
use fgit_forge::source_symbols::{
    MAX_SYMBOL_WORK, PROFILE, SymbolKind, SymbolMatchMode, SymbolQuery, SymbolReadError,
    SymbolSearchReport,
};
use fgit_node::{NodeConfig, OneNode};
use fgit_types::{
    GitHashAlgorithm, GitOid, RefName, RepositoryAuthorityHeadId, RepositoryId, TenantId,
};
use std::io::Write;
use std::path::PathBuf;

const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const USAGE: &str =
    "usage: fg search --symbols <storage-root> <tenant-id> <repository-id> <full-ref>
  --trusted-local --name <ASCII-identifier> [--match exact|prefix]
  [--kind function|struct|enum|trait|type|module|union|macro]...
  [--path <prefix> | --path-hex <bytes>]... [--object-format sha1|sha256]
  [--expected-head <snapshot-token>] [--expected-commit <native-oid>]
  [--max-matches <1..4096>] [--max-work <1..67108864>]
  [--max-bytes <1..67108864>] [--max-file-bytes <1..8388608>]
  [--max-files <1..20000>]

Search declaration heads in .rs regular files in one verified native snapshot.
Names are case-sensitive ASCII identifiers (without the r# prefix); paths and
source spans are exact bytes. Kind and path filters only narrow the read scope.
This is NOT compiler name resolution: attributes and macro bodies are opaque,
all cfg branches are searched, and other languages are counted but not parsed.
No source code is executed. No index is required, built or refreshed.

Malformed or unsupported Rust source, stale pins and exhausted resource budgets
are errors, not empty successful answers. Syntax errors include a hexadecimal
path and byte offset. The snapshot_token can be reused as --expected-head.
Exit 0: complete answer (including no matches); 3: truncated match prefix;
2: argument, read, shutdown or output error. A prefix is not a paginated cursor.
For existing persisted tables: fg search --symbols --indexed-current --help";

pub(super) fn run(args: &[String]) -> Result<u8, String> {
    if args.first().is_some_and(|arg| arg == "--indexed-current") {
        return indexed::run(&args[1..]);
    }
    if args == ["--help"] {
        write_report(&mut std::io::stdout().lock(), USAGE)?;
        return Ok(0);
    }
    let options = options::parse(args)?;
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
            .block_on(node.search_source_symbols_snapshot_local_in(
                &request,
                &options.reference,
                options.expected_head,
                options.expected_commit,
                &options.query,
                options.limits,
            ))
            .map_err(read_error)
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    finish(&mut std::io::stdout().lock(), &options, operation, cleanup)
}

fn read_error<E: std::fmt::Display>(error: SymbolReadError<E>) -> String {
    match error {
        SymbolReadError::Source(error) => error.to_string(),
        SymbolReadError::Syntax { path, error } => {
            format!("symbol source path_hex={}: {error}", hex(&path))
        }
    }
}

fn finish(
    output: &mut impl Write,
    options: &options::Options,
    operation: Result<(RepositoryAuthorityHeadId, SymbolSearchReport), String>,
    cleanup: Option<String>,
) -> Result<u8, String> {
    let (head, report) = match (operation, cleanup) {
        (Ok(report), None) => report,
        (Err(error), None) => return Err(error),
        (Ok(_), Some(error)) => return Err(format!("symbol search node shutdown failed: {error}")),
        (Err(error), Some(cleanup)) => {
            return Err(format!("{error}; node shutdown also failed: {cleanup}"));
        }
    };
    let rendered = render(options, head, &report)?;
    write_report(output, &rendered)?;
    Ok(if report.completion == SearchCompletion::Complete {
        0
    } else {
        3
    })
}

fn head_token(head: RepositoryAuthorityHeadId) -> String {
    let id = head.as_internal_object_id();
    format!(
        "alg:{}:{}",
        id.algorithm().code_point(),
        hex(id.digest().as_bytes())
    )
}

fn render(
    options: &options::Options,
    head: RepositoryAuthorityHeadId,
    report: &SymbolSearchReport,
) -> Result<String, String> {
    let complete = report.completion == SearchCompletion::Complete;
    let mode = match options.query.mode() {
        SymbolMatchMode::Exact => "exact",
        SymbolMatchMode::Prefix => "prefix",
    };
    let kinds = options
        .query
        .kinds()
        .iter()
        .map(|kind| quote(kind.as_str()))
        .collect::<Vec<_>>()
        .join(",");
    let paths = options
        .query
        .source_scope()
        .prefixes()
        .iter()
        .map(|path| quote(&hex(path.as_bytes())))
        .collect::<Vec<_>>()
        .join(",");
    let mut out = format!(
        concat!(
            "{{\"type\":\"source_symbol_search\",\"schema_version\":1,\"profile\":{},",
            "\"tenant_id\":{},\"repository_id\":{},\"object_format\":{},\"reference_hex\":{},",
            "\"source_head\":{},\"snapshot_token\":{},\"source_rcr\":{},\"source_commit\":{},\"source_tree\":{},",
            "\"name_hex\":{},\"match_mode\":{},\"kinds\":[{}],\"path_prefixes_hex\":[{}],",
            "\"complete\":{},\"truncated_reason\":{},\"match_count\":{},\"max_matches\":{},",
            "\"files_selected\":{},\"files_read\":{},\"bytes_read\":{},\"bytes_searched\":{},",
            "\"non_regular_entries\":{},\"unsupported_language_files\":{},\"declarations_examined\":{},",
            "\"macro_bodies_skipped\":{},\"attributes_skipped\":{},\"work_units\":{},",
            "\"node_closed\":true,\"repository_changed\":false,\"index_changed\":false,\"matches\":["
        ),
        quote(PROFILE),
        quote(&options.tenant.to_string()),
        quote(&report.repository.to_string()),
        quote(options.format.as_str()),
        quote(&hex(options.reference.as_bytes())),
        quote(&head.to_string()),
        quote(&head_token(head)),
        quote(&report.source_rcr.to_string()),
        quote(&report.source_commit.to_string()),
        quote(&report.source_tree.to_string()),
        quote(&hex(options.query.name())),
        quote(mode),
        kinds,
        paths,
        complete,
        if complete { "null" } else { "\"match_limit\"" },
        report.matches.len(),
        options.limits.max_matches,
        report.files_selected,
        report.files_read,
        report.bytes_read,
        report.bytes_searched,
        report.non_regular_entries,
        report.unsupported_language_files,
        report.declarations_examined,
        report.macro_bodies_skipped,
        report.attributes_skipped,
        quote(&report.work_units.to_string()),
    );
    append_matches(&mut out, &report.matches)?;
    out.push_str("]}");
    if out.len() > MAX_OUTPUT_BYTES {
        return Err("symbol search JSON exceeds its output budget".into());
    }
    Ok(out)
}

fn append_matches(
    out: &mut String,
    matches: &[fgit_forge::source_symbols::SymbolMatch],
) -> Result<(), String> {
    for (ordinal, hit) in matches.iter().enumerate() {
        if ordinal != 0 {
            out.push(',');
        }
        let location = &hit.location;
        out.push_str(&format!(
            concat!(
                "{{\"name_hex\":{},\"kind\":{},\"raw_identifier\":{},\"path_hex\":{},\"blob\":{},",
                "\"byte_offset\":{},\"line\":{},\"byte_column\":{},\"excerpt_hex\":{},",
                "\"excerpt_offset\":{},\"match_length\":{}}}"
            ),
            quote(&hex(&hit.name)),
            quote(hit.kind.as_str()),
            hit.raw_identifier,
            quote(&hex(&location.path)),
            quote(&location.blob.to_string()),
            location.byte_offset,
            location.line,
            location.byte_column,
            quote(&hex(&location.excerpt)),
            location.excerpt_offset,
            location.match_length,
        ));
        if out.len() > MAX_OUTPUT_BYTES {
            return Err("symbol search JSON exceeds its output budget".into());
        }
    }
    Ok(())
}
