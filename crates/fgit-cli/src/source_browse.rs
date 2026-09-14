//! Read-only source discovery and exact file bytes through the node boundary.
mod options;
use fgit_forge::source_browse::{SourceBrowseContent, SourceBrowseReport};
use fgit_node::{NodeConfig, OneNode};
use fgit_types::{HeadGeneration, RepositoryAuthorityHeadId};
use std::io::Write;
use super::publication_support::quote;
use options::Options;

const USAGE: &str = "usage: fg tree <storage-root> <tenant-id> <repository-id> --trusted-local
  (--ref <full-ref> | --ref-hex <bytes>) [--path <path> | --path-hex <bytes>]
  [--limit <1..1000>] [--after-hex <child-name> --expected-head <snapshot-token>]
  [--expected-commit <native-oid>] [--object-format sha1|sha256]
usage: fg show <storage-root> <tenant-id> <repository-id> --trusted-local
  (--ref <full-ref> | --ref-hex <bytes>) (--path <path> | --path-hex <bytes>)
  [--max-bytes <1..1048576>] [--offset <byte-offset> --expected-head <snapshot-token>]
  [--expected-commit <native-oid>] [--object-format sha1|sha256]

Tree pages contain immediate children sorted by raw name bytes. An omitted tree
path means the root. All path/name bytes and file payloads have exact hex fields;
text_utf8 is an optional convenience, never a replacement for bytes_hex. Symlink
payloads are data and never followed. Gitlinks list as opaque IDs, not local files.
Use snapshot_token from the first page for every continuation. If authority moved,
restart instead of combining pages. --expected-commit pins independently reviewed
source identity; it does not select historical state or reveal hidden references.
Read-only: no publication credentials, host checkout, implicit latest-tip mutation,
symlink traversal or external Git. Limits bound decoded objects and whole reads,
not just output ranges. Exit 0: complete page; 2: input/read/cleanup/output error.";

pub(super) fn run(args: &[String], file: bool) -> Result<u8, String> {
    if args == ["--help"] { emit(&mut std::io::stdout().lock(), USAGE)?; return Ok(0); }
    let options = options::parse(args, file)?;
    let mut node = OneNode::open_existing(NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
        .with_object_format(options.format)).map_err(|error| format!("cannot open source node: {error}"))?;
    let result = (|| {
        node.bring_into_service(HeadGeneration::FIRST).map_err(|error| error.to_string())?;
        let request = node.request_context();
        node.runtime().block_on(node.browse_source_local_in(&request, &options.reference, &options.query))
            .map_err(|error| error.to_string())
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    finish(&mut std::io::stdout().lock(), &options, result, cleanup)
}
fn finish(output: &mut impl Write, options: &Options, result: Result<SourceBrowseReport, String>,
    cleanup: Option<String>) -> Result<u8, String> {
    match (result, cleanup) {
        (Ok(report), None) => { emit(output, &receipt(options, &report))?; Ok(0) }
        (result, cleanup) => {
            let read = result.err().map_or_else(String::new, |error| format!("; read: {error}"));
            let close = cleanup.map_or_else(String::new, |error| format!("; shutdown: {error}"));
            Err(format!("no complete source page returned{read}{close}"))
        }
    }
}
fn emit(output: &mut impl Write, page: &str) -> Result<(), String> {
    writeln!(output, "{page}").and_then(|()| output.flush())
        .map_err(|error| format!("source page output incomplete: {error}"))
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }
fn head_token(head: RepositoryAuthorityHeadId) -> String {
    let id = head.as_internal_object_id();
    format!("alg:{}:{}", id.algorithm().code_point(), hex(id.digest().as_bytes()))
}
fn optional_hex(bytes: Option<&[u8]>) -> String { bytes.map_or_else(|| "null".into(), |bytes| quote(&hex(bytes))) }
fn receipt(options: &Options, report: &SourceBrowseReport) -> String {
    let common = format!(concat!("\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},",
        "\"reference_hex\":{},\"object_format\":{},\"source_head\":{},\"snapshot_token\":{},",
        "\"source_rcr\":{},\"source_commit\":{},\"root_tree\":{},\"object_id\":{},\"path_hex\":{},",
        "\"node_closed\":true,\"repository_changed\":false"),
        quote(&options.tenant.to_string()), quote(&report.repository_id.to_string()), quote(&hex(options.reference.as_bytes())),
        quote(options.format.as_str()), quote(&report.source_head.to_string()), quote(&head_token(report.source_head)),
        quote(&report.source_rcr.to_string()), quote(&report.source_commit.to_string()), quote(&report.root_tree.to_string()),
        quote(&report.object_id.to_string()), optional_hex(report.path.as_deref()));
    match &report.content {
        SourceBrowseContent::Directory { entries, next_after } => {
            let entries = entries.iter().map(|entry| format!("{{\"name_hex\":{},\"kind\":{},\"object_id\":{}}}",
                quote(&hex(&entry.name)), quote(entry.kind.as_str()), quote(&entry.oid.to_string())))
                .collect::<Vec<_>>().join(",");
            format!("{{\"type\":\"source_tree\",{common},\"entries\":[{entries}],\"next_after_hex\":{},\"has_more\":{}}}",
                optional_hex(next_after.as_deref()), next_after.is_some())
        }
        SourceBrowseContent::Blob { kind, bytes, total_bytes, offset, next_offset } => {
            let text = std::str::from_utf8(bytes).ok().map_or_else(|| "null".into(), quote);
            let next = next_offset.map_or_else(|| "null".into(), |value| value.to_string());
            format!(concat!("{{\"type\":\"source_file\",{},\"kind\":{},\"bytes_hex\":{},\"text_utf8\":{},",
                "\"total_bytes\":{},\"offset\":{},\"returned_bytes\":{},\"next_offset\":{},\"has_more\":{}}}"),
                common, quote(kind.as_str()), quote(&hex(bytes)), text, total_bytes, offset, bytes.len(), next, next_offset.is_some())
        }
    }
}
#[cfg(test)]
mod tests;
