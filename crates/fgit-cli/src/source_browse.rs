//! Read-only source discovery and exact file bytes through the node boundary.
mod options;
use fgit_forge::source_browse::{
    SourceBrowseAction, SourceBrowseContent, SourceBrowseQuery, SourceBrowseReport, SourceEntryKind,
};
use fgit_node::{NodeConfig, OneNode};
use fgit_types::{HeadGeneration, RepositoryAuthorityHeadId};
use std::io::Write;
use std::path::PathBuf;
use super::merge_apply::preparation::{publish_new_bundle, require_absent};
use super::publication_support::quote;
use options::Options;

const MAX_EXPORT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_EXPORT_PAGES: usize = 4096;

const USAGE: &str = "usage: fg tree <storage-root> <tenant-id> <repository-id> --trusted-local
  (--ref <full-ref> | --ref-hex <bytes>) [--path <path> | --path-hex <bytes>]
  [--limit <1..1000>] [--after-hex <child-name> --expected-head <snapshot-token>]
  [--expected-commit <native-oid>] [--object-format sha1|sha256]
usage: fg show <storage-root> <tenant-id> <repository-id> --trusted-local
  (--ref <full-ref> | --ref-hex <bytes>) (--path <path> | --path-hex <bytes>)
  [--max-bytes <1..1048576>] [--offset <byte-offset> --expected-head <snapshot-token>]
  [--expected-commit <native-oid>] [--object-format sha1|sha256]
  [--output <new-file>]

Tree pages contain immediate children sorted by raw name bytes. An omitted tree
path means the root. All path/name bytes and file payloads have exact hex fields;
text_utf8 is an optional convenience, never a replacement for bytes_hex. Symlink
payloads are data and never followed. Gitlinks list as opaque IDs, not local files.
Use snapshot_token from the first page for every continuation. If authority moved,
restart instead of combining pages. --expected-commit pins independently reviewed
source identity; it does not select historical state or reveal hidden references.

show --output exports the COMPLETE verified file as a new regular file, preserving
binary bytes rather than writing a JSON page. It requires offset zero and follows
all ranges with the first page's head, commit, object and length pinned. --max-bytes
controls each read, not truncation. At most 128 MiB and 4096 reads are allowed;
use --max-bytes 1048576 for large files. Empty files and symlink payload bytes are
supported; symlinks are not created or followed and executable permissions are not
applied. No output is published until all reads and node shutdown succeed. Existing
files are never replaced. A JSON completion receipt is written to stdout afterward.
Read-only: no publication credentials, host checkout, implicit latest-tip mutation,
symlink traversal or external Git. Limits bound decoded objects and whole reads,
not just output ranges. Exit 0: complete page/export; 2: input/read/cleanup/output error.";

pub(super) fn run(args: &[String], file: bool) -> Result<u8, String> {
    if args == ["--help"] { emit(&mut std::io::stdout().lock(), USAGE)?; return Ok(0); }
    let (args, destination) = export_arguments(args, file)?;
    let options = options::parse(&args, file)?;
    if let Some(destination) = destination {
        return export_file(&options, &destination);
    }
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

/// Consume option values as values: a file literally named --output must not
/// accidentally become an output option. The existing parser owns all other grammar.
fn export_arguments(args: &[String], file: bool) -> Result<(Vec<String>, Option<PathBuf>), String> {
    if args.len() < 3 || args.len() > 26 || args.iter().any(|arg| arg.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 32768
    {
        return Err(USAGE.into());
    }
    let mut remaining = args[..3].to_vec();
    let mut destination = None;
    let mut cursor = 3;
    while cursor < args.len() {
        let flag = &args[cursor];
        cursor += 1;
        if flag == "--output" {
            if !file || destination.is_some() {
                return Err("--output is accepted exactly once, by show only".into());
            }
            let value = args.get(cursor).ok_or("missing --output path")?;
            cursor += 1;
            let path = PathBuf::from(value);
            if value.is_empty() || path.file_name().is_none() {
                return Err("--output must name a new regular file".into());
            }
            destination = Some(path);
        } else {
            remaining.push(flag.clone());
            if flag != "--trusted-local" {
                let value = args.get(cursor).ok_or_else(|| format!("missing value for {flag}"))?;
                remaining.push(value.clone());
                cursor += 1;
            }
        }
    }
    Ok((remaining, destination))
}

struct FileExport {
    first: SourceBrowseReport,
    bytes: Vec<u8>,
    pages: usize,
}

/// Pages come only from the node's verified source-read boundary in production.
/// The injected reader lets adversarial tests exercise the same assembly logic.
fn collect_file(
    options: &Options,
    mut read: impl FnMut(&SourceBrowseQuery) -> Result<SourceBrowseReport, String>,
) -> Result<FileExport, String> {
    let SourceBrowseAction::Read { offset: 0, limit } = options.query.action else {
        return Err("complete file export requires a file read at offset zero".into());
    };
    let mut query = options.query.clone();
    let mut first: Option<SourceBrowseReport> = None;
    let mut output = Vec::new();
    for pages in 1..=MAX_EXPORT_PAGES {
        let report = read(&query)?;
        if report.repository_id != options.repository || report.path != query.path
            || query.expected_head.is_some_and(|head| head != report.source_head)
            || query.expected_commit.is_some_and(|commit| commit != report.source_commit)
        {
            return Err("source export snapshot or path changed".into());
        }
        let SourceBrowseContent::Blob { kind, bytes, total_bytes, offset, next_offset } = &report.content else {
            return Err("source export requires a file or symlink payload".into());
        };
        if !matches!(kind, SourceEntryKind::File | SourceEntryKind::Executable | SourceEntryKind::Symlink) {
            return Err("unsupported source export entry kind".into());
        }
        if *total_bytes > MAX_EXPORT_BYTES {
            return Err("source export exceeds the 128 MiB byte limit".into());
        }
        if let Some(initial) = &first {
            let SourceBrowseContent::Blob { kind: original_kind, total_bytes: original_size, .. } = &initial.content else {
                return Err("source export lost its initial file identity".into());
            };
            if report.source_head != initial.source_head || report.source_commit != initial.source_commit
                || report.source_rcr != initial.source_rcr || report.root_tree != initial.root_tree
                || report.object_id != initial.object_id || kind != original_kind || total_bytes != original_size
            {
                return Err("source export object identity or size changed".into());
            }
        }
        let end = offset.checked_add(bytes.len() as u64).ok_or("source export byte offset overflow")?;
        if *offset != output.len() as u64 || bytes.len() > limit as usize || end > *total_bytes
            || match next_offset {
                Some(next) => bytes.is_empty() || *next != end || end >= *total_bytes,
                None => end != *total_bytes,
            }
        {
            return Err("incomplete or inconsistent source export range".into());
        }
        output.try_reserve(bytes.len()).map_err(|_| "cannot allocate bounded source export")?;
        output.extend_from_slice(bytes);
        let next = *next_offset;
        query.expected_head = Some(report.source_head);
        query.expected_commit = Some(report.source_commit);
        if first.is_none() { first = Some(report); }
        if let Some(offset) = next {
            query.action = SourceBrowseAction::Read { offset, limit };
        } else {
            return Ok(FileExport {
                first: first.ok_or("source export has no verified first page")?,
                bytes: output,
                pages,
            });
        }
    }
    Err("source export exceeds the 4096-read limit; increase --max-bytes".into())
}

fn export_file(options: &Options, destination: &std::path::Path) -> Result<u8, String> {
    if !matches!(options.query.action, SourceBrowseAction::Read { offset: 0, .. }) {
        return Err("--output requires --offset 0 (a complete file, not a range)".into());
    }
    require_absent(destination)?;
    let mut node = OneNode::open_existing(NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
        .with_object_format(options.format)).map_err(|error| format!("cannot open source node: {error}"))?;
    let result = (|| {
        node.bring_into_service(HeadGeneration::FIRST).map_err(|error| error.to_string())?;
        let request = node.request_context();
        collect_file(options, |query| {
            node.runtime().block_on(node.browse_source_local_in(&request, &options.reference, query))
                .map_err(|error| error.to_string())
        })
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    let export = completed_export(result, cleanup)?;
    publish_new_bundle(destination, &export.bytes)?;
    let report = &export.first;
    let receipt = format!(concat!("{{\"type\":\"source_file_export\",\"schema_version\":1,",
        "\"tenant_id\":{},\"repository_id\":{},\"reference_hex\":{},\"object_format\":{},",
        "\"source_head\":{},\"snapshot_token\":{},\"source_commit\":{},\"object_id\":{},",
        "\"path_hex\":{},\"bytes_written\":{},\"pages_read\":{},\"output_created\":true,",
        "\"node_closed\":true,\"repository_changed\":false,\"symlink_followed\":false}}"),
        quote(&options.tenant.to_string()), quote(&options.repository.to_string()),
        quote(&hex(options.reference.as_bytes())), quote(options.format.as_str()),
        quote(&report.source_head.to_string()), quote(&head_token(report.source_head)),
        quote(&report.source_commit.to_string()), quote(&report.object_id.to_string()),
        optional_hex(report.path.as_deref()), export.bytes.len(), export.pages);
    emit(&mut std::io::stdout().lock(), &receipt)
        .map_err(|error| format!("complete source file was created, but receipt failed: {error}"))?;
    Ok(0)
}

/// Keep the publication barrier testable: neither read failure nor failed node
/// shutdown may yield bytes for the atomic output publisher.
fn completed_export(result: Result<FileExport, String>, cleanup: Option<String>) -> Result<FileExport, String> {
    match (result, cleanup) {
        (Ok(export), None) => Ok(export),
        (result, cleanup) => {
            let read = result.err().map_or_else(String::new, |error| format!("; read: {error}"));
            let close = cleanup.map_or_else(String::new, |error| format!("; shutdown: {error}"));
            Err(format!("no source file published{read}{close}"))
        }
    }
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

#[cfg(test)]
mod export_tests {
    use super::*;
    use fgit_types::{CANONICAL_CODEC_VERSION, GitHashAlgorithm, GitOid, RepositoryCommitId};
    use fgit_types::hash::{DigestAlgorithmId, DigestBytes};

    fn args() -> Vec<String> {
        vec!["not-opened".into(), "01".repeat(16), "02".repeat(16),
            "--trusted-local".into(), "--ref".into(), "refs/heads/main".into(),
            "--path".into(), "file".into(), "--max-bytes".into(), "2".into()]
    }
    fn options() -> Options { options::parse(&args(), true).unwrap() }
    fn oid(byte: &str) -> GitOid { GitOid::from_hex(GitHashAlgorithm::Sha1, &byte.repeat(20)).unwrap() }
    fn page(bytes: &[u8], total: u64, offset: u64, next: Option<u64>) -> SourceBrowseReport {
        let digest = |byte| DigestBytes::try_new(&[byte; 32]).unwrap();
        let algorithm = DigestAlgorithmId::try_new(2).unwrap();
        SourceBrowseReport {
            repository_id: options().repository,
            source_head: RepositoryAuthorityHeadId::from_digest(algorithm, CANONICAL_CODEC_VERSION, digest(9)),
            source_rcr: RepositoryCommitId::from_digest(algorithm, CANONICAL_CODEC_VERSION, digest(8)),
            source_commit: oid("12"), root_tree: oid("34"), object_id: oid("56"), path: Some(b"file".to_vec()),
            content: SourceBrowseContent::Blob { kind: SourceEntryKind::File, bytes: bytes.to_vec(),
                total_bytes: total, offset, next_offset: next },
        }
    }
    #[test]
    fn export_option_is_not_confused_with_an_option_value() {
        let mut input = args();
        input[7] = "--output".into();
        let (ordinary, target) = export_arguments(&input, true).unwrap();
        assert_eq!(ordinary, input);
        assert!(target.is_none());
        input.extend(["--output".into(), "new.bin".into()]);
        let (ordinary, target) = export_arguments(&input, true).unwrap();
        assert_eq!(ordinary[7], "--output");
        assert_eq!(target, Some(PathBuf::from("new.bin")));
        assert!(export_arguments(&input, false).is_err());
        input.extend(["--output".into(), "other.bin".into()]);
        assert!(export_arguments(&input, true).is_err());
    }
    #[test]
    fn complete_binary_export_pins_every_continuation() {
        let initial = page(&[0, 255], 4, 0, Some(2));
        let mut calls = 0;
        let export = collect_file(&options(), |query| {
            calls += 1;
            if calls == 1 {
                assert!(query.expected_head.is_none());
                Ok(initial.clone())
            } else {
                assert_eq!(query.expected_head, Some(initial.source_head));
                assert_eq!(query.expected_commit, Some(initial.source_commit));
                assert_eq!(query.action, SourceBrowseAction::Read { offset: 2, limit: 2 });
                Ok(page(&[13, 10], 4, 2, None))
            }
        }).unwrap();
        assert_eq!(export.bytes, [0, 255, 13, 10]);
        assert_eq!(export.pages, 2);
        assert_eq!(calls, 2);
    }
    #[test]
    fn empty_files_and_symlink_payloads_are_exact_bytes() {
        let export = collect_file(&options(), |_| Ok(page(b"", 0, 0, None))).unwrap();
        assert!(export.bytes.is_empty());
        assert_eq!(export.pages, 1);
        let mut link = page(b"..", 2, 0, None);
        if let SourceBrowseContent::Blob { kind, .. } = &mut link.content { *kind = SourceEntryKind::Symlink; }
        assert_eq!(collect_file(&options(), |_| Ok(link.clone())).unwrap().bytes, b"..");
    }
    #[test]
    fn changed_snapshot_object_path_or_file_metadata_refuses() {
        for mutation in 0..9 {
            let mut calls = 0;
            assert!(collect_file(&options(), |_| {
                calls += 1;
                if calls == 1 { return Ok(page(b"ab", 4, 0, Some(2))); }
                let mut changed = page(b"cd", 4, 2, None);
                match mutation {
                    0 => changed.source_head = RepositoryAuthorityHeadId::from_digest(
                        DigestAlgorithmId::try_new(2).unwrap(), CANONICAL_CODEC_VERSION,
                        DigestBytes::try_new(&[7; 32]).unwrap()),
                    1 => changed.source_commit = oid("13"),
                    2 => changed.object_id = oid("57"),
                    3 => changed.root_tree = oid("35"),
                    4 => changed.path = Some(b"other".to_vec()),
                    5 => if let SourceBrowseContent::Blob { total_bytes, .. } = &mut changed.content { *total_bytes = 5; },
                    6 => if let SourceBrowseContent::Blob { kind, .. } = &mut changed.content { *kind = SourceEntryKind::Executable; },
                    7 => changed.source_rcr = RepositoryCommitId::from_digest(
                        DigestAlgorithmId::try_new(2).unwrap(), CANONICAL_CODEC_VERSION,
                        DigestBytes::try_new(&[7; 32]).unwrap()),
                    _ => changed.repository_id = fgit_types::RepositoryId::from_hex(&"03".repeat(16)).unwrap(),
                }
                Ok(changed)
            }).is_err(), "mutation {mutation}");
        }
    }
    #[test]
    fn truncated_nonprogressing_and_oversized_ranges_never_export() {
        for malformed in [
            page(b"a", 2, 0, None), page(b"", 2, 0, Some(0)),
            page(b"ab", 3, 0, Some(1)), page(b"ab", 2, 0, Some(2)),
            page(b"ab", 2, 1, None), page(b"abc", 3, 0, None),
            page(b"a", MAX_EXPORT_BYTES + 1, 0, Some(1)),
        ] {
            assert!(collect_file(&options(), |_| Ok(malformed.clone())).is_err());
        }
    }
    #[test]
    fn partial_requests_and_read_budgets_fail_closed() {
        let mut partial = options();
        partial.query.action = SourceBrowseAction::Read { offset: 1, limit: 2 };
        assert!(collect_file(&partial, |_| panic!("partial export must not read")).is_err());
        let mut calls = 0;
        let mut small = options();
        small.query.action = SourceBrowseAction::Read { offset: 0, limit: 1 };
        assert!(collect_file(&small, |_| {
            let offset = calls as u64;
            calls += 1;
            Ok(page(b"x", MAX_EXPORT_PAGES as u64 + 1, offset, Some(offset + 1)))
        }).is_err());
        assert_eq!(calls, MAX_EXPORT_PAGES);
    }
    #[test]
    fn cleanup_barrier_withholds_successful_bytes() {
        let export = collect_file(&options(), |_| Ok(page(b"ab", 2, 0, None))).unwrap();
        assert!(completed_export(Ok(export), Some("not closed".into())).is_err());
        let error = completed_export(Err("read failed".into()), Some("close failed".into())).err().unwrap();
        assert!(error.contains("read failed") && error.contains("close failed"));
    }
}
