//! Machine-readable, read-only source search for a trusted local operator.
use std::io::Write;
use std::path::PathBuf;
use fgit_forge::source_search::{SearchCase, SearchCompletion, SearchLimits, SourceQuery, SourceSearchReport};
use fgit_node::{NodeConfig, OneNode};
use fgit_types::{GitHashAlgorithm, HeadGeneration, RefName, RepositoryId, TenantId};
use super::publication_support::{quote, set_once};

const USAGE: &str = "usage: fg search <storage-root> <tenant-id> <repository-id> <ref> --trusted-local (--literal <text> | --literal-hex <bytes>) [--object-format sha1|sha256] [--path <prefix> | --path-hex <prefix-bytes>]... [--ignore-ascii-case] [--max-matches <1..4096>] [--max-bytes <1..67108864>] [--max-file-bytes <1..8388608>] [--max-files <1..20000>]\nExit 0: complete answer (including zero matches); 3: truncated match prefix; 2: error. LiteralBytesV1 searches regular-file bytes, never symlink targets or submodules.";
struct Options {
    storage: PathBuf, tenant: TenantId, repository: RepositoryId,
    reference: RefName, format: GitHashAlgorithm, query: SourceQuery, limits: SearchLimits,
}

pub(super) fn run(arguments: &[String]) -> Result<u8, String> {
    if arguments == ["--help"] { println!("{USAGE}"); return Ok(0); }
    let options = parse(arguments)?;
    let mut node = OneNode::open_existing(NodeConfig::new(
        options.storage, options.tenant, options.repository).with_object_format(options.format))
        .map_err(|error| error.to_string())?;
    let operation = (|| {
        node.bring_into_service(HeadGeneration::FIRST).map_err(|error| error.to_string())?;
        let request = node.request_context();
        node.runtime().block_on(node.search_source_local_in(
            &request, &options.reference, &options.query, options.limits)).map_err(|error| error.to_string())
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    let report = match (operation, cleanup) {
        (Ok(report), None) => report,
        (Err(error), None) => return Err(error),
        (Ok(_), Some(error)) => return Err(format!("source search node shutdown failed: {error}")),
        (Err(error), Some(cleanup)) => return Err(format!("{error}; node shutdown also failed: {cleanup}")),
    };
    let output = render(&options.reference, &options.query, options.limits, &report)?;
    write_report(&mut std::io::stdout().lock(), &output)?;
    Ok(match report.completion { SearchCompletion::Complete => 0, SearchCompletion::MatchLimit => 3 })
}

fn parse(arguments: &[String]) -> Result<Options, String> {
    if arguments.len() < 4 { return Err(USAGE.to_owned()); }
    if arguments.len() > 280 || arguments.iter().any(|arg| arg.len() > 8192)
        || arguments.iter().map(String::len).sum::<usize>() > 128 * 1024
    { return Err("source search arguments exceed the bounded profile".to_owned()); }
    if arguments[0].is_empty() { return Err("storage root must be nonempty".to_owned()); }
    let tenant = TenantId::from_hex(&arguments[1]).map_err(|error| error.to_string())?;
    let repository = RepositoryId::from_hex(&arguments[2]).map_err(|error| error.to_string())?;
    let reference = RefName::try_new(arguments[3].as_bytes()).map_err(|error| error.to_string())?;
    let mut trusted = false;
    let mut insensitive = false;
    let (mut needle, mut format, mut matches, mut bytes, mut file_bytes, mut files) = (None,None,None,None,None,None);
    let mut paths = Vec::new();
    let mut cursor = 4;
    while cursor < arguments.len() {
        let flag = arguments[cursor].as_str(); cursor += 1;
        match flag {
            "--trusted-local" => {
                if trusted { return Err("duplicate --trusted-local".to_owned()); }
                trusted = true; continue;
            }
            "--ignore-ascii-case" => {
                if insensitive { return Err("duplicate --ignore-ascii-case".to_owned()); }
                insensitive = true; continue;
            }
            _ => {}
        }
        let value = arguments.get(cursor).ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        match flag {
            "--literal" => set_once(&mut needle, value.as_bytes().to_vec(), "literal query")?,
            "--literal-hex" => set_once(&mut needle, unhex(value,256)?, "literal query")?,
            "--path" | "--path-hex" => {
                if paths.len() == 128 { return Err("at most 128 path prefixes are supported".to_owned()); }
                paths.push(if flag == "--path" { value.as_bytes().to_vec() } else { unhex(value,4096)? });
            }
            "--object-format" => set_once(&mut format, match value.as_str() {
                "sha1" => GitHashAlgorithm::Sha1, "sha256" => GitHashAlgorithm::Sha256,
                _ => return Err("--object-format must be sha1 or sha256".to_owned()),
            }, flag)?,
            "--max-matches" => set_once(&mut matches, decimal(value)?, flag)?,
            "--max-bytes" => set_once(&mut bytes, decimal(value)?, flag)?,
            "--max-file-bytes" => set_once(&mut file_bytes, decimal(value)?, flag)?,
            "--max-files" => set_once(&mut files, decimal(value)?, flag)?,
            _ => return Err(format!("unknown source search option {flag}; regex and implicit decoding are unsupported")),
        }
    }
    if !trusted { return Err("--trusted-local is required: the operator authorizes whole-repository source reads".to_owned()); }
    let defaults = SearchLimits::default();
    let limits = SearchLimits { max_matches: matches.unwrap_or(defaults.max_matches),
        max_total_bytes: bytes.unwrap_or(defaults.max_total_bytes),
        max_file_bytes: file_bytes.unwrap_or(defaults.max_file_bytes),
        max_files: files.unwrap_or(defaults.max_files), ..defaults };
    limits.validate().map_err(|error| error.to_string())?;
    let case = if insensitive { SearchCase::AsciiInsensitive } else { SearchCase::Exact };
    let query = SourceQuery::new(&needle.ok_or("--literal or --literal-hex is required")?, case, &paths)
        .map_err(|error| error.to_string())?;
    Ok(Options { storage: arguments[0].clone().into(), tenant, repository, reference,
        format: format.unwrap_or(GitHashAlgorithm::Sha1), query, limits })
}
fn decimal(text: &str) -> Result<usize, String> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) || text.starts_with('0') {
        return Err("limits must be positive canonical decimal integers".to_owned());
    }
    text.parse().map_err(|_| "limit is outside the platform integer range".to_owned())
}
fn unhex(text: &str, limit: usize) -> Result<Vec<u8>, String> {
    if text.is_empty() || text.len() > limit * 2 || text.len() % 2 != 0 || !text.is_ascii() {
        return Err("hex bytes must be nonempty, even-length and within the field limit".to_owned());
    }
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i+2],16)
        .map_err(|_| "invalid hexadecimal byte".to_owned())).collect()
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }
fn render(reference: &RefName, query: &SourceQuery, limits: SearchLimits, report: &SourceSearchReport) -> Result<String,String> {
    let complete = report.completion == SearchCompletion::Complete;
    let reason = if complete { "null" } else { "\"match_limit\"" };
    let case = match query.case() { SearchCase::Exact => "exact", SearchCase::AsciiInsensitive => "ascii_insensitive" };
    let paths = query.prefixes().iter().map(|path| quote(&hex(path.as_bytes()))).collect::<Vec<_>>().join(",");
    let mut out = format!("{{\"type\":\"source_search\",\"profile\":\"literal-bytes-v1\",\"scope\":\"selected_regular_files\",\"repository_id\":{},\"source_rcr\":{},\"source_commit\":{},\"source_tree\":{},\"reference_hex\":{},\"query_hex\":{},\"case\":{},\"path_prefixes_hex\":[{}],\"complete\":{},\"truncated_reason\":{},\"match_count\":{},\"max_matches\":{},\"files_selected\":{},\"files_read\":{},\"bytes_read\":{},\"bytes_searched\":{},\"non_regular_entries\":{},\"node_closed\":true,\"matches\":[",
        quote(&report.repository.to_string()),quote(&report.source_rcr.to_string()),quote(&report.source_commit.to_string()),
        quote(&report.source_tree.to_string()),quote(&hex(reference.as_bytes())),quote(&hex(query.needle())),quote(case),paths,
        complete,reason,report.matches.len(),limits.max_matches,report.files_selected,report.files_read,
        report.bytes_read,report.bytes_searched,report.non_regular_entries);
    for (i,hit) in report.matches.iter().enumerate() {
        if i != 0 { out.push(','); }
        out.push_str(&format!("{{\"path_hex\":{},\"blob\":{},\"byte_offset\":{},\"line\":{},\"byte_column\":{},\"excerpt_hex\":{},\"excerpt_offset\":{},\"match_length\":{}}}",
            quote(&hex(&hit.path)),quote(&hit.blob.to_string()),hit.byte_offset,hit.line,hit.byte_column,
            quote(&hex(&hit.excerpt)),hit.excerpt_offset,hit.match_length));
        if out.len() > 48 * 1024 * 1024 { return Err("source search response exceeds the output ceiling; narrow the query".to_owned()); }
    }
    out.push_str("]}");
    Ok(out)
}
fn write_report(out: &mut impl Write, report: &str) -> Result<(),String> {
    writeln!(out,"{report}").and_then(|()|out.flush()).map_err(|error|format!("source search report output failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args() -> Vec<String> { vec!["node".into(),"11".repeat(16),"22".repeat(16),"refs/heads/main".into(),
        "--trusted-local".into(),"--literal".into(),"needle".into()] }
    #[test]
    fn byte_queries_formats_and_prefixes_are_explicit() {
        let mut a=args(); a.extend(["--object-format","sha256","--path","src","--ignore-ascii-case"].map(str::to_owned));
        let o=parse(&a).unwrap(); assert_eq!(o.format,GitHashAlgorithm::Sha256);
        assert_eq!(o.query.case(),SearchCase::AsciiInsensitive); assert_eq!(o.query.prefixes()[0].as_bytes(),b"src");
        let mut b=args(); b[5]="--literal-hex".into(); b[6]="00ff".into();
        assert_eq!(parse(&b).unwrap().query.needle(),b"\0\xff");
    }
    #[test]
    fn missing_trust_duplicates_unknowns_and_invalid_limits_refuse_before_io() {
        let mut a=args(); a.remove(4); assert!(parse(&a).is_err());
        for pair in [["--literal","other"],["--literal-hex","aa"],["--regex",".*"],
            ["--max-matches","4097"],["--max-bytes","0"],["--max-files","01"],
            ["--path","../secret"],["--path-hex","ffz0"]] {
            let mut a=args(); a.extend(pair.map(str::to_owned)); assert!(parse(&a).is_err(),"{pair:?}");
        }
        let mut a=args(); a.extend(["--max-matches","1","--max-matches","2"].map(str::to_owned));
        assert!(parse(&a).is_err());
    }
    #[test]
    fn byte_rendering_never_normalizes_or_emits_terminal_control_bytes() {
        for bytes in [b"a\x1b\n\0".as_slice(),b"\xff\xfe", "é".as_bytes()] {
            assert_eq!(unhex(&hex(bytes),256).unwrap(),bytes);
            assert!(hex(bytes).bytes().all(|byte| byte.is_ascii_hexdigit()));
        }
    }
    #[test]
    fn report_write_and_flush_errors_are_not_success() {
        struct Failure(bool);
        impl Write for Failure {
            fn write(&mut self, bytes:&[u8])->std::io::Result<usize> {
                if self.0 { Ok(bytes.len()) } else { Err(std::io::ErrorKind::BrokenPipe.into()) }
            }
            fn flush(&mut self)->std::io::Result<()> { Err(std::io::ErrorKind::BrokenPipe.into()) }
        }
        assert!(write_report(&mut Failure(false),"{}").is_err());
        assert!(write_report(&mut Failure(true),"{}").is_err());
    }
}
