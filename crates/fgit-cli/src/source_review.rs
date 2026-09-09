//! Read-only native source review. Input selection and comparison mode are
//! explicit; all source bytes come from the node's authenticated object owner.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;
use fgit_forge::review::{ComparisonMode, EntryIdentity, ReviewContent, ReviewedEntry,
    ReviewOptions, ReviewSelection, ReviewSpan, SourceReview};
use fgit_forge::{AggregateVersion, PullRequestNumber};
use fgit_node::{NodeConfig, OneNode};
use fgit_types::{CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, GitHashAlgorithm,
    HeadGeneration, RefName, RepositoryAuthorityHeadId, RepositoryId, TenantId};
use super::publication_support::quote;

const USAGE: &str = "\
usage: fg diff <storage-root> <tenant-id> <repository-id> <before-ref> <after-ref>
  --trusted-local [--refs-hex] [--comparison direct|merge-base]
usage: fg pr diff <storage-root> <tenant-id> <repository-id> <number>
  --trusted-local [--expected-version <positive-version>] [--comparison merge-base|direct]

Both forms accept: [--expected-head <alg:n:hex>] [--object-format sha1|sha256]
  [--path <component-prefix> | --path-hex <raw-bytes>]... [--context-lines <0..20>]
  [--max-changes <1..512>] [--max-blob-bytes <1..1048576>]
  [--max-output-bytes <1..8388608>] [--max-diff-work <1..1000000>]

Branch diff defaults to direct; PR diff defaults to unique merge-base versus recorded source.
PR tips do not float when branches move. All ranges are half-open bytes and zero-based lines.
JSON carries exact hunk bytes as hex, plus text only when valid UTF-8. Binary changes and
submodules are explicit identity records. Directories are entries, not regular-file counts.
No rename guesses, attribute/textconv drivers, external Git, approval or mutation occurs.
Exit 0 means a complete selected-scope report; exit 2 means no successful review returned.";
const MAX_JSON_BYTES: usize = 64 * 1024 * 1024;

struct Options {
    storage: PathBuf, tenant: TenantId, repository: RepositoryId, format: GitHashAlgorithm,
    selection: ReviewSelection, expected_head: Option<RepositoryAuthorityHeadId>, review: ReviewOptions,
}

pub(super) fn run(arguments: &[String], pr: bool) -> Result<(), String> {
    if arguments == ["--help"] { return emit(&mut std::io::stdout().lock(), USAGE); }
    let options = parse(arguments, pr)?;
    let mut node = OneNode::open_existing(NodeConfig::new(options.storage.clone(), options.tenant,
        options.repository).with_object_format(options.format)).map_err(|error| error.to_string())?;
    let result = (|| {
        node.bring_into_service(HeadGeneration::FIRST).map_err(|error| error.to_string())?;
        let request = node.request_context();
        node.runtime().block_on(node.review_source_in(&request, &options.selection, &Default::default(),
            options.expected_head, &options.review)).map_err(|error| error.to_string())
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    let review = match (result, cleanup) {
        (Ok(review), None) => review,
        (Err(error), None) => return Err(error),
        (Ok(_), Some(error)) => return Err(format!("review node shutdown failed: {error}; no successful report returned")),
        (Err(error), Some(cleanup)) => return Err(format!("{error}; node shutdown also failed: {cleanup}")),
    };
    let report = render(&options, &review)?;
    emit(&mut std::io::stdout().lock(), &report)
}
fn emit(output: &mut impl Write, report: &str) -> Result<(), String> {
    writeln!(output, "{report}").and_then(|()| output.flush())
        .map_err(|error| format!("review output incomplete: {error}"))
}

fn parse(arguments: &[String], pr: bool) -> Result<Options, String> {
    let positional = if pr { 4 } else { 5 };
    if arguments.len() < positional { return Err(USAGE.into()); }
    if arguments.len() > 160 || arguments.iter().any(|arg| arg.len() > 8192)
        || arguments.iter().map(String::len).sum::<usize>() > 512 * 1024
    { return Err("review arguments exceed the bounded profile".into()); }
    if arguments[0].is_empty() || arguments[0].len() > 4096 { return Err("invalid storage path".into()); }
    let tenant = TenantId::from_hex(&arguments[1]).map_err(|_| "invalid tenant ID")?;
    let repository = RepositoryId::from_hex(&arguments[2]).map_err(|_| "invalid repository ID")?;
    let mut review = ReviewOptions { mode: if pr { ComparisonMode::MergeBase } else { ComparisonMode::Direct },
        ..ReviewOptions::default() };
    let mut format = GitHashAlgorithm::Sha1;
    let (mut head, mut version) = (None, None);
    let (mut trusted, mut refs_hex) = (false, false);
    let mut seen = BTreeSet::new();
    let mut at = positional;
    while at < arguments.len() {
        let flag = arguments[at].as_str(); at += 1;
        if !matches!(flag, "--path" | "--path-hex") && !seen.insert(flag) {
            return Err(format!("duplicate review option {flag:?}"));
        }
        match flag {
            "--trusted-local" => { trusted = true; continue; }
            "--refs-hex" if !pr => { refs_hex = true; continue; }
            _ => {}
        }
        let value = arguments.get(at).ok_or_else(|| format!("missing value for {flag:?}"))?; at += 1;
        match flag {
            "--comparison" => review.mode = match value.as_str() {
                "direct" => ComparisonMode::Direct, "merge-base" => ComparisonMode::MergeBase,
                _ => return Err("comparison must be direct or merge-base".into()),
            },
            "--object-format" => format = match value.as_str() {
                "sha1" => GitHashAlgorithm::Sha1, "sha256" => GitHashAlgorithm::Sha256,
                _ => return Err("object format must be sha1 or sha256".into()),
            },
            "--expected-head" => head = Some(parse_head(value)?),
            "--expected-version" if pr => version = Some(AggregateVersion::try_new(decimal(value)?)
                .ok_or("expected version must be positive")?),
            "--path" | "--path-hex" => {
                if review.paths.len() >= 64 { return Err("at most 64 path prefixes".into()); }
                review.paths.push(if flag == "--path" { value.as_bytes().to_vec() } else { unhex(value, 4096)? });
            }
            "--context-lines" => review.context_lines = size(value)?,
            "--max-changes" => review.limits.max_changes = size(value)?,
            "--max-blob-bytes" => review.limits.max_blob_bytes = size(value)?,
            "--max-output-bytes" => review.limits.max_output_bytes = size(value)?,
            "--max-diff-work" => review.limits.max_diff_work = size(value)?,
            _ => return Err(format!("unknown or inapplicable review option {flag:?}")),
        }
    }
    if !trusted { return Err("--trusted-local is required for this local/ref-authorized review".into()); }
    review.paths.sort(); review.paths.dedup();
    review.validate().map_err(|error| error.to_string())?;
    let selection = if pr {
        ReviewSelection::PullRequest { number: PullRequestNumber::try_new(decimal(&arguments[3])?)
            .ok_or("PR number must be positive")?, expected_version: version }
    } else {
        let reference = |value: &str| {
            let bytes = if refs_hex { unhex(value, 1024)? } else { value.as_bytes().to_vec() };
            RefName::try_new(&bytes).map_err(|_| "invalid reference name".to_owned())
        };
        ReviewSelection::References { before: reference(&arguments[3])?, after: reference(&arguments[4])? }
    };
    Ok(Options { storage: arguments[0].clone().into(), tenant, repository, format,
        selection, expected_head: head, review })
}
fn decimal(value: &str) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0')) { return Err("expected canonical decimal integer".into()); }
    value.parse().map_err(|_| "integer overflow".into())
}
fn size(value: &str) -> Result<usize, String> {
    usize::try_from(decimal(value)?).map_err(|_| "integer exceeds target width".into())
}
fn unhex(value: &str, limit: usize) -> Result<Vec<u8>, String> {
    if value.is_empty() || value.len() > limit * 2 || value.len() % 2 != 0
        || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    { return Err("expected bounded lowercase hex".into()); }
    let digit = |b: u8| if b.is_ascii_digit() { b - b'0' } else { b - b'a' + 10 };
    Ok(value.as_bytes().chunks_exact(2).map(|pair| (digit(pair[0]) << 4) | digit(pair[1])).collect())
}
fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(value.len() * 2);
    for byte in value { out.push(char::from(DIGITS[usize::from(byte >> 4)])); out.push(char::from(DIGITS[usize::from(byte & 15)])); }
    out
}
fn head_token(head: RepositoryAuthorityHeadId) -> String {
    let id = head.as_internal_object_id();
    format!("alg:{}:{}", id.algorithm().code_point(), hex(id.digest().as_bytes()))
}
fn parse_head(text: &str) -> Result<RepositoryAuthorityHeadId, String> {
    let text = text.strip_prefix("head:").unwrap_or(text);
    let (algorithm, bytes) = text.strip_prefix("alg:").and_then(|text| text.split_once(':'))
        .ok_or("expected algorithm-qualified authority head token")?;
    let algorithm = DigestAlgorithmId::try_new(u16::try_from(decimal(algorithm)?).map_err(|_| "algorithm overflow")?)
        .map_err(|_| "invalid algorithm")?;
    let bytes = DigestBytes::try_new(&unhex(bytes, 64)?).map_err(|_| "invalid head digest")?;
    Ok(RepositoryAuthorityHeadId::from_digest(algorithm, CANONICAL_CODEC_VERSION, bytes))
}
fn span(value: ReviewSpan) -> String {
    format!("{{\"byte_start\":{},\"byte_end\":{},\"line_start\":{},\"line_count\":{}}}",
        value.byte_start, value.byte_end, value.line_start, value.line_count)
}
fn entry_identity(value: Option<EntryIdentity>) -> String {
    value.map_or_else(|| "null".into(), |value| format!("{{\"oid\":{},\"mode\":\"{:06o}\"}}", quote(&value.oid.to_string()), value.mode))
}
fn text(value: &[u8]) -> String { std::str::from_utf8(value).map_or_else(|_| "null".into(), quote) }
fn render_entry(entry: &ReviewedEntry) -> String {
    let content = match &entry.content {
        ReviewContent::Identical => "{\"kind\":\"identical\"}".to_owned(),
        ReviewContent::ObjectOnly => "{\"kind\":\"object_only\"}".to_owned(),
        ReviewContent::Binary { before_bytes, after_bytes } => format!("{{\"kind\":\"binary\",\"before_bytes\":{before_bytes},\"after_bytes\":{after_bytes}}}"),
        ReviewContent::Text { algorithm, additions, deletions, before_bytes, after_bytes, hunks } => {
            let hunks = hunks.iter().map(|hunk| format!(concat!("{{\"old\":{},\"new\":{},",
                "\"before_hex\":{},\"after_hex\":{},\"before_text\":{},\"after_text\":{}}}"),
                span(hunk.old), span(hunk.new), quote(&hex(&hunk.before)), quote(&hex(&hunk.after)), text(&hunk.before), text(&hunk.after)))
                .collect::<Vec<_>>().join(",");
            format!("{{\"kind\":\"text\",\"algorithm\":{},\"additions\":{additions},\"deletions\":{deletions},\"before_bytes\":{before_bytes},\"after_bytes\":{after_bytes},\"hunks\":[{hunks}]}}", quote(&format!("{algorithm:?}")))
        }
    };
    format!("{{\"path_hex\":{},\"path_text\":{},\"change\":{},\"before\":{},\"after\":{},\"content\":{content}}}",
        quote(&hex(&entry.path)), text(&entry.path), quote(&format!("{:?}", entry.kind)),
        entry_identity(entry.before), entry_identity(entry.after))
}
fn render(options: &Options, review: &SourceReview) -> Result<String, String> {
    let comparison = &review.comparison;
    if review.repository_id != options.repository || comparison.mode != options.review.mode
        || options.expected_head.is_some_and(|head| head != review.source_head)
        || comparison.entries.len() > options.review.limits.max_changes
        || !comparison.entries.windows(2).all(|pair| pair[0].path < pair[1].path)
    { return Err("review response binding/order mismatch".into()); }
    let selection_matches = match &options.selection {
        ReviewSelection::References { before, after } => review.pull_request.is_none()
            && before == &review.before_reference && after == &review.after_reference,
        ReviewSelection::PullRequest { number, expected_version } => review.pull_request
            .is_some_and(|(actual, version)| actual == *number && expected_version.is_none_or(|wanted| wanted == version)),
    };
    if !selection_matches || [comparison.requested_before, comparison.requested_after,
        comparison.compared_before, comparison.before_tree, comparison.after_tree].iter()
        .any(|id| id.is_zero() || id.algorithm() != options.format)
    { return Err("review source/selection identity mismatch".into()); }
    let paths = options.review.paths.iter().map(|path| quote(&hex(path))).collect::<Vec<_>>().join(",");
    let pr = review.pull_request.map_or_else(|| "null".into(), |(number, version)|
        format!("{{\"number\":{},\"version\":{}}}", number.get(), version.get()));
    let mode = match comparison.mode { ComparisonMode::Direct => "direct", ComparisonMode::MergeBase => "merge-base" };
    let mut out = format!(concat!("{{\"type\":\"source_review\",\"schema_version\":1,\"profile\":\"path-myers-v1\",",
        "\"complete\":true,\"scope\":\"selected_paths\",\"node_closed\":true,",
        "\"tenant_id\":{},\"repository_id\":{},\"object_format\":{},\"source_head\":{},\"snapshot_token\":{},",
        "\"before_reference_hex\":{},\"after_reference_hex\":{},\"pull_request\":{},",
        "\"comparison\":{},\"requested_before\":{},\"requested_after\":{},\"compared_before\":{},",
        "\"before_tree\":{},\"after_tree\":{},\"context_lines\":{},\"path_prefixes_hex\":[{}],",
        "\"line_origin\":0,\"entry_count\":{},\"entries\":["),
        quote(&options.tenant.to_string()), quote(&options.repository.to_string()), quote(options.format.as_str()),
        quote(&review.source_head.to_string()), quote(&head_token(review.source_head)),
        quote(&hex(review.before_reference.as_bytes())), quote(&hex(review.after_reference.as_bytes())), pr,
        quote(mode), quote(&comparison.requested_before.to_string()), quote(&comparison.requested_after.to_string()),
        quote(&comparison.compared_before.to_string()), quote(&comparison.before_tree.to_string()),
        quote(&comparison.after_tree.to_string()), options.review.context_lines, paths, comparison.entries.len());
    for (index, entry) in comparison.entries.iter().enumerate() {
        let row = render_entry(entry);
        if out.len().saturating_add(row.len()).saturating_add(3) > MAX_JSON_BYTES {
            return Err("review JSON exceeds its output limit".into());
        }
        if index != 0 { out.push(','); } out.push_str(&row);
    }
    out.push_str("]}"); Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(pr: bool) -> Vec<String> {
        let mut args = vec!["node".into(), "11".repeat(16), "22".repeat(16),
            if pr { "17".into() } else { "refs/heads/main".into() }];
        if !pr { args.push("refs/heads/topic".into()); }
        args.push("--trusted-local".into()); args
    }
    #[test]
    fn modes_pins_domains_and_duplicate_flags_are_explicit() {
        assert_eq!(parse(&args(false), false).unwrap().review.mode, ComparisonMode::Direct);
        assert_eq!(parse(&args(true), true).unwrap().review.mode, ComparisonMode::MergeBase);
        for pr in [false, true] {
            let mut input = args(pr); input.extend(["--expected-head".into(), format!("alg:1:{}", "ab".repeat(32)),
                "--object-format".into(), "sha256".into(), "--context-lines".into(), "0".into()]);
            let options = parse(&input, pr).unwrap(); assert_eq!(options.review.context_lines, 0);
            assert_eq!(options.format, GitHashAlgorithm::Sha256);
            assert_eq!(parse_head(&head_token(options.expected_head.unwrap())).unwrap(), options.expected_head.unwrap());
            input.extend(["--context-lines".into(), "0".into()]); assert!(parse(&input, pr).is_err());
        }
    }
    #[test]
    fn invalid_inputs_refuse_without_opening_a_repository() {
        for extra in [vec!["--expected-version", "1"], vec!["--max-changes", "0"],
            vec!["--max-blob-bytes", "1048577"], vec!["--context-lines", "21"],
            vec!["--path", "../x"], vec!["--path-hex", "xx"], vec!["--driver", "shell"],
            vec!["--comparison", "automatic"], vec!["--trusted-local"]]
        {
            let mut input = args(false); input.extend(extra.iter().map(|s| (*s).to_owned()));
            assert!(parse(&input, false).is_err());
        }
        let mut input = args(true); input.pop(); assert!(parse(&input, true).is_err());
        input = args(true); input.extend(["--expected-version".into(), "0".into()]);
        assert!(parse(&input, true).is_err());
    }
    #[test]
    fn raw_paths_and_reference_names_are_lossless() {
        let mut input = args(false); input[3] = hex(b"refs/heads/\xff"); input[4] = hex(b"refs/heads/topic");
        input.extend(["--refs-hex".into(), "--path-hex".into(), "ff".into(), "--path".into(), "src".into()]);
        let options = parse(&input, false).unwrap();
        let ReviewSelection::References { before, .. } = options.selection else { panic!("refs"); };
        assert_eq!(before.as_bytes(), b"refs/heads/\xff");
        assert_eq!(options.review.paths, vec![b"src".to_vec(), vec![255]]);
        assert_eq!(text(b"\xff"), "null");
        assert_eq!(text(b"\x1b[2J"), "\"\\u001b[2J\"");
    }
    #[test]
    fn output_write_and_flush_errors_do_not_return_success() {
        struct Broken(bool);
        impl Write for Broken {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.0 { Err(std::io::Error::other("write failure")) } else { Ok(bytes.len()) }
            }
            fn flush(&mut self) -> std::io::Result<()> { Err(std::io::Error::other("flush failure")) }
        }
        assert!(emit(&mut Broken(true), "{}").is_err());
        assert!(emit(&mut Broken(false), "{}").is_err());
        let mut output = Vec::new(); emit(&mut output, "{}").unwrap(); assert_eq!(output, b"{}\n");
    }
}
