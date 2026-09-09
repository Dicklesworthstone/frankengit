//! Candidate inspection shares the source-review parser and byte-exact renderer.
//! Its enclosing receipt explicitly distinguishes uploaded candidate bytes from
//! canonical parent history. It never produces an approval or calls admission.

use std::collections::BTreeMap;
use fgit_forge::event::NativeMerge;
use fgit_types::GitOid;
use super::{Options, ReviewSelection, ComparisonMode, NodeConfig, OneNode, HeadGeneration,
    RefName, emit, render, quote, hex, text, unhex};
use crate::publication_support::{parse_oid, read_bundle};

const MAX_BUNDLE_BYTES: usize = 128 * 1024 * 1024;
const USAGE: &str = "\
usage: fg workspace inspect <storage-root> <tenant-id> <repository-id> <target-ref> <bundle-path>
  --trusted-local --expected-base <oid> --expected-commit <candidate-oid>
usage: fg merge inspect <storage-root> <tenant-id> <repository-id> <target-ref> <bundle-path>
  --trusted-local --expected-target <oid> --expected-commit <candidate-oid>
  --source-ref <branch> --expected-source <oid> --merge-base <oid>

Both accept --expected-head <snapshot-token>, --path/--path-hex, --context-lines,
--max-changes, --max-blob-bytes, --max-output-bytes and --max-diff-work as fg diff.
--refs-hex decodes the positional target ref; --source-ref-hex decodes the source.
Object format is inferred from explicit expectations; --object-format must agree.
The fixed comparison is target-before -> ACTUAL candidate, never PR source-side diff.
Parents must still match visible current refs. Full parent and candidate closures are
verified before a scoped diff returns. Thin bases cannot read unrelated ref history.
Candidate objects remain in memory; no staging, seal, ref movement or approval occurs.
A successful JSON receipt describes exact bytes, not trusted provenance or authorization.
Exit 0: complete selected-scope inspection after node close. Exit 2: no successful report.";

struct Input {
    options: Options,
    path: std::path::PathBuf,
    target: RefName,
    base: GitOid,
    candidate: GitOid,
    merge: Option<NativeMerge>,
}

pub(crate) fn run(arguments: &[String], merging: bool) -> Result<(), String> {
    if arguments == ["--help"] { return emit(&mut std::io::stdout().lock(), USAGE); }
    let input = parse(arguments, merging)?;
    let bytes = read_bundle(&input.path, MAX_BUNDLE_BYTES)?;
    let options = &input.options;
    let mut node = OneNode::open_existing(NodeConfig::new(options.storage.clone(), options.tenant,
        options.repository).with_object_format(options.format)).map_err(|error| error.to_string())?;
    let operation = (|| {
        node.bring_into_service(HeadGeneration::FIRST).map_err(|error| error.to_string())?;
        let request = node.request_context();
        match &input.merge {
            Some(merge) => node.runtime().block_on(node.inspect_merge_bundle_in(&request, merge, &bytes,
                &Default::default(), options.expected_head, &options.review)),
            None => node.runtime().block_on(node.inspect_workspace_bundle_in(&request, &input.target,
                input.base, input.candidate, &bytes, &Default::default(), options.expected_head, &options.review)),
        }.map_err(|error| error.to_string())
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    let result = match (operation, cleanup) {
        (Ok(result), None) => result,
        (Err(error), None) => return Err(error),
        (Ok(_), Some(error)) => return Err(format!("inspection node shutdown failed: {error}; no successful report returned")),
        (Err(error), Some(cleanup)) => return Err(format!("{error}; node shutdown also failed: {cleanup}")),
    };
    let expected_parents = input.merge.as_ref().map_or_else(|| vec![input.base], |merge| vec![input.base, merge.source_tip]);
    if result.review.comparison.mode != ComparisonMode::Direct
        || result.review.comparison.requested_before != input.base
        || result.review.comparison.compared_before != input.base
        || result.review.comparison.requested_after != input.candidate
        || result.parents != expected_parents || result.bundle_bytes != bytes.len()
        || result.merge_base != input.merge.as_ref().map(|merge| merge.base_tip)
    { return Err("inspection response does not match explicit candidate expectations".into()); }
    let review = render(options, &result.review)?;
    let parents = result.parents.iter().map(|id| quote(&id.to_string())).collect::<Vec<_>>().join(",");
    let prerequisites = result.prerequisites.iter().map(|id| quote(&id.to_string())).collect::<Vec<_>>().join(",");
    let source_reference = input.merge.as_ref().map_or_else(|| "null".into(), |merge| quote(&hex(merge.source_ref.as_bytes())));
    let merge_base = result.merge_base.map_or_else(|| "null".into(), |id| quote(&id.to_string()));
    let report = format!(concat!("{{\"type\":\"candidate_review\",\"schema_version\":1,\"profile\":\"verified-bundle-v1\",",
        "\"candidate_origin\":\"untrusted_bundle\",\"kind\":{},\"published_to_repository\":false,",
        "\"approval_granted\":false,\"objects_staged\":false,\"node_closed\":true,",
        "\"bundle_sha256\":{},\"bundle_bytes\":{},\"pack_bytes\":{},\"pack_objects\":{},",
        "\"expanded_bytes\":{},\"closure_objects\":{},\"transport_only_objects\":{},",
        "\"candidate_commit\":{},\"parents\":[{}],\"merge_base\":{},\"source_reference_hex\":{},",
        "\"prerequisites\":[{}],\"candidate_commit_hex\":{},\"candidate_commit_text\":{},\"review\":{}}}"),
        quote(if merging { "merge" } else { "workspace" }), quote(&hex(&result.bundle_sha256)),
        result.bundle_bytes, result.pack_bytes, result.pack_objects, result.expanded_bytes,
        result.closure_objects, result.transport_only_objects, quote(&input.candidate.to_string()),
        parents, merge_base, source_reference, prerequisites, quote(&hex(&result.candidate_commit_body)),
        text(&result.candidate_commit_body), review);
    if report.len() > super::MAX_JSON_BYTES { return Err("inspection JSON exceeds the output limit".into()); }
    emit(&mut std::io::stdout().lock(), &report)
}

fn parse(arguments: &[String], merging: bool) -> Result<Input, String> {
    if arguments.len() < 5 { return Err(USAGE.into()); }
    if arguments.len() > 180 || arguments.iter().any(|argument| argument.len() > 8192)
        || arguments.iter().map(String::len).sum::<usize>() > 512 * 1024
    { return Err("inspection arguments exceed the bounded profile".into()); }
    if arguments[4].is_empty() || arguments[4].len() > 4096 { return Err("invalid bundle path".into()); }
    let mut shared = vec![arguments[0].clone(), arguments[1].clone(), arguments[2].clone(), arguments[3].clone(), arguments[3].clone()];
    let mut values = BTreeMap::new();
    let mut format_supplied = false;
    let mut cursor = 5;
    while cursor < arguments.len() {
        let flag = arguments[cursor].as_str(); cursor += 1;
        if matches!(flag, "--trusted-local" | "--refs-hex") { shared.push(flag.to_owned()); continue; }
        let value = arguments.get(cursor).ok_or_else(|| format!("missing value for {flag:?}"))?; cursor += 1;
        let own = match flag {
            "--expected-base" if !merging => Some("base"),
            "--expected-target" if merging => Some("base"),
            "--expected-commit" => Some("candidate"),
            "--source-ref" | "--source-ref-hex" | "--expected-source" | "--merge-base" if merging => Some(flag),
            _ => None,
        };
        if let Some(key) = own {
            if values.insert(key, value.as_str()).is_some() { return Err(format!("duplicate inspection option {flag:?}")); }
        } else if matches!(flag, "--expected-head" | "--object-format" | "--path" | "--path-hex" | "--context-lines"
            | "--max-changes" | "--max-blob-bytes" | "--max-output-bytes" | "--max-diff-work")
        {
            format_supplied |= flag == "--object-format";
            shared.extend([flag.to_owned(), value.clone()]);
        } else { return Err(format!("unknown or inapplicable inspection option {flag:?}")); }
    }
    let required = |name: &str| values.get(name).copied().ok_or_else(|| format!("missing inspection expectation {name}"));
    let base = parse_oid(required("base")?)?;
    let candidate = parse_oid(required("candidate")?)?;
    if candidate == base || candidate.algorithm() != base.algorithm() { return Err("candidate and parent identities must be distinct and use the same format".into()); }
    if !format_supplied { shared.extend(["--object-format".into(), base.algorithm().as_str().into()]); }
    let options = super::parse(&shared, false)?;
    if options.format != base.algorithm() { return Err("explicit object format disagrees with candidate expectations".into()); }
    let ReviewSelection::References { before: target, .. } = &options.selection else { return Err("invalid target selection".into()); };
    let target = target.clone();
    if !target.as_bytes().starts_with(b"refs/heads/") { return Err("candidate target must be a branch".into()); }
    let merge = if merging {
        let source = match (values.get("--source-ref"), values.get("--source-ref-hex")) {
            (Some(name), None) => name.as_bytes().to_vec(),
            (None, Some(name)) => unhex(name, 1024)?,
            _ => return Err("supply exactly one source-ref spelling".into()),
        };
        let merge = NativeMerge {
            source_ref: RefName::try_new(&source).map_err(|_| "invalid source ref")?,
            source_tip: parse_oid(required("--expected-source")?)?, base_tip: parse_oid(required("--merge-base")?)?,
            target_ref: target.clone(), target_tip_before: base, merge_commit: candidate,
        };
        merge.validate().map_err(|_| "invalid native merge expectations")?;
        if merge.source_tip == base { return Err("merge parents must be distinct".into()); }
        Some(merge)
    } else { None };
    Ok(Input { options, path: arguments[4].clone().into(), target, base, candidate, merge })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input(merge: bool, width: usize) -> Vec<String> {
        let mut args = vec!["node".into(), "11".repeat(16), "22".repeat(16), "refs/heads/main".into(), "candidate.bundle".into(),
            "--trusted-local".into(), if merge { "--expected-target".into() } else { "--expected-base".into() },
            "a".repeat(width), "--expected-commit".into(), "b".repeat(width)];
        if merge { args.extend(["--source-ref".into(), "refs/heads/topic".into(), "--expected-source".into(), "c".repeat(width),
            "--merge-base".into(), "d".repeat(width)]); }
        args
    }
    #[test]
    fn exact_expectations_and_direct_comparison_are_required_in_both_domains() {
        for width in [40, 64] { for merging in [false, true] {
            let args = input(merging, width); let parsed = parse(&args, merging).unwrap();
            assert_eq!(parsed.options.review.mode, ComparisonMode::Direct);
            assert_eq!(parsed.candidate.to_string(), "b".repeat(width));
            for flag in [if merging { "--expected-target" } else { "--expected-base" }, "--expected-commit"] {
                let mut missing = args.clone(); let at = missing.iter().position(|arg| arg == flag).unwrap();
                missing.drain(at..at + 2); assert!(parse(&missing, merging).is_err());
            }
        }}
    }
    #[test]
    fn duplicate_unknown_mutation_and_source_side_diff_options_refuse_before_io() {
        for merging in [false, true] {
            for extras in [vec!["--comparison", "merge-base"], vec!["--approve", "yes"], vec!["--principal", "x"],
                vec!["--expected-commit", "bad"], vec!["--max-changes", "0"], vec!["--object-format", "sha256"], vec!["--trusted-local"]]
            {
                let mut args = input(merging, 40); args.extend(extras.iter().map(|value| (*value).to_owned()));
                assert!(parse(&args, merging).is_err());
            }
            let mut args = input(merging, 40); args.retain(|arg| arg != "--trusted-local");
            assert!(parse(&args, merging).is_err());
        }
    }
    #[test]
    fn raw_refs_pins_and_paths_reuse_the_existing_review_contract() {
        let mut args = input(true, 64); args[3] = hex(b"refs/heads/\xff");
        let at = args.iter().position(|arg| arg == "--source-ref").unwrap();
        args[at] = "--source-ref-hex".into(); args[at + 1] = hex(b"refs/heads/\xfe");
        args.extend(["--refs-hex".into(), "--path-hex".into(), "ff".into(), "--expected-head".into(), format!("alg:1:{}", "ab".repeat(32))]);
        let value = parse(&args, true).unwrap();
        assert_eq!(value.target.as_bytes(), b"refs/heads/\xff");
        assert_eq!(value.merge.unwrap().source_ref.as_bytes(), b"refs/heads/\xfe");
        assert_eq!(value.options.review.paths, vec![vec![255]]);
        assert!(value.options.expected_head.is_some());
    }
}
