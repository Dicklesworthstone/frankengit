//! Explicit one-commit cherry-pick/revert preparation. Artifacts use the existing
//! create-only writer and separate workspace inspection/admission workflow.
mod resolution;

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use fgit_crypto::sha256_digest;
use fgit_forge::preparation::{MergeMetadata, PreparationLimits};
use fgit_forge::preparation::replay::{ReplayDirection, ReplayPreparation, ReplayRequest};
use fgit_node::{NodeConfig, OneNode};
use fgit_types::{CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, HeadGeneration,
    RefName, RepositoryAuthorityHeadId, RepositoryId, TenantId};
use crate::merge_apply::preparation::{publish_new_bundle, render_conflict, require_absent};
use crate::publication_support::{parse_oid, quote, read_bundle};

const USAGE: &str = "usage: fg <cherry-pick|revert> <prepare|resolve> <storage-root> <tenant-id> <repository-id> <target-ref> <output-bundle>\n  --trusted-local --profile path-v1 --source-ref <visible-branch>\n  --expected-target <tip> --expected-source <tip> --commit <selected-historical-commit>\n  --author <name-and-email> [--committer <name-and-email>] --timestamp <unix-seconds>\n  (--message <text> | --message-file <raw-bytes>) [--mainline <one-based-parent>]\n  [--expected-head <snapshot-token>] [--target-ref-hex] [--source-ref-hex <bytes>]\n  [--max-commits <n>] [--max-edges <n>] [--max-output-bytes <n>]\n  resolve choices: --ours <path> | --theirs <path> | --base <path> | --delete <path>\n                   --file <path> <100644|100755> <local-file>\n  Choice flags also accept -hex suffixes for raw repository paths.\n\nresolve requires every and only actual conflicts; it is not a sequencer,\nand it creates no partial candidate. Revert's Theirs means the selected parent.\n\nExactly one selected commit, not a range or sequencer. Merge commits require\n--mainline; root commits use the empty tree. Source and target may be the same\nbranch. Conflicts and no-change results create no bundle. Metadata is explicit,\nnot inherited or authenticated. No Git process, hook, rename heuristic or\nexternal driver runs. Independently inspect and apply the saved single-parent\nbundle with workspace inspect/apply. Preparation never mutates the repository.\nExit 0: prepared or no-change; 3: conflicts; 2: input/infrastructure/output error.";

struct Options {
    storage: PathBuf, tenant: TenantId, repository: RepositoryId,
    target: RefName, source: RefName, output: PathBuf,
    inputs: ReplayRequest, head: Option<RepositoryAuthorityHeadId>,
    metadata: MergeMetadata, message_file: Option<PathBuf>, limits: PreparationLimits,
    resolutions: Option<Vec<resolution::LocalResolution>>,
}

pub(super) fn run(args: &[String], direction: ReplayDirection) -> Result<u8, String> {
    if args == ["--help"] || args == ["prepare", "--help"] || args == ["resolve", "--help"] {
        write_receipt(&mut std::io::stdout().lock(), USAGE, false)?; return Ok(0);
    }
    let mut options = parse(args, direction)?;
    if let Some(path) = &options.message_file { options.metadata.message = read_bundle(path, 64 * 1024)?; }
    options.metadata.validate().map_err(|error| error.to_string())?;
    // Validate all paths/choices and load bounded exact bytes before opening a
    // node. An empty resolution file is a valid file, not an implicit deletion.
    let resolutions = options.resolutions.as_ref().map(|choices|
        resolution::load(choices, options.limits)).transpose()?;
    require_absent(&options.output)?;
    let mut node = OneNode::open_existing(NodeConfig::new(options.storage.clone(), options.tenant,
        options.repository).with_object_format(options.inputs.target.algorithm())).map_err(|error| error.to_string())?;
    let operation = (|| {
        node.bring_into_service(HeadGeneration::FIRST).map_err(|error| error.to_string())?;
        let request = node.request_context();
        match resolutions.as_deref() {
            Some(choices) => node.runtime().block_on(node.prepare_resolved_replay_bundle_in(
                &request, &options.target, &options.source, options.inputs, &Default::default(),
                options.head, choices, &options.metadata, options.limits))
                .map(|result| (result.artifact, result.resolutions)).map_err(|error| error.to_string()),
            None => node.runtime().block_on(node.prepare_replay_bundle_in(&request, &options.target, &options.source,
                options.inputs, &Default::default(), options.head, &options.metadata, options.limits))
                .map(|artifact| (artifact, Vec::new())).map_err(|error| error.to_string()),
        }
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    let (artifact, resolved_paths) = match (operation, cleanup) {
        (Ok(value), None) => value,
        (Err(error), None) => return Err(error),
        (Ok(_), Some(error)) => return Err(format!("node shutdown failed: {error}; no bundle was published")),
        (Err(error), Some(cleanup)) => return Err(format!("{error}; node shutdown also failed: {cleanup}; no bundle was published")),
    };
    // Validate and render before creating any visible artifact. The same
    // writer used by merge preparation distinguishes post-link uncertainty.
    let (receipt, exit) = render(&options, artifact.source_head, &artifact.outcome,
        artifact.bundle.as_deref(), artifact.pack_objects, artifact.borrowed_objects)?;
    let receipt = if let Some(choices) = resolutions.as_deref() {
        if matches!(artifact.outcome, ReplayPreparation::Conflicted { .. }) {
            return Err("explicit resolution returned unresolved conflicts; no bundle was published".into());
        }
        resolution::decorate_receipt(receipt, choices, &resolved_paths, options.inputs.target.algorithm())?
    } else {
        if !resolved_paths.is_empty() { return Err("automatic replay returned unsolicited resolutions".into()); }
        receipt
    };
    if let Some(bundle) = &artifact.bundle { publish_new_bundle(&options.output, bundle)?; }
    write_receipt(&mut std::io::stdout().lock(), &receipt, artifact.bundle.is_some())?;
    Ok(exit)
}

fn parse(args: &[String], direction: ReplayDirection) -> Result<Options, String> {
    if args.len() < 6 || !matches!(args[0].as_str(), "prepare" | "resolve") { return Err(USAGE.into()); }
    let resolving = args[0] == "resolve";
    let argument_limit = if resolving { 48 + 4 * PreparationLimits::default().max_conflicts } else { 48 };
    if args.len() > argument_limit || args.iter().any(|s| s.len() > 64 * 1024)
        || args.iter().map(String::len).sum::<usize>() > 128 * 1024
    { return Err("replay arguments exceed the bounded profile".into()); }
    if [args[1].as_str(), args[5].as_str()].iter().any(|s| s.is_empty() || s.len() > 4096) {
        return Err("storage/output paths must be nonempty and bounded".into());
    }
    let tenant = TenantId::from_hex(&args[2]).map_err(|_| "invalid tenant ID")?;
    let repository = RepositoryId::from_hex(&args[3]).map_err(|_| "invalid repository ID")?;
    let mut flags = BTreeMap::new(); let mut at = 6;
    let mut choices = Vec::new();
    while at < args.len() {
        let flag = args[at].as_str(); at += 1;
        if resolution::is_choice(flag) {
            if !resolving { return Err("conflict choices require the explicit resolve command".into()); }
            if choices.len() >= PreparationLimits::default().max_conflicts { return Err("too many conflict choices".into()); }
            choices.push(resolution::parse_choice(flag, args, &mut at)?);
            continue;
        }
        let switch = matches!(flag, "--trusted-local" | "--target-ref-hex");
        if !switch && !matches!(flag, "--profile" | "--source-ref" | "--source-ref-hex" | "--expected-source"
            | "--expected-target" | "--commit" | "--author" | "--committer" | "--timestamp" | "--message"
            | "--message-file" | "--mainline" | "--expected-head" | "--max-commits" | "--max-edges" | "--max-output-bytes")
        { return Err(format!("unknown replay option {flag:?}")); }
        let value = if switch { "" } else { let value = args.get(at).ok_or_else(|| format!("missing value for {flag}"))?; at += 1; value.as_str() };
        if flags.insert(flag, value).is_some() { return Err(format!("duplicate {flag}")); }
    }
    if !flags.contains_key("--trusted-local") { return Err("--trusted-local is required".into()); }
    if flags.get("--profile") != Some(&"path-v1") { return Err("explicit --profile path-v1 is required".into()); }
    let required = |name| flags.get(name).copied().ok_or_else(|| format!("{name} is required"));
    let target_bytes = if flags.contains_key("--target-ref-hex") { unhex(&args[4], 4096)? } else { args[4].as_bytes().to_vec() };
    let source_bytes = match (flags.get("--source-ref"), flags.get("--source-ref-hex")) {
        (Some(value), None) if value.len() <= 4096 => value.as_bytes().to_vec(),
        (None, Some(value)) => unhex(value, 4096)?,
        _ => return Err("exactly one bounded --source-ref or --source-ref-hex is required".into()),
    };
    let target = RefName::try_new(&target_bytes).map_err(|_| "invalid target reference")?;
    let source = RefName::try_new(&source_bytes).map_err(|_| "invalid source reference")?;
    if target_bytes.len() > 4096 || [target.as_bytes(), source.as_bytes()].iter().any(|name| !name.starts_with(b"refs/heads/")) {
        return Err("source and target must be bounded fully qualified branches".into());
    }
    let expected_target = parse_oid(required("--expected-target")?)?;
    let source_tip = parse_oid(required("--expected-source")?)?;
    let selected_commit = parse_oid(required("--commit")?)?;
    if [source_tip, selected_commit].iter().any(|id| id.algorithm() != expected_target.algorithm()) {
        return Err("all native identities must use the same object format".into());
    }
    let mainline = flags.get("--mainline").map(|text| decimal(text).and_then(|n| u16::try_from(n).ok().filter(|n| *n > 0)
        .ok_or_else(|| "mainline must be a positive one-based u16".into()))).transpose()?;
    let (message, message_file) = match (flags.get("--message"), flags.get("--message-file")) {
        (Some(value), None) => (value.as_bytes().to_vec(), None),
        (None, Some(path)) if !path.is_empty() && path.len() <= 4096 => (Vec::new(), Some(PathBuf::from(*path))),
        _ => return Err("exactly one --message or --message-file is required".into()),
    };
    let author = required("--author")?.to_owned();
    let metadata = MergeMetadata { committer: flags.get("--committer").map_or_else(|| author.clone(), |s| (*s).to_owned()),
        author, timestamp: decimal(required("--timestamp")?)?, message };
    if message_file.is_none() { metadata.validate().map_err(|error| error.to_string())?; }
    let mut limits = PreparationLimits::default();
    for (name, field) in [("--max-commits", &mut limits.max_commits), ("--max-edges", &mut limits.max_edges),
        ("--max-output-bytes", &mut limits.max_output_bytes)] {
        if let Some(value) = flags.get(name) { *field = usize::try_from(decimal(value)?).map_err(|_| "limit exceeds target width")?; }
    }
    limits.validate().map_err(|error| error.to_string())?;
    let resolutions = if resolving {
        if choices.is_empty() { return Err("resolve requires at least one explicit conflict choice".into()); }
        resolution::validate_inputs(&choices, limits)?;
        Some(choices)
    } else { None };
    let head = flags.get("--expected-head").map(|s| parse_head(s)).transpose()?;
    let output = PathBuf::from(&args[5]);
    if output.file_name().is_none() { return Err("output must name a new file".into()); }
    Ok(Options { storage: args[1].clone().into(), tenant, repository, target, source, output,
        inputs: ReplayRequest { direction, target: expected_target, source_tip, selected_commit, mainline },
        head, metadata, message_file, limits, resolutions })
}
fn decimal(text: &str) -> Result<u64, String> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) || (text.len() > 1 && text.starts_with('0')) {
        return Err("expected canonical unsigned decimal".into());
    }
    text.parse().map_err(|_| "integer overflow".into())
}
fn unhex(text: &str, limit: usize) -> Result<Vec<u8>, String> {
    if text.is_empty() || text.len() > limit * 2 || text.len() % 2 != 0
        || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    { return Err("expected bounded lowercase hex".into()); }
    let digit = |b| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    Ok(text.as_bytes().chunks_exact(2).map(|pair| digit(pair[0]) * 16 + digit(pair[1])).collect())
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
fn token(head: RepositoryAuthorityHeadId) -> String {
    let id = head.as_internal_object_id(); format!("alg:{}:{}", id.algorithm().code_point(), hex(id.digest().as_bytes()))
}
fn parse_head(text: &str) -> Result<RepositoryAuthorityHeadId, String> {
    let (algorithm, bytes) = text.strip_prefix("alg:").and_then(|s| s.split_once(':')).ok_or("expected algorithm-qualified head token")?;
    let algorithm = DigestAlgorithmId::try_new(u16::try_from(decimal(algorithm)?).map_err(|_| "algorithm overflow")?)
        .map_err(|_| "invalid algorithm")?;
    let digest = DigestBytes::try_new(&unhex(bytes, 64)?).map_err(|_| "invalid head digest")?;
    Ok(RepositoryAuthorityHeadId::from_digest(algorithm, CANONICAL_CODEC_VERSION, digest))
}

fn render(options: &Options, head: RepositoryAuthorityHeadId, outcome: &ReplayPreparation,
    bundle: Option<&[u8]>, pack_objects: usize, borrowed_objects: usize) -> Result<(String, u8), String> {
    if options.head.is_some_and(|expected| expected != head) { return Err("replay snapshot binding mismatch".into()); }
    let (coordinates, result, code, details) = match outcome {
        ReplayPreparation::Clean(plan) => {
            let bytes = bundle.filter(|bytes| !bytes.is_empty()).ok_or("clean replay omitted its bundle")?;
            if pack_objects == 0 || borrowed_objects > pack_objects { return Err("replay pack accounting invalid".into()); }
            (&plan.coordinates, "prepared", 0, format!(concat!("\"candidate_commit\":{},\"root_tree\":{},",
                "\"generated_objects\":{},\"pack_objects\":{},\"borrowed_objects\":{},\"bundle_bytes\":{},\"bundle_sha256\":{}"),
                quote(&plan.commit.to_string()), quote(&plan.tree.to_string()), plan.objects.len(), pack_objects,
                borrowed_objects, bytes.len(), quote(&hex(&sha256_digest(bytes)))))
        }
        ReplayPreparation::Conflicted { coordinates, conflicts } => {
            if bundle.is_some() || pack_objects != 0 || borrowed_objects != 0 || conflicts.is_empty() {
                return Err("conflicted replay carried inconsistent artifacts".into());
            }
            (coordinates, "conflicted", 3, format!("\"conflicts\":[{}]",
                conflicts.iter().map(render_conflict).collect::<Vec<_>>().join(",")))
        }
        ReplayPreparation::NoChange { coordinates } => {
            if bundle.is_some() || pack_objects != 0 || borrowed_objects != 0 { return Err("no-change replay carried an artifact".into()); }
            (coordinates, "no_change", 0, "\"net_tree_change\":false".into())
        }
    };
    if coordinates.request != options.inputs { return Err("replay input binding mismatch".into()); }
    let operation = match options.inputs.direction { ReplayDirection::CherryPick => "cherry-pick", ReplayDirection::Revert => "revert" };
    let receipt = format!(concat!("{{\"type\":\"commit_replay_preparation\",\"schema_version\":1,\"profile\":\"path-v1\",",
        "\"operation\":{},\"outcome\":{},\"tenant_id\":{},\"repository_id\":{},\"object_format\":{},",
        "\"source_head\":{},\"snapshot_token\":{},\"target_reference_hex\":{},\"source_reference_hex\":{},",
        "\"expected_target\":{},\"expected_source\":{},\"selected_commit\":{},\"selected_parent\":{},\"mainline\":{},",
        "\"author\":{},\"committer\":{},\"timestamp\":{},\"message_hex\":{},",
        "\"bundle_created\":{},\"bundle_path\":{},\"published_to_repository\":false,",
        "\"objects_staged\":false,\"approval_granted\":false,\"node_closed\":true,{}}}"),
        quote(operation), quote(result), quote(&options.tenant.to_string()), quote(&options.repository.to_string()),
        quote(options.inputs.target.algorithm().as_str()), quote(&head.to_string()), quote(&token(head)),
        quote(&hex(options.target.as_bytes())), quote(&hex(options.source.as_bytes())),
        quote(&options.inputs.target.to_string()), quote(&options.inputs.source_tip.to_string()), quote(&options.inputs.selected_commit.to_string()),
        coordinates.selected_parent.map_or_else(|| "null".into(), |id| quote(&id.to_string())),
        coordinates.selected_mainline.map_or_else(|| "null".into(), |n| n.to_string()),
        quote(&options.metadata.author), quote(&options.metadata.committer), options.metadata.timestamp, quote(&hex(&options.metadata.message)),
        bundle.is_some(), if bundle.is_some() { quote(&options.output.to_string_lossy()) } else { "null".into() }, details);
    if receipt.len() > 4 * 1024 * 1024 { return Err("replay receipt exceeds output bound".into()); }
    Ok((receipt, code))
}
fn write_receipt(out: &mut impl Write, receipt: &str, artifact_published: bool) -> Result<(), String> {
    writeln!(out, "{receipt}").and_then(|()| out.flush()).map_err(|error|
        format!("replay receipt incomplete: {error}; bundle_published={artifact_published}; repository state was not changed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(width: usize) -> Vec<String> {
        ["prepare", "node", &"11".repeat(16), &"22".repeat(16), "refs/heads/main", "out.bundle",
            "--trusted-local", "--profile", "path-v1", "--source-ref", "refs/heads/main",
            "--expected-target", &"a".repeat(width), "--expected-source", &"a".repeat(width),
            "--commit", &"b".repeat(width), "--author", "T <t@x>", "--timestamp", "2", "--message", "raw\r\n"]
            .into_iter().map(str::to_owned).collect()
    }
    #[test]
    fn exact_coordinates_metadata_and_profile_are_required_for_both_hash_formats() {
        for width in [40, 64] {
            let input = args(width); let parsed = parse(&input, ReplayDirection::Revert).unwrap();
            assert_eq!(parsed.target, parsed.source); assert_eq!(parsed.metadata.message, b"raw\r\n");
            for flag in ["--profile", "--source-ref", "--expected-target", "--expected-source", "--commit", "--author", "--timestamp", "--message"] {
                let at = input.iter().position(|s| s == flag).unwrap();
                let mut missing = input.clone(); missing.drain(at..at+2); assert!(parse(&missing, ReplayDirection::CherryPick).is_err());
                let mut duplicate = input.clone(); duplicate.extend([flag.into(), input[at+1].clone()]);
                assert!(parse(&duplicate, ReplayDirection::CherryPick).is_err());
            }
            let mut untrusted = input; untrusted.retain(|s| s != "--trusted-local"); assert!(parse(&untrusted, ReplayDirection::Revert).is_err());
        }
    }
    #[test]
    fn invalid_mainlines_mixed_domains_and_mutation_options_refuse() {
        for extra in [vec!["--mainline","0"], vec!["--mainline","01"], vec!["--mainline","65536"],
            vec!["--force","true"], vec!["--max-commits","0"], vec!["--max-output-bytes","33554433"],
            vec!["--source-ref-hex","726566732f68656164732f6d61696e"], vec!["--message-file","file"]] {
            let mut bad = args(40); bad.extend(extra.into_iter().map(str::to_owned)); assert!(parse(&bad, ReplayDirection::CherryPick).is_err());
        }
        let mut mixed = args(40); let at = mixed.iter().position(|s| s == "--commit").unwrap(); mixed[at+1] = "b".repeat(64);
        assert!(parse(&mixed, ReplayDirection::CherryPick).is_err());
        let mut valid = args(64); valid.extend(["--mainline".into(), "2".into()]);
        assert_eq!(parse(&valid, ReplayDirection::Revert).unwrap().inputs.mainline, Some(2));
    }
    #[test]
    fn raw_reference_inputs_and_head_pins_are_lossless() {
        let mut input = args(40); input[4] = hex(b"refs/heads/\xff"); input.push("--target-ref-hex".into());
        let at = input.iter().position(|s| s == "--source-ref").unwrap();
        input[at] = "--source-ref-hex".into(); input[at+1] = hex(b"refs/heads/\xfe");
        let head = format!("alg:1:{}", "ab".repeat(32)); input.extend(["--expected-head".into(), head.clone()]);
        let options = parse(&input, ReplayDirection::CherryPick).unwrap();
        assert_eq!(options.target.as_bytes(), b"refs/heads/\xff"); assert_eq!(options.source.as_bytes(), b"refs/heads/\xfe");
        assert_eq!(token(options.head.unwrap()), head);
    }
    #[test]
    fn no_change_receipts_and_output_errors_do_not_claim_publication() {
        use fgit_forge::preparation::replay::ReplayCoordinates;
        let options = parse(&args(40), ReplayDirection::Revert).unwrap();
        let head = parse_head(&format!("alg:1:{}", "ab".repeat(32))).unwrap();
        let result = ReplayPreparation::NoChange { coordinates: ReplayCoordinates {
            request: options.inputs, selected_parent: Some(options.inputs.target), selected_mainline: Some(1),
        } };
        let (text, status) = render(&options, head, &result, None, 0, 0).unwrap();
        assert_eq!(status, 0); assert!(text.contains("\"bundle_created\":false"));
        assert!(text.contains("\"objects_staged\":false")); assert!(render(&options, head, &result, Some(b"bad"), 1, 0).is_err());
        struct Fail;
        impl Write for Fail {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> { Err(std::io::Error::other("broken output")) }
            fn flush(&mut self) -> std::io::Result<()> { Err(std::io::Error::other("broken flush")) }
        }
        assert!(write_receipt(&mut Fail, &text, true).unwrap_err().contains("bundle_published=true"));
        assert!(write_receipt(&mut Fail, &text, false).unwrap_err().contains("bundle_published=false"));
    }
}
