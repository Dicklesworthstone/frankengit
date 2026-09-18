//! Explicit local-owner entry point for repository-bound workflow execution.
//! Parsing never opens a repository or interprets workflow text as authority.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::PathBuf;
use fgit_types::{CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, GitHashAlgorithm,
    GitOid, RefName, RepositoryAuthorityHeadId, RepositoryId, RepositoryIncarnationId, TenantId};
use super::publication_support::quote;

const USAGE: &str = "usage: fg workflow run <storage-root> <tenant-id> <repository-id> <ref>
  --trusted-local --workflow <repository-path> --run-parent <absolute-private-directory>
  --run-id <32-lowercase-hex> --input <top-level-path> [--input <top-level-path> ...]
  [--object-format sha1|sha256] [--expected-head <snapshot-token>]
  [--expected-commit <native-oid>] [--expected-incarnation <id>]
  [--ref-hex] [--workflow-hex <hex> instead of --workflow]
  [--input-hex <hex> instead of each --input]

Unpublished candidate: replace run with run-candidate and also supply
  --bundle <stable-local-file> --candidate-commit <reviewed-native-oid>
  --expected-commit <canonical-base-oid> (mandatory for run-candidate).
Only an exact single-parent candidate with the base as its prerequisite is
supported. Workflow scripts AND copied inputs come from the candidate, not the
base. Review and trust those candidate scripts before invoking. The bundle is
validated without object import, ref publication, or a canonical green check.
Canonical base provenance and actual executed candidate remain separate in JSON.

Linux only. The run parent must already exist with mode 0700. Review and trust
ALL scripts before invoking: jobs run as your host user, not inside a hostile-code
sandbox. Inputs select copied repository files; they do not restrict host access.
The workflow must be included in the explicit input prefixes. Its entire graph
must use runs-on: fgit-trusted-local and the native supported YAML subset.

One pinned source snapshot; fresh private copies for jobs; ordered steps within
jobs. No automatic retries, source publication, secret injection, remote listener,
trigger service, or authoritative green check. Native defaults: 60 seconds per
step, 600 seconds per run, 256 KiB per captured stream, 16 MiB total captured output.

Each run creates workflow-<run-id>/attempt.json before starting any process and
report.json after close or explicit containment. Occupied run IDs always refuse.
A missing report after interruption is NOT proof that no command ran. Do not
remove an interrupted slot or choose a new run ID until effects and descendants
are reconciled. Uncertain workspaces are retained, not silently erased.

Stdout is one JSON result after explicit node shutdown; raw tool bytes are hex.
Exit 0: all jobs succeeded and cleanup completed; 1: non-green completed report;
2: input, infrastructure, receipt-output or node-cleanup failure.";

#[derive(Debug)]
struct Candidate { bundle: PathBuf, base: GitOid, commit: GitOid }
#[derive(Debug)]
struct Options {
    storage: PathBuf, tenant: TenantId, repository: RepositoryId, reference: RefName,
    format: GitHashAlgorithm, workflow: Vec<u8>, inputs: Vec<Vec<u8>>, parent: PathBuf,
    run_id: [u8; 16], head: Option<RepositoryAuthorityHeadId>, commit: Option<GitOid>,
    incarnation: Option<RepositoryIncarnationId>, candidate: Option<Candidate>,
}

pub(super) fn run(args: &[String]) -> Result<u8, String> {
    if args == ["--help"] || args == ["run", "--help"] || args == ["run-candidate", "--help"] {
        writeln!(std::io::stdout().lock(), "{USAGE}").map_err(|e| e.to_string())?;
        return Ok(0);
    }
    let options = parse(args)?;
    #[cfg(target_os = "linux")]
    { execute(options) }
    #[cfg(not(target_os = "linux"))]
    { let _ = options; Err("trusted workflow execution requires Linux; no alternative runner is selected".into()) }
}

fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 5 || !matches!(args.first().map(String::as_str), Some("run" | "run-candidate")) { return Err(USAGE.into()); }
    let candidate_mode = args[0] == "run-candidate";
    if args.len() > 2100 || args.iter().any(|s| s.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 128 * 1024
    { return Err("workflow arguments exceed the bounded profile".into()); }
    if args[1].is_empty() || args[1].len() > 4096 { return Err("invalid storage path".into()); }
    let tenant = TenantId::from_hex(&args[2]).map_err(|_| "invalid tenant ID")?;
    let repository = RepositoryId::from_hex(&args[3]).map_err(|_| "invalid repository ID")?;
    let mut flags = BTreeMap::new(); let mut inputs = BTreeSet::new(); let mut cursor = 5;
    while cursor < args.len() {
        let flag = args[cursor].as_str(); cursor += 1;
        if matches!(flag, "--trusted-local" | "--ref-hex") {
            if flags.insert(flag, "").is_some() { return Err(format!("duplicate {flag}")); }
            continue;
        }
        if !matches!(flag, "--workflow" | "--workflow-hex" | "--input" | "--input-hex"
            | "--run-parent" | "--run-id" | "--object-format" | "--expected-head"
            | "--expected-commit" | "--expected-incarnation")
            && !(candidate_mode && matches!(flag, "--bundle" | "--candidate-commit"))
        { return Err(format!("unknown workflow option {flag:?}")); }
        let value = args.get(cursor).ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        if matches!(flag, "--input" | "--input-hex") {
            let bytes = if flag == "--input-hex" { unhex(value, 4096)? } else { value.as_bytes().to_vec() };
            validate_path(&bytes)?;
            if bytes.contains(&b'/') || inputs.len() >= 1024 || !inputs.insert(bytes) {
                return Err("inputs must be distinct top-level file/directory names, at most 1024".into());
            }
        } else if flags.insert(flag, value.as_str()).is_some() { return Err(format!("duplicate {flag}")); }
    }
    if !flags.contains_key("--trusted-local") { return Err("--trusted-local is mandatory: scripts have host-user privileges".into()); }
    let value = |flag: &str| flags.get(flag).copied().ok_or_else(|| format!("missing {flag}"));
    let format = match flags.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1, "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("object format must be sha1 or sha256".into()),
    };
    let reference = if flags.contains_key("--ref-hex") { unhex(&args[4], 4096)? } else { args[4].as_bytes().to_vec() };
    let reference = RefName::try_new(&reference).map_err(|_| "invalid reference bytes")?;
    let workflow = match (flags.get("--workflow"), flags.get("--workflow-hex")) {
        (Some(path), None) => path.as_bytes().to_vec(),
        (None, Some(path)) => unhex(path, 4096)?,
        _ => return Err("supply exactly one of --workflow and --workflow-hex".into()),
    };
    validate_path(&workflow)?;
    if inputs.is_empty() || inputs.iter().map(Vec::len).sum::<usize>() > 64 * 1024
        || !inputs.iter().any(|prefix| workflow == *prefix
            || workflow.strip_prefix(prefix.as_slice()).is_some_and(|rest| rest.starts_with(b"/")))
    { return Err("bounded explicit inputs must include the workflow path".into()); }
    let run_id: [u8; 16] = unhex(value("--run-id")?, 16)?.try_into().map_err(|_| "run ID must have 32 hex digits")?;
    if run_id == [0; 16] { return Err("run ID cannot be zero".into()); }
    let parent = PathBuf::from(value("--run-parent")?);
    if !parent.is_absolute() { return Err("run parent must be an absolute private directory".into()); }
    let head = flags.get("--expected-head").map(|text| parse_head(text)).transpose()?;
    let commit = flags.get("--expected-commit").map(|text| native_oid(text, format)).transpose()?;
    let incarnation = flags.get("--expected-incarnation").map(|text|
        RepositoryIncarnationId::from_hex(text).map_err(|_| "invalid incarnation ID".to_owned())).transpose()?;
    let candidate = if candidate_mode {
        let base = commit.ok_or("--expected-commit is mandatory for run-candidate")?;
        let candidate = native_oid(value("--candidate-commit")?, format)?;
        let bundle = value("--bundle")?;
        if bundle.is_empty() || bundle.len() > 4096 { return Err("bundle must be a bounded local file path".into()); }
        if candidate == base || !reference.as_bytes().starts_with(b"refs/heads/") || reference.as_bytes().len() > 4096 {
            return Err("candidate requires a bounded branch and must differ from the canonical base".into());
        }
        Some(Candidate { bundle: bundle.into(), base, commit: candidate })
    } else { None };
    Ok(Options { storage: args[1].clone().into(), tenant, repository, reference, format,
        workflow, inputs: inputs.into_iter().collect(), parent, run_id, head, commit, incarnation, candidate })
}
fn native_oid(text: &str, format: GitHashAlgorithm) -> Result<GitOid, String> {
    if unhex(text, format.digest_len())?.len() != format.digest_len() { return Err("invalid expected commit width".into()); }
    let oid = GitOid::from_hex(format, text).map_err(|_| "invalid expected commit")?;
    if oid.is_zero() { return Err("expected commit cannot be zero".into()); }
    Ok(oid)
}
fn validate_path(path: &[u8]) -> Result<(), String> {
    if path.is_empty() || path.len() > 4096 || path.contains(&0)
        || path.split(|b| *b == b'/').any(|p| p.is_empty() || p == b"." || p == b"..")
    { return Err("invalid repository path".into()); }
    Ok(())
}
fn unhex(text: &str, maximum: usize) -> Result<Vec<u8>, String> {
    if text.is_empty() || text.len() % 2 != 0 || text.len() > maximum * 2
        || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    { return Err("expected bounded lowercase hexadecimal".into()); }
    let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    Ok(text.as_bytes().chunks_exact(2).map(|p| (digit(p[0]) << 4) | digit(p[1])).collect())
}
fn parse_head(text: &str) -> Result<RepositoryAuthorityHeadId, String> {
    let (algorithm, digest) = text.strip_prefix("head:").unwrap_or(text).strip_prefix("alg:")
        .and_then(|s| s.split_once(':')).ok_or("expected algorithm-qualified snapshot token")?;
    if algorithm.is_empty() || !algorithm.bytes().all(|b| b.is_ascii_digit())
        || (algorithm.len() > 1 && algorithm.starts_with('0')) { return Err("invalid head algorithm".into()); }
    let algorithm = DigestAlgorithmId::try_new(algorithm.parse().map_err(|_| "head algorithm overflow")?)
        .map_err(|_| "invalid head algorithm")?;
    let digest = DigestBytes::try_new(&unhex(digest, 64)?).map_err(|_| "invalid head digest")?;
    Ok(RepositoryAuthorityHeadId::from_digest(algorithm, CANONICAL_CODEC_VERSION, digest))
}

#[cfg(target_os = "linux")]
fn execute(options: Options) -> Result<u8, String> {
    use fgit_node::{NodeConfig, OneNode};
    // Complete bounded local intake before opening repository state. The file
    // is transport only; native validation still precedes host execution.
    let bundle = options.candidate.as_ref().map(|candidate|
        super::publication_support::read_bundle(&candidate.bundle, 128 * 1024 * 1024)).transpose()?;
    let mut node = OneNode::open_existing(NodeConfig::new(options.storage, options.tenant, options.repository)
        .with_object_format(options.format)).map_err(|e| e.to_string())?;
    let operation = (|| -> Result<_, String> {
        if options.incarnation.is_some_and(|expected| expected != node.repository_incarnation_id()) {
            return Err("repository incarnation changed; no workflow started".into());
        }
        let head = node.runtime().block_on(node.authenticate_authority_head()).map_err(|e| e.to_string())?;
        node.bring_into_service(head.receipt().generation()).map_err(|e| e.to_string())?;
        let request = node.request_context();
        let result = match (&options.candidate, bundle.as_deref()) {
            (Some(candidate), Some(bytes)) => node.runtime().block_on(node.run_trusted_candidate_workflow_in(
                &request, &options.reference, (candidate.base, candidate.commit), bytes,
                &options.workflow, options.run_id, &options.parent, &options.inputs, options.head, Default::default())),
            (None, None) => node.runtime().block_on(node.run_trusted_workflow_in(&request, &options.reference,
                &options.workflow, options.run_id, &options.parent, &options.inputs,
                (options.head, options.commit), Default::default())),
            _ => return Err("candidate input was not loaded; no workflow started".into()),
        }.map_err(|e| e.to_string())?;
        Ok((result.to_json(), result.succeeded(), result.run_directory.clone()))
    })();
    let cleanup = node.shutdown().err().map(|e| e.to_string());
    match operation {
        Ok((report, succeeded, directory)) => finish(&mut std::io::stdout().lock(), &report,
            succeeded, cleanup.as_deref()).map_err(|e| format!("{e}; completed report remains at {}; do not replay the attempt", directory.join("report.json").display())),
        Err(error) => Err(format!("{error}{}; inspect any existing attempt directory before retrying; an error is not proof that no command ran",
            cleanup.map_or_else(String::new, |e| format!("; node shutdown also failed: {e}")))),
    }
}
#[cfg(any(target_os = "linux", test))]
fn finish(output: &mut impl Write, report: &str, succeeded: bool, cleanup: Option<&str>) -> Result<u8, String> {
    let error = cleanup.map_or_else(|| "null".to_owned(), quote);
    writeln!(output, "{{\"type\":\"workflow_result\",\"schema_version\":1,\"node_closed\":{},\"node_cleanup_error\":{error},\"run\":{report}}}", cleanup.is_none())
        .and_then(|()| output.flush()).map_err(|e| format!("workflow receipt output incomplete: {e}"))?;
    Ok(if cleanup.is_some() { 2 } else if succeeded { 0 } else { 1 })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args() -> Vec<String> {
        vec!["run".into(), "node".into(), "11".repeat(16), "22".repeat(16), "refs/heads/main".into(),
            "--trusted-local".into(), "--workflow".into(), "ci/run.yml".into(), "--input".into(), "ci".into(),
            "--input".into(), "src".into(), "--run-id".into(), "33".repeat(16),
            "--run-parent".into(), std::env::temp_dir().to_string_lossy().into_owned()]
    }
    #[test]
    fn explicit_trust_exact_selection_and_byte_paths_parse_before_io() {
        let options = parse(&args()).unwrap(); assert_eq!(options.inputs, [b"ci".to_vec(), b"src".to_vec()]);
        let mut raw = args(); raw[6] = "--workflow-hex".into(); raw[7] = "63692fff".into();
        raw[4] = "726566732f68656164732fff".into(); raw.push("--ref-hex".into());
        raw.extend(["--expected-head".into(), format!("alg:1:{}", "ab".repeat(32))]);
        let options = parse(&raw).unwrap(); assert_eq!(options.workflow, b"ci/\xff");
        assert_eq!(options.reference.as_bytes(), b"refs/heads/\xff"); assert!(options.head.is_some());
    }
    #[test]
    fn ambiguous_paths_flags_and_replay_identifiers_refuse() {
        for extra in [vec!["--trusted-local"], vec!["--input", "ci"], vec!["--input", "../secret"],
            vec!["--input", "src/deep"], vec!["--workflow-hex", "6162"], vec!["--force"],
            vec!["--object-format", "sha512"], vec!["--expected-commit", "abc"]] {
            let mut input = args(); input.extend(extra.into_iter().map(str::to_owned)); assert!(parse(&input).is_err());
        }
        let mut input = args(); input.remove(5); assert!(parse(&input).is_err());
        let mut input = args(); input[13] = "00".repeat(16); assert!(parse(&input).is_err());
        let mut input = args(); input[7] = "outside/run.yml".into(); assert!(parse(&input).is_err());
        let mut input = args(); input[15] = "relative".into(); assert!(parse(&input).is_err());
    }
    #[test]
    fn known_execution_survives_cleanup_failure_and_broken_output_never_succeeds() {
        let mut out = Vec::new(); assert_eq!(finish(&mut out, "{}", true, Some("close\nfailed")).unwrap(), 2);
        let text = String::from_utf8(out).unwrap(); assert!(text.contains("\"node_closed\":false"));
        assert!(text.contains("\"run\":{}"));
        let mut out = Vec::new(); assert_eq!(finish(&mut out, "{}", false, None).unwrap(), 1);
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> { Err(std::io::Error::other("broken pipe")) }
            fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
        }
        assert!(finish(&mut Broken, "{}", true, None).is_err());
    }
    #[test]
    fn candidate_command_requires_independent_base_candidate_and_bundle_before_io() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let mut input = args(); input[0] = "run-candidate".into();
            let base = "a".repeat(format.digest_len()*2); let candidate = "b".repeat(format.digest_len()*2);
            input.extend(["--object-format".into(), format.as_str().into(), "--expected-commit".into(), base.clone(),
                "--candidate-commit".into(), candidate.clone(), "--bundle".into(), "not-opened-at-parse.bundle".into()]);
            let options = parse(&input).unwrap();
            let selected = options.candidate.unwrap();
            assert_eq!(selected.base.to_string(), base); assert_eq!(selected.commit.to_string(), candidate);
            for flag in ["--bundle", "--expected-commit", "--candidate-commit"] {
                let mut missing = input.clone(); let at = missing.iter().position(|s| s == flag).unwrap();
                missing.drain(at..at+2); assert!(parse(&missing).is_err());
            }
            let mut canonical = input.clone(); canonical[0] = "run".into(); assert!(parse(&canonical).is_err());
            let mut untrusted = input.clone(); untrusted.remove(5); assert!(parse(&untrusted).is_err());
            let mut same = input.clone(); let at = same.iter().position(|s| s == "--candidate-commit").unwrap();
            same[at+1] = base; assert!(parse(&same).is_err());
        }
    }
}
