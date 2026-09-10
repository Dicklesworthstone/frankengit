//! Explicit conflict-only resolutions reuse the preparation parser, create-only
//! output publisher and real node adapter. They never call merge admission.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use fgit_forge::preparation::resolution::{ConflictResolution, ResolutionChoice, ResolutionInputs,
    ResolvedMerge, validate_resolutions};
use fgit_types::{GitHashAlgorithm, RepositoryAuthorityHeadId};
use super::{Options, PreparationLimits, NodeConfig, OneNode, HeadGeneration,
    parse, require_absent, publish_new_bundle, hex, render_entry, render_conflict, quote, set_once};
use crate::publication_support::parse_oid;

pub(super) const USAGE: &str = "\
usage: fg merge resolve <storage-root> <tenant-id> <repository-id> <target-ref> <output-bundle>
  --trusted-local --profile path-v1 --source-ref <branch>
  --expected-target <oid> --expected-source <oid> --merge-base <oid>
  --author <name-and-email> [--committer <name-and-email>] --timestamp <unix-seconds> --message <message>
  [--ours <path> | --theirs <path> | --base <path> | --delete <path>]...
  [--file <path> <100644|100755> <local-file>]...

Each choice also has a -hex spelling for raw repository paths, e.g. --file-hex.
All and only actual conflicts must have one choice. Missing sides never imply deletion.
Empty and binary file bytes are preserved. Files must be stable regular local inputs.
Both native hash formats are inferred from the exact tips; --object-format must agree.
The two visible branch tips must still match, and the merge base must be uniquely best.
Clean paths cannot be overridden, no user code runs, and no repository state is changed.
Output is a new bundle plus JSON. Review with merge inspect, then separately merge apply.
Exit 0: complete candidate created after node close; exit 2: failure, not publication.";

struct Input {
    options: Options,
    inputs: ResolutionInputs,
    resolutions: Vec<ConflictResolution>,
    files: Vec<(usize, PathBuf)>,
}

pub(super) fn run(arguments: &[String]) -> Result<(), String> {
    if arguments == ["resolve", "--help"] {
        return emit(&mut std::io::stdout().lock(), USAGE, None);
    }
    let mut input = parse_input(arguments)?;
    require_absent(&input.options.output)?;
    load_files(&mut input)?;
    let options = &input.options;
    let mut node = OneNode::open_existing(NodeConfig::new(options.storage.clone(), options.tenant,
        options.repository).with_object_format(input.inputs.target.algorithm())).map_err(|error| error.to_string())?;
    let operation = (|| {
        node.bring_into_service(HeadGeneration::FIRST).map_err(|error| error.to_string())?;
        let request = node.request_context();
        node.runtime().block_on(node.prepare_resolved_merge_bundle_in(&request, &options.target, &options.incoming,
            &Default::default(), None, input.inputs, &input.resolutions, &options.metadata, PreparationLimits::default()))
            .map_err(|error| error.to_string())
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    let artifact = match (operation, cleanup) {
        (Ok(artifact), None) => artifact,
        (Err(error), None) => return Err(error),
        (Ok(_), Some(error)) => return Err(format!("node shutdown failed: {error}; no resolved bundle was published")),
        (Err(error), Some(cleanup)) => return Err(format!("{error}; node shutdown also failed: {cleanup}; no resolved bundle was published")),
    };
    // Render and check bindings before making a complete artifact visible.
    let report = render(&input, artifact.source_head, &artifact.resolved, &artifact.bundle_sha256, artifact.bundle.len())?;
    publish_new_bundle(&options.output, &artifact.bundle)?;
    emit(&mut std::io::stdout().lock(), &report, Some((&options.output, artifact.resolved.plan.commit)))
}

fn emit(output: &mut impl Write, report: &str, artifact: Option<(&Path, fgit_types::GitOid)>) -> Result<(), String> {
    writeln!(output, "{report}").and_then(|()| output.flush()).map_err(|error| {
        artifact.map_or_else(|| format!("merge resolution output failed: {error}"), |(path, commit)|
            format!("complete resolved candidate {commit} exists at {}; receipt output failed: {error}; repository state was not changed", path.display()))
    })
}

/// Split only resolution-specific arguments, then use the existing preparation
/// parser for profile, trust, branch, identity, time and message semantics.
fn parse_input(arguments: &[String]) -> Result<Input, String> {
    if arguments.len() < 6 || arguments[0] != "resolve" { return Err(USAGE.into()); }
    if arguments.len() > 600 || arguments.iter().any(|arg| arg.len() > 64 * 1024)
        || arguments.iter().map(String::len).sum::<usize>() > 512 * 1024
    { return Err("resolution arguments exceed their bounded profile".into()); }
    let mut normal = arguments[..6].to_vec(); normal[0] = "prepare".into();
    let (mut base, mut target, mut source, mut declared_format) = (None, None, None, None);
    let mut resolutions = Vec::new();
    let mut files = Vec::new();
    let mut cursor = 6;
    while cursor < arguments.len() {
        let flag = arguments[cursor].as_str(); cursor += 1;
        if flag == "--trusted-local" { normal.push(flag.into()); continue; }
        let value = arguments.get(cursor).ok_or_else(|| format!("missing value for {flag}"))?; cursor += 1;
        match flag {
            "--expected-target" => set_once(&mut target, parse_oid(value)?, flag)?,
            "--expected-source" => set_once(&mut source, parse_oid(value)?, flag)?,
            "--merge-base" => set_once(&mut base, parse_oid(value)?, flag)?,
            "--object-format" => set_once(&mut declared_format, match value.as_str() {
                "sha1" => GitHashAlgorithm::Sha1, "sha256" => GitHashAlgorithm::Sha256,
                _ => return Err("object format must be sha1 or sha256".into()),
            }, flag)?,
            "--source-ref" | "--profile" | "--author" | "--committer" | "--timestamp" | "--message" => {
                normal.extend([flag.into(), value.clone()]);
            }
            "--ours" | "--ours-hex" | "--theirs" | "--theirs-hex" | "--base" | "--base-hex"
            | "--delete" | "--delete-hex" | "--file" | "--file-hex" => {
                if resolutions.len() >= PreparationLimits::default().max_conflicts {
                    return Err("too many explicit resolutions".into());
                }
                let path = if flag.ends_with("-hex") { unhex_path(value)? } else { value.as_bytes().to_vec() };
                let choice = match flag.trim_end_matches("-hex") {
                    "--ours" => ResolutionChoice::Ours,
                    "--theirs" => ResolutionChoice::Theirs,
                    "--base" => ResolutionChoice::Base,
                    "--delete" => ResolutionChoice::Delete,
                    "--file" => {
                        let mode = match arguments.get(cursor).map(String::as_str) {
                            Some("100644") => 0o100644, Some("100755") => 0o100755,
                            _ => return Err("--file requires an explicit 100644 or 100755 mode".into()),
                        };
                        let file = arguments.get(cursor + 1).filter(|path| !path.is_empty() && path.len() <= 4096)
                            .ok_or("--file requires a bounded local file path")?;
                        cursor += 2;
                        files.push((resolutions.len(), PathBuf::from(file)));
                        ResolutionChoice::File { mode, bytes: Vec::new() }
                    }
                    _ => return Err("invalid resolution choice".into()),
                };
                resolutions.push(ConflictResolution { path, choice });
            }
            _ => return Err(format!("unknown merge resolve option {flag}; blanket defaults and arbitrary edits are unsupported")),
        }
    }
    let inputs = ResolutionInputs {
        base: base.ok_or("--merge-base is required")?, target: target.ok_or("--expected-target is required")?,
        source: source.ok_or("--expected-source is required")?,
    };
    inputs.validate(inputs.target.algorithm()).map_err(|error| error.to_string())?;
    if declared_format.is_some_and(|format| format != inputs.target.algorithm()) {
        return Err("declared object format disagrees with the expected tips".into());
    }
    if resolutions.is_empty() { return Err("at least one explicit conflict resolution is required".into()); }
    validate_resolutions(&resolutions, PreparationLimits::default()).map_err(|error| error.to_string())?;
    let options = parse(&normal)?;
    Ok(Input { options, inputs, resolutions, files })
}

fn unhex_path(value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty() || value.len() > 8192 || value.len() % 2 != 0
        || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    { return Err("expected bounded lowercase path hex".into()); }
    let digit = |b| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    Ok(value.as_bytes().chunks_exact(2).map(|pair| (digit(pair[0]) << 4) | digit(pair[1])).collect())
}

fn load_files(input: &mut Input) -> Result<(), String> {
    let limits = PreparationLimits::default();
    let mut bytes = input.resolutions.iter().map(|r| r.path.len()).sum::<usize>();
    for (index, path) in &input.files {
        let remaining = limits.max_output_bytes.checked_sub(bytes).ok_or("resolution input budget exhausted")?;
        let content = read_resolution_file(path, limits.max_text_bytes.min(remaining))?;
        bytes = bytes.checked_add(content.len()).ok_or("resolution input length overflow")?;
        let ResolutionChoice::File { bytes, .. } = &mut input.resolutions[*index].choice else {
            return Err("resolution file binding mismatch".into());
        };
        *bytes = content;
    }
    validate_resolutions(&input.resolutions, limits).map_err(|error| error.to_string())
}

/// Unlike bundle intake, empty bytes are a valid manual file resolution.
/// This is a stable trusted-local input, not hostile-filesystem isolation.
fn read_resolution_file(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("resolution input must be a bounded regular file, not a symlink or device".into());
    }
    let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let opened = file.metadata().map_err(|error| error.to_string())?;
    if !opened.is_file() || opened.len() > limit as u64 {
        return Err("resolution input changed to a non-regular or oversized file".into());
    }
    let mut content = Vec::new();
    content.try_reserve(usize::try_from(opened.len()).map_err(|_| "resolution length overflow")?)
        .map_err(|_| "resolution allocation refused")?;
    file.take(limit as u64 + 1).read_to_end(&mut content).map_err(|error| error.to_string())?;
    if content.len() > limit || content.len() as u64 != opened.len() {
        return Err("resolution input changed length or exceeded its byte limit".into());
    }
    Ok(content)
}

fn render(input: &Input, head: RepositoryAuthorityHeadId, resolved: &ResolvedMerge,
    bundle_sha256: &[u8; 32], bundle_bytes: usize) -> Result<String, String>
{
    let plan = &resolved.plan;
    if plan.base != input.inputs.base || plan.target != input.inputs.target || plan.source != input.inputs.source
        || plan.commit.is_zero() || plan.commit.algorithm() != input.inputs.target.algorithm()
        || resolved.resolutions.len() != input.resolutions.len()
        || !resolved.resolutions.windows(2).all(|pair| pair[0].conflict.path < pair[1].conflict.path)
    { return Err("resolved candidate response binding mismatch".into()); }
    let mut rows = Vec::new();
    for result in &resolved.resolutions {
        if !input.resolutions.iter().any(|r| r.path == result.conflict.path && r.choice.kind() == result.choice) {
            return Err("resolution response does not match submitted choices".into());
        }
        rows.push(format!("{{\"conflict\":{},\"choice\":{},\"result\":{}}}",
            render_conflict(&result.conflict), quote(&format!("{:?}", result.choice)), render_entry(result.result.as_ref())));
    }
    let out = format!(concat!("{{\"type\":\"merge_resolution\",\"schema_version\":1,\"profile\":\"path-resolved-v1\",",
        "\"outcome\":\"prepared\",\"published_to_repository\":false,\"node_closed\":true,\"bundle_created\":true,",
        "\"repository_id\":{},\"source_head\":{},\"object_format\":{},\"target_reference_hex\":{},\"source_reference_hex\":{},",
        "\"expected_target\":{},\"expected_source\":{},\"merge_base\":{},\"candidate_commit\":{},\"root_tree\":{},",
        "\"object_count\":{},\"bundle_bytes\":{},\"bundle_sha256\":{},\"bundle_path\":{},",
        "\"resolution_count\":{},\"resolutions\":[{}]}}"),
        quote(&input.options.repository.to_string()), quote(&head.to_string()), quote(plan.commit.algorithm().as_str()),
        quote(&hex(input.options.target.as_bytes())), quote(&hex(input.options.incoming.as_bytes())),
        quote(&plan.target.to_string()), quote(&plan.source.to_string()), quote(&plan.base.to_string()),
        quote(&plan.commit.to_string()), quote(&plan.tree.to_string()), plan.objects.len(), bundle_bytes,
        quote(&hex(bundle_sha256)), quote(&input.options.output.to_string_lossy()), rows.len(), rows.join(","));
    if out.len() > 4 * 1024 * 1024 { return Err("resolution receipt exceeds its byte limit".into()); }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    fn args() -> Vec<String> {
        ["resolve", "node", &"11".repeat(16), &"22".repeat(16), "refs/heads/main", "out.bundle",
            "--trusted-local", "--profile", "path-v1", "--source-ref", "refs/heads/topic",
            "--author", "T <t@x>", "--timestamp", "1", "--message", "resolved\n",
            "--expected-target", &"11".repeat(20), "--expected-source", &"22".repeat(20),
            "--merge-base", &"33".repeat(20), "--ours", "file"].into_iter().map(str::to_owned).collect()
    }
    #[test]
    fn pins_profile_trust_and_choices_are_required_without_repository_access() {
        let valid = args(); assert!(parse_input(&valid).is_ok());
        for flag in ["--expected-target", "--expected-source", "--merge-base", "--profile", "--ours", "--author"] {
            let mut invalid = valid.clone(); let at = invalid.iter().position(|arg| arg == flag).unwrap();
            invalid.drain(at..at + 2); assert!(parse_input(&invalid).is_err(), "{flag}");
        }
        let mut invalid = valid.clone(); invalid.retain(|arg| arg != "--trusted-local"); assert!(parse_input(&invalid).is_err());
        for extra in [vec!["--ours", "file"], vec!["--theirs", "../escape"], vec!["--file", "other", "120000", "link"],
            vec!["--object-format", "sha256"], vec!["--expected-target", &"44".repeat(20)], vec!["--all-ours", "true"]]
        {
            let mut invalid = valid.clone(); invalid.extend(extra.into_iter().map(str::to_owned));
            assert!(parse_input(&invalid).is_err());
        }
        let mut sha256 = args();
        for flag in ["--expected-target", "--expected-source", "--merge-base"] {
            let at = sha256.iter().position(|arg| arg == flag).unwrap(); let first = sha256[at + 1][..2].to_owned();
            sha256[at + 1] = first.repeat(32);
        }
        assert_eq!(parse_input(&sha256).unwrap().inputs.target.algorithm(), GitHashAlgorithm::Sha256);
    }
    #[test]
    fn raw_paths_and_file_modes_are_not_lossy_or_implicit() {
        let mut input = args(); input.truncate(input.len() - 2);
        input.extend(["--file-hex".into(), "ff".into(), "100755".into(), "local.bytes".into()]);
        let parsed = parse_input(&input).unwrap(); assert_eq!(parsed.resolutions[0].path, vec![255]);
        assert!(matches!(parsed.resolutions[0].choice, ResolutionChoice::File { mode: 0o100755, .. }));
        assert_eq!(parsed.files, vec![(0, PathBuf::from("local.bytes"))]);
        input.extend(["--ours-hex".into(), "FF".into()]); assert!(parse_input(&input).is_err());
    }
    #[test]
    fn manual_file_intake_accepts_empty_and_binary_but_refuses_symlinks_and_bounds() {
        let root = std::env::temp_dir().join(format!("fg-resolution-input-{}-{}", std::process::id(),
            super::super::NEXT_TEMP.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir(&root).unwrap(); let file = root.join("bytes");
        std::fs::write(&file, b"").unwrap(); assert_eq!(read_resolution_file(&file, 0).unwrap(), b"");
        std::fs::write(&file, b"\xff\0\r\n").unwrap(); assert_eq!(read_resolution_file(&file, 4).unwrap(), b"\xff\0\r\n");
        assert!(read_resolution_file(&file, 3).is_err()); assert!(read_resolution_file(&root, 10).is_err());
        #[cfg(unix)] {
            let link = root.join("link"); std::os::unix::fs::symlink(&file, &link).unwrap();
            assert!(read_resolution_file(&link, 4).is_err());
        }
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn receipt_write_and_flush_failures_preserve_known_artifact_state() {
        struct Broken(bool);
        impl Write for Broken {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.0 { Err(std::io::Error::other("write")) } else { Ok(bytes.len()) }
            }
            fn flush(&mut self) -> std::io::Result<()> { Err(std::io::Error::other("flush")) }
        }
        let commit = parse_oid(&"11".repeat(20)).unwrap();
        for broken in [true, false] {
            let error = emit(&mut Broken(broken), "{}", Some((Path::new("out.bundle"), commit))).unwrap_err();
            assert!(error.contains(&commit.to_string())); assert!(error.contains("exists at"));
        }
    }
}
