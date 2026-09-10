//! Explicit PathMergeV1 preparation. This command never publishes repository
//! authority; a saved candidate must be independently reviewed and applied.

mod resolution;
pub(super) const RESOLUTION_USAGE: &str = resolution::USAGE;

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_forge::preparation::{MergeConflict, MergeEntry, MergeMetadata, MergePreparation, PreparationLimits};
use fgit_node::{NodeConfig, OneNode};
use fgit_types::{HeadGeneration, RefName, RepositoryId, TenantId};

use super::super::publication_support::{quote, set_once};

pub(super) const USAGE: &str = "usage: fg merge prepare <storage-root> <tenant-id> <repository-id> <target-ref> <output-bundle> --trusted-local --profile path-v1 --source-ref <branch> --author <name-and-email> [--committer <name-and-email>] --timestamp <unix-seconds> --message <message>";
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct Options {
    storage: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    target: RefName,
    incoming: RefName,
    output: PathBuf,
    metadata: MergeMetadata,
}

pub(super) fn run(arguments: &[String]) -> Result<(), String> {
    if arguments.first().is_some_and(|arg| arg == "resolve") { return resolution::run(arguments); }
    if arguments == ["prepare", "--help"] {
        println!("{USAGE}\n\npath-v1 is an explicit bounded path-based merge, not a claim of Git ort equivalence. No rename heuristics, virtual bases, external merge drivers or hooks are run. Conflicts produce JSON and no bundle. Repository state is never changed.");
        return Ok(());
    }
    let options = parse(arguments)?;
    require_absent(&options.output)?;
    let mut node = OneNode::open_existing(NodeConfig::new(
        options.storage.clone(), options.tenant, options.repository,
    )).map_err(|error| error.to_string())?;
    let result = (|| {
        node.bring_into_service(HeadGeneration::FIRST).map_err(|error| error.to_string())?;
        let request = node.request_context();
        node.runtime().block_on(node.prepare_merge_bundle_in(
            &request, &options.target, &options.incoming, &Default::default(),
            &options.metadata, PreparationLimits::default(),
        )).map_err(|error| error.to_string())
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    let artifact = match (result, cleanup) {
        (Ok(artifact), None) => artifact,
        (Err(error), None) => return Err(error),
        (Ok(_), Some(error)) => return Err(format!("node shutdown failed: {error}; no candidate bundle was published")),
        (Err(error), Some(cleanup)) => return Err(format!("{error}; node shutdown also failed: {cleanup}; no candidate bundle was published")),
    };
    let mut fields = vec![
        "\"type\":\"merge_preparation\"".to_owned(),
        "\"profile\":\"path-v1\"".to_owned(),
        "\"published_to_repository\":false".to_owned(),
        "\"node_closed\":true".to_owned(),
        format!("\"source_head\":{}", quote(&artifact.source_head.to_string())),
        format!("\"repository_id\":{}", quote(&options.repository.to_string())),
        format!("\"source_reference_hex\":\"{}\"", hex(options.incoming.as_bytes())),
        format!("\"target_reference_hex\":\"{}\"", hex(options.target.as_bytes())),
    ];
    let conflicted = match &artifact.outcome {
        MergePreparation::Clean(plan) => {
            let bundle = artifact.bundle.as_deref().ok_or("clean preparation omitted its bundle")?;
            publish_new_bundle(&options.output, bundle)?;
            fields.extend([
                "\"outcome\":\"prepared\"".to_owned(),
                "\"bundle_created\":true".to_owned(),
                format!("\"bundle_path\":{}", quote(&options.output.to_string_lossy())),
                format!("\"expected_source\":\"{}\"", plan.source),
                format!("\"expected_target\":\"{}\"", plan.target),
                format!("\"merge_base\":\"{}\"", plan.base),
                format!("\"candidate_commit\":\"{}\"", plan.commit),
                format!("\"root_tree\":\"{}\"", plan.tree),
                format!("\"object_count\":{}", plan.objects.len()),
                format!("\"bundle_bytes\":{}", bundle.len()),
            ]);
            false
        }
        MergePreparation::Conflicted { base, conflicts } => {
            if artifact.bundle.is_some() { return Err("conflicted preparation unexpectedly carried a bundle".to_owned()); }
            fields.extend([
                "\"outcome\":\"conflicted\"".to_owned(),
                "\"bundle_created\":false".to_owned(),
                format!("\"merge_base\":\"{base}\""),
                format!("\"conflicts\":[{}]", conflicts.iter().map(render_conflict).collect::<Vec<_>>().join(",")),
            ]);
            true
        }
        MergePreparation::AlreadyUpToDate { target } => {
            if artifact.bundle.is_some() { return Err("no-op preparation unexpectedly carried a bundle".to_owned()); }
            fields.extend([
                "\"outcome\":\"already_up_to_date\"".to_owned(),
                "\"bundle_created\":false".to_owned(),
                format!("\"expected_target\":\"{target}\""),
            ]);
            false
        }
    };
    let receipt = format!("{{{}}}", fields.join(","));
    let mut output = std::io::stdout().lock();
    writeln!(output, "{receipt}").and_then(|()| output.flush()).map_err(|error| {
        if matches!(artifact.outcome, MergePreparation::Clean(_)) {
            format!("complete candidate bundle exists at {}; receipt output failed: {error}; repository state was not changed", options.output.display())
        } else {
            format!("preparation receipt output failed: {error}; no bundle or repository mutation was published")
        }
    })?;
    if conflicted { Err("merge conflicts require explicit resolution; no candidate bundle was created".to_owned()) }
    else { Ok(()) }
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }
fn render_entry(entry: Option<&MergeEntry>) -> String {
    entry.map_or_else(|| "null".to_owned(), |entry|
        format!("{{\"mode\":{},\"oid\":\"{}\"}}", entry.mode, entry.oid))
}
pub(crate) fn render_conflict(conflict: &MergeConflict) -> String {
    format!("{{\"path_hex\":\"{}\",\"kind\":{},\"base\":{},\"ours\":{},\"theirs\":{}}}",
        hex(&conflict.path), quote(&format!("{:?}", conflict.kind)),
        render_entry(conflict.base.as_ref()), render_entry(conflict.ours.as_ref()), render_entry(conflict.theirs.as_ref()))
}

fn parse(arguments: &[String]) -> Result<Options, String> {
    if arguments.len() < 6 || arguments[0] != "prepare" { return Err(USAGE.to_owned()); }
    if arguments.len() > 24 || arguments.iter().any(|arg| arg.len() > 64 * 1024) {
        return Err("merge prepare arguments exceed the bounded profile".to_owned());
    }
    if arguments[1].is_empty() || arguments[5].is_empty() {
        return Err("storage root and output path must be nonempty".to_owned());
    }
    let target = RefName::try_new(arguments[4].as_bytes()).map_err(|error| error.to_string())?;
    let tenant = TenantId::from_hex(&arguments[2]).map_err(|error| error.to_string())?;
    let repository = RepositoryId::from_hex(&arguments[3]).map_err(|error| error.to_string())?;
    let (mut incoming, mut author, mut committer, mut timestamp, mut message, mut profile) =
        (None, None, None, None, None, None);
    let mut trusted = false;
    let mut cursor = 6;
    while cursor < arguments.len() {
        let flag = arguments[cursor].as_str(); cursor += 1;
        if flag == "--trusted-local" {
            if trusted { return Err("duplicate --trusted-local".to_owned()); }
            trusted = true; continue;
        }
        let value = arguments.get(cursor).ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        match flag {
            "--source-ref" => set_once(&mut incoming, RefName::try_new(value.as_bytes()).map_err(|error| error.to_string())?, flag)?,
            "--profile" => {
                if value != "path-v1" { return Err("only the explicitly selected path-v1 merge profile is supported".to_owned()); }
                set_once(&mut profile, (), flag)?;
            }
            "--author" => set_once(&mut author, value.clone(), flag)?,
            "--committer" => set_once(&mut committer, value.clone(), flag)?,
            "--message" => set_once(&mut message, value.as_bytes().to_vec(), flag)?,
            "--timestamp" => {
                if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) || value.starts_with('0') {
                    return Err("timestamp must be canonical positive decimal Unix seconds".to_owned());
                }
                set_once(&mut timestamp, value.parse::<u64>().map_err(|_| "timestamp overflow")?, flag)?;
            }
            _ => return Err(format!("unknown merge prepare option {flag}; no implicit approval or publication is supported")),
        }
    }
    if !trusted { return Err("--trusted-local is required for repository disclosure and artifact creation".to_owned()); }
    profile.ok_or("--profile path-v1 is required; rename/driver/virtual-base semantics are not implied")?;
    let incoming = incoming.ok_or("--source-ref is required")?;
    if target == incoming || !target.as_bytes().starts_with(b"refs/heads/") || !incoming.as_bytes().starts_with(b"refs/heads/") {
        return Err("source and target must be distinct fully qualified branch names".to_owned());
    }
    let author = author.ok_or("--author is required")?;
    let metadata = MergeMetadata {
        committer: committer.unwrap_or_else(|| author.clone()), author,
        timestamp: timestamp.ok_or("--timestamp is required")?,
        message: message.ok_or("--message is required")?,
    };
    metadata.validate().map_err(|error| error.to_string())?;
    let output = PathBuf::from(&arguments[5]);
    if output.file_name().is_none() { return Err("output must name a new regular file".to_owned()); }
    Ok(Options { storage: arguments[1].clone().into(), tenant, repository, target, incoming, output, metadata })
}

pub(crate) fn require_absent(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err("output path already exists; refusing to replace a file, symlink or directory".to_owned()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

/// Publish complete bytes without a clobber window. The temporary file is in
/// the destination directory, synchronized before an atomic create-only hard
/// link. Unsupported filesystems refuse; there is no overwrite-rename fallback.
/// This is a trusted local-operator filesystem, not an adversarial host boundary.
pub(crate) fn publish_new_bundle(path: &Path, bytes: &[u8]) -> Result<(), String> {
    require_absent(path)?;
    let parent = path.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let mut selected = None;
    for _ in 0..32 {
        let temp = parent.join(format!(".fg-merge-prepare-{}-{}.tmp", std::process::id(), NEXT_TEMP.fetch_add(1, Ordering::Relaxed)));
        let mut options = OpenOptions::new(); options.write(true).create_new(true);
        #[cfg(unix)]
        { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
        match options.open(&temp) {
            Ok(file) => { selected = Some((temp, file)); break; }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("cannot create candidate temporary file: {error}")),
        }
    }
    let (temp, mut file) = selected.ok_or("candidate temporary-name budget exhausted")?;
    let mut visible = false;
    let operation: Result<(), std::io::Error> = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::hard_link(&temp, path)?;
        visible = true;
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    drop(file);
    let cleanup = fs::remove_file(&temp).err();
    match (operation, cleanup) {
        (Ok(()), None) => Ok(()),
        (result, cleanup) => {
            let state = if visible {
                format!("complete bundle is visible at {}; artifact finalization was not fully acknowledged", path.display())
            } else { "no candidate bundle was published".to_owned() };
            let error = result.err().map_or_else(String::new, |error| format!("; {error}"));
            let cleanup = cleanup.map_or_else(String::new, |error| format!("; temporary file {} could not be removed: {error}", temp.display()));
            Err(format!("{state}{error}{cleanup}; repository state was not changed"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args() -> Vec<String> {
        ["prepare", "node", &"11".repeat(16), &"22".repeat(16), "refs/heads/main", "candidate.bundle",
            "--trusted-local", "--profile", "path-v1", "--source-ref", "refs/heads/topic",
            "--author", "Test <test@example.invalid>", "--timestamp", "1", "--message", "merge\n"]
            .into_iter().map(str::to_owned).collect()
    }
    #[test]
    fn parsing_requires_explicit_profile_time_identity_and_trust() {
        let parsed = parse(&args()).unwrap();
        assert_eq!(parsed.metadata.author, parsed.metadata.committer);
        for flag in ["--profile", "--source-ref", "--author", "--timestamp", "--message"] {
            let mut invalid = args(); let at = invalid.iter().position(|arg| arg == flag).unwrap();
            invalid.drain(at..at + 2); assert!(parse(&invalid).is_err(), "missing {flag}");
            let mut duplicate = args(); let at = duplicate.iter().position(|arg| arg == flag).unwrap();
            duplicate.extend([flag.to_owned(), duplicate[at + 1].clone()]); assert!(parse(&duplicate).is_err());
        }
        let mut untrusted = args(); untrusted.retain(|arg| arg != "--trusted-local");
        assert!(parse(&untrusted).is_err());
        for value in ["0", "01", "+1", "-1", "18446744073709551616"] {
            let mut invalid = args(); let at = invalid.iter().position(|arg| arg == "--timestamp").unwrap();
            invalid[at + 1] = value.into(); assert!(parse(&invalid).is_err());
        }
        let mut injection = args(); let at = injection.iter().position(|arg| arg == "--author").unwrap();
        injection[at + 1] = "Test <test@example.invalid>\nparent bad".into();
        assert!(parse(&injection).is_err());
    }
    #[test]
    fn artifact_publication_is_create_only_and_cleans_its_temporary_name() {
        let root = std::env::temp_dir().join(format!("fg-merge-bundle-test-{}-{}", std::process::id(), NEXT_TEMP.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&root).unwrap();
        let output = root.join("candidate.bundle");
        publish_new_bundle(&output, b"complete original").unwrap();
        assert!(publish_new_bundle(&output, b"replacement").is_err());
        assert_eq!(fs::read(&output).unwrap(), b"complete original");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn simultaneous_artifact_writers_cannot_replace_the_winner() {
        let root = std::env::temp_dir().join(format!("fg-merge-bundle-race-{}-{}", std::process::id(), NEXT_TEMP.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&root).unwrap();
        let path = root.join("candidate.bundle");
        let first = path.clone(); let second = path.clone();
        let a = std::thread::spawn(move || publish_new_bundle(&first, b"first"));
        let b = std::thread::spawn(move || publish_new_bundle(&second, b"second"));
        assert_ne!(a.join().unwrap().is_ok(), b.join().unwrap().is_ok());
        let bytes = fs::read(path).unwrap(); assert!(bytes == b"first" || bytes == b"second");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }
}
