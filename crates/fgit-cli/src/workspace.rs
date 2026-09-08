//! The explicit local-operator TreeFS tool workflow. No repository ref write.

use fgit_node::{NodeConfig, OneNode};
use fgit_types::numeric::HeadGeneration;
use fgit_types::{GitHashAlgorithm, RefName, RepositoryId, TenantId};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const USAGE: &str = "usage: fg workspace run <storage-root> <tenant-id> <repository-id> <ref> <private-parent> <workspace-id-hex> <new-bundle-name> --trusted-local --read <top-level-path> [--read ...] [--write <exact-output-path> ...] --author 'Name <email>' --timestamp <unix-seconds> --message <text> [--timeout-secs <1..3600>] -- /absolute/tool [args...]";
static TEMPORARY: AtomicU64 = AtomicU64::new(0);

struct Options {
    storage: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    reference: RefName,
    parent: PathBuf,
    workspace: [u8; 16],
    destination: PathBuf,
    reads: Vec<Vec<u8>>,
    writes: Vec<Vec<u8>>,
    author: String,
    timestamp: u64,
    message: String,
    timeout: Duration,
    program: String,
    arguments: Vec<String>,
}

pub(super) fn run(arguments: &[String]) -> Result<(), String> {
    let options = parse(arguments)?;
    match fs::symlink_metadata(&options.destination) {
        Ok(_) => return Err("bundle destination already exists; no tool was run".to_owned()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("cannot inspect bundle destination: {error}")),
    }
    let mut node = OneNode::open_existing(NodeConfig::new(
        options.storage.clone(), options.tenant, options.repository,
    )).map_err(|error| error.to_string())?;
    let operation = (|| {
        node.bring_into_service(HeadGeneration::FIRST).map_err(|error| error.to_string())?;
        let request = node.request_context();
        let mut command = Command::new(&options.program);
        command.args(&options.arguments);
        node.runtime().block_on(node.run_trusted_workspace_tool_in(
            &request, &options.reference, options.workspace, &options.parent,
            &options.reads, &options.writes, &mut command, options.timeout,
            (&options.author, options.timestamp, options.message.as_bytes()),
        )).map_err(|error| error.to_string())
    })();
    let cleanup = node.shutdown();
    let result = match (operation, cleanup) {
        (Ok(result), Ok(())) => result,
        (Err(error), Ok(())) => return Err(error),
        (Ok(_), Err(error)) => return Err(format!("candidate prepared but node shutdown failed; bundle not published: {error}")),
        (Err(error), Err(cleanup)) => return Err(format!("{error}; node shutdown also failed: {cleanup}")),
    };
    let format = match result.object_format { GitHashAlgorithm::Sha1 => "sha1", GitHashAlgorithm::Sha256 => "sha256" };
    // Standard Git bundle v3: the receiver must already possess the source
    // commit and its reachable objects. No promisor filter or thin delta is
    // claimed. Native object construction/compression remains in fgit-pack.
    let mut header = format!("# v3 git bundle\n@object-format={format}\n-{} TreeFS source prerequisite\n{} ",
        result.source_commit, result.candidate_commit).into_bytes();
    header.extend_from_slice(options.reference.as_bytes());
    header.extend_from_slice(b"\n\n");
    publish_bundle(&options.destination, &header, result.pack_bytes())?;
    let changed = result.changed_paths.iter().map(|path| quote(&hex(path))).collect::<Vec<_>>().join(",");
    let receipt = format!(
        "{{\"type\":\"workspace_candidate\",\"published_to_repository\":false,\"object_format\":\"{format}\",\"source_commit\":\"{}\",\"source_rcr\":\"{}\",\"candidate_commit\":\"{}\",\"root_tree\":\"{}\",\"objects\":{},\"changed_paths_hex\":[{}],\"bundle\":{}}}",
        result.source_commit, result.source_rcr, result.candidate_commit, result.root_tree,
        result.object_count, changed, quote(&options.destination.to_string_lossy()),
    );
    writeln!(std::io::stdout().lock(), "{receipt}")
        .map_err(|error| format!("bundle is published at {}; receipt output failed: {error}", options.destination.display()))
}

fn parse(arguments: &[String]) -> Result<Options, String> {
    if arguments.len() < 10 || arguments[0] != "run" { return Err(USAGE.to_owned()); }
    let boundary = arguments[8..].iter().position(|arg| arg == "--").map(|index| index + 8)
        .ok_or_else(|| USAGE.to_owned())?;
    if boundary + 1 >= arguments.len() { return Err(USAGE.to_owned()); }
    let tenant = TenantId::from_hex(&arguments[2]).map_err(|e| e.to_string())?;
    let repository = RepositoryId::from_hex(&arguments[3]).map_err(|e| e.to_string())?;
    let reference = RefName::try_new(arguments[4].as_bytes()).map_err(|e| e.to_string())?;
    let workspace = workspace_id(&arguments[6])?;
    let name = Path::new(&arguments[7]);
    if name.file_name() != Some(name.as_os_str()) || arguments[7].is_empty()
        || arguments[7] == format!("workspace-{}", arguments[6])
    { return Err("bundle name must be one new filename distinct from the workspace slot".to_owned()); }
    let parent = PathBuf::from(&arguments[5]);
    let destination = parent.join(name);
    let (mut reads, mut writes) = (Vec::new(), Vec::new());
    let (mut author, mut timestamp, mut message, mut timeout) = (None, None, None, None);
    let mut trusted = false;
    let mut cursor = 8;
    while cursor < boundary {
        let flag = arguments[cursor].as_str();
        cursor += 1;
        if flag == "--trusted-local" {
            if trusted { return Err("duplicate --trusted-local".to_owned()); }
            trusted = true;
            continue;
        }
        let value = arguments.get(cursor).filter(|_| cursor < boundary)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        match flag {
            "--read" => reads.push(value.as_bytes().to_vec()),
            "--write" => writes.push(value.as_bytes().to_vec()),
            "--author" => set_once(&mut author, value.clone(), flag)?,
            "--message" => set_once(&mut message, value.clone(), flag)?,
            "--timestamp" => set_once(&mut timestamp, number(value)?, flag)?,
            "--timeout-secs" => set_once(&mut timeout, number(value)?, flag)?,
            _ => return Err(format!("unknown workspace option {flag}")),
        }
    }
    if !trusted { return Err("--trusted-local is required: this command runs with host-user privileges, not in a hostile-code sandbox".to_owned()); }
    if reads.is_empty() || reads.len() > 1024 || writes.len() > 10_000 { return Err("invalid read/output count".to_owned()); }
    let seconds = timeout.unwrap_or(60);
    if seconds == 0 || seconds > 3600 { return Err("timeout must be 1..3600 seconds".to_owned()); }
    Ok(Options {
        storage: arguments[1].clone().into(), tenant, repository, reference,
        parent, workspace, destination, reads, writes,
        author: author.ok_or("--author is required")?,
        timestamp: timestamp.ok_or("--timestamp is required")?,
        message: message.ok_or("--message is required")?,
        timeout: Duration::from_secs(seconds), program: arguments[boundary + 1].clone(),
        arguments: arguments[boundary + 2..].to_vec(),
    })
}
fn set_once<T>(slot: &mut Option<T>, value: T, name: &str) -> Result<(), String> {
    if slot.is_some() { return Err(format!("duplicate {name}")); }
    *slot = Some(value);
    Ok(())
}
fn number(value: &str) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("expected unsigned decimal integer".to_owned());
    }
    value.parse().map_err(|_| "integer exceeds u64".to_owned())
}
fn workspace_id(value: &str) -> Result<[u8; 16], String> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err("workspace identity must be 32 lowercase hexadecimal characters".to_owned());
    }
    let mut id = [0; 16];
    for (index, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(id)
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }
fn quote(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""), '\\' => out.push_str("\\\\"),
            c if c <= '\u{1f}' => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Body first; atomically create the final name without replacing any file.
/// The caller-owned private parent is the same one validated by the host
/// workspace adapter. A post-link failure reports that output is visible.
fn publish_bundle(destination: &Path, header: &[u8], pack: &[u8]) -> Result<(), String> {
    let parent = destination.parent().ok_or("bundle destination has no parent")?;
    let directory = File::open(parent).map_err(|e| e.to_string())?;
    let (temporary, mut file) = (0..16).find_map(|_| {
        let path = parent.join(format!(".fg-bundle-{}-{}.tmp", std::process::id(), TEMPORARY.fetch_add(1, Ordering::Relaxed)));
        if path == destination { return None; }
        match OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path) {
            Ok(file) => Some(Ok((path, file))),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
            Err(error) => Some(Err(error.to_string())),
        }
    }).ok_or("cannot reserve a private bundle temporary")??;
    let mut visible = false;
    let written = (|| -> std::io::Result<()> {
        file.write_all(header)?;
        file.write_all(pack)?;
        file.sync_all()?;
        fs::hard_link(&temporary, destination)?;
        visible = true;
        fs::remove_file(&temporary)?;
        directory.sync_all()
    })();
    if let Err(error) = written {
        let cleanup = match fs::remove_file(&temporary) {
            Ok(()) => String::new(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => format!("; temporary {} also could not be removed: {e}", temporary.display()),
        };
        return Err(format!("bundle {} at {}: {error}{cleanup}",
            if visible { "is visible but finalization failed" } else { "was not published" }, destination.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args() -> Vec<String> {
        ["run", "node", "11111111111111111111111111111111", "22222222222222222222222222222222",
            "refs/heads/main", "/private/workspaces", "33333333333333333333333333333333", "candidate.bundle",
            "--trusted-local", "--read", "src", "--write", "src/lib.rs", "--author", "Test <test@example.invalid>",
            "--timestamp", "0", "--message", "workspace candidate", "--", "/usr/bin/true"]
            .into_iter().map(str::to_owned).collect()
    }
    #[test]
    fn complete_invocation_parses_without_running_anything() {
        let options = parse(&args()).unwrap();
        assert_eq!(options.reads, vec![b"src".to_vec()]);
        assert_eq!(options.writes, vec![b"src/lib.rs".to_vec()]);
        assert_eq!(options.timestamp, 0);
        assert_eq!(options.program, "/usr/bin/true");
        assert_eq!(options.destination, PathBuf::from("/private/workspaces/candidate.bundle"));
    }
    #[test]
    fn trust_opt_in_and_non_escaping_output_are_required() {
        let mut untrusted = args();
        untrusted.retain(|arg| arg != "--trusted-local");
        assert!(parse(&untrusted).is_err());
        for bad in ["../escape", "/outside", ".", "..", "sub/output"] {
            let mut escaped = args(); escaped[7] = bad.to_owned();
            assert!(parse(&escaped).is_err(), "{bad}");
        }
        assert!(parse(&args()).is_ok());
    }
    #[test]
    fn arguments_after_the_separator_remain_tool_arguments() {
        let mut values = args(); values.extend(["--message".to_owned(), "do not parse this".to_owned()]);
        assert_eq!(parse(&values).unwrap().arguments, vec!["--message", "do not parse this"]);
        assert_eq!(quote("a\n\"b\\é"), "\"a\\u000a\\\"b\\\\é\"");
    }
}
