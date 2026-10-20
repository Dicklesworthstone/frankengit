//! Whole saved-run check publication with exact snapshot scope and stable keys.
use super::publish::{absolute_directory, decimal, digest, fixed_hex, pin};
use super::quote;
use fgit_crypto::Digest;
use fgit_types::{
    GitHashAlgorithm, PrincipalId, RefName, RepositoryId, RepositoryIncarnationId, TenantId,
};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

const USAGE: &str =
    "usage: fg workflow publish-run <storage-root> <tenant-id> <repository-id> <ref>
  --trusted-local --run-directory <absolute-private-run-directory>
  --journal-id <original-attempt-marker-sha256> --at-pin <bytes>:<tail-sha256>
  --principal-id <32-lowercase-hex> --expected-incarnation <32-lowercase-hex>
  [--object-format sha1|sha256] [--ref-hex] [--plan-only]
  [--expected-set <set-sha256>] [--max-checks <1..128>] [--max-evidence-mib <1..16>]

Use the original scope and exact snapshot from fg workflow recover. Every completed
job in that snapshot is verified before any submission. Queued/in-progress facts
are not checks. A saved prefix is not proof of whole-run completion or containment.
--plan-only verifies and prints the selected set without canonical submission.
--expected-set optionally binds a previously reviewed set; no caller-supplied
replacement idempotency key or automatic workflow retry is permitted.

The native publisher derives stable full child keys and uses ordinary per-check
admission. The set is not atomic: each check and its outbox effect have their own
canonical decision. Replay the identical invocation after interruption. Earlier
children recover historical decisions; undecided children still require the
current reporting branch to name their actual executed commit. No refs are moved,
no journal is acknowledged and no workflow runs. Publishing a Failure is a
successful publication, not a passing build or permission to merge.

One bounded native request covers preparation and all admissions. SIGTERM/SIGINT
stop new work without erasing known decisions; SIGKILL is abrupt. Keep the original
journal and snapshot pins independently. A changed snapshot must be explicitly
reselected; evidence hashes are integrity, not independent runner authentication.
Linux, trusted local operator only. Retain stable private parent directories.

Stdout: one verified set, each terminal decision as it occurs, then a summary after
node shutdown. Exit 0: requested checks committed (or plan-only/empty selection);
3: one or more canonical refusals; 2: input, incomplete outcome, output or cleanup
failure. A nonzero exit never proves that earlier children did not commit.";

#[derive(Debug)]
struct Options {
    storage: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    reference: RefName,
    format: GitHashAlgorithm,
    directory: PathBuf,
    journal: Digest,
    snapshot: (u64, Digest),
    publisher: PrincipalId,
    incarnation: RepositoryIncarnationId,
    plan_only: bool,
    expected_set: Option<[u8; 32]>,
    limits: (usize, usize),
}
fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 5 || args.len() > 40 || args[0] != "publish-run" {
        return Err(USAGE.into());
    }
    if args.iter().any(|a| a.len() > 4096 || a.contains('\0'))
        || args.iter().map(String::len).sum::<usize>() > 32 * 1024
        || args[1].is_empty()
    {
        return Err("publish-run arguments exceed the bounded local profile".into());
    }
    fixed_hex(&args[2], 16)?;
    fixed_hex(&args[3], 16)?;
    let tenant = TenantId::from_hex(&args[2]).map_err(|_| "invalid tenant ID")?;
    let repository = RepositoryId::from_hex(&args[3]).map_err(|_| "invalid repository ID")?;
    let mut flags = BTreeMap::new();
    let mut i = 5;
    while i < args.len() {
        let flag = args[i].as_str();
        i += 1;
        let value = if matches!(flag, "--trusted-local" | "--ref-hex" | "--plan-only") {
            ""
        } else {
            if !matches!(
                flag,
                "--run-directory"
                    | "--journal-id"
                    | "--at-pin"
                    | "--principal-id"
                    | "--expected-incarnation"
                    | "--object-format"
                    | "--expected-set"
                    | "--max-checks"
                    | "--max-evidence-mib"
            ) {
                return Err(format!("unknown publish-run option {flag}"));
            }
            let v = args.get(i).ok_or_else(|| format!("missing {flag} value"))?;
            i += 1;
            v.as_str()
        };
        if flags.insert(flag, value).is_some() {
            return Err(format!("duplicate {flag}"));
        }
    }
    if !flags.contains_key("--trusted-local") {
        return Err("--trusted-local is mandatory for check reporting".into());
    }
    let required = |flag| {
        flags
            .get(flag)
            .copied()
            .ok_or_else(|| format!("missing {flag}"))
    };
    let reference = if flags.contains_key("--ref-hex") {
        super::unhex(&args[4], 4096)?
    } else {
        args[4].as_bytes().to_vec()
    };
    let reference = RefName::try_new(&reference).map_err(|_| "invalid reporting ref")?;
    if !reference.as_bytes().starts_with(b"refs/heads/") {
        return Err("publish-run requires a reporting branch".into());
    }
    let format = match flags.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1,
        "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("object format must be sha1 or sha256".into()),
    };
    let principal = required("--principal-id")?;
    fixed_hex(principal, 16)?;
    let incarnation = required("--expected-incarnation")?;
    fixed_hex(incarnation, 16)?;
    Ok(Options {
        storage: args[1].clone().into(),
        tenant,
        repository,
        reference,
        format,
        directory: absolute_directory(required("--run-directory")?)?,
        journal: digest(required("--journal-id")?)?,
        snapshot: pin(required("--at-pin")?)?,
        publisher: PrincipalId::from_hex(principal).map_err(|_| "invalid publisher")?,
        incarnation: RepositoryIncarnationId::from_hex(incarnation)
            .map_err(|_| "invalid incarnation")?,
        plan_only: flags.contains_key("--plan-only"),
        expected_set: flags
            .get("--expected-set")
            .map(|s| {
                fixed_hex(s, 32).and_then(|bytes| {
                    <[u8; 32]>::try_from(bytes).map_err(|_| "invalid SHA-256 width".to_owned())
                })
            })
            .transpose()?,
        limits: (
            flags
                .get("--max-checks")
                .map_or(Ok(128), |s| decimal(s, 1, 128))? as usize,
            flags
                .get("--max-evidence-mib")
                .map_or(Ok(16), |s| decimal(s, 1, 16))? as usize
                * 1024
                * 1024,
        ),
    })
}
pub(super) fn run(args: &[String], output: &mut impl Write) -> Result<u8, String> {
    if args == ["publish-run", "--help"] {
        writeln!(output, "{USAGE}")
            .and_then(|()| output.flush())
            .map_err(|e| e.to_string())?;
        return Ok(0);
    }
    let options = parse(args)?;
    #[cfg(target_os = "linux")]
    {
        execute(options, output)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (options, output);
        Err("saved check-set publication requires Linux".into())
    }
}
#[cfg(target_os = "linux")]
fn execute(options: Options, output: &mut impl Write) -> Result<u8, String> {
    use fgit_node::{NodeConfig, OneNode, TerminationSignals};
    let signals = TerminationSignals::install().map_err(|e| e.to_string())?;
    let mut node = OneNode::open_existing(
        NodeConfig::new(options.storage, options.tenant, options.repository)
            .with_object_format(options.format),
    )
    .map_err(|e| e.to_string())?;
    let mut monitor_cleanup = None;
    let operation = (|| {
        if node.repository_incarnation_id() != options.incarnation {
            return Err("repository incarnation changed; no checks submitted".to_owned());
        }
        let head = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .map_err(|e| e.to_string())?;
        if let Err(error) = node.bring_into_service(head.receipt().generation()) {
            eprintln!(
                "check-set intake unavailable ({error}); only original outcome recovery may succeed"
            );
        }
        let (result, cleanup) = super::with_signal_request(&node, signals, |request| {
            let set = node
                .prepare_trusted_workflow_check_set(
                    request,
                    &options.directory,
                    options.journal,
                    options.snapshot,
                    options.publisher,
                    options.reference,
                    options.limits,
                )
                .map_err(|e| e.to_string())?;
            if options.expected_set.is_some_and(|id| id != set.identity()) {
                return Err(
                    "saved check-set identity differs from --expected-set; no checks submitted"
                        .into(),
                );
            }
            emit(output, &set.to_json())
                .map_err(|e| format!("set receipt failed before any check submission: {e}"))?;
            if options.plan_only {
                return Ok(None);
            }
            Ok(Some(node.runtime().block_on(
                node.publish_trusted_workflow_check_set_in(request, &set, |decision| {
                    emit(output, &decision.to_json())
                }),
            )))
        })?;
        monitor_cleanup = cleanup;
        result
    })();
    let cleanup = super::workflow_cleanup(
        monitor_cleanup,
        node.shutdown().err().map(|e| e.to_string()),
    );
    match operation {
        Ok(Some(result)) => {
            let code = if result.error.is_some() {
                2
            } else if result.all_committed() {
                0
            } else {
                3
            };
            finish(
                output,
                Some(&result.to_json()),
                false,
                code,
                None,
                cleanup.as_deref(),
            )
        }
        Ok(None) => finish(output, None, true, 0, None, cleanup.as_deref()),
        Err(error) => finish(
            output,
            None,
            options.plan_only,
            2,
            Some(&error),
            cleanup.as_deref(),
        ),
    }
}
fn emit(output: &mut impl Write, text: &str) -> Result<(), String> {
    writeln!(output, "{text}")
        .and_then(|()| output.flush())
        .map_err(|e| e.to_string())
}
fn finish(
    output: &mut impl Write,
    result: Option<&str>,
    plan_only: bool,
    code: u8,
    error: Option<&str>,
    cleanup: Option<&str>,
) -> Result<u8, String> {
    let text = format!(
        "{{\"type\":\"workflow_publish_run_result\",\"schema_version\":1,\"plan_only\":{plan_only},\"node_closed\":{},\"operation_error\":{},\"node_cleanup_error\":{},\"publication\":{}}}",
        cleanup.is_none(),
        error.map_or_else(|| "null".into(), quote),
        cleanup.map_or_else(|| "null".into(), quote),
        result.unwrap_or("null")
    );
    emit(output,&text).map_err(|e|format!("check-set receipt output failed: {e}; original child decisions may already be canonical; retry the same saved snapshot, never the workflow"))?;
    Ok(if error.is_some() || cleanup.is_some() {
        2
    } else {
        code
    })
}
#[cfg(test)]
mod tests;
