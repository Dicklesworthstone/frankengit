//! Explicit loopback repository HTTP service with operator credentials.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::time::Duration;

use fgit_crypto::sha256_digest;
use fgit_node::index_maintenance::{IndexKind, MaintenanceConfig, MaintenanceGroup};
use fgit_node::{
    GitDaemonReceiveProcessingTimeout, GitDaemonServerLimits, GitDaemonServerReceipt,
    GitDaemonSessionTimeout, HttpTrustedOrigin, NodeConfig, OneNode,
};
use fgit_types::{
    GitHashAlgorithm, PrincipalId, RefName, RepositoryId, RepositoryIncarnationId, TenantId,
};

use crate::publication_support::quote;

use crate::service_stop as stop_file;

#[cfg(target_os = "linux")]
mod workflow;

const USAGE: &str = "usage: fg serve-http <storage-root> <tenant-id> <repository-id> <loopback-address>
  --trusted-local (--token-file <path> --principal <id> | --credentials-file <path>)
  [--allow-receive] [--allow-issues] [--allow-outcomes] [--allow-pulls] [--allow-source]
  [--allow-protection] [--lfs-root <private-directory>] [--artifact-root <absolute-private-directory>]
  [--expected-incarnation <id>] [--max-sessions <1..1000000>] [--max-in-flight <1..16>]
  [--idle-timeout-secs <1..86400>] [--session-timeout-secs <1..3600>]
  [--continuous --stop-file <path>]
  [--processing-timeout-secs <1..3600>] [--receive-max-input-mib <1..1024>]
  [--receive-max-expanded-mib <1..1024>] [--pack-max-expanded-mib <1..65536>] [--pack-max-blob-mib <non-zero>] [--pack-cache-mib <0..65536>]
  [--trusted-origin <origin>]
  [--index-state-dir <private-directory> --index-state init|resume
   --index-profile lexical|symbols|both --index-format sha1|sha256
   [--index-symbol-state-dir <private-directory>]
   --index-ref <full-ref> [--index-ref <full-ref> ...]
   [--index-interval-secs <1..3600>] [--index-attempt-timeout-secs <1..3600>]]
  [--workflow-trusted-local --workflow-ref <refs/heads/...>
   --workflow-format sha1|sha256 --workflow-dir <committed-directory>
   --workflow-input <top-level-entry> [--workflow-input <top-level-entry> ...]
   --workflow-run-parent <absolute-private-directory>
   [--workflow-interval-ms <10..60000>] [--workflow-attempt-timeout-secs <1..3600>]
   [--workflow-publish-checks --workflow-principal <id>]
   [--workflow-pull-request <number>] [--workflow-artifact-logs]
   [--workflow-merge-candidate-ref <separate-ci-branch> --workflow-merge-principal <id>
    --workflow-merge-author <name-and-email> --workflow-merge-committer <name-and-email>
    --workflow-merge-timestamp <positive-unix-seconds> --workflow-merge-message <text>
    [--workflow-merge-profile path|exact-renames]
    [--workflow-merge-method merge-commit|squash]]]

Continuous mode has no lifetime request cap or idle retirement. It requires an
initially absent stop file in an existing operator-owned directory. Create that
regular file to stop accepting and drain every accepted request before shutdown.
The file is never removed automatically. Inaccessible or non-regular control
entries cause a draining error, not silent continued service. Do not combine
--continuous with --max-sessions or --idle-timeout-secs; all per-request deadlines,
connection limits, credentials and quotas remain enforced.

Optional index maintenance requires --allow-source and scoped credentials.
Create each private state directory with mode 0700 before starting; select init
once, then resume. Select 1-32 full refs and lexical, symbols or both profiles.
The both profile requires --index-symbol-state-dir for separate symbol progress;
--index-state-dir then holds lexical progress. Each worker waits 5 seconds
between passes by default, reconciles one attempt at a time with a 300-second
ceiling, and preserves its own pending publication recovery
across restarts. --index-attempt-timeout-secs only narrows inherited budgets.
The interval is a polling delay, not a catch-up deadline. Readiness follows
authentication and exclusive progress ownership for every configured profile;
no index attempt starts before readiness succeeds. A controller failure drains
the HTTP service. Stopping the listener also cancels and drains maintenance
before node shutdown. Index work does not run inside requests and does not
publish repository state.

On Linux, the optional workflow service runs selected committed scripts as a
native sibling of the HTTP listener. It requires --credentials-file, --continuous,
--stop-file and a separate --workflow-trusted-local acknowledgement that trusts
all future selected scripts with host-user privileges. Select 1-64 unique top-level
inputs covering the workflow directory, and an existing absolute private run
parent. The worker waits 1000 ms between polls and bounds each attempt to 300 seconds
by default. --workflow-publish-checks and --workflow-principal require an explicit
--expected-incarnation; --workflow-artifact-logs requires --artifact-root. Readiness
follows exclusive workflow custody; execution begins after readiness is flushed.
Stopping drains execution and reports workflow_service_drained before HTTP drain.
The merge-candidate group requires --workflow-pull-request and --expected-incarnation.
It authorizes ordinary exact-old create/rewrite of the selected CI branch, then
executes the actual merge or squash candidate there. The CI branch must differ
from both PR branches. Explicit stable commit metadata makes it reproducible;
conflicts never run scripts. Canonical checks name that candidate and CI ref.
Use --workflow-merge-candidate-ref-hex for raw branch bytes instead of text.
No workflow option enables receive, source or another HTTP permission. See
docs/NATIVE_HTTP_WORKFLOW_SERVICE.md for retained custody and recovery limits.

Provisioning (reads/authenticates the repository, opens no listener):
  fg serve-http <storage-root> <tenant-id> <repository-id> 127.0.0.1:0
    --trusted-local --print-credentials-header [--expected-incarnation <id>]

Requires an existing repository. Git pushes, issue APIs, PR APIs, source APIs,
protection APIs and outcome queries are disabled by default. --allow-receive enables
Git pushes for receive-scoped tokens. --allow-issues, --allow-outcomes, --allow-pulls,
--allow-source and --allow-protection require --credentials-file and the token's
appropriate scopes. No switch enables another service. --allow-source exposes
read-only source queries to read-scoped tokens; it grants no mutation permission.

--token-file keeps the static Git-only profile and contains 64 lowercase hex
characters, optionally followed by one newline. --credentials-file is reloaded
for every request and contains token HASHES, never plaintext bearer secrets:
  frankengit-http-credentials-v1 <tenant-id> <repository-id> <incarnation-id>
  <sha256-of-64-character-token> <principal-id> <comma-separated-scopes>
Optional v2 uses frankengit-http-credentials-v2 in the same bound header and adds
a fourth field on every row: all, none, or comma-separated exact:<lowercase-hex> /
prefix:<lowercase-hex> selectors. Prefixes must end with a slash in decoded bytes.
At most 64 selectors / 4096 decoded bytes per row restrict every Git and native
source/merge ref write, including deletes and both ends of renames. They do not
filter reads or grant a service. See docs/HTTP_REF_WRITE_SCOPES.md.
Choose scopes once in this order:
  read,receive,issues-read,issues-write,outcomes-read,pulls-read,pulls-write,reviews-read,reviews-write,merges-write,protection-read,protection-write,lfs-read,lfs-write,artifact-read
No scope implies another. The header must match the exact repository incarnation.
At most 256 entries and 64 KiB are accepted; a header alone revokes all tokens.
Duplicate hashes or malformed rows refuse the entire table. Files must be private
regular files on Unix (0600 or stricter), not symlinks. Atomically replace the
table to rotate/revoke credentials without restarting. Already authenticated
in-flight requests retain their bounded grant.

On Linux, --lfs-root enables the Git LFS basic transfer API in an existing
private (0700) artifact-fabric directory. It requires --credentials-file and
independent lfs-read/lfs-write grants; neither grants Git reads or pushes.
Stock Git LFS uses <repository-url>/info/lfs with Basic token-as-password or
Bearer credentials. Payloads are SHA-256 verified before immutable publication
and before download; interrupted uploads can be retried under the same identity.
The bounded profile accepts objects up to 64 MiB, at most 100 objects per batch,
and at most 64 MiB total declared payload bytes per batch. Payloads are retained
permanently: pointer-aware collection, partial-upload resume and LFS locking are
outside this profile. Git pointer files are never rewritten by the service.
See docs/GIT_LFS_BASIC_TRANSFER.md for provisioning and custody/backup limits.

On Linux, --artifact-root enables read-only workflow artifact metadata/downloads
from an existing absolute private (0700) custody root. Requires --credentials-file
and the independent artifact-read grant. It exposes the ENTIRE selected repository
incarnation's trusted-workflow-local-owner namespace, including outputs produced
from hidden refs. Git, issue, PR, LFS and check grants do not imply this access.
GET /api/v1/artifacts/<artifact-sha256> inspects complete verified custody;
GET /api/v1/artifacts/<artifact-sha256>/content downloads verified bytes (64 MiB max).
Use exact artifact IDs from workflow result or saved job artifact receipts. No
upload, directory listing, caller-selected path/trust scope, producer authority,
canonical check or cache reuse is granted. See docs/HTTP_WORKFLOW_ARTIFACTS.md.

Git requests authenticate with a Bearer token or Basic token-as-password; the
native APIs accept only an explicit Bearer token. Any request other than GET or
HEAD whose Origin or Sec-Fetch-Site names another site is refused with 403.
--trusted-origin names one more origin to accept, exactly as a browser sends it
(for example https://git.example.com): the public origin of the external TLS
terminator in front of this listener.
Stock Git pushes obtain a discovery-scoped retry URL. Native metadata mutations
need a client-selected Idempotency-Key; reuse it only for the identical command.
Rotation to a new token for the same principal preserves its retry identity.
The opt-in issue API is at <repository-url>/api/v1/issues:
  GET /api/v1/issues[?limit=50&after=N&expected_head=TOKEN]
  GET /api/v1/issues/N[?limit=50&after_version=V&expected_head=TOKEN]
  POST /api/v1/issues/N/<open|edit|close|reopen|comment>
POST bodies use application/x-www-form-urlencoded and require expected_version
(0 for open, a positive exact predecessor otherwise). Open needs title and body;
comment needs body; edit accepts title/body/label or clear_labels=true. Repeated
label fields form a set. Replies are bounded JSON. Continuation requires the
first page's snapshot_token and uses that retained head across ordinary writes.
Unavailable snapshots return 409; they are never replaced with a different head.

The independently enabled native PR API is at <repository-url>/api/v1/pulls:
  GET /api/v1/pulls[?limit=50&after=N&expected_head=TOKEN]
  GET /api/v1/pulls/N[?expected_head=TOKEN]
  POST /api/v1/pulls/N/<open|update|close>
Each metadata POST is a complete URL-encoded command containing expected_version,
object_format (sha1 or sha256), source_ref, target_ref, source_tip, target_tip,
title and body. Closing preserves the exact prior data. No latest-tip lookup,
implicit partial edit, automatic issue number or cross-repository PR is supplied.
PR pages retain snapshots and current hidden-ref policy. Use pulls-read/pulls-write
grants; write does not imply read. Candidate preparation/resolution/inspection
require read AND pulls-read on one token. Review and merge endpoints use their
own reviews-read/reviews-write/merges-write grants; see docs/HTTP_REVIEW_MERGE_API.md.

Read-only source queries use body-bearing POSTs with NO Idempotency-Key:
  POST /api/v1/source/tree    (ref, object_format; optional path_hex, limit, after_hex)
  POST /api/v1/source/blob    (ref, object_format, path_hex; optional offset, limit)
  POST /api/v1/source/search  (ref, object_format, needle_hex; optional case, path_prefix_hex)
Bodies use application/x-www-form-urlencoded, not URL query parameters. Raw paths,
file bytes and search excerpts use hexadecimal byte encoding. Every response names
its source commit and exact snapshot_token. Supply expected_head for continuation;
source browsing uses strict current-head pins, not retained historical pagination.
expected_commit can additionally compare the selected ref tip. Source reads never
stage objects or create transactions. Search match limits are explicitly partial,
not complete no-match results. See docs/HTTP_SOURCE_API.md for limits and examples.

Complete independently pinned file proofs use the same read grant and --allow-source:
  GET /api/v1/source/verified-blob?ref_hex=HEX&path_hex=HEX&expected_head=PIN
This bodyless read returns a bounded binary canonical proof, requires an exact
current-head pin, and rejects Idempotency-Key. Select --root-layout ref-merkle-v1
when initializing a new repository; existing legacy roots are not migrated.
Use fg verify-read with a separately trusted head to check the complete response.
Original tree witnesses include sibling entries within the authorized ref.
See docs/VERIFIED_BLOB_READS.md for byte limits and the complete client flow.

The independently enabled protection API uses protection-read/protection-write:
  GET /api/v1/protection
  POST /api/v1/protection
Replacement requires a complete URL-encoded form with positive expected_version,
expected_epoch, repeated administrator=<principal-hex> fields and either repeated
required_reviewer=<raw-reference-bytes-hex>:<principal-hex> fields or clear=true.
Current canonical administrators authorize replacement; proposed administrators
cannot authorize themselves. First installation remains local through fg protection
set or the separate MCP protection-admin profile. Reuse the original Idempotency-Key
only for the identical complete command. See docs/HTTP_PROTECTION_API.md.

Outcome lookup uses a bodyless POST and the ORIGINAL Idempotency-Key:
  POST /api/v1/outcomes                 (metadata transaction or atomic push)
  POST /api/v1/outcomes/receive         (whole recorded non-atomic session)
  POST /api/v1/outcomes/receive/INDEX   (non-atomic push; zero-based command index)
No original command body, transaction ID or pack is needed. The authenticated
principal can inspect only its own key scope. These queries never re-seal,
resubmit or cancel work. Missing/undecided observations do not prove rollback;
a single receive-command result does not prove completion of the whole session.
INDEX is canonical decimal within the native receive command limit.

Forwarded identity headers never authenticate. This is an operator credential
profile, not organization/team IAM, per-ref/per-item ACLs, account lifecycle or
TLS. Use an authenticated external TLS terminator for nonlocal access.
Default bounds: 1024 requests, 4 in flight, 300-second phases, 128 MiB receive
envelopes and a 4096 MiB upload pack envelope (packs stream; memory is the delta window);
metadata forms have a separate 256 KiB ceiling and pages contain at most 100 entries.
Outcome replies have a separate per-principal quota; single-transaction replies
are capped at 16 KiB and whole-session replies at 16 MiB. Source reads have another
independent quota, 1 MiB maximum file slices, and an 8 MiB JSON response ceiling.
";

enum CredentialInput {
    Static {
        token_file: PathBuf,
        principal: PrincipalId,
    },
    Reloadable(PathBuf),
    HeaderOnly,
}
struct Options {
    config: NodeConfig,
    tenant: TenantId,
    repository: RepositoryId,
    listen: SocketAddr,
    credentials: CredentialInput,
    allow_receive: bool,
    allow_issues: bool,
    allow_outcomes: bool,
    allow_pulls: bool,
    allow_source: bool,
    allow_protection: bool,
    limits: GitDaemonServerLimits,
    idle_timeout: Duration,
    stop_file: Option<PathBuf>,
    index_maintenance: Option<MaintenanceGroup>,
    #[cfg(target_os = "linux")]
    workflow_service: Option<fgit_node::workflow_watch::WorkflowWatchConfig>,
}

fn number(
    flags: &BTreeMap<&str, &str>,
    name: &str,
    default: u64,
    maximum: u64,
) -> Result<u64, String> {
    let Some(value) = flags.get(name) else {
        return Ok(default);
    };
    if value.is_empty()
        || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(format!("{name} requires a canonical positive decimal"));
    }
    let value: u64 = value
        .parse()
        .map_err(|_| format!("{name} is out of range"))?;
    if value == 0 || value > maximum {
        return Err(format!("{name} must be in 1..={maximum}"));
    }
    Ok(value)
}

fn parse(arguments: &[String]) -> Result<Options, String> {
    if arguments.len() < 4 {
        return Err(USAGE.into());
    }
    if arguments.len() > 320
        || arguments.iter().any(|arg| arg.len() > 4096)
        || arguments.iter().map(String::len).sum::<usize>() > 32768
    {
        return Err("serve-http arguments exceed the bounded profile".into());
    }
    if arguments[0].is_empty() {
        return Err("storage root must not be empty".into());
    }
    let tenant = TenantId::from_hex(&arguments[1]).map_err(|_| "invalid tenant ID")?;
    let repository = RepositoryId::from_hex(&arguments[2]).map_err(|_| "invalid repository ID")?;
    let listen: SocketAddr = arguments[3]
        .parse()
        .map_err(|_| "expected a numeric loopback socket address")?;
    if !listen.ip().is_loopback() {
        return Err("serve-http refuses non-loopback plaintext listeners".into());
    }
    let mut flags = BTreeMap::new();
    let mut index_refs = Vec::new();
    let mut workflow_inputs = Vec::new();
    let mut index = 4;
    while index < arguments.len() {
        let name = arguments[index].as_str();
        index += 1;
        let boolean = matches!(
            name,
            "--trusted-local"
                | "--allow-receive"
                | "--allow-issues"
                | "--allow-outcomes"
                | "--allow-pulls"
                | "--allow-source"
                | "--allow-protection"
                | "--print-credentials-header"
                | "--continuous"
                | "--workflow-trusted-local"
                | "--workflow-publish-checks"
                | "--workflow-artifact-logs"
        );
        if !boolean
            && !matches!(
                name,
                "--token-file"
                    | "--principal"
                    | "--credentials-file"
                    | "--lfs-root"
                    | "--artifact-root"
                    | "--expected-incarnation"
                    | "--stop-file"
                    | "--max-sessions"
                    | "--max-in-flight"
                    | "--idle-timeout-secs"
                    | "--session-timeout-secs"
                    | "--processing-timeout-secs"
                    | "--receive-max-input-mib"
                    | "--receive-max-expanded-mib"
                    | "--pack-max-expanded-mib"
                    | "--pack-max-blob-mib"
                    | "--pack-cache-mib"
                    | "--trusted-origin"
                    | "--index-state-dir"
                    | "--index-symbol-state-dir"
                    | "--index-state"
                    | "--index-profile"
                    | "--index-format"
                    | "--index-ref"
                    | "--index-interval-secs"
                    | "--index-attempt-timeout-secs"
                    | "--workflow-ref"
                    | "--workflow-dir"
                    | "--workflow-input"
                    | "--workflow-run-parent"
                    | "--workflow-format"
                    | "--workflow-interval-ms"
                    | "--workflow-attempt-timeout-secs"
                    | "--workflow-principal"
                    | "--workflow-pull-request"
            )
            && crate::workflow_merge_watch::server_option(name).is_none()
        {
            return Err("unknown serve-http option".into());
        }
        let value = if boolean {
            ""
        } else {
            let value = arguments
                .get(index)
                .ok_or_else(|| format!("missing value for {name}"))?;
            index += 1;
            if value.is_empty() || (value.starts_with("--") && name != "--workflow-merge-message") {
                return Err(format!("missing value for {name}"));
            }
            value.as_str()
        };
        if name == "--index-ref" {
            if index_refs.len() == 32 {
                return Err("index maintenance accepts at most 32 refs".into());
            }
            index_refs.push(
                RefName::try_new(value.as_bytes()).map_err(|_| "invalid index maintenance ref")?,
            );
        } else if name == "--workflow-input" {
            if workflow_inputs.len() == 64 {
                return Err("workflow service accepts at most 64 inputs".into());
            }
            workflow_inputs.push(value.as_bytes().to_vec());
        } else if flags.insert(name, value).is_some() {
            return Err(format!("duplicate serve-http option {name}"));
        }
    }
    if !flags.contains_key("--trusted-local") {
        return Err(
            "--trusted-local is required for this operator-owned capability profile".into(),
        );
    }
    let stop_file = match (flags.contains_key("--continuous"), flags.get("--stop-file")) {
        (false, None) => None,
        (true, Some(path)) => {
            if flags.contains_key("--max-sessions") || flags.contains_key("--idle-timeout-secs") {
                return Err(
                    "--continuous cannot be combined with --max-sessions or --idle-timeout-secs"
                        .into(),
                );
            }
            Some(PathBuf::from(*path))
        }
        _ => return Err("--continuous and --stop-file must be supplied together".into()),
    };
    let credentials = if flags.contains_key("--print-credentials-header") {
        if !index_refs.is_empty()
            || !workflow_inputs.is_empty()
            || flags.keys().any(|name| {
                !matches!(
                    *name,
                    "--trusted-local" | "--print-credentials-header" | "--expected-incarnation"
                )
            })
        {
            return Err(
                "header provisioning cannot be combined with serving or credential options".into(),
            );
        }
        CredentialInput::HeaderOnly
    } else if let Some(path) = flags.get("--credentials-file") {
        if flags.contains_key("--token-file") || flags.contains_key("--principal") {
            return Err(
                "--credentials-file cannot be combined with --token-file or --principal".into(),
            );
        }
        CredentialInput::Reloadable(PathBuf::from(*path))
    } else {
        let token_file = PathBuf::from(
            *flags
                .get("--token-file")
                .ok_or("supply --credentials-file or --token-file with --principal")?,
        );
        let principal = PrincipalId::from_hex(
            flags
                .get("--principal")
                .copied()
                .ok_or("--principal is required with --token-file")?,
        )
        .map_err(|_| "invalid principal ID")?;
        CredentialInput::Static {
            token_file,
            principal,
        }
    };
    let allow_issues = flags.contains_key("--allow-issues");
    let allow_outcomes = flags.contains_key("--allow-outcomes");
    let allow_pulls = flags.contains_key("--allow-pulls");
    let allow_source = flags.contains_key("--allow-source");
    let allow_protection = flags.contains_key("--allow-protection");
    if flags.contains_key("--lfs-root") {
        if !matches!(&credentials, CredentialInput::Reloadable(_)) {
            return Err("Git LFS requires explicit scopes in --credentials-file".into());
        }
        #[cfg(not(target_os = "linux"))]
        return Err("the Git LFS artifact-fabric backend requires Linux".into());
    }
    if let Some(root) = flags.get("--artifact-root") {
        if !matches!(&credentials, CredentialInput::Reloadable(_)) {
            return Err(
                "workflow artifacts require explicit artifact-read in --credentials-file".into(),
            );
        }
        if root.len() > 4096 || !Path::new(root).is_absolute() {
            return Err("artifact root must be an absolute bounded private directory".into());
        }
        #[cfg(not(target_os = "linux"))]
        return Err("workflow artifact custody requires Linux".into());
    }
    if (allow_issues || allow_outcomes || allow_pulls || allow_source || allow_protection)
        && !matches!(&credentials, CredentialInput::Reloadable(_))
    {
        return Err(
            "issue/PR/source/protection/outcome endpoints require explicit scopes in --credentials-file"
                .into(),
        );
    }
    let index_maintenance = if !index_refs.is_empty()
        || flags.keys().any(|name| name.starts_with("--index-"))
    {
        if !allow_source {
            return Err("index maintenance requires --allow-source and scoped credentials".into());
        }
        let required = |name: &str| -> Result<&str, String> {
            flags
                .get(name)
                .copied()
                .ok_or_else(|| format!("index maintenance requires {name}"))
        };
        let profiles: &[IndexKind] = match required("--index-profile")? {
            "lexical" => &[IndexKind::Lexical],
            "symbols" => &[IndexKind::Symbols],
            "both" => &[IndexKind::Lexical, IndexKind::Symbols],
            _ => return Err("--index-profile must be lexical, symbols or both".into()),
        };
        if profiles.len() == 1 && flags.contains_key("--index-symbol-state-dir") {
            return Err("--index-symbol-state-dir requires --index-profile both".into());
        }
        let format = match required("--index-format")? {
            "sha1" => GitHashAlgorithm::Sha1,
            "sha256" => GitHashAlgorithm::Sha256,
            _ => return Err("--index-format must be sha1 or sha256".into()),
        };
        let initialize = match required("--index-state")? {
            "init" => true,
            "resume" => false,
            _ => return Err("--index-state must be init or resume".into()),
        };
        let interval = Duration::from_secs(number(&flags, "--index-interval-secs", 5, 3600)?);
        let timeout =
            Duration::from_secs(number(&flags, "--index-attempt-timeout-secs", 300, 3600)?);
        let mut configs = Vec::with_capacity(profiles.len());
        for (ordinal, &kind) in profiles.iter().enumerate() {
            let directory = required(if ordinal == 0 {
                "--index-state-dir"
            } else {
                "--index-symbol-state-dir"
            })?;
            let config = MaintenanceConfig::try_new(
                kind,
                format,
                PathBuf::from(directory),
                initialize,
                interval,
                index_refs.clone(),
            )
            .and_then(|config| config.with_attempt_timeout(timeout))
            .map_err(|error| error.to_string())?;
            configs.push(config);
        }
        Some(MaintenanceGroup::try_new(configs).map_err(|error| error.to_string())?)
    } else {
        None
    };
    #[cfg(not(target_os = "linux"))]
    if !workflow_inputs.is_empty() || flags.keys().any(|name| name.starts_with("--workflow-")) {
        return Err("native workflow service requires Linux".into());
    }
    #[cfg(target_os = "linux")]
    let workflow_service = workflow::parse(&flags, workflow_inputs)?;
    let sessions = number(&flags, "--max-sessions", 1024, 1_000_000)? as usize;
    let in_flight = number(&flags, "--max-in-flight", 4, 16)? as usize;
    let limits = GitDaemonServerLimits::try_new(sessions, in_flight).map_err(|e| e.to_string())?;
    let idle_timeout = Duration::from_secs(number(&flags, "--idle-timeout-secs", 300, 86400)?);
    let timeout = GitDaemonSessionTimeout::try_new(Duration::from_secs(number(
        &flags,
        "--session-timeout-secs",
        300,
        3600,
    )?))
    .map_err(|e| e.to_string())?;
    let processing = GitDaemonReceiveProcessingTimeout::try_new(Duration::from_secs(number(
        &flags,
        "--processing-timeout-secs",
        300,
        3600,
    )?))
    .map_err(|e| e.to_string())?;
    let bytes = |name| -> Result<usize, String> {
        usize::try_from(number(&flags, name, 128, 1024)? * 1024 * 1024)
            .map_err(|_| "byte envelope is not supported on this platform".into())
    };
    let mut config = NodeConfig::new(arguments[0].clone().into(), tenant, repository)
        .with_git_daemon_session_timeout(timeout)
        .with_git_daemon_receive_processing_timeout(processing)
        .with_git_daemon_receive_byte_envelope(
            Some(bytes("--receive-max-input-mib")?),
            Some(bytes("--receive-max-expanded-mib")?),
        );
    // Served packs stream through scratch custody (frankengit-8xyq), so the
    // node's default upload envelope stands unless the operator names one.
    if flags.contains_key("--pack-max-expanded-mib") {
        let mib = number(&flags, "--pack-max-expanded-mib", 1, 65536)?;
        config = config.with_selected_pack_byte_envelope(
            usize::try_from(mib * 1024 * 1024)
                .map_err(|_| "byte envelope is not supported on this platform".to_owned())?,
        );
    }
    if let Some(value) = flags.get("--pack-max-blob-mib") {
        config = config.with_selected_pack_blob_limit(
            fgit_cli::parse_pack_blob_mib(value).map_err(|error| error.to_string())?,
        );
    }
    if let Some(value) = flags.get("--pack-cache-mib") {
        config = config.with_pack_cache_bytes(
            fgit_cli::parse_pack_cache_mib(value).map_err(|error| error.to_string())?,
        );
    }
    if allow_protection {
        config = config.with_http_protection_admin();
    }
    if let Some(root) = flags.get("--lfs-root") {
        config = config.with_http_lfs_root(PathBuf::from(*root));
    }
    if let Some(root) = flags.get("--artifact-root") {
        config = config.with_workflow_artifact_root(PathBuf::from(*root));
    }
    if let Some(origin) = flags.get("--trusted-origin") {
        config = config.with_http_trusted_origin(
            HttpTrustedOrigin::try_new(origin).map_err(|refusal| refusal.to_string())?,
        );
    }
    if let Some(incarnation) = flags.get("--expected-incarnation") {
        config = config.with_expected_repository_incarnation(
            RepositoryIncarnationId::from_hex(incarnation)
                .map_err(|_| "invalid repository incarnation")?,
        );
    }
    Ok(Options {
        config,
        tenant,
        repository,
        listen,
        credentials,
        allow_receive: flags.contains_key("--allow-receive"),
        allow_issues,
        allow_outcomes,
        allow_pulls,
        allow_source,
        allow_protection,
        limits,
        idle_timeout,
        stop_file,
        index_maintenance,
        #[cfg(target_os = "linux")]
        workflow_service,
    })
}

fn token_digest(bytes: &[u8]) -> Result<[u8; 32], String> {
    let token = bytes
        .strip_suffix(b"\r\n")
        .or_else(|| bytes.strip_suffix(b"\n"))
        .unwrap_or(bytes);
    if token.len() != 64
        || !token
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err("token file must contain exactly 64 lowercase hexadecimal characters and at most one final newline".into());
    }
    Ok(sha256_digest(token))
}

fn read_token(path: &Path) -> Result<[u8; 32], String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|e| format!("cannot inspect token file: {e}"))?;
    if !metadata.is_file() || metadata.len() > 66 {
        return Err("token must be a bounded regular file, not a symlink or device".into());
    }
    let mut file = File::open(path).map_err(|e| format!("cannot open token file: {e}"))?;
    let opened = file
        .metadata()
        .map_err(|e| format!("cannot inspect opened token file: {e}"))?;
    if !opened.is_file() || opened.len() > 66 {
        return Err("opened token file is not a bounded regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.dev() != opened.dev()
            || metadata.ino() != opened.ino()
            || metadata.mode() & 0o077 != 0
            || opened.mode() & 0o077 != 0
        {
            return Err(
                "token file must be stable and private: remove all group/other permissions".into(),
            );
        }
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(67)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read token file: {e}"))?;
    token_digest(&bytes)
}

pub fn run(arguments: &[String]) -> Result<u8, String> {
    if arguments == ["--help"] {
        println!("{USAGE}");
        return Ok(0);
    }
    let options = parse(arguments)?;
    let stop = options
        .stop_file
        .as_ref()
        .map(|path| stop_file::StopFile::arm(path))
        .transpose()
        .map_err(|error| format!("cannot arm HTTP stop control: {error}"))?;
    let credential = match &options.credentials {
        CredentialInput::Static { token_file, .. } => Some(read_token(token_file)?),
        _ => None,
    };
    let lfs_enabled = options.config.http_lfs_root().is_some();
    let artifacts_enabled = options.config.workflow_artifact_root().is_some();
    #[cfg(target_os = "linux")]
    let workflow_enabled = options.workflow_service.is_some();
    #[cfg(not(target_os = "linux"))]
    let workflow_enabled = false;
    let workflow_non_green = Cell::new(false);
    let mut node = OneNode::open_existing(options.config).map_err(|e| e.to_string())?;
    if matches!(&options.credentials, CredentialInput::HeaderOnly) {
        let authentication = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .map_err(|e| e.to_string());
        let header = format!(
            "frankengit-http-credentials-v1 {} {} {}",
            options.tenant,
            options.repository,
            node.repository_incarnation_id()
        );
        let cleanup = node.shutdown().map_err(|e| e.to_string());
        authentication?;
        cleanup?;
        let mut out = io::stdout().lock();
        writeln!(out, "{header}")
            .and_then(|()| out.flush())
            .map_err(|e| e.to_string())?;
        return Ok(0);
    }
    let serving = (|| -> Result<GitDaemonServerReceipt, String> {
        if let CredentialInput::Reloadable(path) = &options.credentials {
            node.validate_smart_http_credentials_file(path)
                .map_err(|e| e.to_string())?;
        }
        node.validate_smart_http_lfs_storage()
            .map_err(|e| e.to_string())?;
        #[cfg(target_os = "linux")]
        if artifacts_enabled {
            node.validate_workflow_artifact_storage()
                .map_err(|error| error.to_string())?;
        }
        let head = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .map_err(|e| e.to_string())?;
        node.bring_into_service(head.receipt().generation())
            .map_err(|e| e.to_string())?;
        let listener = TcpListener::bind(options.listen)
            .map_err(|e| format!("cannot bind HTTP listener: {e}"))?;
        let address = listener.local_addr().map_err(|e| e.to_string())?;
        let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes())
            .map_err(|_| "invalid canonical route")?;
        let url = format!("http://{address}{route}");
        let mode = match &options.credentials {
            CredentialInput::Reloadable(_) => "reloadable",
            _ => "static",
        };
        let control = stop.as_ref().map(stop_file::StopControl::new);
        let report_ready = || -> io::Result<()> {
            let mut output = io::stdout().lock();
            writeln!(output, "{{\"type\":\"smart_http_listening\",\"schema_version\":1,\"url\":{},\"receive_enabled\":{},\"issues_enabled\":{},\"outcomes_enabled\":{},\"pulls_enabled\":{},\"source_enabled\":{},\"protection_enabled\":{},\"lfs_enabled\":{},\"artifacts_enabled\":{},\"workflow_enabled\":{},\"repository_incarnation\":{},\"credential_mode\":{},\"lifetime\":{}}}",
            quote(&url), options.allow_receive, options.allow_issues, options.allow_outcomes, options.allow_pulls,
            options.allow_source, options.allow_protection, lfs_enabled, artifacts_enabled, workflow_enabled, quote(&node.repository_incarnation_id().to_string()), quote(mode), quote(if stop.is_some() { "continuous" } else { "bounded" }))
            .and_then(|()| output.flush())
        };
        #[cfg(target_os = "linux")]
        if let Some(workflow) = options.workflow_service {
            let CredentialInput::Reloadable(path) = &options.credentials else {
                return Err("workflow service requires scoped credentials".into());
            };
            let Some(control) = control else {
                return Err("workflow service requires continuous stop control".into());
            };
            let report_workflow_drained =
                |receipt: &fgit_node::workflow_watch::WorkflowWatchReceipt| {
                    workflow_non_green.set(
                        workflow_non_green.get()
                            || receipt.non_green
                            || receipt.interrupted
                            || receipt.requires_reconciliation
                            || receipt.publication_pending,
                    );
                    let mut output = io::stdout().lock();
                    writeln!(output, "{}", receipt.to_json()).and_then(|()| output.flush())
                };
            return node
                .serve_repository_http_with_workflow_and_index_services_until_stopped(
                    &listener,
                    options.limits.max_in_flight(),
                    path,
                    options.allow_receive,
                    options.allow_issues,
                    options.allow_outcomes,
                    options.allow_pulls,
                    options.allow_source,
                    workflow,
                    options.index_maintenance,
                    &|| control.should_stop(),
                    &report_ready,
                    &report_workflow_drained,
                )
                .map_err(|error| error.to_string());
        }
        if let Some(maintenance) = options.index_maintenance {
            let CredentialInput::Reloadable(path) = &options.credentials else {
                return Err("index maintenance requires scoped credentials".into());
            };
            return if let Some(control) = control {
                node.serve_repository_http_with_index_maintenance_until_stopped(
                    &listener,
                    options.limits.max_in_flight(),
                    path,
                    options.allow_receive,
                    options.allow_issues,
                    options.allow_outcomes,
                    options.allow_pulls,
                    maintenance,
                    &|| control.should_stop(),
                    &report_ready,
                )
            } else {
                node.serve_repository_http_with_index_maintenance_bounded(
                    &listener,
                    options.limits,
                    path,
                    options.allow_receive,
                    options.allow_issues,
                    options.allow_outcomes,
                    options.allow_pulls,
                    options.idle_timeout,
                    maintenance,
                    &report_ready,
                )
            }
            .map_err(|error| error.to_string());
        }
        report_ready().map_err(|e| format!("cannot report HTTP readiness: {e}"))?;
        if let Some(control) = control {
            let should_stop = || control.should_stop();
            // One continuous service, not repeated bounded windows: quotas and
            // accepted-child accounting remain live until the requested stop.
            return match &options.credentials {
                CredentialInput::Static { principal, .. } => node.serve_smart_http_until_stopped(
                    &listener,
                    options.limits.max_in_flight(),
                    credential.ok_or("static credential missing")?,
                    *principal,
                    options.allow_receive,
                    &should_stop,
                ),
                CredentialInput::Reloadable(path) => node.serve_repository_http_until_stopped(
                    &listener,
                    options.limits.max_in_flight(),
                    path,
                    options.allow_receive,
                    options.allow_issues,
                    options.allow_outcomes,
                    options.allow_pulls,
                    options.allow_source,
                    &should_stop,
                ),
                CredentialInput::HeaderOnly => {
                    return Err("header-only operation cannot serve".into());
                }
            }
            .map_err(|error| error.to_string());
        }
        match &options.credentials {
            CredentialInput::Static { principal, .. } => node.serve_smart_http_bounded(
                &listener,
                options.limits,
                credential.ok_or("static credential missing")?,
                *principal,
                options.allow_receive,
                options.idle_timeout,
            ),
            CredentialInput::Reloadable(path) if options.allow_source => node
                .serve_repository_http_with_source_bounded(
                    &listener,
                    options.limits,
                    path,
                    options.allow_receive,
                    options.allow_issues,
                    options.allow_outcomes,
                    options.allow_pulls,
                    options.idle_timeout,
                ),
            CredentialInput::Reloadable(path) if options.allow_pulls => node
                .serve_repository_http_with_pull_requests_bounded(
                    &listener,
                    options.limits,
                    path,
                    options.allow_receive,
                    options.allow_issues,
                    options.allow_outcomes,
                    options.idle_timeout,
                ),
            CredentialInput::Reloadable(path) => node
                .serve_repository_http_with_credentials_file_bounded(
                    &listener,
                    options.limits,
                    path,
                    options.allow_receive,
                    options.allow_issues,
                    options.allow_outcomes,
                    options.idle_timeout,
                ),
            CredentialInput::HeaderOnly => return Err("header-only operation cannot serve".into()),
        }
        .map_err(|e| e.to_string())
    })();
    let cleanup = node.shutdown().map_err(|e| e.to_string());
    let receipt = match (serving, cleanup) {
        (Ok(receipt), Ok(())) => receipt,
        (Err(error), Ok(())) => return Err(error),
        (Ok(_), Err(error)) => {
            return Err(format!(
                "HTTP service drained but node shutdown failed: {error}"
            ));
        }
        (Err(error), Err(cleanup)) => {
            return Err(format!(
                "HTTP service failed ({error}); node shutdown also failed ({cleanup})"
            ));
        }
    };
    let mut output = io::stdout().lock();
    writeln!(
        output,
        "{{\"type\":\"smart_http_drained\",\"schema_version\":1,\"accepted\":{},\"completed_transports\":{},\"refused_transports\":{}}}",
        receipt.accepted_sessions(),
        receipt.completed_sessions(),
        receipt.refused_sessions()
    )
    .and_then(|()| output.flush())
    .map_err(|error| format!("cannot report HTTP drain: {error}"))?;
    Ok(u8::from(workflow_non_green.get()))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn arguments() -> Vec<String> {
        [
            "state",
            &"11".repeat(16),
            &"22".repeat(16),
            "127.0.0.1:0",
            "--trusted-local",
            "--token-file",
            "token",
            "--principal",
            &"33".repeat(16),
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }
    #[test]
    fn safe_defaults_require_credentials_and_do_not_enable_receive() {
        let options = parse(&arguments()).unwrap();
        assert!(!options.allow_receive);
        assert!(!options.allow_issues);
        assert!(!options.allow_outcomes);
        assert!(!options.allow_pulls);
        assert!(!options.allow_source);
        assert!(!options.allow_protection);
        assert!(options.index_maintenance.is_none());
        #[cfg(target_os = "linux")]
        assert!(options.workflow_service.is_none());
        assert!(!options.config.http_protection_admin_enabled());
        assert!(options.config.http_lfs_root().is_none());
        assert!(options.config.workflow_artifact_root().is_none());
        assert_eq!(options.limits.max_sessions(), 1024);
        assert_eq!(options.limits.max_in_flight(), 4);
        let mut args = arguments();
        args.retain(|arg| arg != "--trusted-local");
        assert!(parse(&args).is_err());
    }

    #[test]
    fn workflow_options_are_rejected_during_header_provisioning() {
        for flags in [
            vec!["--workflow-trusted-local"],
            vec!["--workflow-input", "ci"],
            vec!["--workflow-ref", "refs/heads/main"],
        ] {
            let mut args = arguments()[..5].to_vec();
            args.push("--print-credentials-header".into());
            args.extend(flags.into_iter().map(str::to_owned));
            assert!(
                parse(&args)
                    .err()
                    .unwrap()
                    .contains("header provisioning cannot be combined")
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn workflow_options_require_linux() {
        let mut args = arguments()[..5].to_vec();
        args.extend(
            ["--credentials-file", "grants", "--workflow-input", "ci"]
                .into_iter()
                .map(str::to_owned),
        );
        assert!(parse(&args).err().unwrap().contains("requires Linux"));
    }

    #[test]
    fn lfs_requires_an_explicit_custody_root_and_scoped_credentials() {
        let mut static_args = arguments();
        static_args.extend(["--lfs-root".into(), "lfs-custody".into()]);
        assert!(parse(&static_args).is_err());

        let mut scoped = arguments()[..5].to_vec();
        scoped.extend(
            ["--credentials-file", "grants", "--lfs-root", "lfs-custody"]
                .into_iter()
                .map(str::to_owned),
        );
        #[cfg(target_os = "linux")]
        {
            let options = parse(&scoped).unwrap();
            assert_eq!(
                options.config.http_lfs_root(),
                Some(Path::new("lfs-custody"))
            );
            assert!(!options.allow_receive && !options.allow_source && !options.allow_pulls);
        }
        #[cfg(not(target_os = "linux"))]
        assert!(parse(&scoped).is_err());
        scoped.extend(["--lfs-root".into(), "other".into()]);
        assert!(parse(&scoped).is_err());
        let mut header = arguments()[..5].to_vec();
        header.extend(
            ["--print-credentials-header", "--lfs-root", "lfs-custody"]
                .into_iter()
                .map(str::to_owned),
        );
        assert!(parse(&header).is_err());
    }

    #[test]
    fn artifacts_require_an_explicit_private_root_and_scoped_credentials() {
        let mut static_args = arguments();
        static_args.extend(["--artifact-root".into(), "/private/artifacts".into()]);
        assert!(parse(&static_args).is_err());
        let mut scoped = arguments()[..5].to_vec();
        scoped.extend(
            [
                "--credentials-file",
                "grants",
                "--artifact-root",
                "/private/artifacts",
            ]
            .into_iter()
            .map(str::to_owned),
        );
        #[cfg(target_os = "linux")]
        {
            let options = parse(&scoped).unwrap();
            assert_eq!(
                options.config.workflow_artifact_root(),
                Some(Path::new("/private/artifacts"))
            );
            assert!(
                !options.allow_receive
                    && !options.allow_source
                    && !options.allow_pulls
                    && !options.allow_issues
            );
            assert!(options.config.http_lfs_root().is_none());
        }
        #[cfg(not(target_os = "linux"))]
        assert!(parse(&scoped).is_err());
        let mut relative = scoped.clone();
        *relative.last_mut().unwrap() = "relative-artifacts".into();
        assert!(parse(&relative).is_err());
        scoped.extend(["--artifact-root".into(), "/another".into()]);
        assert!(parse(&scoped).is_err());
        let mut header = arguments()[..5].to_vec();
        header.extend(
            [
                "--print-credentials-header",
                "--artifact-root",
                "/private/artifacts",
            ]
            .into_iter()
            .map(str::to_owned),
        );
        assert!(parse(&header).is_err());
    }

    fn maintenance_arguments() -> Vec<String> {
        let mut args = arguments()[..5].to_vec();
        args.extend(
            [
                "--credentials-file",
                "grants",
                "--allow-source",
                "--index-state-dir",
                "maintenance",
                "--index-state",
                "init",
                "--index-profile",
                "lexical",
                "--index-format",
                "sha1",
                "--index-ref",
                "refs/heads/main",
            ]
            .into_iter()
            .map(str::to_owned),
        );
        args
    }

    #[test]
    fn maintenance_requires_complete_explicit_scope_and_uses_bounded_defaults() {
        let args = maintenance_arguments();
        let options = parse(&args).unwrap();
        let group = options.index_maintenance.unwrap();
        assert_eq!(group.configs().len(), 1);
        let maintenance = &group.configs()[0];
        assert_eq!(maintenance.kind(), IndexKind::Lexical);
        assert_eq!(maintenance.format(), GitHashAlgorithm::Sha1);
        assert_eq!(maintenance.directory(), Path::new("maintenance"));
        assert!(maintenance.initialize());
        assert_eq!(maintenance.interval(), Duration::from_secs(5));
        assert_eq!(maintenance.attempt_timeout(), Duration::from_secs(300));
        assert_eq!(maintenance.refs()[0].as_bytes(), b"refs/heads/main");
        assert!(!options.allow_receive);
        for flag in [
            "--index-state-dir",
            "--index-state",
            "--index-profile",
            "--index-format",
            "--index-ref",
        ] {
            let mut missing = args.clone();
            let at = missing.iter().position(|arg| arg == flag).unwrap();
            missing.drain(at..at + 2);
            assert!(parse(&missing).is_err(), "{flag}");
        }
        let mut no_source = args;
        no_source.retain(|arg| arg != "--allow-source");
        assert!(parse(&no_source).is_err());
    }

    #[test]
    fn maintenance_supports_symbols_resume_and_canonical_sorted_refs() {
        let mut args = maintenance_arguments();
        for (flag, value) in [
            ("--index-state", "resume"),
            ("--index-profile", "symbols"),
            ("--index-format", "sha256"),
        ] {
            let at = args.iter().position(|arg| arg == flag).unwrap();
            args[at + 1] = value.into();
        }
        args.extend(
            [
                "--index-ref",
                "refs/heads/develop",
                "--index-interval-secs",
                "1",
                "--index-attempt-timeout-secs",
                "7",
            ]
            .into_iter()
            .map(str::to_owned),
        );
        let group = parse(&args).unwrap().index_maintenance.unwrap();
        assert_eq!(group.configs().len(), 1);
        let config = &group.configs()[0];
        assert_eq!(config.kind(), IndexKind::Symbols);
        assert_eq!(config.format(), GitHashAlgorithm::Sha256);
        assert!(!config.initialize());
        assert_eq!(config.interval(), Duration::from_secs(1));
        assert_eq!(config.attempt_timeout(), Duration::from_secs(7));
        assert_eq!(
            config
                .refs()
                .iter()
                .map(RefName::as_bytes)
                .collect::<Vec<_>>(),
            [b"refs/heads/develop".as_slice(), b"refs/heads/main"]
        );
    }

    #[test]
    fn both_indexes_keep_separate_progress_with_the_same_explicit_scope() {
        let mut args = maintenance_arguments();
        for (flag, value) in [
            ("--index-profile", "both"),
            ("--index-format", "sha256"),
            ("--index-state", "resume"),
        ] {
            let at = args.iter().position(|arg| arg == flag).unwrap();
            args[at + 1] = value.into();
        }
        args.extend(
            [
                "--index-symbol-state-dir",
                "symbol-maintenance",
                "--index-ref",
                "refs/heads/develop",
                "--index-interval-secs",
                "2",
                "--index-attempt-timeout-secs",
                "11",
            ]
            .into_iter()
            .map(str::to_owned),
        );
        let options = parse(&args).unwrap();
        let group = options.index_maintenance.unwrap();
        let configs = group.configs();
        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0].kind(), IndexKind::Lexical);
        assert_eq!(configs[0].directory(), Path::new("maintenance"));
        assert_eq!(configs[1].kind(), IndexKind::Symbols);
        assert_eq!(configs[1].directory(), Path::new("symbol-maintenance"));
        for config in configs {
            assert_eq!(config.format(), GitHashAlgorithm::Sha256);
            assert!(!config.initialize());
            assert_eq!(config.interval(), Duration::from_secs(2));
            assert_eq!(config.attempt_timeout(), Duration::from_secs(11));
            assert_eq!(
                config
                    .refs()
                    .iter()
                    .map(RefName::as_bytes)
                    .collect::<Vec<_>>(),
                [b"refs/heads/develop".as_slice(), b"refs/heads/main"]
            );
        }
        assert!(!options.allow_receive);
        assert!(!options.allow_pulls);
    }

    #[test]
    fn both_indexes_require_distinct_explicit_progress_without_ignored_options() {
        let mut both = maintenance_arguments();
        let at = both
            .iter()
            .position(|arg| arg == "--index-profile")
            .unwrap();
        both[at + 1] = "both".into();
        assert!(
            parse(&both)
                .err()
                .unwrap()
                .contains("--index-symbol-state-dir")
        );
        both.extend(["--index-symbol-state-dir".into(), "maintenance".into()]);
        assert!(
            parse(&both).is_err(),
            "one directory cannot hold both owners"
        );
        *both.last_mut().unwrap() = "symbols".into();
        assert!(parse(&both).is_ok());
        both.extend(["--index-symbol-state-dir".into(), "different".into()]);
        assert!(
            parse(&both).is_err(),
            "a duplicate destination is ambiguous"
        );
        for profile in ["lexical", "symbols"] {
            let mut single = maintenance_arguments();
            let at = single
                .iter()
                .position(|arg| arg == "--index-profile")
                .unwrap();
            single[at + 1] = profile.into();
            single.extend(["--index-symbol-state-dir".into(), "symbols".into()]);
            assert!(
                parse(&single)
                    .err()
                    .unwrap()
                    .contains("requires --index-profile both"),
                "the extra directory must not be silently ignored"
            );
        }
    }

    #[test]
    fn maintenance_refuses_ambiguous_scopes_and_unbounded_scheduling() {
        for (flag, value) in [
            ("--index-state", "auto"),
            ("--index-profile", "unknown"),
            ("--index-format", "auto"),
            ("--index-ref", "main"),
        ] {
            let mut args = maintenance_arguments();
            let at = args.iter().position(|arg| arg == flag).unwrap();
            args[at + 1] = value.into();
            assert!(parse(&args).is_err(), "{flag}");
        }
        for seconds in ["0", "01", "3601"] {
            for flag in ["--index-interval-secs", "--index-attempt-timeout-secs"] {
                let mut args = maintenance_arguments();
                args.extend([flag.into(), seconds.into()]);
                assert!(parse(&args).is_err());
            }
        }
        let mut duplicate = maintenance_arguments();
        duplicate.extend(["--index-ref".into(), "refs/heads/main".into()]);
        assert!(parse(&duplicate).is_err());
        let mut too_many = maintenance_arguments();
        for n in 0..32 {
            too_many.extend(["--index-ref".into(), format!("refs/heads/topic-{n}")]);
        }
        assert!(parse(&too_many).is_err());
        let mut header = arguments()[..5].to_vec();
        header.extend(
            [
                "--print-credentials-header",
                "--index-ref",
                "refs/heads/main",
            ]
            .into_iter()
            .map(str::to_owned),
        );
        assert!(parse(&header).is_err());
    }

    #[test]
    fn non_loopback_and_unbounded_limits_are_refused_before_side_effects() {
        let mut args = arguments();
        args[3] = "0.0.0.0:8080".into();
        assert!(parse(&args).is_err());
        for (flag, value) in [
            ("--max-in-flight", "17"),
            ("--max-sessions", "0"),
            ("--idle-timeout-secs", "0"),
            ("--session-timeout-secs", "3601"),
            ("--receive-max-input-mib", "1025"),
            ("--pack-max-expanded-mib", "0"),
            ("--pack-max-expanded-mib", "65537"),
        ] {
            let mut args = arguments();
            args.extend([flag.into(), value.into()]);
            assert!(parse(&args).is_err(), "{flag}");
        }
    }
    /// frankengit-8xyq: served packs stream, so the upload envelope is the
    /// node's 4 GiB default unless named, and a named one may exceed the old
    /// 1 GiB ceiling.
    #[test]
    fn the_pack_envelope_keeps_the_node_default_unless_named() {
        let debug = |args: &[String]| format!("{:?}", parse(args).unwrap().config);
        let default = debug(&arguments());
        assert!(
            default.contains("max_total_expanded_bytes: 4294967296"),
            "{default}"
        );
        let mut args = arguments();
        args.extend(["--pack-max-expanded-mib".into(), "8192".into()]);
        let widened = debug(&args);
        assert!(
            widened.contains("max_total_expanded_bytes: 8589934592"),
            "{widened}"
        );
        assert!(!widened.contains("max_total_expanded_bytes: 4294967296"));
    }

    #[test]
    fn selected_blob_limit_has_the_same_explicit_opt_in_as_other_transports() {
        assert_eq!(
            parse(&arguments())
                .unwrap()
                .config
                .selected_pack_blob_limit(),
            None
        );
        for (value, bytes) in [
            ("1", 1 << 20),
            ("32", 32 << 20),
            ("33", 33 << 20),
            ("96", 96 << 20),
        ] {
            let mut args = arguments();
            args.extend(["--pack-max-blob-mib".into(), value.into()]);
            assert_eq!(
                parse(&args).unwrap().config.selected_pack_blob_limit(),
                Some(bytes)
            );
        }
        for value in ["0", "18446744073709551615", "-1", "+1", "1.5"] {
            let mut args = arguments();
            args.extend(["--pack-max-blob-mib".into(), value.into()]);
            assert!(parse(&args).is_err(), "{value}");
        }
        let mut duplicate = arguments();
        duplicate
            .extend(["--pack-max-blob-mib", "32", "--pack-max-blob-mib", "96"].map(str::to_owned));
        assert!(parse(&duplicate).is_err());
        let mut missing = arguments();
        missing.push("--pack-max-blob-mib".into());
        assert!(parse(&missing).is_err());
    }

    #[test]
    fn pack_cache_capacity_has_the_shared_default_and_zero_disables_it() {
        assert_eq!(
            parse(&arguments()).unwrap().config.pack_cache_bytes(),
            64 << 20
        );
        for (value, bytes) in [("0", 0), ("1", 1 << 20), ("128", 128 << 20)] {
            let mut args = arguments();
            args.extend(["--pack-cache-mib".into(), value.into()]);
            assert_eq!(parse(&args).unwrap().config.pack_cache_bytes(), bytes);
        }
        for value in ["65537", "18446744073709551615", "-1", "+1", "1.5"] {
            let mut args = arguments();
            args.extend(["--pack-cache-mib".into(), value.into()]);
            assert!(parse(&args).is_err(), "{value}");
        }
        let mut duplicate = arguments();
        duplicate.extend(["--pack-cache-mib", "0", "--pack-cache-mib", "1"].map(str::to_owned));
        assert!(parse(&duplicate).is_err());
        let mut missing = arguments();
        missing.push("--pack-cache-mib".into());
        assert!(parse(&missing).is_err());
    }

    /// frankengit-root-doctrine-x2mv.4.31: the one trusted browser origin
    /// reaches the node configuration only in exact form, and only once.
    #[test]
    fn a_trusted_origin_is_exact_single_and_off_by_default() {
        assert_eq!(
            parse(&arguments()).unwrap().config.http_trusted_origin(),
            None
        );
        let mut args = arguments();
        args.extend(["--trusted-origin".into(), "https://git.example.com".into()]);
        let options = parse(&args).unwrap();
        assert_eq!(
            options
                .config
                .http_trusted_origin()
                .map(HttpTrustedOrigin::as_str),
            Some("https://git.example.com")
        );
        for refused in ["https://git.example.com/", "https://Git.example.com", "*"] {
            let mut args = arguments();
            args.extend(["--trusted-origin".into(), refused.into()]);
            assert!(parse(&args).is_err(), "{refused}");
        }
        args.extend(["--trusted-origin".into(), "https://other.example".into()]);
        assert!(parse(&args).is_err());
    }
    #[test]
    fn duplicate_flags_cannot_change_the_security_profile() {
        let mut args = arguments();
        args.extend(["--principal".into(), "44".repeat(16)]);
        assert!(parse(&args).is_err());
        let mut args = arguments();
        args.extend(["--allow-receive".into(), "--allow-receive".into()]);
        assert!(parse(&args).is_err());
        let mut args = arguments();
        args.push("--allow-receive".into());
        assert!(parse(&args).unwrap().allow_receive);
    }
    #[test]
    fn token_encoding_is_exact_and_errors_do_not_echo_secrets() {
        let token = "a".repeat(64);
        for ending in ["", "\n", "\r\n"] {
            assert_eq!(
                token_digest(format!("{token}{ending}").as_bytes()).unwrap(),
                sha256_digest(token.as_bytes())
            );
        }
        for bytes in [
            b"".as_slice(),
            b"short",
            b"secret token",
            &[b'A'; 64],
            &[b'a'; 65],
        ] {
            let error = token_digest(bytes).unwrap_err();
            assert!(!error.contains("secret token"));
        }
        assert!(token_digest(format!("{token}\n\n").as_bytes()).is_err());
    }
    #[test]
    fn reloadable_mode_never_accepts_a_static_principal_override() {
        let mut args = arguments()[..5].to_vec();
        args.extend(["--credentials-file".into(), "grants".into()]);
        assert!(matches!(
            parse(&args).unwrap().credentials,
            CredentialInput::Reloadable(_)
        ));
        assert!(!parse(&args).unwrap().allow_receive);
        for extra in [
            vec!["--principal".into(), "33".repeat(16)],
            vec!["--token-file".into(), "token".into()],
        ] {
            let mut invalid = args.clone();
            invalid.extend(extra);
            assert!(parse(&invalid).is_err());
        }
    }
    #[test]
    fn issue_api_requires_explicit_opt_in_and_file_scopes() {
        let mut static_args = arguments();
        static_args.push("--allow-issues".into());
        assert!(parse(&static_args).is_err());
        let mut args = arguments()[..5].to_vec();
        args.extend(["--credentials-file".into(), "grants".into()]);
        assert!(!parse(&args).unwrap().allow_issues);
        args.push("--allow-issues".into());
        let options = parse(&args).unwrap();
        assert!(options.allow_issues);
        assert!(!options.allow_receive);
        assert!(!options.allow_outcomes);
        assert!(!options.allow_pulls);
        args.push("--allow-issues".into());
        assert!(parse(&args).is_err());
    }
    #[test]
    fn outcome_recovery_is_opt_in_and_does_not_enable_either_write_service() {
        let mut static_args = arguments();
        static_args.push("--allow-outcomes".into());
        assert!(parse(&static_args).is_err());
        let mut args = arguments()[..5].to_vec();
        args.extend(["--credentials-file".into(), "grants".into()]);
        assert!(!parse(&args).unwrap().allow_outcomes);
        args.push("--allow-outcomes".into());
        let options = parse(&args).unwrap();
        assert!(options.allow_outcomes);
        assert!(!options.allow_receive && !options.allow_issues && !options.allow_pulls);
        args.push("--allow-outcomes".into());
        assert!(parse(&args).is_err());
    }
    #[test]
    fn pull_requests_require_explicit_file_grants_and_do_not_enable_other_services() {
        let mut static_args = arguments();
        static_args.push("--allow-pulls".into());
        assert!(parse(&static_args).is_err());
        let mut args = arguments()[..5].to_vec();
        args.extend(["--credentials-file".into(), "grants".into()]);
        assert!(!parse(&args).unwrap().allow_pulls);
        args.push("--allow-pulls".into());
        let options = parse(&args).unwrap();
        assert!(options.allow_pulls);
        assert!(!options.allow_receive && !options.allow_issues && !options.allow_outcomes);
        args.push("--allow-pulls".into());
        assert!(parse(&args).is_err());
    }
    #[test]
    fn source_reads_are_opt_in_and_do_not_enable_publication_or_other_apis() {
        let mut static_args = arguments();
        static_args.push("--allow-source".into());
        assert!(parse(&static_args).is_err());
        let mut args = arguments()[..5].to_vec();
        args.extend(["--credentials-file".into(), "grants".into()]);
        assert!(!parse(&args).unwrap().allow_source);
        args.push("--allow-source".into());
        let options = parse(&args).unwrap();
        assert!(options.allow_source);
        assert!(
            !options.allow_receive
                && !options.allow_issues
                && !options.allow_outcomes
                && !options.allow_pulls
        );
        let mut all = args.clone();
        all.extend([
            "--allow-pulls".into(),
            "--allow-issues".into(),
            "--allow-outcomes".into(),
            "--allow-receive".into(),
        ]);
        let all = parse(&all).unwrap();
        assert!(
            all.allow_source
                && all.allow_pulls
                && all.allow_issues
                && all.allow_outcomes
                && all.allow_receive
        );
        args.push("--allow-source".into());
        assert!(parse(&args).is_err());
    }
    #[test]
    fn protection_requires_scoped_credentials_and_never_enables_other_services() {
        let mut static_args = arguments();
        static_args.push("--allow-protection".into());
        assert!(parse(&static_args).is_err());
        let mut args = arguments()[..5].to_vec();
        args.extend(["--credentials-file".into(), "grants".into()]);
        let defaults = parse(&args).unwrap();
        assert!(!defaults.allow_protection);
        assert!(!defaults.config.http_protection_admin_enabled());
        args.push("--allow-protection".into());
        let options = parse(&args).unwrap();
        assert!(options.allow_protection);
        assert!(options.config.http_protection_admin_enabled());
        assert!(
            !options.allow_receive
                && !options.allow_issues
                && !options.allow_outcomes
                && !options.allow_pulls
                && !options.allow_source
        );
        args.push("--allow-protection".into());
        assert!(parse(&args).is_err());
        let mut provisioning = arguments()[..5].to_vec();
        provisioning.extend([
            "--print-credentials-header".into(),
            "--allow-protection".into(),
        ]);
        assert!(parse(&provisioning).is_err());
    }
    #[test]
    fn header_provisioning_is_a_separate_read_only_operation() {
        let mut args = arguments()[..5].to_vec();
        args.push("--print-credentials-header".into());
        assert!(matches!(
            parse(&args).unwrap().credentials,
            CredentialInput::HeaderOnly
        ));
        args.push("--allow-receive".into());
        assert!(parse(&args).is_err());
    }

    #[test]
    fn continuous_cli_mode_requires_an_explicit_stop_control() {
        let base = arguments();
        assert!(parse(&base).unwrap().stop_file.is_none());
        for flags in [vec!["--continuous"], vec!["--stop-file", "stop"]] {
            let mut args = base.clone();
            args.extend(flags.into_iter().map(str::to_owned));
            assert!(parse(&args).is_err());
        }
        let mut args = base;
        args.extend(["--continuous".into(), "--stop-file".into(), "stop".into()]);
        let options = parse(&args).unwrap();
        assert_eq!(options.stop_file, Some(PathBuf::from("stop")));
        assert_eq!(options.limits.max_in_flight(), 4);
        assert!(!options.allow_receive);
    }

    #[test]
    fn continuous_cli_mode_never_silently_ignores_requested_retirement_limits() {
        for (flag, value) in [("--max-sessions", "2"), ("--idle-timeout-secs", "1")] {
            let mut args = arguments();
            args.extend([flag.into(), value.into()]);
            assert!(parse(&args).is_ok());
            args.extend(["--continuous".into(), "--stop-file".into(), "stop".into()]);
            assert!(parse(&args).is_err());
        }
    }

    #[test]
    fn continuous_cli_does_not_relax_scopes_or_connection_bounds() {
        let mut args = arguments();
        args.extend(["--continuous".into(), "--stop-file".into(), "stop".into()]);
        let mut too_many = args.clone();
        too_many.extend(["--max-in-flight".into(), "17".into()]);
        assert!(parse(&too_many).is_err());
        args.extend(["--max-in-flight".into(), "16".into()]);
        assert!(parse(&args).is_ok());
        args.push("--allow-issues".into());
        assert!(parse(&args).is_err());
    }

    #[test]
    fn continuous_reloadable_mode_preserves_all_independent_endpoint_ceilings() {
        let mut args = arguments()[..5].to_vec();
        args.extend([
            "--credentials-file".into(),
            "grants".into(),
            "--continuous".into(),
            "--stop-file".into(),
            "stop".into(),
        ]);
        let options = parse(&args).unwrap();
        assert!(options.stop_file.is_some());
        assert!(
            !options.allow_receive
                && !options.allow_issues
                && !options.allow_outcomes
                && !options.allow_pulls
                && !options.allow_source
                && !options.allow_protection
        );
        assert!(!options.config.http_protection_admin_enabled());
        for flag in [
            "--allow-receive",
            "--allow-issues",
            "--allow-outcomes",
            "--allow-pulls",
            "--allow-source",
            "--allow-protection",
        ] {
            let mut selected = args.clone();
            selected.push(flag.into());
            let options = parse(&selected).unwrap();
            assert_eq!(options.allow_receive, flag == "--allow-receive");
            assert_eq!(options.allow_issues, flag == "--allow-issues");
            assert_eq!(options.allow_outcomes, flag == "--allow-outcomes");
            assert_eq!(options.allow_pulls, flag == "--allow-pulls");
            assert_eq!(options.allow_source, flag == "--allow-source");
            assert_eq!(options.allow_protection, flag == "--allow-protection");
            assert_eq!(
                options.config.http_protection_admin_enabled(),
                flag == "--allow-protection"
            );
        }
    }
}
