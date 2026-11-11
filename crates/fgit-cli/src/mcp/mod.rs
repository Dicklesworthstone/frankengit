//! Explicit operator or sponsored-agent MCP process; no ambient repository discovery.
mod backend;
mod json;
mod maintenance;
mod protocol;
use fgit_types::{GitHashAlgorithm, PrincipalId, RepositoryId, RepositoryIncarnationId, TenantId};
use std::collections::BTreeMap;
use std::path::PathBuf;

const USAGE: &str = "usage: fg-mcp <storage-root> <tenant-id> <repository-id>\n  --trusted-local [--allow-issues] [--allow-discussions] [--allow-pulls] [--allow-source]\n  [--allow-issue-writes] [--allow-discussion-writes] [--allow-pull-writes] [--allow-source-writes]\n  [--allow-notification-writes (--allow-issues|--allow-discussions|--allow-pulls)]\n  [--allow-review-writes] [--allow-reviewed-merges] [--allow-outcomes]\n  [--allow-queues] [--allow-queue-writes] [--allow-queue-landings]\n  [--allow-agent-context --principal <id> --expected-incarnation <id>]\n  [--allow-artifacts --artifact-root <private-absolute-root> --expected-incarnation <id>]\n  [--principal <id> --expected-incarnation <id>]\n  [--object-format sha1|sha256] [--max-messages <1..100000>]\n\nAn existing repository only. Discussion reads and writes each require their own\nexplicit grant; issue access never implies discussion access.\nRead groups, issue/discussion/PR/source/review writes, reviewed\nmerges and outcome recovery are INDEPENDENT grants. Writes or recovery require\nboth a launch-bound principal and an exact incarnation pin. No write grant\nimplies another write, read or recovery grant. Self inbox reads require the selected kind's --allow-issues, --allow-discussions or --allow-pulls\ngrant plus the launch-bound principal and incarnation; kind defaults to issue.\nNotification writes additionally require --allow-notification-writes; content-write\npermission does not grant them. Read acknowledgements supply an explicit observed\nthread prefix; later activity\nstays unread. No tool accepts another notification recipient. Queue reads, metadata writes and\nfast-forward head landings have separate grants. Queue writes/landings require\ncanonical launch identities plus matching expected_incarnation/object_format\nin every call; landing also pins queue/PR versions, both tips and policy epoch.\nNative branch protection remains mandatory and no merge-method fallback exists.\nAgent context requires its independent grant, a launch-bound sponsor principal\nand the exact incarnation pin. It opens a bounded, invocation-only read run and\nreturns authenticated source evidence; it grants no writes or durable execution.\nArtifact reads require their independent grant, an existing private absolute root\nand the exact incarnation pin. They disclose the ENTIRE configured workflow\nnamespace, including hidden-ref outputs; source-read grants do not filter it.\nArtifact provenance records custody, not canonical checks or producer authority.\nThe operator sponsors every mutation as that principal; this is not remote IAM\nor a broker-backed Intent Run. Never proxy this process to untrusted clients.\nEvery mutation requires its original durable client key. Exact-version tools retain\ntheir predecessors; explicit append tools select the current publication position.\nA lost response, timeout or disconnect does not prove rollback. Recover the key\nor retry the identical command with a NEW JSON-RPC ID and the SAME durable key.\nSource writes use non-forced native admission. Bundles are bounded to 24 KiB.\nReviews bind exact candidate bytes, PR/reviewer versions, tips and policy epoch.\nChange requests and withdrawals require a nonblank explanation. Review permission\ndoes not grant code publication. Reviewed merge requires every explicitly named\nreviewer to approve the exact candidate; opener and submitter votes cannot count.\nThere is no unreviewed merge fallback or repository-wide protection configuration.\nNo shell, secret, network listener, sampling, or ambient filesystem tool is available.\nMCP protocol remains 2025-06-18.\nComplete newline-delimited messages only; operations are serial and native-budget\nbounded. Late cancellation does not undo a canonical decision or preempt work.\nEOF, output failure, or the message bound closes the node explicitly.\nRepository text and client capabilities cannot change identity or grants.";

const MAINTENANCE_USAGE: &str = "Optional operator-owned index maintenance for either profile:
  --expected-incarnation <id> (--allow-source|--allow-agent-context)
  --index-profile lexical|symbols|both --index-format sha1|sha256
  --index-state init|resume --index-state-dir <existing-private-directory>
  [--index-symbol-state-dir <separate-private-directory>] (required only for both)
  --index-ref <full-ref> [--index-ref <full-ref> ...]
  [--index-interval-secs <1..3600>] [--index-attempt-timeout-secs <1..3600>]

Index format must equal --object-format. Use 1-32 unique refs and existing 0700
Unix progress directories. Interval defaults to 5 seconds; attempt ceiling to
300 seconds, met with the inherited background budget. Resume preserves the
exact profile/ref/namespace binding and unresolved original candidates.
These launch options grant the local operator maintenance responsibility; no
MCP tool or source credential grants index writes. Read scopes remain independent.
All progress owners are acquired before serving; index attempts start only after
the initialization response is successfully flushed. Readiness does not promise
fresh indexes. EOF, framing/output failure and the message bound stop and join
all controllers before node shutdown. A failed controller stops its siblings;
blocking stdio reports the failure at its next input/output boundary.";

const AGENT_USAGE: &str = "Sponsored-agent source and metadata profile:
  fg-mcp <storage-root> <tenant-id> <repository-id>
    --agent-token-file <private-file> --expected-incarnation <id>
    [--allow-issues] [--allow-discussions] [--allow-pulls] [--allow-source]
    [--allow-agent-context]
    [--allow-issue-writes] [--allow-discussion-writes] [--allow-pull-writes]
    [--allow-outcomes] [--object-format sha1|sha256] [--max-messages <1..100000>]

Choose this profile instead of --trusted-local. --principal is forbidden: the
canonical credential supplies the agent and sponsor. Every selected read, write
and recovery group is an independent ceiling, checked against the current grant
for every call. At least one is required. Write never implies read or recovery.
Current source browsing, search, reference listing and initial/context retrieval
require --allow-source and the canonical source-read scope. --allow-agent-context
independently exposes the authenticated Agent Protocol context document under
that same canonical scope; neither launch flag grants the other tool group.
History, blame, historical tree/blob and reference comparison tools independently
require source-history-read. With source-candidates, --allow-source exposes only
prepare_patch (regular-file exact-tree-v1) and single-parent inspect operations of
frankengit_source_candidate. Candidate data grants no publication authority.
Source work preserves the credential's real agent, sponsor and original request
deadline, and creates no durable execution run. Source writes, initial-history,
symlink/replay/rebase/PR/queue candidate preparation, PR-specific diffs, Git
transport and general bundle export/import remain unavailable.
Issue, PR metadata/conversation, discussion and own-principal outcome tools keep
their independent grants. Milestones, notifications, checks, reviews, artifacts,
queues, events and administration remain unavailable.
The token file is private, regular and bounded; its contents are never arguments
or receipts. Each call binds the complete tool name/arguments and original key
to a bounded IntentRun. Expiry/revocation is checked again on the next request;
native admission also revalidates before publication. Rotate by issuing another
credential for the same agent and restarting this process with its private file.
A revoked/expired token cannot recover a prior request. An authorized replacement
for that same agent can recover the original outcome without changing its author.
MCP responses retain their existing schema and durable retry semantics.";

/// Independent launch-time mutation ceilings. None implies a read/recovery grant.
#[derive(Clone, Copy, Debug, Default)]
struct WriteGrants {
    issues: bool,
    discussions: bool,
    notifications: bool,
    pulls: bool,
    source: bool,
    reviews: bool,
    merges: bool,
}
impl WriteGrants {
    const fn any(self) -> bool {
        self.issues
            || self.discussions
            || self.notifications
            || self.pulls
            || self.source
            || self.reviews
            || self.merges
    }
}

/// Queue observation, metadata management and code publication are separate.
#[derive(Clone, Copy, Debug, Default)]
struct QueueGrants {
    read: bool,
    write: bool,
    land: bool,
}
impl QueueGrants {
    const fn mutation(self) -> bool {
        self.write || self.land
    }
    const fn any(self) -> bool {
        self.read || self.mutation()
    }
}

#[derive(Clone, Debug)]
struct Options {
    storage: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    format: GitHashAlgorithm,
    incarnation: Option<RepositoryIncarnationId>,
    issues: bool,
    discussions: bool,
    pulls: bool,
    source: bool,
    queues: QueueGrants,
    agent_context: bool,
    artifacts: bool,
    artifact_root: Option<PathBuf>,
    writes: WriteGrants,
    outcomes: bool,
    principal: Option<PrincipalId>,
    agent_token_file: Option<PathBuf>,
    max_messages: usize,
    index_maintenance: Option<fgit_node::index_maintenance::MaintenanceGroup>,
}
impl Options {
    fn validate_access(&self) -> Result<(), String> {
        if !(self.issues
            || self.discussions
            || self.pulls
            || self.source
            || self.queues.any()
            || self.agent_context
            || self.artifacts
            || self.writes.any()
            || self.outcomes)
        {
            return Err("at least one explicit MCP grant is required".into());
        }
        if let Some(group) = &self.index_maintenance {
            if !cfg!(unix) {
                return Err("MCP index maintenance requires Unix progress ownership".into());
            }
            if !(self.source || self.agent_context) || self.incarnation.is_none() {
                return Err("MCP index maintenance requires --expected-incarnation and an independent --allow-source or --allow-agent-context grant".into());
            }
            if group
                .configs()
                .iter()
                .any(|config| config.format() != self.format)
            {
                return Err("MCP index format must match --object-format".into());
            }
        }
        if let Some(path) = &self.agent_token_file {
            if path.as_os_str().is_empty() || self.incarnation.is_none() {
                return Err("agent MCP requires a token file and --expected-incarnation".into());
            }
            if self.principal.is_some() {
                return Err("agent MCP identity comes only from its canonical credential; --principal is forbidden".into());
            }
            if self.queues.any()
                || self.artifacts
                || self.artifact_root.is_some()
                || self.writes.notifications
                || self.writes.source
                || self.writes.reviews
                || self.writes.merges
            {
                return Err("agent MCP permits only independent current-source, agent-context, issue, discussion, pull metadata and outcome grants".into());
            }
            return Ok(());
        }
        if self.artifacts != self.artifact_root.is_some() {
            return Err("--allow-artifacts and --artifact-root must be supplied together".into());
        }
        if let Some(root) = &self.artifact_root {
            if !cfg!(unix) {
                return Err("workflow artifact reads are supported only on Unix".into());
            }
            if self.incarnation.is_none() {
                return Err("artifact reads require --expected-incarnation".into());
            }
            if !root.is_absolute()
                || root.components().any(|part| {
                    !matches!(
                        part,
                        std::path::Component::RootDir | std::path::Component::Normal(_)
                    )
                })
            {
                return Err(
                    "artifact root must be an absolute path without parent traversal".into(),
                );
            }
        }
        if self.writes.notifications && !(self.issues || self.discussions || self.pulls) {
            return Err("--allow-notification-writes also requires --allow-issues, --allow-discussions or --allow-pulls for the selected thread domain".into());
        }
        let principal_scoped = self.writes.any()
            || self.queues.mutation()
            || self.outcomes
            || self.agent_context
            || ((self.issues || self.discussions || self.pulls) && self.principal.is_some());
        if principal_scoped && (self.principal.is_none() || self.incarnation.is_none()) {
            return Err(
                "writes, recovery, agent context and personal inbox reads require --principal and --expected-incarnation"
                    .into(),
            );
        }
        if !principal_scoped && self.principal.is_some() {
            return Err(
                "--principal requires an explicit write, outcome, issue/discussion/pull-read or agent-context grant".into(),
            );
        }
        Ok(())
    }
}
pub fn run(arguments: &[String]) -> Result<(), String> {
    if arguments
        .first()
        .is_some_and(|value| value == "--protection-admin")
    {
        return backend::protection::run(&arguments[1..]);
    }
    if arguments == ["--help"] {
        eprintln!(
            "{USAGE}\n\n{AGENT_USAGE}\n\n{MAINTENANCE_USAGE}\n\nSeparate policy-inspection profile with independent write/recovery grants: fg-mcp --protection-admin --help"
        );
        return Ok(());
    }
    let options = parse_options(arguments)?;
    let maximum = options.max_messages;
    let mut backend = backend::NodeTools::open(options)?;
    let served = protocol::serve(
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
        &mut backend,
        maximum,
    );
    let closed = backend.close();
    match (served, closed) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}; {cleanup}")),
    }
}
fn parse_options(arguments: &[String]) -> Result<Options, String> {
    if arguments.len() < 3 || arguments.len() > 128 {
        return Err(format!("{USAGE}\n\n{AGENT_USAGE}\n\n{MAINTENANCE_USAGE}"));
    }
    if arguments.iter().any(|s| s.len() > 4096) || arguments[0].is_empty() {
        return Err("invalid bounded MCP arguments".into());
    }
    let tenant = TenantId::from_hex(&arguments[1]).map_err(|_| "invalid tenant ID")?;
    let repository = RepositoryId::from_hex(&arguments[2]).map_err(|_| "invalid repository ID")?;
    let mut flags = BTreeMap::new();
    let mut index_refs = Vec::new();
    let mut at = 3;
    while at < arguments.len() {
        let name = arguments[at].as_str();
        at += 1;
        if name == "--index-ref" {
            let value = arguments.get(at).ok_or("missing index reference")?;
            at += 1;
            if index_refs.len() == 32 {
                return Err("index maintenance accepts at most 32 explicit references".into());
            }
            index_refs.push(
                fgit_types::RefName::try_new(value.as_bytes())
                    .map_err(|_| "invalid index reference")?,
            );
            continue;
        }
        let value = match name {
            "--trusted-local"
            | "--allow-issues"
            | "--allow-discussions"
            | "--allow-pulls"
            | "--allow-source"
            | "--allow-queues"
            | "--allow-queue-writes"
            | "--allow-queue-landings"
            | "--allow-agent-context"
            | "--allow-issue-writes"
            | "--allow-discussion-writes"
            | "--allow-notification-writes"
            | "--allow-pull-writes"
            | "--allow-source-writes"
            | "--allow-review-writes"
            | "--allow-reviewed-merges"
            | "--allow-outcomes"
            | "--allow-artifacts" => "",
            "--object-format"
            | "--expected-incarnation"
            | "--max-messages"
            | "--principal"
            | "--artifact-root"
            | "--agent-token-file"
            | "--index-profile"
            | "--index-format"
            | "--index-state"
            | "--index-state-dir"
            | "--index-symbol-state-dir"
            | "--index-interval-secs"
            | "--index-attempt-timeout-secs" => {
                let value = arguments.get(at).ok_or("missing option value")?;
                at += 1;
                value.as_str()
            }
            _ => return Err("unknown MCP option".into()),
        };
        if flags.insert(name, value).is_some() {
            return Err("duplicate MCP option".into());
        }
    }
    if flags.contains_key("--trusted-local") == flags.contains_key("--agent-token-file") {
        return Err("select exactly one MCP profile: --trusted-local or --agent-token-file".into());
    }
    let format = match flags.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1,
        "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("unsupported object format".into()),
    };
    let incarnation = flags
        .get("--expected-incarnation")
        .map(|value| RepositoryIncarnationId::from_hex(value).map_err(|_| "invalid incarnation ID"))
        .transpose()?;
    let principal = flags
        .get("--principal")
        .map(|value| PrincipalId::from_hex(value).map_err(|_| "invalid principal ID"))
        .transpose()?;
    let maximum = flags
        .get("--max-messages")
        .map(|value| json::decimal(value))
        .transpose()?
        .unwrap_or(1024);
    if !(1..=100_000).contains(&maximum) {
        return Err("message bound must be 1..100000".into());
    }
    let options = Options {
        storage: arguments[0].clone().into(),
        tenant,
        repository,
        format,
        incarnation,
        issues: flags.contains_key("--allow-issues"),
        discussions: flags.contains_key("--allow-discussions"),
        pulls: flags.contains_key("--allow-pulls"),
        source: flags.contains_key("--allow-source"),
        queues: QueueGrants {
            read: flags.contains_key("--allow-queues"),
            write: flags.contains_key("--allow-queue-writes"),
            land: flags.contains_key("--allow-queue-landings"),
        },
        agent_context: flags.contains_key("--allow-agent-context"),
        artifacts: flags.contains_key("--allow-artifacts"),
        artifact_root: flags
            .get("--artifact-root")
            .map(|value| PathBuf::from(*value)),
        writes: WriteGrants {
            issues: flags.contains_key("--allow-issue-writes"),
            discussions: flags.contains_key("--allow-discussion-writes"),
            notifications: flags.contains_key("--allow-notification-writes"),
            pulls: flags.contains_key("--allow-pull-writes"),
            source: flags.contains_key("--allow-source-writes"),
            reviews: flags.contains_key("--allow-review-writes"),
            merges: flags.contains_key("--allow-reviewed-merges"),
        },
        outcomes: flags.contains_key("--allow-outcomes"),
        principal,
        agent_token_file: flags
            .get("--agent-token-file")
            .map(|value| PathBuf::from(*value)),
        max_messages: maximum as usize,
        index_maintenance: maintenance::parse(&flags, index_refs, format)?,
    };
    options.validate_access()?;
    if options.queues.mutation()
        && (flags.get("--principal").copied()
            != options
                .principal
                .as_ref()
                .map(ToString::to_string)
                .as_deref()
            || flags.get("--expected-incarnation").copied()
                != options
                    .incarnation
                    .as_ref()
                    .map(ToString::to_string)
                    .as_deref())
    {
        return Err(
            "queue writes and landings require canonical lowercase launch identities".into(),
        );
    }
    Ok(options)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn arguments() -> Vec<String> {
        [
            "/unused",
            &"11".repeat(16),
            &"22".repeat(16),
            "--trusted-local",
            "--allow-issues",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
    }
    #[test]
    fn launch_grants_are_explicit_and_cannot_be_expanded_by_unknown_options() {
        assert!(parse_options(&arguments()).is_ok());
        for flag in ["--trusted-local", "--allow-issues"] {
            let args = arguments()
                .into_iter()
                .filter(|arg| arg != flag)
                .collect::<Vec<_>>();
            assert!(parse_options(&args).is_err());
        }
        for extra in [
            vec!["--allow-shell"],
            vec!["--allow-issues"],
            vec!["--max-messages", "0"],
            vec!["--max-messages", "01"],
            vec!["--object-format", "auto"],
            vec!["--expected-incarnation", "bad"],
        ] {
            let mut args = arguments();
            args.extend(extra.into_iter().map(str::to_owned));
            assert!(parse_options(&args).is_err());
        }
    }
    #[test]
    fn write_and_recovery_grants_require_identity_and_incarnation_but_imply_no_reads() {
        for flag in [
            "--allow-issue-writes",
            "--allow-discussion-writes",
            "--allow-pull-writes",
            "--allow-source-writes",
            "--allow-review-writes",
            "--allow-reviewed-merges",
            "--allow-outcomes",
        ] {
            let mut args = arguments();
            args.retain(|s| s != "--allow-issues");
            args.push(flag.into());
            assert!(parse_options(&args).is_err());
            args.extend(["--principal".into(), "33".repeat(16)]);
            assert!(parse_options(&args).is_err());
            args.extend(["--expected-incarnation".into(), "44".repeat(16)]);
            let options = parse_options(&args).unwrap();
            assert!(!options.issues && !options.pulls && !options.source);
            assert!(!options.discussions);
            assert_eq!(options.writes.issues, flag == "--allow-issue-writes");
            assert_eq!(
                options.writes.discussions,
                flag == "--allow-discussion-writes"
            );
            assert_eq!(options.writes.pulls, flag == "--allow-pull-writes");
            assert_eq!(options.writes.source, flag == "--allow-source-writes");
            assert_eq!(options.writes.reviews, flag == "--allow-review-writes");
            assert_eq!(options.writes.merges, flag == "--allow-reviewed-merges");
            assert_eq!(options.outcomes, flag == "--allow-outcomes");
        }
        let mut args = arguments();
        args.extend(["--principal".into(), "33".repeat(16)]);
        assert!(parse_options(&args).is_err());
    }
}

#[cfg(test)]
mod grant_tests {
    use super::*;
    #[test]
    fn read_groups_are_independent_and_at_least_one_is_required() {
        for mask in 0..16 {
            let mut args = vec![
                "/unused".to_owned(),
                "11".repeat(16),
                "22".repeat(16),
                "--trusted-local".to_owned(),
            ];
            for (bit, flag) in [
                (1, "--allow-issues"),
                (2, "--allow-pulls"),
                (4, "--allow-source"),
                (8, "--allow-discussions"),
            ] {
                if mask & bit != 0 {
                    args.push(flag.to_owned());
                }
            }
            let parsed = parse_options(&args);
            if mask == 0 {
                assert!(parsed.is_err());
            } else {
                let options = parsed.unwrap();
                assert_eq!(options.issues, mask & 1 != 0);
                assert_eq!(options.pulls, mask & 2 != 0);
                assert_eq!(options.source, mask & 4 != 0);
                assert_eq!(options.discussions, mask & 8 != 0);
                assert!(!options.writes.any() && !options.outcomes && options.principal.is_none());
            }
        }
    }
}

#[cfg(test)]
mod mutation_grant_tests {
    use super::*;
    #[test]
    fn all_launch_grant_combinations_preserve_independent_write_ceilings() {
        let flags = [
            "--allow-issues",
            "--allow-pulls",
            "--allow-source",
            "--allow-issue-writes",
            "--allow-pull-writes",
            "--allow-source-writes",
            "--allow-outcomes",
            "--allow-review-writes",
            "--allow-reviewed-merges",
        ];
        for mask in 0_u16..512 {
            let mut args = vec![
                "/unused".into(),
                "11".repeat(16),
                "22".repeat(16),
                "--trusted-local".into(),
            ];
            for (bit, flag) in flags.iter().enumerate() {
                if mask & (1 << bit) != 0 {
                    args.push((*flag).into());
                }
            }
            let scoped = mask & 504 != 0;
            if scoped {
                assert!(parse_options(&args).is_err());
                args.extend([
                    "--principal".into(),
                    "33".repeat(16),
                    "--expected-incarnation".into(),
                    "44".repeat(16),
                ]);
            }
            let result = parse_options(&args);
            if mask == 0 {
                assert!(result.is_err());
                continue;
            }
            let options = result.unwrap();
            assert_eq!(options.issues, mask & 1 != 0);
            assert_eq!(options.pulls, mask & 2 != 0);
            assert_eq!(options.source, mask & 4 != 0);
            assert_eq!(options.writes.issues, mask & 8 != 0);
            assert_eq!(options.writes.pulls, mask & 16 != 0);
            assert_eq!(options.writes.source, mask & 32 != 0);
            assert_eq!(options.outcomes, mask & 64 != 0);
            assert_eq!(options.writes.reviews, mask & 128 != 0);
            assert_eq!(options.writes.merges, mask & 256 != 0);
            assert_eq!(options.writes.any(), mask & 440 != 0);
        }
    }
}

#[cfg(test)]
mod artifact_grant_tests;

#[cfg(test)]
mod agent_context_grant_tests;

#[cfg(test)]
mod queue_grant_tests;

#[cfg(test)]
mod agent_grant_tests;
