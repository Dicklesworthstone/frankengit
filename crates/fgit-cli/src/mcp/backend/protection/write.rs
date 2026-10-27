//! Bounded complete-policy replacement through the existing durable admission.
//! No authority read refreshes the supplied version, epoch or original retry key.
use fgit_forge::{
    AggregateVersion, ExpectedVersion,
    event::protection::{
        MAX_BRANCH_REQUIRED_CHECKS, MAX_BRANCH_REVIEWERS, MAX_POLICY_ADMINISTRATORS,
        MAX_PROTECTED_BRANCHES, MAX_REF_POLICY_FRAME_BYTES, MAX_REF_POLICY_SOURCE_BYTES,
        ProtectedBranch, ProtectionCommand, RequiredWorkflowCheck, ReviewProtection,
        compile_ref_policy, decode_ref_policy,
    },
};
use fgit_types::{DecisionOutcome, PolicyEpoch, PrincipalId, RefName};

use super::super::{decimal_schema, unhex};
use super::{
    NodeTools, Object, Tool, ToolError, Value, canonical_principal, json, mutations, object,
    policy_value, require_fields, text,
};

pub(super) const NAME: &str = "frankengit_protection_set";
const REQUIRED_FIELDS: &[&str] = &[
    "idempotency_key",
    "expected_version",
    "expected_epoch",
    "administrators",
    "branches",
];
const FIELDS: &[&str] = &[
    "idempotency_key",
    "expected_version",
    "expected_epoch",
    "administrators",
    "branches",
    "ref_policy_source",
    "ref_policy_frame_hex",
];
const MAX_REF_BYTES: usize = fgit_types::MAX_REF_NAME_LEN;

fn principal_schema() -> Value {
    object([
        ("type", text("string")),
        ("pattern", text("^[0-9a-f]{32}$")),
        ("minLength", json::number(32)),
        ("maxLength", json::number(32)),
    ])
}
fn principals_schema(maximum: usize, minimum: u64) -> Value {
    object([
        ("type", text("array")),
        ("minItems", json::number(minimum)),
        ("maxItems", json::number(maximum as u64)),
        ("uniqueItems", Value::Bool(true)),
        ("items", principal_schema()),
        (
            "description",
            text(
                "Canonical lower-case principal IDs, strictly sorted and unique. Order is checked before sealing.",
            ),
        ),
    ])
}
pub(super) fn tool() -> Tool {
    let mut branch = Object::new();
    branch.insert(
        "reference_hex".into(),
        object([
            ("type", text("string")),
            ("maxLength", json::number((MAX_REF_BYTES * 2) as u64)),
            ("pattern", text("^(?:[0-9a-f]{2})+$")),
            (
                "description",
                text("Exact native refs/heads/* bytes as lowercase hex; non-UTF-8 names are retained."),
            ),
        ]),
    );
    branch.insert(
        "required_reviewers".into(),
        principals_schema(MAX_BRANCH_REVIEWERS, 0),
    );
    branch.insert(
        "required_approvals".into(),
        object([
            ("type", text("integer")),
            ("minimum", json::number(0)),
            ("maximum", json::number(MAX_BRANCH_REVIEWERS as u64)),
            ("description", text("Number of distinct eligible reviewers who must approve the exact candidate. Omitted means all listed reviewers. Use 1 through the reviewer count, or 0 only with no reviewers and at least one required check. The PR opener and merge submitter never contribute votes.")),
        ]),
    );
    let mut check = Object::new();
    check.insert("source_ref_hex".into(), branch["reference_hex"].clone());
    check.insert("publisher".into(), principal_schema());
    check.insert(
        "graph_root".into(),
        object([
            ("type", text("string")),
            ("pattern", text("^[0-9a-f]{64}$")),
            ("minLength", json::number(64)),
            ("maxLength", json::number(64)),
        ]),
    );
    check.insert(
        "job".into(),
        object([
            ("type", text("string")),
            ("minLength", json::number(1)),
            (
                "maxLength",
                json::number(fgit_forge::event::workflow_check::MAX_CHECK_JOB_BYTES as u64),
            ),
            (
                "description",
                text(
                    "Exact UTF-8 workflow job name, at most 1024 bytes and no control characters.",
                ),
            ),
        ]),
    );
    branch.insert("required_checks".into(), object([
        ("type", text("array")), ("maxItems", json::number(MAX_BRANCH_REQUIRED_CHECKS as u64)),
        ("uniqueItems", Value::Bool(true)),
        ("items", mutations::input_schema(check, &["source_ref_hex", "publisher", "graph_root", "job"])),
        ("description", text("Explicit trusted publishers, strictly sorted by source reference bytes, publisher, graph bytes, then UTF-8 job bytes. Empty grants no check authority. Each branch needs reviewers or checks.")),
    ]));
    let mut properties = Object::new();
    properties.insert("idempotency_key".into(), mutations::key_schema());
    properties.insert("expected_version".into(), decimal_schema());
    properties.insert("expected_epoch".into(), decimal_schema());
    properties.insert(
        "administrators".into(),
        principals_schema(MAX_POLICY_ADMINISTRATORS, 1),
    );
    properties.insert(
        "branches".into(),
        object([
            ("type", text("array")),
            ("maxItems", json::number(MAX_PROTECTED_BRANCHES as u64)),
            ("uniqueItems", Value::Bool(true)),
            (
                "items",
                mutations::input_schema(branch, &["reference_hex", "required_reviewers", "required_checks"]),
            ),
            (
                "description",
                text("Complete policy, strictly sorted by exact reference bytes with no duplicate branches. An explicit empty array disables review requirements while retaining administrators."),
            ),
        ]),
    );
    properties.insert("ref_policy_source".into(), object([
        ("type", text("string")),
        ("minLength", json::number(1)),
        ("maxLength", json::number(MAX_REF_POLICY_SOURCE_BYTES as u64)),
        ("description", text("Optional complete policy DSL over ref facts and the request's actor.id. Compiled and validated before sealing; actor kind, authentication strength, membership, ancestry, time and evidence predicates are unavailable and refuse. The actor ID uses this transport's existing trusted-local principal boundary. Mutually exclusive with ref_policy_frame_hex. Omitting both removes the DSL component on this COMPLETE replacement.")),
    ]));
    properties.insert("ref_policy_frame_hex".into(), object([
        ("type", text("string")),
        ("minLength", json::number(2)),
        ("maxLength", json::number((MAX_REF_POLICY_FRAME_BYTES * 2) as u64)),
        ("pattern", text("^(?:[0-9a-f]{2})+$")),
        ("description", text("Exact canonical policy frame returned by protection_show, encoded as lowercase hex. Retains the selected compiled snapshot without needing its original source. Mutually exclusive with ref_policy_source. Protection requests carrying source/frame have a 256 KiB envelope; all other fields retain the ordinary MCP limits.")),
    ]));
    Tool {
        name: NAME,
        description: "Replace complete required-review, trusted-workflow and optional reference DSL protection at an exact version and policy epoch. Omitted DSL source/frame removes that component. Version zero requests first installation by the explicitly trusted local operator. Current canonical administrators authorize subsequent changes; the new list never authorizes itself. Original key and complete command must remain identical on retry. No Git refs move. Source/frame requests have a bounded 256 KiB envelope; the other fields retain ordinary MCP limits.",
        schema: mutations::input_schema(properties, REQUIRED_FIELDS),
    }
}

fn array<'a>(args: &'a Object, name: &str, maximum: usize) -> Result<&'a [Value], ToolError> {
    let Some(Value::Array(values)) = args.get(name) else {
        return Err(ToolError::invalid("policy_array_required"));
    };
    if values.len() > maximum {
        return Err(ToolError::invalid("policy_array_limit"));
    }
    Ok(values)
}
fn principals(
    args: &Object,
    name: &str,
    maximum: usize,
    allow_empty: bool,
) -> Result<Vec<PrincipalId>, ToolError> {
    let values = array(args, name, maximum)?;
    if values.is_empty() && !allow_empty {
        return Err(ToolError::invalid("policy_principals_required"));
    }
    let mut ids = Vec::with_capacity(values.len());
    for value in values {
        let id = canonical_principal(
            value
                .text()
                .ok_or(ToolError::invalid("invalid_principal_id"))?,
        )?;
        if ids.last().is_some_and(|previous| *previous >= id) {
            return Err(ToolError::invalid("policy_principals_not_canonical"));
        }
        ids.push(id);
    }
    Ok(ids)
}
pub(super) fn parse(args: &Object) -> Result<ProtectionCommand, ToolError> {
    require_fields(args, FIELDS)?;
    let ref_policy = match (
        args.get("ref_policy_source"),
        args.get("ref_policy_frame_hex"),
    ) {
        (Some(_), Some(_)) => return Err(ToolError::invalid("ambiguous_ref_policy")),
        (Some(value), None) => Some(
            compile_ref_policy(
                value
                    .text()
                    .ok_or(ToolError::invalid("invalid_ref_policy_source"))?,
            )
            .map_err(|_| ToolError::invalid("invalid_ref_policy"))?,
        ),
        (None, Some(value)) => {
            let bytes = unhex(
                value
                    .text()
                    .ok_or(ToolError::invalid("invalid_ref_policy_frame"))?,
                MAX_REF_POLICY_FRAME_BYTES,
            )?;
            Some(
                decode_ref_policy(&bytes)
                    .map_err(|_| ToolError::invalid("invalid_ref_policy_frame"))?,
            )
        }
        (None, None) => None,
    };
    let expected_version = match mutations::number(args, "expected_version")? {
        0 => ExpectedVersion::NewStream,
        value => {
            let version = AggregateVersion::try_new(value)
                .ok_or(ToolError::invalid("invalid_policy_version"))?;
            version
                .next()
                .map_err(|_| ToolError::invalid("policy_version_exhausted"))?;
            ExpectedVersion::Exactly(version)
        }
    };
    let expected_epoch = PolicyEpoch::try_new(mutations::number(args, "expected_epoch")?)
        .map_err(|_| ToolError::invalid("invalid_policy_epoch"))?;
    expected_epoch
        .next()
        .map_err(|_| ToolError::invalid("policy_epoch_exhausted"))?;
    let administrators = principals(args, "administrators", MAX_POLICY_ADMINISTRATORS, false)?;
    let raw_branches = array(args, "branches", MAX_PROTECTED_BRANCHES)?;
    let mut branches: Vec<ProtectedBranch> = Vec::with_capacity(raw_branches.len());
    for value in raw_branches {
        let fields = value
            .object()
            .ok_or(ToolError::invalid("policy_branch_object_required"))?;
        require_fields(
            fields,
            &[
                "reference_hex",
                "required_reviewers",
                "required_checks",
                "required_approvals",
            ],
        )?;
        let raw = unhex(mutations::required(fields, "reference_hex")?, MAX_REF_BYTES)?;
        if !raw.starts_with(b"refs/heads/") {
            return Err(ToolError::invalid("full_branch_required"));
        }
        let name =
            RefName::try_new(&raw).map_err(|_| ToolError::invalid("invalid_policy_branch"))?;
        if branches
            .last()
            .is_some_and(|previous| previous.name >= name)
        {
            return Err(ToolError::invalid("policy_branches_not_canonical"));
        }
        let mut required_checks = Vec::new();
        for value in array(fields, "required_checks", MAX_BRANCH_REQUIRED_CHECKS)? {
            let check = value
                .object()
                .ok_or(ToolError::invalid("policy_check_object_required"))?;
            require_fields(check, &["source_ref_hex", "publisher", "graph_root", "job"])?;
            let check = RequiredWorkflowCheck {
                source_ref: RefName::try_new(&unhex(
                    mutations::required(check, "source_ref_hex")?,
                    MAX_REF_BYTES,
                )?)
                .map_err(|_| ToolError::invalid("invalid_check_source"))?,
                publisher: canonical_principal(mutations::required(check, "publisher")?)?,
                graph_root: unhex(mutations::required(check, "graph_root")?, 32)?
                    .try_into()
                    .map_err(|_| ToolError::invalid("invalid_check_graph"))?,
                job: mutations::required(check, "job")?.to_owned(),
            };
            check
                .validate()
                .map_err(|_| ToolError::invalid("invalid_required_check"))?;
            if required_checks
                .last()
                .is_some_and(|previous| previous >= &check)
            {
                return Err(ToolError::invalid("policy_checks_not_canonical"));
            }
            required_checks.push(check);
        }
        let reviewers = principals(
            fields,
            "required_reviewers",
            MAX_BRANCH_REVIEWERS,
            !required_checks.is_empty(),
        )?;
        let required_approvals = match fields.get("required_approvals") {
            Some(value) => u16::try_from(
                value
                    .unsigned()
                    .ok_or(ToolError::invalid("invalid_required_approvals"))?,
            )
            .map_err(|_| ToolError::invalid("invalid_required_approvals"))?,
            None => reviewers.len() as u16,
        };
        branches.push(ProtectedBranch {
            required_approvals,
            required_checks,
            name,
            reviewers,
        });
    }
    let protection = ReviewProtection {
        administrators,
        branches,
        ref_policy,
    };
    protection
        .validate()
        .map_err(|_| ToolError::invalid("invalid_review_protection"))?;
    Ok(ProtectionCommand {
        expected_version,
        expected_epoch,
        protection,
    })
}

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    let command = parse(args)?;
    let requested_policy = policy_value(&command.protection)?;
    let session = mutations::session(backend, mutations::key(args)?)?;
    let principal = session
        .authenticated_session()
        .ok_or(ToolError::invalid("principal_not_bound"))?
        .principal_id();
    command
        .proposed_event(principal)
        .map_err(|_| ToolError::invalid("invalid_protection_command"))?;
    let request = fgit_cli::command_request_context(&backend.node);
    let (tx, terminal) = backend
        .node
        .runtime()
        .block_on(backend.node.admit_review_protection_durable_in(
            &request,
            &session,
            &command,
            Default::default(),
        ))
        .map_err(|_| ToolError::uncertain("mutation_outcome_unknown"))?;
    // A verified historical terminal is sufficient. Never read today's policy
    // here: a later replacement must not make the original command look failed.
    let committed = matches!(terminal.outcome, DecisionOutcome::Committed { .. });
    let expected_version = match command.expected_version {
        ExpectedVersion::NewStream => 0,
        ExpectedVersion::Exactly(version) => version.get(),
    };
    let mut result = mutations::binding(backend, principal, false);
    result.extend(mutations::terminal(tx, &terminal));
    result.insert("type".into(), text("review_protection_publication"));
    result.insert(
        "authority_profile".into(),
        text("operator_authorized_local"),
    );
    result.insert(
        "principal_source".into(),
        text("operator_asserted_at_launch"),
    );
    result.insert(
        "expected_version".into(),
        text(expected_version.to_string()),
    );
    result.insert(
        "expected_epoch".into(),
        text(command.expected_epoch.get().to_string()),
    );
    result.insert(
        "resulting_version".into(),
        if committed {
            text((expected_version + 1).to_string())
        } else {
            Value::Null
        },
    );
    result.insert(
        "resulting_policy_epoch".into(),
        if committed {
            text((command.expected_epoch.get() + 1).to_string())
        } else {
            Value::Null
        },
    );
    result.insert("requested_policy".into(), requested_policy);
    result.insert("complete".into(), Value::Bool(true));
    result.insert("refs_changed".into(), Value::Bool(false));
    result.insert("delivery_acknowledged".into(), Value::Null);
    result.insert("historical_outcome".into(), Value::Bool(true));
    Ok(Value::Object(result))
}
