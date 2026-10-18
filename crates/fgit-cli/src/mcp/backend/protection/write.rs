//! Bounded complete-policy replacement through the existing durable admission.
//! No authority read refreshes the supplied version, epoch or original retry key.
use fgit_forge::{
    AggregateVersion, ExpectedVersion,
    event::protection::{
        MAX_BRANCH_REVIEWERS, MAX_POLICY_ADMINISTRATORS, MAX_PROTECTED_BRANCHES, ProtectedBranch,
        ProtectionCommand, ReviewProtection,
    },
};
use fgit_types::{DecisionOutcome, PolicyEpoch, PrincipalId, RefName};

use super::super::{decimal_schema, unhex};
use super::{
    NodeTools, Object, Tool, ToolError, Value, canonical_principal, json, mutations, object,
    policy_value, require_fields, text,
};

pub(super) const NAME: &str = "frankengit_protection_set";
const FIELDS: &[&str] = &[
    "idempotency_key",
    "expected_version",
    "expected_epoch",
    "administrators",
    "branches",
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
fn principals_schema(maximum: usize) -> Value {
    object([
        ("type", text("array")),
        ("minItems", json::number(1)),
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
        principals_schema(MAX_BRANCH_REVIEWERS),
    );
    let mut properties = Object::new();
    properties.insert("idempotency_key".into(), mutations::key_schema());
    properties.insert("expected_version".into(), decimal_schema());
    properties.insert("expected_epoch".into(), decimal_schema());
    properties.insert(
        "administrators".into(),
        principals_schema(MAX_POLICY_ADMINISTRATORS),
    );
    properties.insert(
        "branches".into(),
        object([
            ("type", text("array")),
            ("maxItems", json::number(MAX_PROTECTED_BRANCHES as u64)),
            ("uniqueItems", Value::Bool(true)),
            (
                "items",
                mutations::input_schema(branch, &["reference_hex", "required_reviewers"]),
            ),
            (
                "description",
                text("Complete policy, strictly sorted by exact reference bytes with no duplicate branches. An explicit empty array disables review requirements while retaining administrators."),
            ),
        ]),
    );
    Tool {
        name: NAME,
        description: "Replace complete required-review protection at an exact version and policy epoch. Version zero requests first installation by the explicitly trusted local operator. Current canonical administrators authorize subsequent changes; the new list never authorizes itself. Original key and complete command must remain identical on retry. No Git refs move. Subject to the existing 64 KiB MCP input limit.",
        schema: mutations::input_schema(properties, FIELDS),
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
fn principals(args: &Object, name: &str, maximum: usize) -> Result<Vec<PrincipalId>, ToolError> {
    let values = array(args, name, maximum)?;
    if values.is_empty() {
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
    let administrators = principals(args, "administrators", MAX_POLICY_ADMINISTRATORS)?;
    let raw_branches = array(args, "branches", MAX_PROTECTED_BRANCHES)?;
    let mut branches: Vec<ProtectedBranch> = Vec::with_capacity(raw_branches.len());
    for value in raw_branches {
        let fields = value
            .object()
            .ok_or(ToolError::invalid("policy_branch_object_required"))?;
        require_fields(fields, &["reference_hex", "required_reviewers"])?;
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
        branches.push(ProtectedBranch {
            name,
            reviewers: principals(fields, "required_reviewers", MAX_BRANCH_REVIEWERS)?,
        });
    }
    let protection = ReviewProtection {
        administrators,
        branches,
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
    result.insert("requested_policy".into(), policy_value(&command.protection));
    result.insert("complete".into(), Value::Bool(true));
    result.insert("refs_changed".into(), Value::Bool(false));
    result.insert("delivery_acknowledged".into(), Value::Null);
    result.insert("historical_outcome".into(), Value::Bool(true));
    Ok(Value::Object(result))
}
