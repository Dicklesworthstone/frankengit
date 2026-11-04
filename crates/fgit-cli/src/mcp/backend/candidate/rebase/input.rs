//! Exact source/onto selection and one whole-series preparation allowance.
use super::*;
use fgit_forge::preparation::rebase::resolutions::validate_rebase_resolutions;

pub(super) const SELECTION_FIELDS: &[&str] = &[
    "operation",
    "profile",
    "reference",
    "reference_hex",
    "onto_reference",
    "onto_reference_hex",
    "expected_source",
    "expected_onto",
    "expected_head",
];
const PREPARATION_FIELDS: &[&str] = &[
    "upstream",
    "empty",
    "committer",
    "timestamp",
    "max_commits",
    "max_edges",
    "max_tree_entries",
    "max_preparation_bytes",
];
const LIMITS: &[(&str, usize, usize)] = &[
    ("max_commits", MAX_COMMITS, MAX_COMMITS),
    ("max_edges", 16_384, 16_384),
    ("max_tree_entries", 100_000, 100_000),
    ("max_preparation_bytes", 256 * 1024, 1024 * 1024),
];

#[derive(Debug)]
pub(super) struct Selection {
    pub reference: RefName,
    pub onto_reference: RefName,
    pub source: GitOid,
    pub onto: GitOid,
    pub head: Option<RepositoryAuthorityHeadId>,
}
#[derive(Debug)]
pub(super) struct Input {
    pub selection: Selection,
    pub request: RebaseRequest,
    pub committer: RebaseCommitter,
    pub limits: PreparationLimits,
    pub resolutions: Option<Vec<RebaseCommitResolution>>,
}
impl Input {
    pub fn operation(&self) -> &'static str {
        if self.resolutions.is_some() {
            RESOLVE
        } else {
            PREPARE
        }
    }
}
pub(super) fn selection(args: &Object, format: GitHashAlgorithm) -> Result<Selection, ToolError> {
    if required(args, "profile")? != "linear-v1" {
        return Err(ToolError::invalid("unsupported_rebase_profile"));
    }
    let reference = branch(args, "reference", "reference_hex")?;
    let onto_reference = branch(args, "onto_reference", "onto_reference_hex")?;
    if reference == onto_reference {
        return Err(ToolError::invalid("rebase_requires_distinct_branches"));
    }
    Ok(Selection {
        reference,
        onto_reference,
        source: oid(args, "expected_source", format)?,
        onto: oid(args, "expected_onto", format)?,
        head: head(args, 0)?,
    })
}
pub(super) fn bound(
    args: &Object,
    name: &str,
    default: usize,
    minimum: usize,
    maximum: usize,
) -> Result<usize, ToolError> {
    let value = args
        .get(name)
        .map(|value| {
            value
                .unsigned()
                .ok_or(ToolError::invalid("invalid_rebase_limit"))
        })
        .transpose()?
        .unwrap_or(default as u64);
    let value = usize::try_from(value).map_err(|_| ToolError::invalid("invalid_rebase_limit"))?;
    if !(minimum..=maximum).contains(&value) {
        return Err(ToolError::invalid("invalid_rebase_limit"));
    }
    Ok(value)
}
fn preparation_bound(args: &Object, name: &str) -> Result<usize, ToolError> {
    let &(_, default, maximum) = LIMITS
        .iter()
        .find(|row| row.0 == name)
        .ok_or(ToolError::invalid("invalid_rebase_limit"))?;
    bound(args, name, default, 1, maximum)
}
pub(super) fn parse(args: &Object, format: GitHashAlgorithm) -> Result<Input, ToolError> {
    let resolving = match required(args, "operation")? {
        PREPARE => false,
        RESOLVE => true,
        _ => return Err(ToolError::invalid("unsupported_candidate_operation")),
    };
    let mut fields = SELECTION_FIELDS.to_vec();
    fields.extend_from_slice(PREPARATION_FIELDS);
    if resolving {
        fields.push("resolutions");
    }
    require_fields(args, &fields)?;
    let selection = selection(args, format)?;
    if resolving && selection.head.is_none() {
        return Err(ToolError::invalid("resolution_snapshot_required"));
    }
    let empty = match required(args, "empty")? {
        "stop" => EmptyCommitPolicy::Stop,
        "drop" => EmptyCommitPolicy::Drop,
        "keep" => EmptyCommitPolicy::Keep,
        _ => return Err(ToolError::invalid("invalid_empty_commit_policy")),
    };
    let identity = required(args, "committer")?;
    if identity.is_empty() || identity.len() > 1024 {
        return Err(ToolError::invalid("invalid_rebase_committer"));
    }
    let timestamp = json::decimal(required(args, "timestamp")?)
        .map_err(|_| ToolError::invalid("invalid_timestamp"))?;
    let committer = RebaseCommitter {
        identity: identity.to_owned(),
        timestamp,
    };
    committer
        .validate()
        .map_err(|_| ToolError::invalid("invalid_rebase_committer"))?;
    let limits = PreparationLimits {
        max_commits: preparation_bound(args, "max_commits")?,
        max_edges: preparation_bound(args, "max_edges")?,
        max_tree_entries: preparation_bound(args, "max_tree_entries")?,
        max_output_bytes: preparation_bound(args, "max_preparation_bytes")?,
        max_conflicts: MAX_RESOLUTIONS,
        max_objects: 1024,
        ..PreparationLimits::default()
    };
    limits
        .validate()
        .map_err(|_| ToolError::invalid("invalid_rebase_limit"))?;
    let resolutions = if resolving {
        let recipes = resolutions::parse(args, format)?;
        validate_rebase_resolutions(format, limits, &recipes)
            .map_err(|error| rebase_error(&error))?;
        Some(recipes)
    } else {
        None
    };
    let request = RebaseRequest {
        source_tip: selection.source,
        upstream: oid(args, "upstream", format)?,
        onto: selection.onto,
        empty,
    };
    Ok(Input {
        selection,
        request,
        committer,
        limits,
        resolutions,
    })
}
pub(super) fn properties(operation: &str) -> Object {
    let mut properties = common_properties(operation);
    properties.remove("expected_base");
    properties.insert("profile".into(), object([("const", text("linear-v1"))]));
    properties.insert("onto_reference".into(), text_schema(4096));
    properties.insert("onto_reference_hex".into(), hex_schema(4096));
    properties.insert("expected_source".into(), oid_schema());
    properties.insert("expected_onto".into(), oid_schema());
    properties.insert("expected_head".into(), text_schema(140));
    properties
}
pub(super) fn closed_schema(properties: Object, required: &[&str]) -> Value {
    input_schema(
        properties,
        required,
        vec![exactly_one("onto_reference", "onto_reference_hex")],
    )
}
pub(super) fn schema(operation: &str) -> Value {
    let resolving = operation == RESOLVE;
    let mut properties = properties(operation);
    properties.insert("upstream".into(), oid_schema());
    properties.insert("committer".into(), text_schema(1024));
    properties.insert("timestamp".into(), super::super::super::decimal_schema());
    properties.insert("empty".into(), object([
        ("type", text("string")),
        ("enum", Value::Array(vec![text("stop"), text("drop"), text("keep")])),
        ("description", text("Required policy for a newly empty replay. Originally empty commits remain preserved. No automatic policy change on retry.")),
    ]));
    for &(name, default, maximum) in LIMITS {
        properties.insert(
            name.into(),
            object([
                ("type", text("integer")),
                ("minimum", json::number(1)),
                ("maximum", json::number(maximum as u64)),
                ("default", json::number(default as u64)),
            ]),
        );
    }
    let mut required = vec![
        "operation",
        "profile",
        "expected_source",
        "expected_onto",
        "upstream",
        "empty",
        "committer",
        "timestamp",
    ];
    if resolving {
        properties.insert("resolutions".into(), resolutions::schema());
        required.extend(["expected_head", "resolutions"]);
    }
    closed_schema(properties, &required)
}
