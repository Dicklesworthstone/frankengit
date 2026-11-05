//! Literal process inputs, with explicit workflow/job/step inheritance.
//! No host environment, secret lookup or executable interpolation participates.
use super::{Node, Span, WorkflowRefusal};
use std::collections::BTreeMap;

pub const MAX_ENVIRONMENT_ENTRIES: usize = 64;
pub const MAX_ENVIRONMENT_BYTES: usize = 64 * 1024;
pub const MAX_ENVIRONMENT_VALUE_BYTES: usize = 8192;
pub const MAX_WORKING_DIRECTORY_BYTES: usize = 1024;

pub(super) type Environment = BTreeMap<String, String>;

#[derive(Clone, Copy)]
pub(super) enum EnvironmentScope {
    Workflow,
    Job,
    Step,
}
impl EnvironmentScope {
    const fn path(self) -> &'static str {
        match self {
            Self::Workflow => "env",
            Self::Job => "jobs.<id>.env",
            Self::Step => "jobs.<id>.steps[].env",
        }
    }
    const fn value_path(self) -> &'static str {
        match self {
            Self::Workflow => "env.<name>",
            Self::Job => "jobs.<id>.env.<name>",
            Self::Step => "jobs.<id>.steps[].env.<name>",
        }
    }
    const fn entries_limit(self) -> &'static str {
        match self {
            Self::Step => "step environment entries",
            Self::Workflow | Self::Job => "environment entries",
        }
    }
    const fn bytes_limit(self) -> &'static str {
        match self {
            Self::Step => "step environment bytes",
            Self::Workflow | Self::Job => "environment bytes",
        }
    }
}

/// Validated literal environment and workspace-relative directory. A context
/// cannot be mutated after validation or accidentally evaluated as shell text.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StepContext {
    environment: BTreeMap<String, String>,
    working_directory: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContextRefusal {
    Entries,
    Name,
    DuplicateName,
    ReservedName,
    Value,
    Bytes,
    WorkingDirectory,
}
impl ContextRefusal {
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Entries => "at most 64 explicit step environment entries",
            Self::Name => "a 1..64-byte ASCII environment identifier",
            Self::DuplicateName => "unique explicit environment names",
            Self::ReservedName => {
                "a nonreserved environment name; loader, shell startup and runner identity variables are refused"
            }
            Self::Value => {
                "a literal environment value of at most 8192 bytes without NUL or workflow expressions"
            }
            Self::Bytes => "at most 65536 aggregate step environment bytes",
            Self::WorkingDirectory => {
                "a workspace-relative directory without parent traversal, controls, backslashes or expressions"
            }
        }
    }
}
impl std::fmt::Display for ContextRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.description())
    }
}
impl std::error::Error for ContextRefusal {}

impl StepContext {
    pub fn new(
        environment: Vec<(String, String)>,
        working_directory: Option<String>,
    ) -> Result<Self, ContextRefusal> {
        if environment.len() > MAX_ENVIRONMENT_ENTRIES {
            return Err(ContextRefusal::Entries);
        }
        let mut bytes = 0usize;
        let mut selected = BTreeMap::new();
        for (key, value) in environment {
            validate_entry(&key, &value)?;
            bytes = bytes
                .checked_add(key.len())
                .and_then(|n| n.checked_add(value.len()))
                .filter(|n| *n <= MAX_ENVIRONMENT_BYTES)
                .ok_or(ContextRefusal::Bytes)?;
            if selected.insert(key, value).is_some() {
                return Err(ContextRefusal::DuplicateName);
            }
        }
        let working_directory = working_directory
            .map(|value| normalize_directory(&value))
            .transpose()?
            .flatten();
        Ok(Self {
            environment: selected,
            working_directory,
        })
    }
    #[must_use]
    pub const fn environment(&self) -> &BTreeMap<String, String> {
        &self.environment
    }
    #[must_use]
    pub fn working_directory(&self) -> Option<&str> {
        self.working_directory.as_deref()
    }
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.environment.is_empty() && self.working_directory.is_none()
    }
}
fn validate_entry(key: &str, value: &str) -> Result<(), ContextRefusal> {
    let mut chars = key.bytes();
    if key.len() > 64
        || !chars
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        || !chars.all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(ContextRefusal::Name);
    }
    if key.starts_with("LD_")
        || key.starts_with("DYLD_")
        || key.starts_with("FGIT_")
        || key.starts_with("GITHUB_")
        || key.starts_with("RUNNER_")
        || matches!(
            key,
            "BASH_ENV" | "ENV" | "SHELLOPTS" | "BASHOPTS" | "IFS" | "CDPATH"
        )
    {
        return Err(ContextRefusal::ReservedName);
    }
    if value.len() > MAX_ENVIRONMENT_VALUE_BYTES || value.contains('\0') || value.contains("${{") {
        return Err(ContextRefusal::Value);
    }
    Ok(())
}
fn normalize_directory(value: &str) -> Result<Option<String>, ContextRefusal> {
    if value.is_empty()
        || value.len() > MAX_WORKING_DIRECTORY_BYTES
        || value.starts_with('/')
        || value.contains(['\\', ':'])
        || value.chars().any(char::is_control)
        || value.contains("${{")
    {
        return Err(ContextRefusal::WorkingDirectory);
    }
    let path = value.strip_prefix("./").unwrap_or(value);
    if path.is_empty() || path == "." {
        return Ok(None);
    }
    if path
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(ContextRefusal::WorkingDirectory);
    }
    Ok(Some(path.to_owned()))
}

/// Validate one source map before any child can override it. In particular,
/// merging first must not hide reserved names, expressions or oversized values.
pub(super) fn lower_environment(
    node: &Node,
    scope: EnvironmentScope,
) -> Result<Environment, WorkflowRefusal> {
    let mut environment = Environment::new();
    if let Some(env) = node.get("env") {
        let Node::Mapping { entries, .. } = env else {
            return Err(WorkflowRefusal::FieldShape {
                path: scope.path(),
                expected: "a mapping of literal values",
                observed: env.shape(),
                span: env.span(),
            });
        };
        if entries.len() > MAX_ENVIRONMENT_ENTRIES {
            return Err(WorkflowRefusal::LimitExceeded {
                limit: scope.entries_limit(),
                allowed: MAX_ENVIRONMENT_ENTRIES,
                observed: entries.len(),
                span: env.span(),
            });
        }
        let mut bytes = 0usize;
        for (name, value, span) in entries {
            let Node::Scalar { value: text, .. } = value else {
                return Err(WorkflowRefusal::FieldShape {
                    path: scope.value_path(),
                    expected: "a literal scalar",
                    observed: value.shape(),
                    span: value.span(),
                });
            };
            validate_entry(name, text).map_err(|error| invalid(error, *span))?;
            bytes = bytes.saturating_add(name.len()).saturating_add(text.len());
            if bytes > MAX_ENVIRONMENT_BYTES {
                return Err(WorkflowRefusal::LimitExceeded {
                    limit: scope.bytes_limit(),
                    allowed: MAX_ENVIRONMENT_BYTES,
                    observed: bytes,
                    span: *span,
                });
            }
            if environment.insert(name.clone(), text.clone()).is_some() {
                return Err(invalid(ContextRefusal::DuplicateName, *span));
            }
        }
    }
    Ok(environment)
}

/// The same conservative entry allowance as the source-node expansion budget.
/// This charges newly copied inherited strings and map entries before copying.
pub(super) fn allocation_bytes(environment: &Environment) -> usize {
    environment
        .iter()
        .map(|(name, value)| name.len().saturating_add(value.len()).saturating_add(128))
        .fold(0, usize::saturating_add)
}

pub(super) fn inherit_environment(
    inherited: &Environment,
    mut explicit: Environment,
    expanded_bytes: &mut usize,
    span: Span,
) -> Result<Environment, WorkflowRefusal> {
    let mut entries = explicit.len();
    let mut bytes = explicit
        .iter()
        .map(|(name, value)| name.len().saturating_add(value.len()))
        .fold(0, usize::saturating_add);
    let mut copied_bytes = 0usize;
    for (name, value) in inherited {
        if explicit.contains_key(name) {
            continue;
        }
        entries = entries.saturating_add(1);
        bytes = bytes.saturating_add(name.len()).saturating_add(value.len());
        copied_bytes = copied_bytes
            .saturating_add(name.len())
            .saturating_add(value.len())
            .saturating_add(128);
    }
    for (limit, allowed, observed) in [
        (
            "effective environment entries",
            MAX_ENVIRONMENT_ENTRIES,
            entries,
        ),
        ("effective environment bytes", MAX_ENVIRONMENT_BYTES, bytes),
    ] {
        if observed > allowed {
            return Err(WorkflowRefusal::LimitExceeded {
                limit,
                allowed,
                observed,
                span,
            });
        }
    }
    super::matrix::charge_allocation(expanded_bytes, copied_bytes, span)?;
    for (name, value) in inherited {
        if !explicit.contains_key(name) {
            explicit.insert(name.clone(), value.clone());
        }
    }
    Ok(explicit)
}

pub(super) fn lower(
    node: &Node,
    inherited: &Environment,
    expanded_bytes: &mut usize,
) -> Result<StepContext, WorkflowRefusal> {
    let explicit = lower_environment(node, EnvironmentScope::Step)?;
    let environment = inherit_environment(inherited, explicit, expanded_bytes, node.span())?;
    let working_directory = if let Some(cwd) = node.get("working-directory") {
        let Node::Scalar { value, .. } = cwd else {
            return Err(WorkflowRefusal::FieldShape {
                path: "jobs.<id>.steps[].working-directory",
                expected: "a relative path scalar",
                observed: cwd.shape(),
                span: cwd.span(),
            });
        };
        normalize_directory(value).map_err(|error| invalid(error, cwd.span()))?
    } else {
        None
    };
    Ok(StepContext {
        environment,
        working_directory,
    })
}
const fn invalid(error: ContextRefusal, span: Span) -> WorkflowRefusal {
    WorkflowRefusal::Malformed {
        expected: error.description(),
        span,
    }
}
