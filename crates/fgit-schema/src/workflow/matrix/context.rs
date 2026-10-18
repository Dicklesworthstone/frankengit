//! Resolve only whole-value matrix lookups in step environment and directory.
//! In particular, no matrix data is ever interpolated into executable scripts.
use super::{Variables, invalid};
use crate::workflow::{Node, WorkflowRefusal};

pub(super) fn resolve(job: &mut Node, variables: &Variables) -> Result<(), WorkflowRefusal> {
    let Some(Node::Sequence { items, .. }) = field(job, "steps") else {
        return Ok(());
    };
    for step in items {
        if let Some(Node::Mapping { entries, .. }) = field(step, "env") {
            for (_, value, _) in entries {
                scalar(value, variables)?;
            }
        }
        if let Some(directory) = field(step, "working-directory") {
            scalar(directory, variables)?;
        }
    }
    Ok(())
}
fn field<'a>(node: &'a mut Node, name: &str) -> Option<&'a mut Node> {
    match node {
        Node::Mapping { entries, .. } => entries
            .iter_mut()
            .find(|(k, _, _)| k == name)
            .map(|(_, value, _)| value),
        _ => None,
    }
}
fn scalar(node: &mut Node, variables: &Variables) -> Result<(), WorkflowRefusal> {
    let Node::Scalar { value, span } = node else {
        return Ok(());
    };
    if !value.contains("${{") {
        return Ok(());
    }
    let token = value
        .trim()
        .strip_prefix("${{")
        .and_then(|s| s.strip_suffix("}}"))
        .map(str::trim)
        .and_then(|s| s.strip_prefix("matrix."))
        .ok_or_else(|| {
            invalid(
                "one whole-value matrix lookup, without interpolation or other expressions",
                *span,
            )
        })?;
    let literal = variables.get(token).ok_or_else(|| {
        invalid(
            "a matrix variable present in every selected combination",
            *span,
        )
    })?;
    *value = literal.clone();
    Ok(())
}
