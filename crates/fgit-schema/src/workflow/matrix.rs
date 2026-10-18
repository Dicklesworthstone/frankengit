//! Static matrix lowering into the existing native job DAG, not a new scheduler.
use super::{Job, Node, Span, WorkflowRefusal, graph};
use std::collections::{BTreeMap, BTreeSet};
mod context;
mod selection;

type Variables = BTreeMap<String, String>;
pub const MAX_EXPANDED_JOBS: usize = 128;
pub const MAX_EXPANDED_STEPS: usize = 512;
pub const MAX_EXPANDED_EDGES: usize = 8192;
pub const MAX_EXPANDED_BYTES: usize = 8 * 1024 * 1024;

/// Exact origin and values for one expanded job. Values carry no authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatrixBinding {
    source_job: String,
    values: Variables,
}
impl MatrixBinding {
    pub fn source_job(&self) -> &str {
        &self.source_job
    }
    pub fn values(&self) -> &BTreeMap<String, String> {
        &self.values
    }
}

pub(super) fn lower_jobs(
    entries: &[(String, Node, Span)],
    span: Span,
) -> Result<Vec<Job>, WorkflowRefusal> {
    // Keep all original acceptance and canonical bytes for context-free inputs.
    if !entries
        .iter()
        .any(|(_, node, _)| node.get("strategy").is_some())
    {
        return entries
            .iter()
            .map(|(id, node, span)| graph::lower_job(id, node, *span))
            .collect();
    }
    let mut sources = BTreeSet::new();
    let mut plans = Vec::new();
    let mut groups = BTreeMap::new();
    let (mut job_count, mut step_count, mut bytes) = (0usize, 0usize, 0usize);
    for (id, node, key_span) in entries {
        if !sources.insert(id.as_str()) {
            return Err(WorkflowRefusal::DuplicateKey {
                key: id.clone().into(),
                span: *key_span,
            });
        }
        let rows = node.get("strategy").map(selection::select).transpose()?;
        if rows.is_some()
            && (id.is_empty()
                || id.len() > 128
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')))
        {
            return Err(invalid(
                "a 1..128-byte ASCII matrix job identifier",
                *key_span,
            ));
        }
        let count = rows.as_ref().map_or(1, Vec::len);
        job_count += count;
        limit(
            "expanded workflow jobs",
            MAX_EXPANDED_JOBS,
            job_count,
            *key_span,
        )?;
        let steps = match node.get("steps") {
            Some(Node::Sequence { items, .. }) => items.len(),
            _ => 0,
        };
        step_count = step_count.saturating_add(steps.saturating_mul(count));
        limit(
            "expanded workflow steps",
            MAX_EXPANDED_STEPS,
            step_count,
            *key_span,
        )?;
        let cost = node_cost(node).saturating_add(id.len()).saturating_add(128);
        if let Some(rows) = &rows {
            for row in rows {
                let replacement = row.values().map(String::len).max().unwrap_or(0);
                let growth = expression_count(node).saturating_mul(replacement);
                let binding = row
                    .iter()
                    .map(|(k, v)| k.len() + v.len() + 128)
                    .sum::<usize>();
                bytes = bytes.saturating_add(cost.saturating_add(growth).saturating_add(binding));
            }
        } else {
            bytes = bytes.saturating_add(cost);
        }
        limit(
            "expanded workflow allocation bytes",
            MAX_EXPANDED_BYTES,
            bytes,
            *key_span,
        )?;
        let ids = if rows.is_some() {
            (0..count).map(|n| format!("{id}__matrix_{n:03}")).collect()
        } else {
            vec![id.clone()]
        };
        groups.insert(id.clone(), ids);
        plans.push(rows);
    }
    let mut identities = BTreeSet::new();
    for (source, ids) in &groups {
        for id in ids {
            if !identities.insert(id) || (id != source && sources.contains(id.as_str())) {
                return Err(invalid(
                    "matrix-generated job identities disjoint from source job names",
                    span,
                ));
            }
        }
    }
    let mut jobs = Vec::with_capacity(job_count);
    for ((id, node, key_span), rows) in entries.iter().zip(plans) {
        if let Some(rows) = rows {
            for (index, values) in rows.into_iter().enumerate() {
                let mut selected = node.clone();
                if let Node::Mapping { entries, .. } = &mut selected {
                    entries.retain(|(key, _, _)| key != "strategy");
                }
                context::resolve(&mut selected, &values)?;
                let mut job = graph::lower_job(&groups[id][index], &selected, *key_span)?;
                job.matrix = Some(MatrixBinding {
                    source_job: id.clone(),
                    values,
                });
                jobs.push(job);
            }
        } else {
            jobs.push(graph::lower_job(id, node, *key_span)?);
        }
    }
    // Dependency names address declared job groups, never fabricated variants.
    let mut edge_count = 0usize;
    for job in &mut jobs {
        let mut needed = Vec::new();
        for need in &job.needs {
            let ids = groups
                .get(need)
                .ok_or_else(|| WorkflowRefusal::NeedsUnknown {
                    job: job.id.clone().into(),
                    needs: need.clone().into(),
                    span: job.span,
                })?;
            edge_count = edge_count.saturating_add(ids.len());
            limit(
                "expanded workflow dependency edges",
                MAX_EXPANDED_EDGES,
                edge_count,
                job.span,
            )?;
            bytes = bytes.saturating_add(ids.iter().map(|id| id.len() + 128).sum::<usize>());
            limit(
                "expanded workflow allocation bytes",
                MAX_EXPANDED_BYTES,
                bytes,
                job.span,
            )?;
            needed.extend(ids.iter().cloned());
        }
        needed.sort();
        needed.dedup();
        job.needs = needed;
    }
    Ok(jobs)
}

fn invalid(expected: &'static str, span: Span) -> WorkflowRefusal {
    WorkflowRefusal::Malformed { expected, span }
}
fn limit(
    name: &'static str,
    allowed: usize,
    observed: usize,
    span: Span,
) -> Result<(), WorkflowRefusal> {
    if observed > allowed {
        Err(WorkflowRefusal::LimitExceeded {
            limit: name,
            allowed,
            observed,
            span,
        })
    } else {
        Ok(())
    }
}
fn node_cost(node: &Node) -> usize {
    let bytes = match node {
        Node::Scalar { value, .. } => value.len(),
        Node::Mapping { entries, .. } => entries
            .iter()
            .map(|(k, v, _)| k.len().saturating_add(node_cost(v)))
            .fold(0usize, usize::saturating_add),
        Node::Sequence { items, .. } => items
            .iter()
            .map(node_cost)
            .fold(0usize, usize::saturating_add),
    };
    bytes.saturating_add(128)
}
fn expression_count(node: &Node) -> usize {
    match node {
        Node::Scalar { value, .. } => usize::from(value.contains("${{")),
        Node::Mapping { entries, .. } => entries.iter().map(|(_, v, _)| expression_count(v)).sum(),
        Node::Sequence { items, .. } => items.iter().map(expression_count).sum(),
    }
}
