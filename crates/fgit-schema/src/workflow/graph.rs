//! The versioned workflow graph and the lowering that produces it.
//!
//! # Determinism is the acceptance
//!
//! *"Identical source/profile produces byte-identical graph and diagnostics
//! across runs/worker counts/claimed targets."* Everything here is ordered by
//! a rule rather than by arrival:
//!
//! * triggers are sorted and deduplicated, so `[push, pull_request]` and
//!   `[pull_request, push, push]` lower to the same bytes;
//! * `needs` is sorted within a job for the same reason;
//! * jobs are emitted in **topological order with a lexicographic tie-break**,
//!   so two jobs that could run in either order always appear in one;
//! * steps keep source order, because for steps the order IS the meaning.
//!
//! Nothing iterates a map. [`CANONICAL_VERSION`] is stamped into the canonical
//! bytes so a future change to any of these rules is a visible version bump
//! rather than a silent reordering of everyone's goldens.

use crate::workflow::WorkflowRefusal;
use crate::workflow::registry;
use crate::workflow::yaml::{Node, Span};

/// Version of the canonical byte form.
///
/// Bump this when an ordering or normalization rule changes. A golden that
/// moves without this moving is a bug.
pub const CANONICAL_VERSION: &str = "fgit-workflow/v1";

/// One accepted trigger.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Trigger {
    /// Trigger name as written.
    pub name: String,
    /// Where it came from.
    pub span: Span,
}

/// One step of a job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    /// Display name, absent when the step declares none.
    pub name: Option<String>,
    /// The command line, preserved verbatim.
    pub run: String,
    /// Where the step came from.
    pub span: Span,
}

/// One job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    /// Job identifier, unique within the workflow.
    pub id: String,
    /// Runner label.
    pub runs_on: String,
    /// Job identifiers this job depends on, sorted.
    pub needs: Vec<String>,
    /// Steps in source order, which is execution order.
    pub steps: Vec<Step>,
    /// Where the job came from.
    pub span: Span,
}

/// A lowered workflow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkflowGraph {
    /// Display name.
    pub name: String,
    /// Triggers, sorted and deduplicated.
    pub triggers: Vec<Trigger>,
    /// Jobs in topological order with a lexicographic tie-break.
    pub jobs: Vec<Job>,
    /// Span of the whole document.
    pub span: Span,
}

/// Escapes a field for the canonical byte form.
///
/// Tab and newline are the field and record separators, so a value containing
/// one has to be escaped or a crafted `run:` could forge a record. Backslash is
/// escaped first, otherwise `\t` in the source and an escaped tab would decode
/// to the same bytes.
fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\n', "\\n")
}

impl WorkflowGraph {
    /// The canonical byte form: one record per line, tab-separated fields.
    ///
    /// This is the normative identity of the graph. It is deliberately a flat
    /// text table rather than a nested encoding: a reviewer can read a diff of
    /// it, and every ordering rule the module doc states is visible in the
    /// output rather than implied by it.
    #[must_use]
    pub fn canonical_bytes(&self) -> String {
        let mut lines = vec![CANONICAL_VERSION.to_owned()];
        lines.push(format!("name\t{}", escape(&self.name)));
        for trigger in &self.triggers {
            lines.push(format!("trigger\t{}", escape(&trigger.name)));
        }
        for job in &self.jobs {
            lines.push(format!(
                "job\t{}\t{}",
                escape(&job.id),
                escape(&job.runs_on)
            ));
            for need in &job.needs {
                lines.push(format!("need\t{}\t{}", escape(&job.id), escape(need)));
            }
            for (index, step) in job.steps.iter().enumerate() {
                lines.push(format!(
                    "step\t{}\t{index}\t{}\t{}",
                    escape(&job.id),
                    escape(step.name.as_deref().unwrap_or("")),
                    escape(&step.run)
                ));
            }
        }
        lines.join("\n") + "\n"
    }

    /// Job identifiers in emitted order.
    #[must_use]
    pub fn job_ids(&self) -> Vec<&str> {
        self.jobs.iter().map(|job| job.id.as_str()).collect()
    }
}

/// Refuses a construct that the registry marks unsupported or ambiguous.
fn refuse_construct(key: &'static str, span: Span) -> WorkflowRefusal {
    WorkflowRefusal::ConstructUnsupported {
        construct: key,
        reason: registry::reason_for(key),
        span,
    }
}

/// The scalar value of a node, or a shape refusal naming what was found.
fn expect_scalar<'a>(node: &'a Node, path: &'static str) -> Result<&'a str, WorkflowRefusal> {
    match node {
        Node::Scalar { value, .. } => Ok(value),
        other @ (Node::Mapping { .. } | Node::Sequence { .. }) => {
            Err(WorkflowRefusal::FieldShape {
                path,
                expected: "a scalar",
                observed: other.shape(),
                span: other.span(),
            })
        }
    }
}

/// A scalar or a sequence of scalars, as a list. The two spellings are the
/// normalization the registry promises for `workflow.on` and `job.needs`.
fn scalar_or_sequence(
    node: &Node,
    path: &'static str,
) -> Result<Vec<(String, Span)>, WorkflowRefusal> {
    match node {
        Node::Scalar { value, span } => Ok(vec![(value.clone(), *span)]),
        Node::Sequence { items, .. } => items
            .iter()
            .map(|item| expect_scalar(item, path).map(|value| (value.to_owned(), item.span())))
            .collect(),
        other @ Node::Mapping { .. } => Err(WorkflowRefusal::FieldShape {
            path,
            expected: "a scalar or a sequence of scalars",
            observed: other.shape(),
            span: other.span(),
        }),
    }
}

/// Checks every key of a mapping against an accepted set and the registry.
///
/// Three outcomes, and the middle one is why this is not a simple allow-list:
/// an accepted key passes, a key the registry knows and refuses produces the
/// registry's own reason, and anything else is [`WorkflowRefusal::FieldUnknown`].
/// An unrecognised key is never ignored — that would be the silent drop the
/// acceptance forbids.
fn check_keys(
    node: &Node,
    parent: &'static str,
    accepted: &[&str],
    known: &[(&str, &'static str)],
) -> Result<(), WorkflowRefusal> {
    let Node::Mapping { entries, .. } = node else {
        return Ok(());
    };
    for (key, _, span) in entries {
        if accepted.contains(&key.as_str()) {
            continue;
        }
        if let Some((_, construct)) = known.iter().find(|(name, _)| name == key) {
            return Err(refuse_construct(construct, *span));
        }
        return Err(WorkflowRefusal::FieldUnknown {
            key: key.clone().into(),
            parent,
            span: *span,
        });
    }
    Ok(())
}

/// Lowers one step.
fn lower_step(node: &Node) -> Result<Step, WorkflowRefusal> {
    check_keys(
        node,
        "a step",
        &["name", "run"],
        &[
            ("uses", "step.uses"),
            ("with", "step.with"),
            ("if", "step.if"),
        ],
    )?;
    let Node::Mapping { .. } = node else {
        return Err(WorkflowRefusal::FieldShape {
            path: "jobs.<id>.steps[]",
            expected: "a mapping",
            observed: node.shape(),
            span: node.span(),
        });
    };
    let run = node
        .get("run")
        .ok_or_else(|| WorkflowRefusal::FieldMissing {
            path: "jobs.<id>.steps[].run",
            span: node.span(),
        })
        .and_then(|value| expect_scalar(value, "jobs.<id>.steps[].run"))?
        .to_owned();
    let name = match node.get("name") {
        Some(value) => Some(expect_scalar(value, "jobs.<id>.steps[].name")?.to_owned()),
        None => None,
    };
    Ok(Step {
        name,
        run,
        span: node.span(),
    })
}

/// Lowers one job.
fn lower_job(id: &str, node: &Node, span: Span) -> Result<Job, WorkflowRefusal> {
    check_keys(
        node,
        "a job",
        &["runs-on", "needs", "steps"],
        &[
            ("strategy", "job.strategy"),
            ("permissions", "job.permissions"),
            ("environment", "job.environment"),
            ("services", "job.services"),
            ("container", "job.container"),
            ("if", "job.if"),
            ("outputs", "job.outputs"),
            ("timeout-minutes", "job.timeout-minutes"),
            ("continue-on-error", "job.continue-on-error"),
        ],
    )?;
    let runs_on = node
        .get("runs-on")
        .ok_or(WorkflowRefusal::FieldMissing {
            path: "jobs.<id>.runs-on",
            span,
        })
        .and_then(|value| expect_scalar(value, "jobs.<id>.runs-on"))?
        .to_owned();

    let mut needs: Vec<String> = match node.get("needs") {
        Some(value) => scalar_or_sequence(value, "jobs.<id>.needs")?
            .into_iter()
            .map(|(name, _)| name)
            .collect(),
        None => Vec::new(),
    };
    // Sorted and deduplicated: `needs: [a, b]` and `needs: [b, a, a]` express
    // the same dependency set and must produce the same bytes.
    needs.sort();
    needs.dedup();

    let steps_node = node.get("steps").ok_or(WorkflowRefusal::FieldMissing {
        path: "jobs.<id>.steps",
        span,
    })?;
    let Node::Sequence { items, .. } = steps_node else {
        return Err(WorkflowRefusal::FieldShape {
            path: "jobs.<id>.steps",
            expected: "a sequence",
            observed: steps_node.shape(),
            span: steps_node.span(),
        });
    };
    let steps = items
        .iter()
        .map(lower_step)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Job {
        id: id.to_owned(),
        runs_on,
        needs,
        steps,
        span,
    })
}

/// Orders jobs topologically, breaking ties lexicographically.
///
/// Kahn's algorithm with the ready set kept sorted. The tie-break is the whole
/// point: without it two jobs with no dependency between them appear in
/// whichever order the input happened to list them, and the canonical bytes
/// stop being canonical.
fn topological_order(jobs: Vec<Job>, span: Span) -> Result<Vec<Job>, WorkflowRefusal> {
    let names: Vec<String> = jobs.iter().map(|job| job.id.clone()).collect();
    for job in &jobs {
        for need in &job.needs {
            if !names.contains(need) {
                return Err(WorkflowRefusal::NeedsUnknown {
                    job: job.id.clone().into(),
                    needs: need.clone().into(),
                    span: job.span,
                });
            }
        }
    }

    let mut remaining: Vec<Job> = jobs;
    let mut emitted: Vec<Job> = Vec::with_capacity(remaining.len());
    let mut done: Vec<String> = Vec::new();
    while !remaining.is_empty() {
        // Every job whose dependencies are already emitted, in name order.
        let mut ready: Vec<usize> = remaining
            .iter()
            .enumerate()
            .filter(|(_, job)| job.needs.iter().all(|need| done.contains(need)))
            .map(|(index, _)| index)
            .collect();
        ready.sort_by(|left, right| remaining[*left].id.cmp(&remaining[*right].id));

        let Some(&next) = ready.first() else {
            // Nothing is ready and jobs remain, so the rest form at least one
            // cycle. Report it in name order so the diagnostic is stable.
            let mut cycle: Vec<Box<str>> =
                remaining.iter().map(|job| job.id.clone().into()).collect();
            cycle.sort();
            return Err(WorkflowRefusal::NeedsCycle { cycle, span });
        };
        let job = remaining.remove(next);
        done.push(job.id.clone());
        emitted.push(job);
    }
    Ok(emitted)
}

/// Lowers a scanned document into a workflow graph.
pub fn lower(document: &Node) -> Result<WorkflowGraph, WorkflowRefusal> {
    let span = document.span();
    check_keys(
        document,
        "a workflow",
        &["name", "on", "jobs"],
        &[
            ("env", "workflow.env"),
            ("concurrency", "workflow.concurrency"),
            ("permissions", "job.permissions"),
            ("secrets", "workflow.secrets"),
        ],
    )?;
    let Node::Mapping { .. } = document else {
        return Err(WorkflowRefusal::FieldShape {
            path: "<document>",
            expected: "a mapping",
            observed: document.shape(),
            span,
        });
    };

    let name = document
        .get("name")
        .ok_or(WorkflowRefusal::FieldMissing { path: "name", span })
        .and_then(|value| expect_scalar(value, "name"))?
        .to_owned();

    let on = document
        .get("on")
        .ok_or(WorkflowRefusal::FieldMissing { path: "on", span })?;
    let mut triggers: Vec<Trigger> = scalar_or_sequence(on, "on")?
        .into_iter()
        .map(|(name, span)| Trigger { name, span })
        .collect();
    // Sorted and deduplicated by name. The span kept is the first occurrence's,
    // which is the one an author would edit.
    triggers.sort_by(|left, right| left.name.cmp(&right.name));
    triggers.dedup_by(|left, right| left.name == right.name);

    let jobs_node = document
        .get("jobs")
        .ok_or(WorkflowRefusal::FieldMissing { path: "jobs", span })?;
    let Node::Mapping { entries, .. } = jobs_node else {
        return Err(WorkflowRefusal::FieldShape {
            path: "jobs",
            expected: "a mapping of job identifier to job",
            observed: jobs_node.shape(),
            span: jobs_node.span(),
        });
    };
    let jobs = entries
        .iter()
        .map(|(id, node, key_span)| lower_job(id, node, *key_span))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(WorkflowGraph {
        name,
        triggers,
        jobs: topological_order(jobs, span)?,
        span,
    })
}
