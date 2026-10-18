//! Bounded static Cartesian products, then exclusions and ordered inclusions.
use super::{Variables, invalid, limit};
use crate::workflow::{Node, Span, WorkflowRefusal, registry};
use std::collections::{BTreeMap, BTreeSet};

const MAX_AXES: usize = 8;
const MAX_AXIS_VALUES: usize = 64;
const MAX_COMBINATIONS: usize = 256;
const MAX_RECORDS: usize = 64;
const MAX_VARIABLES: usize = 16;
const MAX_VALUE_BYTES: usize = 1024;

pub(super) fn select(strategy: &Node) -> Result<Vec<Variables>, WorkflowRefusal> {
    let Node::Mapping { entries, .. } = strategy else {
        return Err(WorkflowRefusal::ConstructUnsupported {
            construct: "job.strategy",
            reason: registry::reason_for("job.strategy"),
            span: strategy.span(),
        });
    };
    unique(entries)?;
    for (key, _, span) in entries {
        if !matches!(key.as_str(), "matrix" | "fail-fast") {
            return Err(WorkflowRefusal::FieldUnknown {
                key: key.clone().into(),
                parent: "static matrix strategy",
                span: *span,
            });
        }
    }
    if !matches!(strategy.get("fail-fast"), Some(Node::Scalar { value, .. }) if value == "false") {
        return Err(invalid(
            "static matrices require explicit fail-fast: false",
            strategy.span(),
        ));
    }
    let matrix = strategy
        .get("matrix")
        .ok_or_else(|| invalid("a static matrix mapping", strategy.span()))?;
    let Node::Mapping { entries, .. } = matrix else {
        return Err(invalid(
            "a static matrix mapping, not an expression",
            matrix.span(),
        ));
    };
    unique(entries)?;
    let mut axes = BTreeMap::new();
    for (key, values, span) in entries {
        if matches!(key.as_str(), "include" | "exclude") {
            continue;
        }
        name(key, *span)?;
        limit("matrix axes", MAX_AXES, axes.len() + 1, *span)?;
        let Node::Sequence { items, .. } = values else {
            return Err(invalid(
                "a nonempty block sequence of literal matrix values",
                values.span(),
            ));
        };
        limit(
            "matrix axis values",
            MAX_AXIS_VALUES,
            items.len(),
            values.span(),
        )?;
        if items.is_empty() {
            return Err(invalid("a nonempty matrix axis", values.span()));
        }
        let mut unique_values = BTreeSet::new();
        let mut selected = Vec::new();
        for item in items {
            let value = literal(item)?;
            if !unique_values.insert(value.to_owned()) {
                return Err(invalid(
                    "distinct values within each matrix axis",
                    item.span(),
                ));
            }
            selected.push(value.to_owned());
        }
        axes.insert(key.clone(), selected);
    }
    let includes = records(matrix.get("include"))?;
    let excludes = records(matrix.get("exclude"))?;
    for excluded in &excludes {
        if excluded.keys().any(|key| !axes.contains_key(key)) {
            return Err(invalid(
                "exclusions naming only declared matrix axes",
                matrix.span(),
            ));
        }
    }
    let mut product = usize::from(!axes.is_empty());
    for values in axes.values() {
        product = product
            .checked_mul(values.len())
            .ok_or_else(|| invalid("a bounded matrix product", matrix.span()))?;
        limit(
            "matrix Cartesian combinations",
            MAX_COMBINATIONS,
            product,
            matrix.span(),
        )?;
    }
    let mut rows = if axes.is_empty() {
        Vec::new()
    } else {
        vec![Variables::new()]
    };
    for (key, values) in &axes {
        let mut next = Vec::with_capacity(rows.len() * values.len());
        for row in rows {
            for value in values {
                let mut variant = row.clone();
                variant.insert(key.clone(), value.clone());
                next.push(variant);
            }
        }
        rows = next;
    }
    rows.retain(|row| {
        !excludes
            .iter()
            .any(|exclude| exclude.iter().all(|(k, v)| row.get(k) == Some(v)))
    });
    // Only surviving original combinations participate in include merging.
    // Appended include-only rows never become a new merge target.
    let originals = rows.len();
    for include in includes {
        let mut merged = false;
        for row in &mut rows[..originals] {
            if include
                .iter()
                .all(|(key, value)| !axes.contains_key(key) || row.get(key) == Some(value))
            {
                let added = include.keys().filter(|key| !row.contains_key(*key)).count();
                limit(
                    "matrix variables",
                    MAX_VARIABLES,
                    row.len() + added,
                    matrix.span(),
                )?;
                row.extend(include.clone());
                merged = true;
            }
        }
        if !merged {
            limit(
                "matrix selected combinations",
                MAX_COMBINATIONS,
                rows.len() + 1,
                matrix.span(),
            )?;
            rows.push(include);
        }
    }
    if rows.is_empty() {
        return Err(invalid(
            "at least one selected matrix combination",
            matrix.span(),
        ));
    }
    let mut seen = BTreeSet::new();
    for row in &rows {
        if !seen.insert(row) {
            return Err(invalid(
                "distinct selected matrix combinations",
                matrix.span(),
            ));
        }
    }
    Ok(rows)
}

fn records(node: Option<&Node>) -> Result<Vec<Variables>, WorkflowRefusal> {
    let Some(node) = node else {
        return Ok(Vec::new());
    };
    let Node::Sequence { items, .. } = node else {
        return Err(invalid(
            "a block sequence of literal matrix records",
            node.span(),
        ));
    };
    limit(
        "matrix include/exclude records",
        MAX_RECORDS,
        items.len(),
        node.span(),
    )?;
    let mut records = Vec::new();
    for item in items {
        let Node::Mapping { entries, .. } = item else {
            return Err(invalid("a literal matrix record", item.span()));
        };
        unique(entries)?;
        if entries.is_empty() {
            return Err(invalid("a nonempty matrix record", item.span()));
        }
        limit(
            "matrix variables",
            MAX_VARIABLES,
            entries.len(),
            item.span(),
        )?;
        let mut record = Variables::new();
        for (key, value, span) in entries {
            name(key, *span)?;
            record.insert(key.clone(), literal(value)?.to_owned());
        }
        records.push(record);
    }
    Ok(records)
}
fn name(key: &str, span: Span) -> Result<(), WorkflowRefusal> {
    let mut bytes = key.bytes();
    if key.len() > 64
        || !bytes
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        || !bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return Err(invalid("a bounded ASCII matrix variable name", span));
    }
    Ok(())
}
fn literal(node: &Node) -> Result<&str, WorkflowRefusal> {
    match node {
        Node::Scalar { value, span } => {
            limit("matrix value bytes", MAX_VALUE_BYTES, value.len(), *span)?;
            if value.contains('\0') || value.contains("${{") {
                return Err(invalid(
                    "literal matrix values without NUL or expressions",
                    *span,
                ));
            }
            Ok(value)
        }
        _ => Err(invalid("a literal matrix scalar", node.span())),
    }
}
fn unique(entries: &[(String, Node, Span)]) -> Result<(), WorkflowRefusal> {
    let mut seen = BTreeSet::new();
    for (key, _, span) in entries {
        if !seen.insert(key) {
            return Err(WorkflowRefusal::DuplicateKey {
                key: key.clone().into(),
                span: *span,
            });
        }
    }
    Ok(())
}
