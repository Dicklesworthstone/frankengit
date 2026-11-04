use super::*;
use fgit_admission::AdmissionResult;
use fgit_authority::{ExpectedOld, ProposedNew, RefCommand, TerminalOutcome};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::tags::{TagRead, TagSignatureState};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, TxId};
use std::collections::BTreeSet;

fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), ToolError> {
    if live() {
        Ok(())
    } else {
        Err(ToolError::failed("tag_read_cancelled"))
    }
}
fn invalid() -> ToolError {
    ToolError::failed("invalid_tag_report")
}
pub(super) fn bounded_inspection(fields: Object) -> Result<Value, ToolError> {
    let value = Value::Object(fields);
    value
        .encode(MAX_RESULT_BYTES)
        .map_err(|_| ToolError::failed("tag_result_limit"))?;
    Ok(value)
}
fn body_hex(bytes: &[u8], live: &mut impl FnMut() -> bool) -> Result<String, ToolError> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::new();
    result
        .try_reserve_exact(bytes.len().checked_mul(2).ok_or_else(invalid)?)
        .map_err(|_| ToolError::failed("allocation_refused"))?;
    for chunk in bytes.chunks(16 * 1024) {
        checkpoint(live)?;
        for byte in chunk {
            result.push(char::from(DIGITS[usize::from(byte >> 4)]));
            result.push(char::from(DIGITS[usize::from(byte & 15)]));
        }
    }
    Ok(result)
}

pub(super) fn inspection(
    format: GitHashAlgorithm,
    query: &input::Inspection,
    report: &TagRead,
    live: &mut impl FnMut() -> bool,
) -> Result<Object, ToolError> {
    checkpoint(live)?;
    if report.reference != query.reference
        || query.expected_head.is_some_and(|head| head != report.head)
        || query.expected_object.is_some_and(|id| id != report.tip)
        || report.annotations.len() > query.limits.max_tags
        || report.peeled_kind == GitObjectKind::Tag
        || [report.tip, report.peeled]
            .iter()
            .any(|id| id.is_zero() || id.algorithm() != format)
    {
        return Err(invalid());
    }
    let mut expected = report.tip;
    let mut seen = BTreeSet::new();
    let mut bytes = 0_usize;
    let mut annotations = Vec::new();
    for (index, row) in report.annotations.iter().enumerate() {
        checkpoint(live)?;
        bytes = bytes
            .checked_add(row.body.len())
            .filter(|total| *total <= query.limits.max_total_bytes)
            .ok_or_else(invalid)?;
        let next_kind = if index + 1 == report.annotations.len() {
            report.peeled_kind
        } else {
            GitObjectKind::Tag
        };
        if row.id != expected
            || !seen.insert(row.id)
            || row.target.is_zero()
            || row.target.algorithm() != format
            || row.target_kind != next_kind
            || row.body.len() > query.limits.max_object_bytes
            || git_object_id(format, GitObjectKind::Tag, &row.body) != row.id
        {
            return Err(invalid());
        }
        expected = row.target;
        annotations.push(object([
            ("object_id", text(row.id.to_string())),
            ("target", text(row.target.to_string())),
            ("target_kind", text(row.target_kind.label())),
            (
                "signature",
                text(match row.signature {
                    TagSignatureState::Absent => "absent",
                    TagSignatureState::OpaqueUnverifiable => "opaque_unverifiable",
                }),
            ),
            ("signature_verified", Value::Bool(false)),
            ("body_bytes", text(row.body.len().to_string())),
            ("body_hex", text(body_hex(&row.body, live)?)),
        ]));
    }
    if expected != report.peeled || seen.contains(&report.peeled) {
        return Err(invalid());
    }
    checkpoint(live)?;
    let Value::Object(result) = object([
        ("type", text("source_tag")),
        ("schema_version", json::number(1)),
        ("source_head", text(report.head.to_string())),
        ("reference_hex", text(hex(report.reference.as_bytes()))),
        ("object_id", text(report.tip.to_string())),
        ("peeled_object", text(report.peeled.to_string())),
        ("peeled_kind", text(report.peeled_kind.label())),
        (
            "annotation_count",
            text(report.annotations.len().to_string()),
        ),
        ("annotations", Value::Array(annotations)),
        ("complete", Value::Bool(true)),
        ("repository_changed", Value::Bool(false)),
        ("transaction_created", Value::Bool(false)),
        ("published", Value::Bool(false)),
        ("signature_verified", Value::Bool(false)),
        ("tagger_is_authenticated_principal", Value::Bool(false)),
    ]) else {
        unreachable!()
    };
    Ok(result)
}

pub(super) fn terminal(result: &AdmissionResult) -> Result<(TxId, TerminalOutcome), ToolError> {
    let [tx] = result.session.tx_ids.as_slice() else {
        return Err(ToolError::uncertain("inconsistent_tag_outcome"));
    };
    let [command] = result.commands.as_slice() else {
        return Err(ToolError::uncertain("inconsistent_tag_outcome"));
    };
    if !result.session.atomic || command.tx_id != *tx {
        return Err(ToolError::uncertain("inconsistent_tag_outcome"));
    }
    Ok((*tx, command.terminal))
}

pub(super) fn publication(
    name: &str,
    command: &RefCommand,
    admitted: &AdmissionResult,
) -> Result<Object, ToolError> {
    let (tx, outcome) = terminal(admitted)?;
    let old = match command.expected_old {
        ExpectedOld::Absent if matches!(name, CREATE | ANNOTATE) => Value::Null,
        ExpectedOld::Exactly(id) if name == DELETE => text(id.to_string()),
        _ => return Err(ToolError::uncertain("inconsistent_tag_outcome")),
    };
    let new = match command.proposed_new {
        ProposedNew::Update(id) if matches!(name, CREATE | ANNOTATE) => text(id.to_string()),
        ProposedNew::Delete if name == DELETE => Value::Null,
        _ => return Err(ToolError::uncertain("inconsistent_tag_outcome")),
    };
    if command.force {
        return Err(ToolError::uncertain("inconsistent_tag_outcome"));
    }
    let mut result = mutations::terminal(tx, &outcome);
    let Value::Object(fields) = object([
        ("type", text("tag_publication")),
        (
            "operation",
            text(match name {
                CREATE => "lightweight",
                ANNOTATE => "annotated",
                _ => "delete",
            }),
        ),
        ("reference_hex", text(hex(command.name.as_bytes()))),
        ("expected_object", old),
        ("new_object", new),
        ("force", Value::Bool(false)),
        ("atomic", Value::Bool(true)),
        ("complete", Value::Bool(true)),
        ("historical_outcome", Value::Bool(true)),
        ("current_refs_asserted", Value::Bool(false)),
        (
            "ref_transaction_committed",
            Value::Bool(matches!(outcome.outcome, DecisionOutcome::Committed { .. })),
        ),
        ("forge_transition", Value::Bool(false)),
        ("signature_verified", Value::Bool(false)),
        ("tagger_is_authenticated_principal", Value::Bool(false)),
    ]) else {
        unreachable!()
    };
    result.extend(fields);
    Ok(result)
}
