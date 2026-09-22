//! Bounded native tag reports. Bodies and reference names are original bytes;
//! a displayed signature is explicitly not a cryptographic verification.

use super::super::super::Status;
use super::super::super::issues::{ApiError, Reply, quote};
use super::request::{Inspection, Operation};
use crate::OneNode;
use fgit_admission::AdmissionResult;
use fgit_authority::{ExpectedOld, ProposedNew, RefCommand, TerminalOutcome};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::tags::{TagRead, TagSignatureState};
use fgit_types::{DecisionOutcome, PrincipalId, TxId};

pub(super) const MAX_REPLY_BYTES: usize = 12 * 1024 * 1024;

struct Json<'a, C> {
    text: String,
    maximum: usize,
    live: &'a mut C,
}
impl<C: FnMut() -> bool> Json<'_, C> {
    fn reserve(&mut self, length: usize) -> Result<(), ApiError> {
        if !(self.live)() {
            return Err(ApiError::from_status(Status::Timeout, false));
        }
        let end = self
            .text
            .len()
            .checked_add(length)
            .filter(|end| *end <= self.maximum)
            .ok_or_else(ApiError::too_large)?;
        if end > self.text.capacity() {
            let capacity = end
                .max(self.text.capacity().saturating_mul(2))
                .min(self.maximum);
            self.text
                .try_reserve_exact(capacity - self.text.len())
                .map_err(|_| ApiError::unavailable())?;
        }
        Ok(())
    }
    fn put(&mut self, value: &str) -> Result<(), ApiError> {
        self.reserve(value.len())?;
        self.text.push_str(value);
        Ok(())
    }
    fn hex(&mut self, bytes: &[u8]) -> Result<(), ApiError> {
        self.reserve(
            bytes
                .len()
                .checked_mul(2)
                .and_then(|count| count.checked_add(2))
                .ok_or_else(ApiError::too_large)?,
        )?;
        self.text.push('"');
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for chunk in bytes.chunks(16 * 1024) {
            if !(self.live)() {
                return Err(ApiError::from_status(Status::Timeout, false));
            }
            for byte in chunk {
                self.text.push(char::from(HEX[usize::from(byte >> 4)]));
                self.text.push(char::from(HEX[usize::from(byte & 15)]));
            }
        }
        self.text.push('"');
        Ok(())
    }
}
fn metadata(node: &OneNode) -> String {
    format!(
        concat!(
            "\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},",
            "\"repository_incarnation\":{},\"object_format\":{}"
        ),
        quote(&node.tenant_id.to_string()),
        quote(&node.repository_id.to_string()),
        quote(&node.repository_incarnation_id().to_string()),
        quote(node.object_format.as_str())
    )
}

pub(super) fn inspection(
    node: &OneNode,
    query: &Inspection,
    report: &TagRead,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<String, ApiError> {
    if report.reference != query.reference
        || query.expected_head.is_some_and(|head| head != report.head)
        || query
            .expected_object
            .is_some_and(|object| object != report.tip)
        || report.annotations.len() > query.limits.max_tags
        || report.peeled_kind == GitObjectKind::Tag
        || [report.tip, report.peeled]
            .iter()
            .any(|id| id.is_zero() || id.algorithm() != node.object_format)
    {
        return Err(ApiError::unavailable());
    }
    let internal = report.head.as_internal_object_id();
    let digest: String = internal
        .digest()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let token = format!("alg:{}:{digest}", internal.algorithm().code_point());
    let mut out = Json {
        text: String::new(),
        maximum: maximum.min(MAX_REPLY_BYTES),
        live,
    };
    out.put(&format!(
        concat!(
            "{{\"type\":\"source_tag\",{},\"source_head\":{},\"snapshot_token\":{},",
            "\"read_only\":true,\"transaction_created\":false,\"published\":false,",
            "\"signature_verified\":false,\"tagger_is_authenticated_principal\":false,\"ref_hex\":"
        ),
        metadata(node),
        quote(&report.head.to_string()),
        quote(&token)
    ))?;
    out.hex(report.reference.as_bytes())?;
    out.put(&format!(",\"object_id\":{},\"peeled_object\":{},\"peeled_kind\":{},\"annotation_count\":{},\"annotations\":[",
        quote(&report.tip.to_string()), quote(&report.peeled.to_string()),
        quote(report.peeled_kind.label()), report.annotations.len()))?;
    let mut expected = report.tip;
    let mut total_bytes = 0usize;
    for (index, annotation) in report.annotations.iter().enumerate() {
        out.reserve(0)?;
        total_bytes = total_bytes
            .checked_add(annotation.body.len())
            .filter(|total| *total <= query.limits.max_total_bytes)
            .ok_or_else(ApiError::unavailable)?;
        let following_kind = if index + 1 == report.annotations.len() {
            report.peeled_kind
        } else {
            GitObjectKind::Tag
        };
        if annotation.id != expected
            || annotation.target.is_zero()
            || annotation.target.algorithm() != node.object_format
            || annotation.target_kind != following_kind
            || annotation.body.len() > query.limits.max_object_bytes
            || git_object_id(node.object_format, GitObjectKind::Tag, &annotation.body)
                != annotation.id
        {
            return Err(ApiError::unavailable());
        }
        expected = annotation.target;
        let signature = match annotation.signature {
            TagSignatureState::Absent => "absent",
            TagSignatureState::OpaqueUnverifiable => "opaque_unverifiable",
        };
        out.put(&format!(
            concat!(
                "{}{{\"object_id\":{},\"target\":{},\"target_kind\":{},",
                "\"signature\":{},\"signature_verified\":false,\"body_bytes\":{},\"body_hex\":"
            ),
            if index == 0 { "" } else { "," },
            quote(&annotation.id.to_string()),
            quote(&annotation.target.to_string()),
            quote(annotation.target_kind.label()),
            quote(signature),
            annotation.body.len()
        ))?;
        out.hex(&annotation.body)?;
        out.put("}")?;
    }
    if expected != report.peeled {
        return Err(ApiError::unavailable());
    }
    out.put("]}")?;
    Ok(out.text)
}

fn terminal(result: &AdmissionResult) -> Result<(TxId, TerminalOutcome), ApiError> {
    let [tx] = result.session.tx_ids.as_slice() else {
        return Err(ApiError::unknown());
    };
    let [command] = result.commands.as_slice() else {
        return Err(ApiError::unknown());
    };
    if !result.session.atomic || command.tx_id != *tx {
        return Err(ApiError::unknown());
    }
    Ok((*tx, command.terminal))
}

pub(super) fn publication(
    node: &OneNode,
    principal: PrincipalId,
    operation: Operation,
    command: &RefCommand,
    result: &AdmissionResult,
    maximum: usize,
) -> Result<Reply, ApiError> {
    let (tx, terminal) = terminal(result)?;
    let build = || -> Result<String, ApiError> {
        let old = match command.expected_old {
            ExpectedOld::Absent => "null".into(),
            ExpectedOld::Exactly(id) => quote(&id.to_string()),
            ExpectedOld::Unspecified => return Err(ApiError::unknown()),
        };
        let new = match command.proposed_new {
            ProposedNew::Update(id) => quote(&id.to_string()),
            ProposedNew::Delete => "null".into(),
        };
        let decision = match terminal.outcome {
            DecisionOutcome::Committed {
                repository_commit_id,
            } => format!(
                "\"outcome\":\"committed\",\"repository_commit_id\":{}",
                quote(&repository_commit_id.to_string())
            ),
            DecisionOutcome::Refused {
                code,
                refusal_record_id,
            } => format!(
                "\"outcome\":\"refused\",\"code\":{},\"code_point\":{},\"refusal_record_id\":{}",
                quote(&format!("{code:?}")),
                code.code_point(),
                quote(&refusal_record_id.to_string())
            ),
        };
        // A canonical terminal result must survive post-admission cancellation.
        // Response limits still fail, but the failure means a lost receipt.
        let mut live = || true;
        let mut out = Json {
            text: String::new(),
            maximum: maximum.min(64 * 1024),
            live: &mut live,
        };
        out.put(&format!(concat!("{{\"type\":\"tag_publication\",{},\"principal_id\":{},\"operation\":{},",
            "\"atomic\":true,\"terminal\":true,\"tx_id\":{},\"decision_sequence\":{},",
            "{},\"expected_object\":{},\"new_object\":{},\"force\":false,\"forge_transition\":false,",
            "\"signature_verified\":false,\"tagger_is_authenticated_principal\":false,\"ref_hex\":"),
            metadata(node), quote(&principal.to_string()), quote(operation.as_str()), quote(&tx.to_string()),
            terminal.decision_sequence.get(), decision, old, new))?;
        out.hex(command.name.as_bytes())?;
        out.put("}")?;
        Ok(out.text)
    };
    let body = build().map_err(|_| {
        eprintln!("Tag HTTP receipt unavailable after canonical transaction {tx}; recover the original key");
        ApiError::unknown()
    })?;
    Ok(Reply {
        status: match terminal.outcome {
            DecisionOutcome::Committed { .. } => Status::Success,
            DecisionOutcome::Refused { .. } => Status::Conflict,
        },
        body,
        terminal: Some((tx, terminal)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hex_is_lossless_and_size_failure_precedes_growth() {
        let mut live = || true;
        let mut out = Json {
            text: String::new(),
            maximum: 32,
            live: &mut live,
        };
        out.hex(b"\xff\r\n<script>").unwrap();
        assert_eq!(out.text, "\"ff0d0a3c7363726970743e\"");
        let prior = out.text.clone();
        assert!(out.hex(b"too many bytes").is_err());
        assert_eq!(out.text, prior);
    }
    #[test]
    fn cancellation_can_interrupt_large_annotation_encoding() {
        let mut calls = 0;
        let mut live = || {
            calls += 1;
            calls < 3
        };
        let mut out = Json {
            text: String::new(),
            maximum: 100_000,
            live: &mut live,
        };
        assert!(out.hex(&vec![0xff; 32_000]).is_err());
    }
    #[test]
    fn empty_or_non_atomic_receipts_cannot_claim_tag_publication() {
        let result = AdmissionResult {
            session: fgit_admission::SessionMapping {
                atomic: false,
                tx_ids: Vec::new(),
            },
            commands: Vec::new(),
        };
        assert!(terminal(&result).unwrap_err().outcome_unknown);
    }
}
