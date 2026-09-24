//! Atomic bundle import/fetch through native quarantine and sealed admission.
//! No current-ref pre-read may change the submitted absence/old-tip leases.

use super::super::super::{
    Status,
    issues::{ApiError, Reply as JsonReply, admission_error, parse_form, quote},
    pulls::{SourceUploadKind, read_source_upload, source_upload},
};
use super::super::Reply;
use super::{Operation, Request, checkpoint, hex};
use crate::smart_http::drive_request_while;
use crate::{
    GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession,
    NodeWorkspaceRefusal, OneNode,
};
use fgit_admission::{AdmissionLimits, AdmissionResult};
use fgit_crypto::sha256_digest;
use fgit_pack::full_bundle::{
    FullBundleError, FullBundleInput, FullBundleLimits, fetch::BundleRefMapping,
};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, PrincipalId, RefName};
use fgit_wire::smart_http::{BodyFraming, HttpLimits};
use std::collections::BTreeSet;
use std::io::Read;

const MAX_MAPPINGS: usize = 64;

fn ref_hex(text: &str) -> Result<RefName, ApiError> {
    if text.is_empty()
        || text.len() > 8192
        || !text.len().is_multiple_of(2)
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApiError::bad("invalid_bundle_ref_hex"));
    }
    let digit = |byte: u8| {
        if byte <= b'9' {
            byte - b'0'
        } else {
            byte - b'a' + 10
        }
    };
    let bytes: Vec<_> = text
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| (digit(pair[0]) << 4) | digit(pair[1]))
        .collect();
    let name = RefName::try_new(&bytes).map_err(|_| ApiError::bad("invalid_bundle_ref"))?;
    if !name.as_bytes().starts_with(b"refs/") {
        return Err(ApiError::bad("full_bundle_ref_required"));
    }
    Ok(name)
}
fn mapping(text: &str, format: GitHashAlgorithm) -> Result<BundleRefMapping, ApiError> {
    let mut fields = text.split(':');
    let source = ref_hex(
        fields
            .next()
            .ok_or_else(|| ApiError::bad("invalid_bundle_mapping"))?,
    )?;
    let destination = ref_hex(
        fields
            .next()
            .ok_or_else(|| ApiError::bad("invalid_bundle_mapping"))?,
    )?;
    let old = fields
        .next()
        .ok_or_else(|| ApiError::bad("explicit_bundle_lease_required"))?;
    if fields.next().is_some() {
        return Err(ApiError::bad("invalid_bundle_mapping"));
    }
    let expected_old = if old == "absent" {
        None
    } else {
        if old.len() != format.digest_len() * 2
            || !old
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ApiError::bad("invalid_bundle_old_tip"));
        }
        let id =
            GitOid::from_hex(format, old).map_err(|_| ApiError::bad("invalid_bundle_old_tip"))?;
        if id.is_zero() {
            return Err(ApiError::bad("use_explicit_absent_lease"));
        }
        Some(id)
    };
    Ok(BundleRefMapping {
        source,
        destination,
        expected_old,
    })
}

fn command(
    bytes: &[u8],
    format: GitHashAlgorithm,
    operation: Operation,
    payload: &[u8],
    live: &mut impl FnMut() -> bool,
) -> Result<Vec<BundleRefMapping>, ApiError> {
    let (mut object_format, mut digest) = (None, None);
    let mut mappings = Vec::new();
    let mut destinations = BTreeSet::new();
    for (name, value) in parse_form(bytes, MAX_MAPPINGS + 2)? {
        checkpoint(live)?;
        match name.as_str() {
            "object_format" if object_format.is_none() => object_format = Some(value),
            "artifact_sha256" if digest.is_none() => digest = Some(value),
            "mapping" if operation == Operation::Fetch => {
                if mappings.len() == MAX_MAPPINGS {
                    return Err(ApiError::too_large());
                }
                let item = mapping(&value, format)?;
                if !destinations.insert(item.destination.clone()) {
                    return Err(ApiError::bad("duplicate_bundle_destination"));
                }
                mappings.push(item);
            }
            _ => return Err(ApiError::bad("unknown_or_duplicate_bundle_field")),
        }
    }
    if object_format.as_deref() != Some(format.as_str()) {
        return Err(ApiError::bad("object_format_mismatch"));
    }
    if operation == Operation::Fetch && mappings.is_empty() {
        return Err(ApiError::bad("bundle_mapping_required"));
    }
    let digest = digest.ok_or_else(|| ApiError::bad("artifact_sha256_required"))?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApiError::bad("invalid_artifact_sha256"));
    }
    checkpoint(live)?;
    let actual = hex(&sha256_digest(payload));
    checkpoint(live)?;
    if actual != digest {
        return Err(ApiError::bad("bundle_artifact_mismatch"));
    }
    // Artifact encoding/digest is transport evidence, not transaction identity.
    // Native admission derives the same seal for equivalent ref semantics.
    Ok(mappings)
}

pub(super) fn execute(
    node: &OneNode,
    request: &Request<'_>,
    session: &LoopbackReceiveSession,
    framing: BodyFraming,
    reader: &mut impl Read,
    http: HttpLimits,
    maximum_response: u64,
) -> Result<Reply, ApiError> {
    let principal = session
        .authenticated_session()
        .ok_or_else(|| ApiError::new(Status::Unauthorized, "unauthorized"))?
        .principal_id();
    let boundary = request.boundary.ok_or_else(ApiError::media)?;
    // Reuse the only source-upload HTTP/MIME parser, including exact terminal
    // framing, suffix refusal, field limits and bounded binary preservation.
    let bytes = read_source_upload(reader, framing, http, SourceUploadKind::Bundle)?;
    let context = node.request_context();
    let deadline = GitDaemonSessionDeadline::new(
        node.git_daemon_session_timeout,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let mut live = || !deadline.expired();
    let (form, payload) = source_upload(&bytes, boundary, SourceUploadKind::Bundle, &mut live)?;
    let mappings = command(
        form,
        node.object_format,
        request.operation,
        payload,
        &mut live,
    )?;
    let limits = FullBundleLimits::default();
    let header = FullBundleInput::parse(payload, limits, &mut live).map_err(envelope_error)?;
    if header.format() != node.object_format {
        return Err(ApiError::bad("object_format_mismatch"));
    }
    let count = match request.operation {
        Operation::Import => header.references().len(),
        Operation::Fetch => header
            .select_updates(&mappings, limits, &mut live)
            .map_err(envelope_error)?
            .len(),
        Operation::Export => return Err(ApiError::bad("invalid_bundle_operation")),
    };
    drop(header);
    let admission = AdmissionLimits::default();
    if count > admission.max_commands {
        return Err(ApiError::too_large());
    }
    let result = match request.operation {
        Operation::Import => drive_request_while(
            node,
            &context,
            node.import_full_git_bundle_durable_in(&context, session, payload, admission),
            &mut live,
        ),
        Operation::Fetch => drive_request_while(
            node,
            &context,
            node.fetch_full_git_bundle_durable_in(&context, session, payload, &mappings, admission),
            &mut live,
        ),
        Operation::Export => return Err(ApiError::bad("invalid_bundle_operation")),
    }
    .map_err(publication_error)?;
    // A returned canonical terminal outcome wins over later cancellation.
    receipt(
        node,
        principal,
        request.operation,
        count,
        result,
        maximum_response,
    )
    .map(Reply::json)
}

fn envelope_error(error: FullBundleError) -> ApiError {
    match error {
        FullBundleError::Limit(_) => ApiError::too_large(),
        FullBundleError::Invalid(_)
        | FullBundleError::Unsupported(_)
        | FullBundleError::FormatMismatch => ApiError::bad("invalid_or_unsupported_full_bundle"),
        FullBundleError::Pack(fgit_pack::PackError::DeadlineExceeded) => {
            ApiError::from_status(Status::Timeout, false)
        }
        _ => ApiError::unavailable(),
    }
}
fn publication_error(error: NodeWorkspaceRefusal) -> ApiError {
    match error {
        NodeWorkspaceRefusal::WorkspacePublication(error) => admission_error(*error),
        NodeWorkspaceRefusal::ObjectFormatMismatch => ApiError::bad("object_format_mismatch"),
        NodeWorkspaceRefusal::RefUnavailable => ApiError::not_found(),
        // These native envelope errors occur before sealing; don't reflect
        // their diagnostics or internal object identities back to the client.
        NodeWorkspaceRefusal::FullBundle(error) => match *error {
            error @ (FullBundleError::Invalid(_)
            | FullBundleError::Unsupported(_)
            | FullBundleError::FormatMismatch
            | FullBundleError::Limit(_)) => envelope_error(error),
            _ => ApiError::unknown(),
        },
        // Store/runner interruption never establishes a terminal non-commit.
        _ => ApiError::unknown(),
    }
}

fn receipt(
    node: &OneNode,
    principal: PrincipalId,
    operation: Operation,
    count: usize,
    result: AdmissionResult,
    maximum: u64,
) -> Result<JsonReply, ApiError> {
    let first = result.commands.first().ok_or_else(ApiError::unknown)?;
    if !result.session.atomic
        || result.session.tx_ids.as_slice() != [first.tx_id]
        || result.commands.len() != count
        || result.commands.iter().any(|command| command != first)
    {
        return Err(ApiError::unknown());
    }
    let terminal = first.terminal;
    let (status, outcome, decision) = match terminal.outcome {
        DecisionOutcome::Committed {
            repository_commit_id,
        } => (
            Status::Success,
            "committed",
            format!(
                "{{\"repository_commit_id\":{}}}",
                quote(&repository_commit_id.to_string())
            ),
        ),
        DecisionOutcome::Refused {
            code,
            refusal_record_id,
        } => (
            Status::Conflict,
            "refused",
            format!(
                "{{\"code\":{},\"code_point\":{},\"refusal_record_id\":{}}}",
                quote(&format!("{code:?}")),
                code.code_point(),
                quote(&refusal_record_id.to_string())
            ),
        ),
    };
    let operation = match operation {
        Operation::Import => "import",
        Operation::Fetch => "fetch",
        Operation::Export => return Err(ApiError::unknown()),
    };
    let body = format!(
        concat!(
            "{{\"type\":\"source_bundle_publication\",\"schema_version\":1,",
            "\"operation\":{},\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},",
            "\"object_format\":{},\"principal_id\":{},\"tx_id\":{},\"decision_sequence\":{},",
            "\"command_count\":{},\"outcome\":{},\"decision\":{},\"atomic\":true,\"terminal\":true,",
            "\"forge_state_imported\":false,\"default_branch_changed\":false,",
            "\"receipt_confirms_transport_revalidation\":false}}"
        ),
        quote(operation),
        quote(&node.tenant_id.to_string()),
        quote(&node.repository_id.to_string()),
        quote(&node.repository_incarnation_id().to_string()),
        quote(node.object_format.as_str()),
        quote(&principal.to_string()),
        quote(&first.tx_id.to_string()),
        terminal.decision_sequence.get(),
        count,
        quote(outcome),
        decision
    );
    if body.len() as u64 > maximum.min(1024 * 1024) {
        eprintln!(
            "Bundle receipt exceeded response limit after canonical transaction {}; recover the original key",
            first.tx_id
        );
        return Err(ApiError::unknown());
    }
    Ok(JsonReply {
        status,
        body,
        terminal: Some((first.tx_id, terminal)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn form(payload: &[u8], format: GitHashAlgorithm) -> String {
        format!(
            "object_format={}&artifact_sha256={}",
            format.as_str(),
            hex(&sha256_digest(payload))
        )
    }
    fn item(source: &str, dest: &str, old: &str) -> String {
        format!("{}:{}:{old}", hex(source.as_bytes()), hex(dest.as_bytes()))
    }
    #[test]
    fn imports_require_exact_artifact_bytes_and_never_accept_lease_or_actor_overrides() {
        let payload = b"exact\0\xffbundle bytes";
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let valid = form(payload, format);
            assert!(
                command(
                    valid.as_bytes(),
                    format,
                    Operation::Import,
                    payload,
                    &mut || true
                )
                .unwrap()
                .is_empty()
            );
            assert!(
                command(
                    valid.as_bytes(),
                    format,
                    Operation::Import,
                    b"changed",
                    &mut || true
                )
                .is_err()
            );
            assert!(
                command(
                    valid.as_bytes(),
                    format,
                    Operation::Import,
                    payload,
                    &mut || false
                )
                .is_err()
            );
            for extra in [
                "&force=true",
                "&expected_head=anything",
                "&principal=admin",
                "&artifact_sha256=00",
                "&mapping=x",
            ] {
                assert!(
                    command(
                        (valid.clone() + extra).as_bytes(),
                        format,
                        Operation::Import,
                        payload,
                        &mut || true
                    )
                    .is_err()
                );
            }
        }
        assert!(
            command(
                b"object_format=sha1",
                GitHashAlgorithm::Sha1,
                Operation::Import,
                payload,
                &mut || true
            )
            .is_err()
        );
    }
    #[test]
    fn fetch_maps_explicit_byte_refs_and_exact_native_leases_in_both_formats() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let id = "a".repeat(format.digest_len() * 2);
            let map = item("refs/heads/main", "refs/remotes/origin/main", &id);
            let value = form(b"bundle", format) + "&mapping=" + &map;
            let mappings = command(
                value.as_bytes(),
                format,
                Operation::Fetch,
                b"bundle",
                &mut || true,
            )
            .unwrap();
            assert_eq!(mappings.len(), 1);
            assert_eq!(mappings[0].expected_old.unwrap().to_string(), id);
            assert_eq!(mappings[0].source.as_bytes(), b"refs/heads/main");
            assert_eq!(
                mappings[0].destination.as_bytes(),
                b"refs/remotes/origin/main"
            );
            assert!(
                mapping(&item("refs/heads/main", "refs/heads/new", "absent"), format)
                    .unwrap()
                    .expected_old
                    .is_none()
            );
            let zero = "0".repeat(format.digest_len() * 2);
            for old in ["", "*", "0", zero.as_str(), "aaa"] {
                assert!(mapping(&item("refs/heads/main", "refs/heads/new", old), format).is_err());
            }
            assert!(
                command(
                    form(b"bundle", format).as_bytes(),
                    format,
                    Operation::Fetch,
                    b"bundle",
                    &mut || true
                )
                .is_err()
            );
            let duplicate = value + "&mapping=" + &map;
            assert!(
                command(
                    duplicate.as_bytes(),
                    format,
                    Operation::Fetch,
                    b"bundle",
                    &mut || true
                )
                .is_err()
            );
        }
    }
    #[test]
    fn fetch_mapping_count_paths_and_namespaces_are_bounded() {
        let mut form = form(b"bundle", GitHashAlgorithm::Sha1);
        for i in 0..MAX_MAPPINGS {
            form += &format!(
                "&mapping={}",
                item("refs/heads/main", &format!("refs/heads/d{i}"), "absent")
            );
        }
        assert_eq!(
            command(
                form.as_bytes(),
                GitHashAlgorithm::Sha1,
                Operation::Fetch,
                b"bundle",
                &mut || true
            )
            .unwrap()
            .len(),
            MAX_MAPPINGS
        );
        form += &format!(
            "&mapping={}",
            item("refs/heads/main", "refs/heads/extra", "absent")
        );
        assert!(
            command(
                form.as_bytes(),
                GitHashAlgorithm::Sha1,
                Operation::Fetch,
                b"bundle",
                &mut || true
            )
            .is_err()
        );
        for name in ["HEAD", "../main", "refs/heads/../secret", "refs/heads/a\0b"] {
            assert!(ref_hex(&hex(name.as_bytes())).is_err());
        }
        assert!(ref_hex(&"ab".repeat(4097)).is_err());
    }
    #[test]
    fn infrastructure_failure_after_intake_retains_uncertainty() {
        assert!(
            publication_error(NodeWorkspaceRefusal::Cancelled { exhaustion: None }).outcome_unknown
        );
        assert!(!publication_error(NodeWorkspaceRefusal::ObjectFormatMismatch).outcome_unknown);
        assert!(!envelope_error(FullBundleError::Unsupported("prerequisite")).outcome_unknown);
    }
}
