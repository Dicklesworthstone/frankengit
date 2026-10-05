//! Exact-coordinate HTTP adapter for the native fast-forward-only PR engine.
//! The existing driver owns the seal, ancestry, protection and atomic RCR.
//! This route stages no objects and never substitutes another merge method.

use std::collections::BTreeMap;
use std::io::Read;

use fgit_admission::merge::native::NativeMergeIntent;
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_forge::{AggregateVersion, PullRequestNumber};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, PrincipalId, RefName, TxId};
use fgit_wire::smart_http::{BodyFraming, HttpLimits, head::Envelope};

use super::super::issues::{
    ApiError, Reply, admission_error, parse_decimal, parse_form, quote, read_form, ref_fields,
};
use super::super::{Profile, Status, bearer_only, retry_key};
use crate::smart_http::drive_request_while;
use crate::{
    GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession, OneNode,
};

const MAX_COMMAND_BYTES: usize = 8 * 1024;

#[derive(Debug)]
pub(super) struct Request<'a> {
    repository_route: &'a str,
    number: PullRequestNumber,
}

#[derive(Debug)]
struct Command {
    version: AggregateVersion,
    source_ref: RefName,
    source_tip: GitOid,
    target_ref: RefName,
    target_tip: GitOid,
}

impl<'a> Request<'a> {
    pub(super) fn parse(head: &Envelope<'a>) -> Result<Option<Self>, ApiError> {
        let (path, query) = head
            .target
            .split_once('?')
            .map_or((head.target, None), |(path, query)| (path, Some(query)));
        let Some((repository_route, suffix)) = path.split_once("/api/v1/pulls/") else {
            return Ok(None);
        };
        let Some((number, "fast-forward")) = suffix.split_once('/') else {
            return Ok(None);
        };
        if repository_route.len() < 2
            || !repository_route.starts_with('/')
            || repository_route[1..].split('/').any(|part| {
                part.is_empty()
                    || matches!(part, "." | "..")
                    || !part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte))
            })
        {
            return Err(ApiError::not_found());
        }
        let number = PullRequestNumber::try_new(parse_decimal(number)?)
            .ok_or_else(|| ApiError::bad("invalid_pull_request_number"))?;
        if head.method != "POST" {
            return Err(ApiError::method());
        }
        if head.git_protocol.is_some() {
            return Err(ApiError::bad("git_protocol_not_applicable"));
        }
        if query.is_some()
            || matches!(head.body, BodyFraming::Empty | BodyFraming::ContentLength(0))
        {
            return Err(ApiError::bad("invalid_mutation_envelope"));
        }
        let media = head.content_type.ok_or_else(ApiError::media)?;
        if !media.eq_ignore_ascii_case("application/x-www-form-urlencoded")
            && !media.eq_ignore_ascii_case("application/x-www-form-urlencoded; charset=utf-8")
        {
            return Err(ApiError::media());
        }
        if matches!(head.body, BodyFraming::ContentLength(n) if n > MAX_COMMAND_BYTES as u64) {
            return Err(ApiError::too_large());
        }
        Ok(Some(Self {
            repository_route,
            number,
        }))
    }

    fn command(&self, bytes: &[u8], format: GitHashAlgorithm) -> Result<Command, ApiError> {
        if bytes.len() > MAX_COMMAND_BYTES {
            return Err(ApiError::too_large());
        }
        let mut fields = BTreeMap::new();
        for (name, value) in parse_form(bytes, 6)? {
            if !matches!(
                name.as_str(),
                "object_format"
                    | "pull_request_version"
                    | "source_ref"
                    | "source_tip"
                    | "target_ref"
                    | "target_tip"
            ) {
                return Err(ApiError::bad("unknown_or_inapplicable_field"));
            }
            if fields.insert(name, value).is_some() {
                return Err(ApiError::bad("duplicate_field"));
            }
        }
        if take(&mut fields, "object_format")? != format.as_str() {
            return Err(ApiError::bad("object_format_mismatch"));
        }
        let version =
            AggregateVersion::try_new(parse_decimal(&take(&mut fields, "pull_request_version")?)?)
                .ok_or_else(|| ApiError::bad("invalid_pull_request_version"))?;
        version
            .next()
            .map_err(|_| ApiError::bad("version_exhausted"))?;
        let command = Command {
            version,
            source_ref: RefName::try_new(take(&mut fields, "source_ref")?.as_bytes())
                .map_err(|_| ApiError::bad("invalid_ref"))?,
            source_tip: oid(&take(&mut fields, "source_tip")?, format)?,
            target_ref: RefName::try_new(take(&mut fields, "target_ref")?.as_bytes())
                .map_err(|_| ApiError::bad("invalid_ref"))?,
            target_tip: oid(&take(&mut fields, "target_tip")?, format)?,
        };
        // Pure validation using the engine's own vocabulary, not a new seal.
        NativeMergeIntent::fast_forward_only(
            self.number,
            command.version,
            command.source_ref.clone(),
            command.source_tip,
            command.target_ref.clone(),
            command.target_tip,
        )
        .map_err(|_| ApiError::bad("invalid_fast_forward_command"))?;
        Ok(command)
    }
}

fn take(fields: &mut BTreeMap<String, String>, name: &'static str) -> Result<String, ApiError> {
    fields
        .remove(name)
        .ok_or_else(|| ApiError::bad("required_field_missing"))
}

fn oid(text: &str, format: GitHashAlgorithm) -> Result<GitOid, ApiError> {
    if text.len() != format.digest_len() * 2
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApiError::bad("invalid_object_id"));
    }
    let value = GitOid::from_hex(format, text).map_err(|_| ApiError::bad("invalid_object_id"))?;
    if value.is_zero() {
        return Err(ApiError::bad("invalid_object_id"));
    }
    Ok(value)
}

pub(super) fn authenticate(
    request: &Request<'_>,
    envelope: &Envelope<'_>,
    raw_head: &[u8],
    profile: &Profile,
) -> Result<LoopbackReceiveSession, ApiError> {
    let grant = profile
        .credentials
        .authenticate(bearer_only(envelope.authorization()))
        .map_err(|error| ApiError::from_status(Status::from(error), false))?;
    if request.repository_route.as_bytes() != profile.route {
        return Err(ApiError::not_found());
    }
    // Reuse the code-publication grant, not the weaker metadata-write grant.
    // Current canonical branch protection remains the native driver's job.
    if !profile.allow_pulls || !grant.permits_reviewed_merge() {
        return Err(ApiError::new(Status::Forbidden, "forbidden"));
    }
    let key = retry_key(raw_head)
        .map_err(|_| ApiError::bad("invalid_idempotency_key"))?
        .ok_or_else(|| ApiError::bad("idempotency_key_required"))?;
    Ok(LoopbackReceiveSession::authenticated(
        grant.principal,
        IdempotencyKey::new(key.to_vec()).map_err(|_| ApiError::bad("invalid_idempotency_key"))?,
    ))
}

fn ingress_limits(limits: HttpLimits) -> HttpLimits {
    HttpLimits {
        max_body_bytes: limits.max_body_bytes.min(MAX_COMMAND_BYTES as u64),
        max_body_wire_bytes: limits.max_body_wire_bytes.min(2 * MAX_COMMAND_BYTES as u64),
        max_chunks: limits.max_chunks.min(1024),
        ..limits
    }
}

pub(super) fn execute(
    node: &OneNode,
    request: &Request<'_>,
    session: &LoopbackReceiveSession,
    framing: BodyFraming,
    reader: &mut impl Read,
    limits: HttpLimits,
    maximum_response: u64,
) -> Result<Reply, ApiError> {
    let principal = session
        .authenticated_session()
        .ok_or_else(|| ApiError::new(Status::Unauthorized, "unauthorized"))?
        .principal_id();
    let bytes = read_form(reader, framing, ingress_limits(limits))?;
    let command = request.command(&bytes, node.object_format)?;
    let deadline = GitDaemonSessionDeadline::new(
        node.git_daemon_session_timeout,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let context = node.session_request_context(&deadline);
    let mut live = || !deadline.expired();
    let (tx, terminal) = drive_request_while(
        node,
        &context,
        node.fast_forward_pull_request_durable_in(
            &context,
            session,
            request.number,
            command.version,
            &command.source_ref,
            command.source_tip,
            &command.target_ref,
            command.target_tip,
            Default::default(),
            Default::default(),
        ),
        &mut live,
    )
    .map_err(admission_error)?;
    // Known terminal evidence wins over cancellation or subsequently moved refs.
    // Never re-read current metadata to render a historical retry receipt.
    let body = receipt(node, request.number, principal, &command, tx, terminal);
    if body.len() as u64 > maximum_response.min(64 * 1024) {
        eprintln!(
            "Fast-forward HTTP reply exceeds limit after canonical outcome for transaction {tx}; recover the original key"
        );
        return Err(ApiError::unknown());
    }
    Ok(Reply {
        status: match terminal.outcome {
            DecisionOutcome::Committed { .. } => Status::Success,
            DecisionOutcome::Refused { .. } => Status::Conflict,
        },
        body,
        terminal: Some((tx, terminal)),
    })
}

fn receipt(
    node: &OneNode,
    number: PullRequestNumber,
    principal: PrincipalId,
    command: &Command,
    tx: TxId,
    terminal: TerminalOutcome,
) -> String {
    let (outcome, commit, refusal, code, code_point) = match terminal.outcome {
        DecisionOutcome::Committed {
            repository_commit_id,
        } => (
            "committed",
            quote(&repository_commit_id.to_string()),
            "null".to_owned(),
            "null".to_owned(),
            "null".to_owned(),
        ),
        DecisionOutcome::Refused {
            code,
            refusal_record_id,
        } => (
            "refused",
            "null".to_owned(),
            quote(&refusal_record_id.to_string()),
            quote(&format!("{code:?}")),
            code.code_point().to_string(),
        ),
    };
    format!(
        concat!(
            "{{\"type\":\"fast_forward_merge_publication\",\"schema_version\":1,",
            "\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},",
            "\"object_format\":{},\"principal_id\":{},\"action\":\"fast-forward\",",
            "\"number\":{},\"pull_request_version\":{},{},{},",
            "\"source_tip\":{},\"target_tip\":{},\"tx_id\":{},\"outcome\":{},",
            "\"decision_sequence\":{},\"repository_commit_id\":{},\"refusal_record_id\":{},",
            "\"refusal_code\":{},\"refusal_code_point\":{},\"delivery_acknowledged\":null}}"
        ),
        quote(&node.tenant_id.to_string()),
        quote(&node.repository_id.to_string()),
        quote(&node.repository_incarnation_id().to_string()),
        quote(node.object_format.as_str()),
        quote(&principal.to_string()),
        number.get(),
        command.version.get(),
        ref_fields("source_ref", &command.source_ref),
        ref_fields("target_ref", &command.target_ref),
        quote(&command.source_tip.to_string()),
        quote(&command.target_tip.to_string()),
        quote(&tx.to_string()),
        quote(outcome),
        terminal.decision_sequence.get(),
        commit,
        refusal,
        code,
        code_point
    )
}

#[cfg(test)]
mod tests;
