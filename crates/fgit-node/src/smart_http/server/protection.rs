//! Repository-scoped review-protection administration. Credentials select the
//! actor and independent gateway grants; the native policy driver authorizes
//! changes against the current administrator set and owns every terminal.
//! Remote bootstrap is deliberately excluded from this HTTP profile.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

use fgit_admission::merge::native::protection::ProtectionState;
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_forge::event::protection::{
    MAX_BRANCH_REVIEWERS, MAX_POLICY_ADMINISTRATORS, MAX_PROTECTED_BRANCHES, ProtectedBranch,
    ProtectionCommand, ReviewProtection,
};
use fgit_forge::{AggregateId, AggregateVersion, ExpectedVersion, ForgeEventPayload};
use fgit_types::{
    DecisionOutcome, MAX_REF_NAME_LEN, PolicyEpoch, PrincipalId, RefName,
    RepositoryAuthorityHeadId, TxId,
};
use fgit_wire::smart_http::{BodyFraming, HttpLimits, head::Envelope};

use super::super::drive_request_while;
use super::issues::{
    ApiError, Reply, admission_error, parse_decimal, parse_form, parse_snapshot, quote, read_form,
};
use super::{Profile, Status, retry_key};
use crate::{
    GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession, OneNode,
};

const ROUTE: &str = "/api/v1/protection";
const MAX_COMMAND_BYTES: usize = 256 * 1024;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_COMMAND_FIELDS: usize =
    3 + MAX_POLICY_ADMINISTRATORS + MAX_PROTECTED_BRANCHES * MAX_BRANCH_REVIEWERS;

/// Recognize the API family before a malformed suffix can fall through to Git.
pub(super) fn is_route(target: &str) -> bool {
    target
        .split_once('?')
        .map_or(target, |(path, _)| path)
        .contains(ROUTE)
}

#[derive(Debug)]
pub(super) struct Request<'a> {
    repository_route: &'a str,
    mutation: bool,
    expected_head: Option<RepositoryAuthorityHeadId>,
}

impl<'a> Request<'a> {
    pub(super) fn parse(envelope: &Envelope<'a>) -> Result<Self, ApiError> {
        let (path, query) = envelope
            .target
            .split_once('?')
            .map_or((envelope.target, None), |(path, query)| (path, Some(query)));
        let (repository_route, suffix) =
            path.rsplit_once(ROUTE).ok_or_else(ApiError::not_found)?;
        if !suffix.is_empty()
            || repository_route.len() < 2
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
        if envelope.git_protocol.is_some() {
            return Err(ApiError::bad("git_protocol_not_applicable"));
        }
        let (mutation, expected_head) = match envelope.method {
            "GET" => {
                if !matches!(
                    envelope.body,
                    BodyFraming::Empty | BodyFraming::ContentLength(0)
                ) || envelope.expect_continue
                {
                    return Err(ApiError::bad("body_not_allowed"));
                }
                let mut expected = None;
                for (name, value) in parse_form(query.unwrap_or("").as_bytes(), 2)? {
                    if name != "expected_head" {
                        return Err(ApiError::bad("unknown_query_field"));
                    }
                    set_once(&mut expected, parse_snapshot(&value)?)?;
                }
                (false, expected)
            }
            "POST" => {
                if query.is_some()
                    || matches!(
                        envelope.body,
                        BodyFraming::Empty | BodyFraming::ContentLength(0)
                    )
                {
                    return Err(ApiError::bad("invalid_mutation_envelope"));
                }
                if !envelope.content_type.is_some_and(|value| {
                    value.eq_ignore_ascii_case("application/x-www-form-urlencoded")
                        || value.eq_ignore_ascii_case(
                            "application/x-www-form-urlencoded; charset=utf-8",
                        )
                }) {
                    return Err(ApiError::media());
                }
                if matches!(
                    envelope.body,
                    BodyFraming::ContentLength(bytes) if bytes > MAX_COMMAND_BYTES as u64
                ) {
                    return Err(ApiError::too_large());
                }
                (true, None)
            }
            _ => return Err(ApiError::method()),
        };
        Ok(Self {
            repository_route,
            mutation,
            expected_head,
        })
    }

    pub(super) const fn is_mutation(&self) -> bool {
        self.mutation
    }
}

pub(super) fn authenticate(
    request: &Request<'_>,
    envelope: &Envelope<'_>,
    raw_head: &[u8],
    profile: &Profile,
) -> Result<LoopbackReceiveSession, ApiError> {
    let grant = profile
        .credentials
        .authenticate(super::bearer_only(envelope.authorization()))
        .map_err(|error| ApiError::from_status(Status::from(error), false))?;
    if request.repository_route.as_bytes() != profile.route {
        return Err(ApiError::not_found());
    }
    if !profile.config.http_protection_admin_enabled()
        || !grant.permits_protection(request.is_mutation())
    {
        return Err(ApiError::new(Status::Forbidden, "forbidden"));
    }
    let key = retry_key(raw_head).map_err(|_| ApiError::bad("invalid_idempotency_key"))?;
    let key = if request.is_mutation() {
        key.ok_or_else(|| ApiError::bad("idempotency_key_required"))?
    } else {
        if key.is_some() {
            return Err(ApiError::bad("idempotency_key_not_allowed"));
        }
        b"protection-read-no-publication".as_slice()
    };
    let key =
        IdempotencyKey::new(key.to_vec()).map_err(|_| ApiError::bad("invalid_idempotency_key"))?;
    Ok(LoopbackReceiveSession::authenticated(grant.principal, key))
}

/// The complete HTTP body precedes admission. Once native admission starts,
/// its terminal wins over local deadlines and connection failures.
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
    let deadline = GitDaemonSessionDeadline::new(
        node.git_daemon_session_timeout,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let context = node.session_request_context(&deadline);
    let mut live = || !deadline.expired();
    let command = if request.is_mutation() {
        let limits = HttpLimits {
            max_body_bytes: limits.max_body_bytes.min(MAX_COMMAND_BYTES as u64),
            max_body_wire_bytes: limits.max_body_wire_bytes.min((512 * 1024) as u64),
            max_chunks: limits.max_chunks.min(1024),
            ..limits
        };
        Some(parse_command(&read_form(reader, framing, limits)?)?)
    } else {
        None
    };
    let maximum = usize::try_from(maximum_response)
        .unwrap_or(usize::MAX)
        .min(MAX_RESPONSE_BYTES);
    if let Some(command) = command {
        command
            .proposed_event(principal)
            .map_err(|_| ApiError::bad("invalid_protection_command"))?;
        let (tx, terminal) = drive_request_while(
            node,
            &context,
            node.admit_review_protection_durable_in(
                &context,
                session,
                &command,
                Default::default(),
            ),
            &mut live,
        )
        .map_err(admission_error)?;
        // A policy read here could replace an identical historical receipt
        // with a later policy or failure. Return only the native terminal.
        let body = receipt(node, principal, &command, tx, terminal)?;
        if body.len() > maximum {
            eprintln!(
                "Protection HTTP response limit after canonical outcome for transaction {tx}; recover the original key"
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
    } else {
        let selected = drive_request_while(
            node,
            &context,
            node.read_review_protection_in(&context),
            &mut live,
        )
        .map_err(|_| ApiError::unavailable())?;
        if request
            .expected_head
            .is_some_and(|expected| expected != selected.source_head)
        {
            return Err(ApiError::snapshot_moved());
        }
        let body = snapshot(node, &selected)?;
        if body.len() > maximum {
            return Err(ApiError::too_large());
        }
        Ok(Reply {
            status: Status::Success,
            body,
            terminal: None,
        })
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), ApiError> {
    if slot.is_some() {
        return Err(ApiError::bad("duplicate_field"));
    }
    *slot = Some(value);
    Ok(())
}

fn parse_command(bytes: &[u8]) -> Result<ProtectionCommand, ApiError> {
    if bytes.len() > MAX_COMMAND_BYTES {
        return Err(ApiError::too_large());
    }
    let (mut expected_version, mut expected_epoch, mut clear) = (None, None, None);
    let mut administrators = BTreeSet::new();
    let mut branches: BTreeMap<RefName, BTreeSet<PrincipalId>> = BTreeMap::new();
    for (name, value) in parse_form(bytes, MAX_COMMAND_FIELDS)? {
        match name.as_str() {
            "expected_version" => {
                set_once(&mut expected_version, parse_decimal(&value)?)?;
            }
            "expected_epoch" => {
                set_once(&mut expected_epoch, parse_decimal(&value)?)?;
            }
            "administrator" => {
                let id = principal(&value)?;
                if !administrators.insert(id) {
                    return Err(ApiError::bad("duplicate_administrator"));
                }
                if administrators.len() > MAX_POLICY_ADMINISTRATORS {
                    return Err(ApiError::too_large());
                }
            }
            "required_reviewer" => {
                let (name, person) = value
                    .split_once(':')
                    .ok_or_else(|| ApiError::bad("invalid_required_reviewer"))?;
                let name = reference(name)?;
                let person = principal(person)?;
                let reviewers = branches.entry(name).or_default();
                if !reviewers.insert(person) {
                    return Err(ApiError::bad("duplicate_required_reviewer"));
                }
                if reviewers.len() > MAX_BRANCH_REVIEWERS
                    || branches.len() > MAX_PROTECTED_BRANCHES
                {
                    return Err(ApiError::too_large());
                }
            }
            "clear" => {
                if value != "true" {
                    return Err(ApiError::bad("invalid_clear"));
                }
                set_once(&mut clear, true)?;
            }
            _ => return Err(ApiError::bad("unknown_or_inapplicable_field")),
        }
    }
    let version = expected_version.ok_or_else(|| ApiError::bad("required_field_missing"))?;
    if version == 0 {
        return Err(ApiError::new(Status::Forbidden, "local_bootstrap_required"));
    }
    let version = AggregateVersion::try_new(version)
        .ok_or_else(|| ApiError::bad("invalid_expected_version"))?;
    version
        .next()
        .map_err(|_| ApiError::bad("version_exhausted"))?;
    let expected_epoch = PolicyEpoch::try_new(
        expected_epoch.ok_or_else(|| ApiError::bad("required_field_missing"))?,
    )
    .map_err(|_| ApiError::bad("invalid_expected_epoch"))?;
    expected_epoch
        .next()
        .map_err(|_| ApiError::bad("epoch_exhausted"))?;
    if branches.is_empty() != clear.is_some() {
        return Err(ApiError::bad("explicit_protection_replacement_required"));
    }
    let protection = ReviewProtection {
        administrators: administrators.into_iter().collect(),
        branches: branches
            .into_iter()
            .map(|(name, reviewers)| ProtectedBranch {
                name,
                reviewers: reviewers.into_iter().collect(),
            })
            .collect(),
    };
    protection
        .validate()
        .map_err(|_| ApiError::bad("invalid_review_protection"))?;
    Ok(ProtectionCommand {
        expected_version: ExpectedVersion::Exactly(version),
        expected_epoch,
        protection,
    })
}

fn principal(text: &str) -> Result<PrincipalId, ApiError> {
    PrincipalId::from_hex(text).map_err(|_| ApiError::bad("invalid_principal_id"))
}

fn reference(text: &str) -> Result<RefName, ApiError> {
    if text.is_empty() || text.len() > 2 * MAX_REF_NAME_LEN || text.len() % 2 != 0 {
        return Err(ApiError::bad("invalid_reference_hex"));
    }
    let bytes = text
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok((hex_digit(pair[0])? << 4) | hex_digit(pair[1])?))
        .collect::<Result<Vec<_>, ApiError>>()?;
    let reference = RefName::try_new(&bytes).map_err(|_| ApiError::bad("invalid_ref"))?;
    if !reference.as_bytes().starts_with(b"refs/heads/") {
        return Err(ApiError::bad("invalid_protected_branch"));
    }
    Ok(reference)
}

fn hex_digit(byte: u8) -> Result<u8, ApiError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(ApiError::bad("invalid_reference_hex")),
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 15)]));
    }
    out
}

fn head_token(head: RepositoryAuthorityHeadId) -> String {
    let id = head.as_internal_object_id();
    format!(
        "alg:{}:{}",
        id.algorithm().code_point(),
        hex(id.digest().as_bytes())
    )
}

fn binding(node: &OneNode) -> String {
    format!(
        "\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},\"object_format\":{}",
        quote(&node.tenant_id.to_string()),
        quote(&node.repository_id.to_string()),
        quote(&node.repository_incarnation_id().to_string()),
        quote(node.object_format.as_str())
    )
}

fn policy_json(protection: &ReviewProtection) -> Result<String, ApiError> {
    protection.validate().map_err(|_| ApiError::unavailable())?;
    let administrators = protection
        .administrators
        .iter()
        .map(|id| quote(&id.to_string()))
        .collect::<Vec<_>>()
        .join(",");
    let branches = protection
        .branches
        .iter()
        .map(|branch| {
            format!(
                "{{\"reference_hex\":{},\"required_reviewers\":[{}]}}",
                quote(&hex(branch.name.as_bytes())),
                branch
                    .reviewers
                    .iter()
                    .map(|id| quote(&id.to_string()))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        "{{\"administrators\":[{administrators}],\"branches\":[{branches}]}}"
    ))
}

fn snapshot(node: &OneNode, selected: &ProtectionState) -> Result<String, ApiError> {
    let (version, installed, enabled, policy) = if let Some(event) = &selected.event {
        let ForgeEventPayload::ReviewProtectionChanged(change) = &event.payload else {
            return Err(ApiError::unavailable());
        };
        if event.aggregate != AggregateId::ReviewProtection
            || change
                .resulting_epoch()
                .map_err(|_| ApiError::unavailable())?
                != selected.policy_epoch
        {
            return Err(ApiError::unavailable());
        }
        (
            event.version.get(),
            true,
            !change.protection.branches.is_empty(),
            policy_json(&change.protection)?,
        )
    } else {
        (0, false, false, "null".to_owned())
    };
    Ok(format!(
        concat!(
            "{{\"type\":\"repository_review_protection\",\"schema_version\":1,{},",
            "\"source_head\":{},\"policy_epoch\":{},\"version\":{},\"installed\":{},",
            "\"enabled\":{},\"policy\":{},\"complete\":true,",
            "\"transaction_created\":false,\"published\":false}}"
        ),
        binding(node),
        quote(&head_token(selected.source_head)),
        quote(&selected.policy_epoch.get().to_string()),
        quote(&version.to_string()),
        installed,
        enabled,
        policy
    ))
}

fn receipt(
    node: &OneNode,
    principal: PrincipalId,
    command: &ProtectionCommand,
    tx: TxId,
    terminal: TerminalOutcome,
) -> Result<String, ApiError> {
    let ExpectedVersion::Exactly(expected_version) = command.expected_version else {
        return Err(ApiError::unknown());
    };
    let (outcome, resulting_epoch, rcr, refusal, code, code_point) = match terminal.outcome {
        DecisionOutcome::Committed {
            repository_commit_id,
        } => (
            "committed",
            quote(
                &command
                    .expected_epoch
                    .next()
                    .map_err(|_| ApiError::unknown())?
                    .get()
                    .to_string(),
            ),
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
            "null".to_owned(),
            quote(&refusal_record_id.to_string()),
            quote(&format!("{code:?}")),
            code.code_point().to_string(),
        ),
    };
    Ok(format!(
        concat!(
            "{{\"type\":\"review_protection_publication\",\"schema_version\":1,{},",
            "\"principal_id\":{},\"expected_version\":{},\"expected_epoch\":{},",
            "\"resulting_epoch\":{},\"tx_id\":{},\"outcome\":{},\"decision_sequence\":{},",
            "\"repository_commit_id\":{},\"refusal_record_id\":{},\"refusal_code\":{},",
            "\"refusal_code_point\":{},\"delivery_acknowledged\":null}}"
        ),
        binding(node),
        quote(&principal.to_string()),
        quote(&expected_version.get().to_string()),
        quote(&command.expected_epoch.get().to_string()),
        resulting_epoch,
        quote(&tx.to_string()),
        quote(outcome),
        quote(&terminal.decision_sequence.get().to_string()),
        rcr,
        refusal,
        code,
        code_point
    ))
}

#[cfg(test)]
mod tests;
