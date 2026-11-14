//! Closed, byte-preserving command grammar; no request can assert an actor,
//! refresh a stale expectation, bootstrap a policy or edit a direct reference.

use super::super::issues::{ApiError, parse_form, parse_snapshot};
use super::{MAX_COMMAND_BYTES, ROUTE};
use fgit_admission::default_branch::DefaultBranchCommand;
use fgit_types::{GitHashAlgorithm, GitOid, MAX_REF_NAME_LEN, RefName, RepositoryAuthorityHeadId};
use fgit_wire::smart_http::{BodyFraming, head::Envelope};
use std::collections::BTreeMap;

#[derive(Debug)]
pub(in super::super) struct Request<'a> {
    pub(super) repository_route: &'a str,
    mutation: bool,
    pub(super) expected_head: Option<RepositoryAuthorityHeadId>,
}
impl<'a> Request<'a> {
    pub(in super::super) fn parse(envelope: &Envelope<'a>) -> Result<Self, ApiError> {
        let (path, query) = envelope
            .target
            .split_once('?')
            .map_or((envelope.target, None), |(path, query)| (path, Some(query)));
        let (repository_route, suffix) = path.rsplit_once(ROUTE).ok_or_else(ApiError::not_found)?;
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
                for (name, value) in parse_form(query.unwrap_or("").as_bytes(), 1)? {
                    if name != "expected_head" || expected.is_some() {
                        return Err(ApiError::bad("invalid_query"));
                    }
                    expected = Some(parse_snapshot(&value)?);
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
                if matches!(envelope.body, BodyFraming::ContentLength(bytes) if bytes > MAX_COMMAND_BYTES as u64)
                {
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
    pub(in super::super) const fn is_mutation(&self) -> bool {
        self.mutation
    }
}

pub(super) fn command(
    bytes: &[u8],
    format: GitHashAlgorithm,
) -> Result<DefaultBranchCommand, ApiError> {
    if bytes.len() > MAX_COMMAND_BYTES {
        return Err(ApiError::too_large());
    }
    let mut fields = BTreeMap::new();
    for (name, value) in parse_form(bytes, 3)? {
        if fields.insert(name, value).is_some() {
            return Err(ApiError::bad("duplicate_field"));
        }
    }
    let expected_head = match (
        fields.remove("expected_default_hex"),
        fields.remove("expect_no_default"),
    ) {
        (Some(value), None) => Some(reference(&value)?),
        (None, Some(value)) if value == "true" => None,
        _ => return Err(ApiError::bad("exact_expected_default_required")),
    };
    let target = reference(
        &fields
            .remove("reference_hex")
            .ok_or_else(|| ApiError::bad("reference_required"))?,
    )?;
    let text = fields
        .remove("expected_tip")
        .ok_or_else(|| ApiError::bad("expected_tip_required"))?;
    if !fields.is_empty() {
        return Err(ApiError::bad("unknown_field"));
    }
    if text.len() != format.digest_len() * 2 || !lower_hex(&text) {
        return Err(ApiError::bad("invalid_native_commit"));
    }
    let tip =
        GitOid::from_hex(format, &text).map_err(|_| ApiError::bad("invalid_native_commit"))?;
    if tip.is_zero() {
        return Err(ApiError::bad("nonzero_native_commit_required"));
    }
    Ok(DefaultBranchCommand {
        expected_head,
        target,
        expected_target_tip: tip,
    })
}
fn lower_hex(text: &str) -> bool {
    text.bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn reference(text: &str) -> Result<RefName, ApiError> {
    if text.is_empty()
        || text.len() % 2 != 0
        || text.len() > MAX_REF_NAME_LEN * 2
        || !lower_hex(text)
    {
        return Err(ApiError::bad("invalid_reference_hex"));
    }
    let bytes: Vec<u8> = text
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |value: u8| {
                if value <= b'9' {
                    value - b'0'
                } else {
                    value - b'a' + 10
                }
            };
            (digit(pair[0]) << 4) | digit(pair[1])
        })
        .collect();
    if !bytes.starts_with(b"refs/heads/") {
        return Err(ApiError::bad("branch_required"));
    }
    RefName::try_new(&bytes).map_err(|_| ApiError::bad("invalid_reference"))
}
