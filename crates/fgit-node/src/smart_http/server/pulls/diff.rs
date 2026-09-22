//! PR diff is source disclosure plus PR metadata disclosure, not approval.
//! Require both grants on the SAME credential before consuming a POST body.

use super::super::issues::{ApiError, MAX_FORM_BYTES, Reply, parse_decimal};
use super::super::source::review;
use super::super::{Profile, Status, retry_key};
use crate::{LoopbackReceiveSession, OneNode};
use fgit_authority::IdempotencyKey;
use fgit_forge::PullRequestNumber;
use fgit_wire::smart_http::{BodyFraming, HttpLimits, Service, head::Envelope};
use std::io::Read;

#[derive(Debug)]
pub(super) struct Request<'a> {
    repository_route: &'a str,
    number: PullRequestNumber,
}
impl<'a> Request<'a> {
    pub(super) fn parse(head: &Envelope<'a>) -> Result<Option<Self>, ApiError> {
        let (path, query) = head
            .target
            .split_once('?')
            .map_or((head.target, None), |(p, q)| (p, Some(q)));
        let Some((repository_route, tail)) = path.split_once("/api/v1/pulls/") else {
            return Ok(None);
        };
        let Some(number) = tail.strip_suffix("/diff") else {
            return Ok(None);
        };
        if repository_route.len() < 2
            || !repository_route.starts_with('/')
            || repository_route[1..].split('/').any(|part| {
                part.is_empty()
                    || matches!(part, "." | "..")
                    || !part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
            })
        {
            return Err(ApiError::not_found());
        }
        let number = PullRequestNumber::try_new(parse_decimal(number)?)
            .ok_or_else(|| ApiError::bad("invalid_pull_request_number"))?;
        if head.method != "POST" {
            return Err(ApiError::method());
        }
        if query.is_some() || head.body == BodyFraming::Empty || head.git_protocol.is_some() {
            return Err(ApiError::bad("invalid_diff_envelope"));
        }
        if !head.content_type.is_some_and(|media| {
            media.eq_ignore_ascii_case("application/x-www-form-urlencoded")
                || media.eq_ignore_ascii_case("application/x-www-form-urlencoded; charset=utf-8")
        }) {
            return Err(ApiError::media());
        }
        if matches!(head.body, BodyFraming::ContentLength(n) if n > MAX_FORM_BYTES as u64) {
            return Err(ApiError::too_large());
        }
        Ok(Some(Self {
            repository_route,
            number,
        }))
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
        .authenticate(envelope.authorization())
        .map_err(|error| ApiError::from_status(Status::from(error), false))?;
    if request.repository_route.as_bytes() != profile.route {
        return Err(ApiError::not_found());
    }
    // Like native PR preparation, PR diffs are enabled by the PR API switch;
    // the separate source-browser switch is not an implicit PR permission.
    if !profile.allow_pulls || !grant.permits(Service::UploadPack) || !grant.permits_pulls(false) {
        return Err(ApiError::new(Status::Forbidden, "forbidden"));
    }
    if retry_key(raw_head)
        .map_err(|_| ApiError::bad("invalid_idempotency_key"))?
        .is_some()
    {
        return Err(ApiError::bad("diff_has_no_transaction_key"));
    }
    Ok(LoopbackReceiveSession::authenticated(
        grant.principal,
        IdempotencyKey::new(b"read-only-pull-request-diff".to_vec())
            .map_err(|_| ApiError::unavailable())?,
    ))
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
    review::execute_pull(
        node,
        request.number,
        session,
        framing,
        reader,
        limits,
        maximum_response,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_wire::smart_http::head;
    #[test]
    fn only_exact_pr_diff_routes_accept_query_bodies() {
        for (method, target, extra, accepted) in [
            ("POST", "/r.git/api/v1/pulls/1/diff", "", true),
            ("GET", "/r.git/api/v1/pulls/1/diff", "", false),
            ("POST", "/r.git/api/v1/pulls/01/diff", "", false),
            ("POST", "/r.git/api/v1/pulls/0/diff", "", false),
            ("POST", "/r.git/api/v1/pulls/1/diff?ref=other", "", false),
            ("POST", "/r.git/api/v1/pulls/1/2/diff", "", false),
            (
                "POST",
                "/r.git/api/v1/pulls/1/diff",
                "Git-Protocol: version=2\r\n",
                false,
            ),
        ] {
            let bytes = format!(
                "{method} {target} HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n{extra}\r\n"
            );
            let envelope = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert_eq!(
                Request::parse(&envelope).is_ok_and(|request| request.is_some()),
                accepted
            );
        }
    }
}
