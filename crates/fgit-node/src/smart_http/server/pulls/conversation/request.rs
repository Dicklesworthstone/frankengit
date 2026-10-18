//! Comments accept only an exact discussion version and complete body. The PR
//! number comes from the route, and the authenticated session owns the actor.

use fgit_forge::event::pull_request_comment::{
    MAX_COMMENT_BYTES, PullRequestCommentCommand, validate_body,
};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_wire::smart_http::{BodyFraming, head::Envelope};

use super::super::super::issues::{
    ApiError, MAX_FORM_BYTES, Page, parse_decimal, parse_form, parse_page,
};

#[derive(Debug)]
pub(in crate::smart_http::server::pulls) struct Request<'a> {
    pub repository_route: &'a str,
    pub number: PullRequestNumber,
    pub page: Page,
    mutation: bool,
}

impl<'a> Request<'a> {
    pub(in crate::smart_http::server::pulls) fn parse(
        head: &Envelope<'a>,
    ) -> Result<Option<Self>, ApiError> {
        let (path, query) = head
            .target
            .split_once('?')
            .map_or((head.target, None), |(path, query)| (path, Some(query)));
        let Some((repository_route, suffix)) = path.split_once("/api/v1/pulls/") else {
            return Ok(None);
        };
        let Some(number) = suffix.strip_suffix("/comments") else {
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
        if head.git_protocol.is_some() {
            return Err(ApiError::bad("git_protocol_not_applicable"));
        }
        let (mutation, page) = match head.method {
            "GET" => {
                if !matches!(
                    head.body,
                    BodyFraming::Empty | BodyFraming::ContentLength(0)
                ) || head.expect_continue
                {
                    return Err(ApiError::bad("body_not_allowed"));
                }
                (false, parse_page(query, "after")?)
            }
            "POST" => {
                if query.is_some()
                    || matches!(
                        head.body,
                        BodyFraming::Empty | BodyFraming::ContentLength(0)
                    )
                {
                    return Err(ApiError::bad("invalid_mutation_envelope"));
                }
                if !head.content_type.is_some_and(|value| {
                    value.eq_ignore_ascii_case("application/x-www-form-urlencoded")
                        || value.eq_ignore_ascii_case(
                            "application/x-www-form-urlencoded; charset=utf-8",
                        )
                }) {
                    return Err(ApiError::media());
                }
                if matches!(head.body, BodyFraming::ContentLength(bytes) if bytes > MAX_FORM_BYTES as u64)
                {
                    return Err(ApiError::too_large());
                }
                (true, parse_page(None, "after")?)
            }
            _ => return Err(ApiError::method()),
        };
        Ok(Some(Self {
            repository_route,
            number,
            page,
            mutation,
        }))
    }

    pub(in crate::smart_http::server::pulls) const fn is_mutation(&self) -> bool {
        self.mutation
    }

    pub(super) fn command(&self, bytes: &[u8]) -> Result<PullRequestCommentCommand, ApiError> {
        if !self.mutation {
            return Err(ApiError::bad("not_a_mutation"));
        }
        let (mut version, mut body) = (None, None);
        for (name, value) in parse_form(bytes, 3)? {
            match name.as_str() {
                "expected_version" if version.is_none() => version = Some(parse_decimal(&value)?),
                "body" if body.is_none() => body = Some(value),
                _ => return Err(ApiError::bad("unknown_or_duplicate_field")),
            }
        }
        let version = version.ok_or_else(|| ApiError::bad("required_field_missing"))?;
        let expected_version = if version == 0 {
            ExpectedVersion::NewStream
        } else {
            let version = AggregateVersion::try_new(version)
                .ok_or_else(|| ApiError::bad("invalid_expected_version"))?;
            version
                .next()
                .map_err(|_| ApiError::bad("version_exhausted"))?;
            ExpectedVersion::Exactly(version)
        };
        let body = body.ok_or_else(|| ApiError::bad("required_field_missing"))?;
        if body.len() > MAX_COMMENT_BYTES {
            return Err(ApiError::too_large());
        }
        validate_body(&body).map_err(|_| ApiError::bad("invalid_comment_body"))?;
        Ok(PullRequestCommentCommand {
            number: self.number,
            expected_version,
            body,
        })
    }
}

#[cfg(test)]
mod tests;
