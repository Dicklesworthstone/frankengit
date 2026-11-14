//! Bounded label grammar: explicit full replacement or explicit clear, with
//! the caller's exact label-stream version. No implicit fetch/merge on retry.

use fgit_forge::event::pull_request_labels::{
    MAX_LABEL_BYTES, MAX_LABELS, PullRequestLabelsCommand, validate_labels,
};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_types::RepositoryAuthorityHeadId;
use fgit_wire::smart_http::{BodyFraming, head::Envelope};

use super::super::super::issues::{
    ApiError, parse_decimal, parse_form, parse_form_with_field_limit, parse_snapshot,
};

const MAX_FORM_BYTES: usize = 8 * 1024;

#[derive(Debug)]
pub(in crate::smart_http::server) struct Request<'a> {
    pub repository_route: &'a str,
    pub number: PullRequestNumber,
    pub expected_head: Option<RepositoryAuthorityHeadId>,
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
        let Some(number) = suffix.strip_suffix("/labels") else {
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
        let (mutation, expected_head) = match head.method {
            "GET" => {
                if !matches!(
                    head.body,
                    BodyFraming::Empty | BodyFraming::ContentLength(0)
                ) || head.expect_continue
                {
                    return Err(ApiError::bad("body_not_allowed"));
                }
                let mut expected = None;
                for (key, value) in parse_form(query.unwrap_or("").as_bytes(), 1)? {
                    if key != "expected_head" {
                        return Err(ApiError::bad("unknown_query_field"));
                    }
                    expected = Some(parse_snapshot(&value)?);
                }
                (false, expected)
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
                (true, None)
            }
            _ => return Err(ApiError::method()),
        };
        Ok(Some(Self {
            repository_route,
            number,
            expected_head,
            mutation,
        }))
    }

    pub(in crate::smart_http::server::pulls) const fn is_mutation(&self) -> bool {
        self.mutation
    }

    pub(super) fn command(&self, bytes: &[u8]) -> Result<PullRequestLabelsCommand, ApiError> {
        if !self.mutation {
            return Err(ApiError::bad("not_a_mutation"));
        }
        if bytes.len() > MAX_FORM_BYTES {
            return Err(ApiError::too_large());
        }
        let mut version = None;
        let mut clear = false;
        let mut labels = Vec::new();
        for (key, value) in
            parse_form_with_field_limit(bytes, MAX_LABELS + 2, "label", MAX_LABEL_BYTES)?
        {
            match key.as_str() {
                "expected_version" if version.is_none() => version = Some(parse_decimal(&value)?),
                "clear_labels" if !clear && value == "true" => clear = true,
                "label" if labels.len() < MAX_LABELS => labels.push(value),
                _ => return Err(ApiError::bad("unknown_duplicate_or_inapplicable_field")),
            }
        }
        if clear != labels.is_empty() {
            return Err(ApiError::bad("explicit_label_replacement_required"));
        }
        labels.sort();
        validate_labels(&labels).map_err(|_| ApiError::bad("invalid_labels"))?;
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
        Ok(PullRequestLabelsCommand {
            number: self.number,
            expected_version,
            labels,
        })
    }
}

#[cfg(test)]
mod tests;
