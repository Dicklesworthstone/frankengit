//! Comments bind an exact discussion version, literal body, and optional exact
//! source coordinates. The route owns the PR; the session owns the actor.

use std::collections::BTreeMap;

use fgit_forge::event::pull_request_comment::{
    MAX_COMMENT_BYTES, PullRequestCommentCommand, SourceCommentAnchor, SourceCommentComparison,
    SourceCommentSide, validate_body,
};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_types::{GitHashAlgorithm, GitOid, RefName};
use fgit_wire::smart_http::{BodyFraming, head::Envelope};

use super::super::super::issues::{
    ApiError, MAX_FORM_BYTES, Page, parse_decimal, parse_form, parse_page,
};

#[derive(Debug)]
pub(in crate::smart_http::server) struct Request<'a> {
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

    pub(super) fn command(
        &self,
        bytes: &[u8],
        format: GitHashAlgorithm,
    ) -> Result<PullRequestCommentCommand, ApiError> {
        if !self.mutation {
            return Err(ApiError::bad("not_a_mutation"));
        }
        let (mut version, mut body) = (None, None);
        let mut anchor_fields = BTreeMap::new();
        for (name, value) in parse_form(bytes, 18)? {
            match name.as_str() {
                "expected_version" if version.is_none() => version = Some(parse_decimal(&value)?),
                "body" if body.is_none() => body = Some(value),
                field if ANCHOR_FIELDS.contains(&field) => {
                    if anchor_fields.insert(name, value).is_some() {
                        return Err(ApiError::bad("unknown_or_duplicate_field"));
                    }
                }
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
            anchor: parse_anchor(&anchor_fields, format)?,
        })
    }
}

const ANCHOR_FIELDS: [&str; 15] = [
    "anchor_pull_request_version",
    "anchor_source_ref_hex",
    "anchor_target_ref_hex",
    "anchor_source_tip",
    "anchor_target_tip",
    "anchor_compared_base",
    "anchor_comparison",
    "anchor_path_hex",
    "anchor_side",
    "anchor_blob",
    "anchor_mode",
    "anchor_byte_start",
    "anchor_byte_end",
    "anchor_line_start",
    "anchor_line_count",
];

fn parse_anchor(
    fields: &BTreeMap<String, String>,
    format: GitHashAlgorithm,
) -> Result<Option<SourceCommentAnchor>, ApiError> {
    if fields.is_empty() {
        return Ok(None);
    }
    let required = |field: &str| {
        fields
            .get(field)
            .map(String::as_str)
            .ok_or_else(|| ApiError::bad("incomplete_source_anchor"))
    };
    let oid = |field| {
        GitOid::from_hex(format, required(field)?)
            .map_err(|_| ApiError::bad("invalid_source_anchor_oid"))
    };
    let reference = |field| {
        RefName::try_new(&anchor_hex(required(field)?)?)
            .map_err(|_| ApiError::bad("invalid_source_anchor_ref"))
    };
    let anchor = SourceCommentAnchor {
        pull_request_version: AggregateVersion::try_new(parse_decimal(required(
            "anchor_pull_request_version",
        )?)?)
        .ok_or_else(|| ApiError::bad("invalid_source_anchor_version"))?,
        source_ref: reference("anchor_source_ref_hex")?,
        target_ref: reference("anchor_target_ref_hex")?,
        source_tip: oid("anchor_source_tip")?,
        target_tip: oid("anchor_target_tip")?,
        compared_base: oid("anchor_compared_base")?,
        comparison: match required("anchor_comparison")? {
            "direct" => SourceCommentComparison::Direct,
            "merge_base" => SourceCommentComparison::MergeBase,
            _ => return Err(ApiError::bad("invalid_source_anchor_comparison")),
        },
        path: anchor_hex(required("anchor_path_hex")?)?,
        side: match required("anchor_side")? {
            "before" => SourceCommentSide::Before,
            "after" => SourceCommentSide::After,
            _ => return Err(ApiError::bad("invalid_source_anchor_side")),
        },
        blob: oid("anchor_blob")?,
        mode: match required("anchor_mode")? {
            "100644" => 0o100644,
            "100755" => 0o100755,
            "120000" => 0o120000,
            _ => return Err(ApiError::bad("invalid_source_anchor_mode")),
        },
        byte_start: parse_decimal(required("anchor_byte_start")?)?,
        byte_end: parse_decimal(required("anchor_byte_end")?)?,
        line_start: parse_decimal(required("anchor_line_start")?)?,
        line_count: parse_decimal(required("anchor_line_count")?)?,
    };
    anchor
        .validate()
        .map_err(|_| ApiError::bad("invalid_source_anchor"))?;
    Ok(Some(anchor))
}

fn anchor_hex(text: &str) -> Result<Vec<u8>, ApiError> {
    if text.is_empty()
        || text.len() > 8192
        || !text.len().is_multiple_of(2)
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApiError::bad("invalid_source_anchor_hex"));
    }
    Ok(text
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |byte| {
                if byte <= b'9' {
                    byte - b'0'
                } else {
                    byte - b'a' + 10
                }
            };
            digit(pair[0]) * 16 + digit(pair[1])
        })
        .collect())
}

#[cfg(test)]
mod tests;
