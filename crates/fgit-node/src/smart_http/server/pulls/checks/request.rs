//! One bounded, immutable page cursor; no caller-selected source ref or tip.

use super::super::super::issues::{ApiError, parse_decimal, parse_form, parse_snapshot};
use fgit_forge::PullRequestNumber;
use fgit_forge::event::workflow_check::WorkflowCheckId;
use fgit_types::RepositoryAuthorityHeadId;
use fgit_wire::smart_http::{BodyFraming, head::Envelope};

#[derive(Clone, Copy, Debug)]
pub(in crate::smart_http::server::pulls) struct Page {
    pub after: Option<WorkflowCheckId>,
    pub limit: u16,
    pub expected_head: Option<RepositoryAuthorityHeadId>,
}

#[derive(Debug)]
pub(in crate::smart_http::server::pulls) struct Request<'a> {
    pub repository_route: &'a str,
    pub number: PullRequestNumber,
    pub page: Page,
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
        let Some(number) = suffix.strip_suffix("/checks") else {
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
        if head.method != "GET" {
            return Err(ApiError::method());
        }
        if head.git_protocol.is_some() {
            return Err(ApiError::bad("git_protocol_not_applicable"));
        }
        if !matches!(
            head.body,
            BodyFraming::Empty | BodyFraming::ContentLength(0)
        ) || head.expect_continue
        {
            return Err(ApiError::bad("body_not_allowed"));
        }
        let (mut after, mut limit, mut expected_head) = (None, None, None);
        for (name, value) in parse_form(query.unwrap_or("").as_bytes(), 3)? {
            match name.as_str() {
                "after" if after.is_none() => {
                    after = Some(
                        WorkflowCheckId::from_label(&value)
                            .ok_or_else(|| ApiError::bad("invalid_check_cursor"))?,
                    );
                }
                "limit" if limit.is_none() => limit = Some(parse_decimal(&value)?),
                "expected_head" if expected_head.is_none() => {
                    expected_head = Some(parse_snapshot(&value)?);
                }
                _ => return Err(ApiError::bad("unknown_or_duplicate_query_field")),
            }
        }
        let limit = limit.unwrap_or(20);
        if !(1..=100).contains(&limit) {
            return Err(ApiError::bad("invalid_page_limit"));
        }
        if after.is_some() && expected_head.is_none() {
            return Err(ApiError::bad("snapshot_required"));
        }
        Ok(Some(Self {
            repository_route,
            number,
            page: Page {
                after,
                limit: limit as u16,
                expected_head,
            },
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_wire::smart_http::{HttpLimits, head};

    #[test]
    fn exact_checks_route_is_get_only_without_body_or_publication_semantics() {
        for (method, number, extra, accepted) in [
            ("GET", "7", "", true),
            ("GET", "7", "Content-Length: 0\r\n", true),
            ("POST", "7", "", false),
            ("GET", "07", "", false),
            ("GET", "0", "", false),
            ("GET", "1/2", "", false),
            ("GET", "7", "Git-Protocol: version=2\r\n", false),
            ("GET", "7", "Content-Length: 1\r\n", false),
            ("GET", "7", "Transfer-Encoding: chunked\r\n", false),
            ("GET", "7", "Expect: 100-continue\r\n", false),
        ] {
            let bytes = format!(
                "{method} /repo.git/api/v1/pulls/{number}/checks HTTP/1.1\r\nHost: local\r\n{extra}\r\n"
            );
            let envelope = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            let routed = super::super::super::Request::parse(&envelope);
            assert_eq!(routed.is_ok(), accepted, "{method} {number} {extra}");
            if let Ok(Some(routed)) = routed {
                assert!(matches!(routed, super::super::super::Request::Checks(_)));
                assert!(!routed.is_mutation());
                assert!(!routed.accepts_body());
            }
        }
    }

    #[test]
    fn checks_require_canonical_pinned_continuations_and_exact_query_fields() {
        let cursor = WorkflowCheckId::from_bytes([0x5a; 32]).to_string();
        let pin = format!("alg:2:{}", "ab".repeat(32));
        for (query, accepted) in [
            (String::new(), true),
            ("limit=1".into(), true),
            ("limit=100".into(), true),
            (format!("after={cursor}&expected_head={pin}"), true),
            (format!("expected_head={pin}&limit=1&after={cursor}"), true),
            (format!("after={cursor}"), false),
            ("limit=0".into(), false),
            ("limit=101".into(), false),
            ("limit=01".into(), false),
            ("limit=1&limit=2".into(), false),
            (
                format!("after={cursor}&after={cursor}&expected_head={pin}"),
                false,
            ),
            (format!("expected_head={pin}&expected_head={pin}"), false),
            (
                format!("after=check/{}&expected_head={pin}", "1".repeat(52)),
                false,
            ),
            (
                format!("after={}&expected_head={pin}", cursor.to_uppercase()),
                false,
            ),
            ("source_ref=refs/heads/private".into(), false),
            ("source_tip=deadbeef".into(), false),
            ("principal=admin".into(), false),
            ("head=latest".into(), false),
        ] {
            let bytes = format!(
                "GET /repo.git/api/v1/pulls/7/checks?{query} HTTP/1.1\r\nHost: local\r\n\r\n"
            );
            let envelope = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert_eq!(Request::parse(&envelope).is_ok(), accepted, "{query}");
        }
    }
}
