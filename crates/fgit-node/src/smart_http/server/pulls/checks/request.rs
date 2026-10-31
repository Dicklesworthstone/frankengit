//! One bounded, immutable page cursor; no caller-selected source ref or tip.

use super::super::super::issues::{ApiError, parse_decimal, parse_form, parse_snapshot};
use fgit_forge::PullRequestNumber;
use fgit_forge::event::workflow_check::WorkflowCheckId;
use fgit_types::RepositoryAuthorityHeadId;
use fgit_wire::smart_http::{BodyFraming, head::Envelope};

#[derive(Clone, Copy, Debug)]
pub(in crate::smart_http::server) struct Page {
    pub after: Option<WorkflowCheckId>,
    pub limit: u16,
    pub expected_head: Option<RepositoryAuthorityHeadId>,
}

#[derive(Debug)]
pub(in crate::smart_http::server) struct Request<'a> {
    pub repository_route: &'a str,
    pub number: PullRequestNumber,
    pub page: Page,
    pub evidence: Option<WorkflowCheckId>,
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
        let (number, evidence_route) = if let Some(number) = suffix.strip_suffix("/checks/evidence")
        {
            (number, true)
        } else if let Some(number) = suffix.strip_suffix("/checks") {
            (number, false)
        } else {
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
        let (mut after, mut limit, mut expected_head, mut evidence) = (None, None, None, None);
        for (name, value) in parse_form(query.unwrap_or("").as_bytes(), 3)? {
            match name.as_str() {
                "after" if !evidence_route && after.is_none() => {
                    after = Some(
                        WorkflowCheckId::from_label(&value)
                            .ok_or_else(|| ApiError::bad("invalid_check_cursor"))?,
                    );
                }
                "limit" if !evidence_route && limit.is_none() => {
                    limit = Some(parse_decimal(&value)?);
                }
                "check" if evidence_route && evidence.is_none() => {
                    evidence = Some(
                        WorkflowCheckId::from_label(&value)
                            .ok_or_else(|| ApiError::bad("invalid_check_id"))?,
                    );
                }
                "expected_head" if expected_head.is_none() => {
                    expected_head = Some(parse_snapshot(&value)?);
                }
                _ => return Err(ApiError::bad("unknown_or_duplicate_query_field")),
            }
        }
        let limit = limit.unwrap_or(if evidence_route { 1 } else { 20 });
        if !(1..=100).contains(&limit) {
            return Err(ApiError::bad("invalid_page_limit"));
        }
        if (evidence_route || after.is_some()) && expected_head.is_none() {
            return Err(ApiError::bad("snapshot_required"));
        }
        if evidence_route && evidence.is_none() {
            return Err(ApiError::bad("check_required"));
        }
        Ok(Some(Self {
            repository_route,
            number,
            page: Page {
                after,
                limit: limit as u16,
                expected_head,
            },
            evidence,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_wire::smart_http::{HttpLimits, head};

    #[test]
    fn evidence_requires_an_exact_check_and_snapshot_without_page_or_write_fields() {
        let check = WorkflowCheckId::from_bytes([0x5a; 32]).to_string();
        let pin = format!("alg:2:{}", "ab".repeat(32));
        for (query, accepted) in [
            (format!("check={check}&expected_head={pin}"), true),
            (
                format!("expected_head={pin}&check={}", check.replace('/', "%2F")),
                true,
            ),
            (String::new(), false),
            (format!("check={check}"), false),
            (format!("expected_head={pin}"), false),
            (format!("check={check}&expected_head={pin}&limit=1"), false),
            (
                format!("check={check}&expected_head={pin}&after={check}"),
                false,
            ),
            (
                format!("check={check}&expected_head={pin}&principal=admin"),
                false,
            ),
            (
                format!("check={check}&check={check}&expected_head={pin}"),
                false,
            ),
            (
                format!("check={check}&expected_head={pin}&expected_head={pin}"),
                false,
            ),
            (
                format!("check={}&expected_head={pin}", check.to_uppercase()),
                false,
            ),
            (
                format!("check=check/{}&expected_head={pin}", "1".repeat(52)),
                false,
            ),
        ] {
            let bytes = format!(
                "GET /repo.git/api/v1/pulls/7/checks/evidence?{query} HTTP/1.1\r\nHost: local\r\n\r\n"
            );
            let envelope = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            let parsed = Request::parse(&envelope);
            assert_eq!(parsed.is_ok(), accepted, "{query}");
            if accepted {
                let request = parsed.unwrap().unwrap();
                assert_eq!(
                    request.evidence,
                    Some(WorkflowCheckId::from_bytes([0x5a; 32]))
                );
                assert_eq!(request.page.limit, 1);
                assert_eq!(request.page.after, None);
                assert!(request.page.expected_head.is_some());
            }
        }
        for (method, extra) in [
            ("POST", ""),
            ("GET", "Content-Length: 1\r\n"),
            ("GET", "Transfer-Encoding: chunked\r\n"),
            ("GET", "Git-Protocol: version=2\r\n"),
            ("GET", "Expect: 100-continue\r\n"),
        ] {
            let bytes = format!(
                "{method} /repo.git/api/v1/pulls/7/checks/evidence?check={check}&expected_head={pin} HTTP/1.1\r\nHost: local\r\n{extra}\r\n"
            );
            let envelope = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert!(Request::parse(&envelope).is_err(), "{method} {extra}");
        }
    }

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
