//! Native PR request grammar. The caller submits every semantic coordinate;
//! the gateway never refreshes tips, expected versions, or text on a retry.

use std::collections::BTreeMap;

use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RepositoryAuthorityHeadId};
use fgit_wire::smart_http::{BodyFraming, head::Envelope};

use super::super::issues::{
    ApiError, MAX_FORM_BYTES, Page, parse_decimal, parse_form, parse_page, parse_snapshot,
};

#[derive(Debug)]
pub(super) enum Operation {
    List(Page),
    Show {
        number: PullRequestNumber,
        expected_head: Option<RepositoryAuthorityHeadId>,
    },
    Mutate {
        number: PullRequestNumber,
        action: PullRequestAction,
    },
}

#[derive(Debug)]
pub(in crate::smart_http::server) struct Request<'a> {
    pub repository_route: &'a str,
    pub(super) operation: Operation,
}

impl<'a> Request<'a> {
    pub(in crate::smart_http::server) fn parse(
        head: &Envelope<'a>,
    ) -> Result<Option<Self>, ApiError> {
        let (path, query) = head
            .target
            .split_once('?')
            .map_or((head.target, None), |(path, query)| (path, Some(query)));
        let Some((repository_route, suffix)) = path.split_once("/api/v1/pulls") else {
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
        if head.git_protocol.is_some() {
            return Err(ApiError::bad("git_protocol_not_applicable"));
        }
        let operation = match head.method {
            "GET" => {
                if !matches!(
                    head.body,
                    BodyFraming::Empty | BodyFraming::ContentLength(0)
                ) || head.expect_continue
                {
                    return Err(ApiError::bad("body_not_allowed"));
                }
                if suffix.is_empty() {
                    Operation::List(parse_page(query, "after")?)
                } else {
                    let number = number(suffix.strip_prefix('/').ok_or_else(ApiError::not_found)?)?;
                    let mut expected_head = None;
                    for (key, value) in parse_form(query.unwrap_or("").as_bytes(), 1)? {
                        if key != "expected_head" {
                            return Err(ApiError::bad("unknown_query_field"));
                        }
                        expected_head = Some(parse_snapshot(&value)?);
                    }
                    Operation::Show {
                        number,
                        expected_head,
                    }
                }
            }
            "POST" => {
                if query.is_some() || head.body == BodyFraming::Empty {
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
                let (number_text, action) = suffix
                    .strip_prefix('/')
                    .and_then(|suffix| suffix.split_once('/'))
                    .ok_or_else(ApiError::not_found)?;
                let action = match action {
                    "open" => PullRequestAction::Open,
                    "update" => PullRequestAction::Update,
                    "close" => PullRequestAction::Close,
                    "reopen" => PullRequestAction::Reopen,
                    _ => return Err(ApiError::not_found()),
                };
                Operation::Mutate {
                    number: number(number_text)?,
                    action,
                }
            }
            _ => return Err(ApiError::method()),
        };
        Ok(Some(Self {
            repository_route,
            operation,
        }))
    }

    pub(in crate::smart_http::server) const fn is_mutation(&self) -> bool {
        matches!(self.operation, Operation::Mutate { .. })
    }

    pub(super) fn command(
        &self,
        bytes: &[u8],
        format: GitHashAlgorithm,
    ) -> Result<PullRequestCommand, ApiError> {
        let Operation::Mutate { number, action } = self.operation else {
            return Err(ApiError::bad("not_a_mutation"));
        };
        let mut fields = BTreeMap::new();
        for (key, value) in parse_form(bytes, 8)? {
            if !matches!(
                key.as_str(),
                "expected_version"
                    | "object_format"
                    | "source_ref"
                    | "target_ref"
                    | "source_tip"
                    | "target_tip"
                    | "title"
                    | "body"
            ) {
                return Err(ApiError::bad("unknown_or_inapplicable_field"));
            }
            if fields.insert(key, value).is_some() {
                return Err(ApiError::bad("duplicate_field"));
            }
        }
        let declared = take(&mut fields, "object_format")?;
        if declared != format.as_str() {
            return Err(ApiError::bad("object_format_mismatch"));
        }
        let version = parse_decimal(&take(&mut fields, "expected_version")?)?;
        if (action == PullRequestAction::Open) != (version == 0) {
            return Err(ApiError::bad("invalid_expected_version"));
        }
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
        let source_ref = RefName::try_new(take(&mut fields, "source_ref")?.as_bytes())
            .map_err(|_| ApiError::bad("invalid_ref"))?;
        let target_ref = RefName::try_new(take(&mut fields, "target_ref")?.as_bytes())
            .map_err(|_| ApiError::bad("invalid_ref"))?;
        let source_tip = oid(&take(&mut fields, "source_tip")?, format)?;
        let target_tip = oid(&take(&mut fields, "target_tip")?, format)?;
        let data = PullRequestData {
            source_ref,
            target_ref,
            source_tip,
            target_tip,
            title: take(&mut fields, "title")?,
            body: take(&mut fields, "body")?,
        };
        data.validate()
            .map_err(|_| ApiError::bad("invalid_pull_request_content"))?;
        Ok(PullRequestCommand {
            number,
            expected_version,
            action,
            data,
        })
    }
}

fn number(text: &str) -> Result<PullRequestNumber, ApiError> {
    PullRequestNumber::try_new(parse_decimal(text)?)
        .ok_or_else(|| ApiError::bad("invalid_pull_request_number"))
}
fn take(fields: &mut BTreeMap<String, String>, name: &str) -> Result<String, ApiError> {
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
    let oid = GitOid::from_hex(format, text).map_err(|_| ApiError::bad("invalid_object_id"))?;
    if oid.is_zero() {
        return Err(ApiError::bad("invalid_object_id"));
    }
    Ok(oid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_wire::smart_http::{HttpLimits, head};

    fn fields(format: GitHashAlgorithm) -> String {
        format!(
            "expected_version=0&object_format={}&source_ref=refs%2Fheads%2Ftopic&target_ref=refs%2Fheads%2Fmain&source_tip={}&target_tip={}&title=Review+%F0%9F%A6%80&body=%252f%0A%22",
            format.as_str(),
            "a".repeat(format.digest_len() * 2),
            "b".repeat(format.digest_len() * 2)
        )
    }
    fn command(
        action: &str,
        body: &str,
        format: GitHashAlgorithm,
    ) -> Result<PullRequestCommand, ApiError> {
        let text = format!(
            "POST /repo.git/api/v1/pulls/7/{action} HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let head = head::parse(text.as_bytes(), HttpLimits::default())
            .unwrap()
            .unwrap();
        Request::parse(&head)?
            .unwrap()
            .command(body.as_bytes(), format)
    }
    #[test]
    fn native_commands_keep_exact_versions_tips_and_decoded_text_in_both_formats() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let body = fields(format);
            let opened = command("open", &body, format).unwrap();
            assert_eq!(opened.data.title, "Review 🦀");
            assert_eq!(opened.data.body, "%2f\n\"");
            assert_eq!(opened.data.source_ref.as_bytes(), b"refs/heads/topic");
            assert_eq!(opened.expected_version, ExpectedVersion::NewStream);
            for action in ["update", "close"] {
                let next = command(
                    action,
                    &body.replace("expected_version=0", "expected_version=1"),
                    format,
                )
                .unwrap();
                assert_eq!(next.data, opened.data);
                assert_eq!(
                    next.expected_version,
                    ExpectedVersion::Exactly(AggregateVersion::FIRST)
                );
            }
        }
    }
    #[test]
    fn commands_cannot_inject_authority_omit_preconditions_or_change_hash_domains() {
        let format = GitHashAlgorithm::Sha1;
        let good = fields(format);
        for body in [
            good.clone() + "&principal=admin",
            good.clone() + "&title=other",
            good.replace("expected_version=0", "expected_version=00"),
            good.replace("expected_version=0&", ""),
            good.replace("object_format=sha1", "object_format=sha256"),
            good.replace(&"a".repeat(40), &"0".repeat(40)),
            good.replace("body=%252f%0A%22", "body=%FF"),
            good.replace("body=%252f%0A%22", "body=%00"),
            good.replace("body=%252f%0A%22", "body=%"),
            good.replace(
                "source_ref=refs%2Fheads%2Ftopic",
                "source_ref=refs%2Ftags%2Ftopic",
            ),
        ] {
            assert!(command("open", &body, format).is_err());
        }
        assert!(command("close", &good, format).is_err());
        assert!(command("reopen", &good, format).is_err());
        assert!(command("merge", &good, format).is_err());
        assert!(
            command(
                "update",
                &good.replace(
                    "expected_version=0",
                    "expected_version=18446744073709551615"
                ),
                format
            )
            .is_err()
        );
    }
    #[test]
    fn read_envelopes_require_pinned_continuations_and_reject_inapplicable_parameters() {
        for suffix in [
            "?after=1",
            "?limit=101",
            "?limit=1&limit=2",
            "/0",
            "/01",
            "/1?after=2",
            "/1?principal=admin",
        ] {
            let bytes =
                format!("GET /repo.git/api/v1/pulls{suffix} HTTP/1.1\r\nHost: local\r\n\r\n");
            let head = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert!(Request::parse(&head).is_err(), "{suffix}");
        }
        for extra in [
            "Content-Length: 1\r\n",
            "Expect: 100-continue\r\n",
            "Git-Protocol: version=2\r\n",
        ] {
            let bytes =
                format!("GET /repo.git/api/v1/pulls HTTP/1.1\r\nHost: local\r\n{extra}\r\n");
            let head = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert!(Request::parse(&head).is_err());
        }
    }

    #[test]
    fn reopen_keeps_the_explicit_version_and_full_native_metadata() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let body = fields(format).replace("expected_version=0", "expected_version=2");
            let reopened = command("reopen", &body, format).unwrap();
            let updated = command("update", &body, format).unwrap();
            assert_eq!(reopened.action, PullRequestAction::Reopen);
            assert_eq!(reopened.number, PullRequestNumber::try_new(7).unwrap());
            assert_eq!(
                reopened.expected_version,
                ExpectedVersion::Exactly(AggregateVersion::try_new(2).unwrap())
            );
            assert_eq!(reopened.data, updated.data);
            assert_eq!(reopened.data.body, "%2f\n\"");
            let actor = fgit_types::PrincipalId::from_bytes([7; 16]);
            assert_ne!(
                reopened.proposed_event(actor, format).unwrap(),
                updated.proposed_event(actor, format).unwrap()
            );
            assert_eq!(super::super::output::action(reopened.action), "reopen");
        }
    }

    #[test]
    fn reopen_cannot_reset_version_omit_content_or_supply_its_own_actor() {
        let format = GitHashAlgorithm::Sha1;
        let body = fields(format).replace("expected_version=0", "expected_version=2");
        for field in [
            "expected_version",
            "object_format",
            "source_ref",
            "target_ref",
            "source_tip",
            "target_tip",
            "title",
            "body",
        ] {
            let missing = body
                .split('&')
                .filter(|part| !part.starts_with(&format!("{field}=")))
                .collect::<Vec<_>>()
                .join("&");
            assert!(
                command("reopen", &missing, format).is_err(),
                "missing {field}"
            );
        }
        for invalid in [
            body.replace("expected_version=2", "expected_version=0"),
            body.replace("expected_version=2", "expected_version=02"),
            body.replace(
                "expected_version=2",
                "expected_version=18446744073709551615",
            ),
            body.clone() + "&principal_id=administrator",
            body.clone() + "&expected_version=3",
            body.replace("object_format=sha1", "object_format=sha256"),
        ] {
            assert!(command("reopen", &invalid, format).is_err());
        }
        assert!(command("reopen", &body, format).is_ok());
    }

    #[test]
    fn reopen_route_is_a_body_bearing_mutation_not_a_read_or_merge_shortcut() {
        let bytes = b"POST /repo.git/api/v1/pulls/7/reopen HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n\r\n";
        let envelope = head::parse(bytes, HttpLimits::default()).unwrap().unwrap();
        // Exercise the full PR route selector, including collaboration routers.
        let routed = super::super::Request::parse(&envelope).unwrap().unwrap();
        assert!(routed.is_mutation());
        assert!(routed.accepts_body());
        for text in [
            "GET /repo.git/api/v1/pulls/7/reopen HTTP/1.1\r\nHost: local\r\n\r\n",
            "POST /repo.git/api/v1/pulls/7/reopen HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n",
            "POST /repo.git/api/v1/pulls/7/reopen?force=true HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n\r\n",
        ] {
            let envelope = head::parse(text.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert!(Request::parse(&envelope).is_err());
        }
    }
}
