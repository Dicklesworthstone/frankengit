//! Native issue routes and form commands. Text never supplies a principal,
//! storage path, authority root, or executable operation outside this grammar.

use fgit_forge::aggregate::{AggregateVersion, ExpectedVersion, IssueNumber};
use fgit_forge::event::issue::{IssueAction, IssueCommand, IssueEdit, MAX_BODY_BYTES, MAX_LABELS};
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::{CANONICAL_CODEC_VERSION, RepositoryAuthorityHeadId};
use fgit_wire::smart_http::{BodyFraming, head::Envelope};

use super::ApiError;

pub(super) const MAX_FORM_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct Page {
    pub after: u64,
    pub limit: u16,
    pub expected_head: Option<RepositoryAuthorityHeadId>,
}

#[derive(Debug)]
pub enum Operation<'a> {
    List(Page),
    Show {
        number: IssueNumber,
        page: Page,
    },
    Search,
    Mutate {
        number: IssueNumber,
        action: &'a str,
    },
}

#[derive(Debug)]
pub struct Request<'a> {
    pub repository_route: &'a str,
    pub operation: Operation<'a>,
}

impl<'a> Request<'a> {
    pub(crate) fn parse(head: &Envelope<'a>) -> Result<Option<Self>, ApiError> {
        let (path, query) = head
            .target
            .split_once('?')
            .map_or((head.target, None), |(p, q)| (p, Some(q)));
        let Some((repository_route, suffix)) = path.split_once("/api/v1/issues") else {
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
        let operation = if head.method == "GET" {
            if !matches!(
                head.body,
                BodyFraming::Empty | BodyFraming::ContentLength(0)
            ) || head.expect_continue
            {
                return Err(ApiError::bad("body_not_allowed"));
            }
            if suffix.is_empty() {
                Operation::List(page(query, "after")?)
            } else {
                let number = suffix.strip_prefix('/').ok_or_else(ApiError::not_found)?;
                Operation::Show {
                    number: issue_number(number)?,
                    page: page(query, "after_version")?,
                }
            }
        } else if head.method == "POST" {
            if query.is_some() || head.body == BodyFraming::Empty {
                return Err(ApiError::bad("invalid_mutation_envelope"));
            }
            if !head.content_type.is_some_and(|value| {
                value.eq_ignore_ascii_case("application/x-www-form-urlencoded")
                    || value
                        .eq_ignore_ascii_case("application/x-www-form-urlencoded; charset=utf-8")
            }) {
                return Err(ApiError::media());
            }
            if matches!(head.body, BodyFraming::ContentLength(n) if n > MAX_FORM_BYTES as u64) {
                return Err(ApiError::too_large());
            }
            if suffix == "/search" {
                Operation::Search
            } else {
                let (number, action) = suffix
                    .strip_prefix('/')
                    .and_then(|s| s.split_once('/'))
                    .ok_or_else(ApiError::not_found)?;
                if !matches!(action, "open" | "edit" | "close" | "reopen" | "comment") {
                    return Err(ApiError::not_found());
                }
                Operation::Mutate {
                    number: issue_number(number)?,
                    action,
                }
            }
        } else {
            return Err(ApiError::method());
        };
        Ok(Some(Self {
            repository_route,
            operation,
        }))
    }

    pub(crate) const fn is_mutation(&self) -> bool {
        matches!(self.operation, Operation::Mutate { .. })
    }

    pub(super) fn command(&self, body: &[u8]) -> Result<IssueCommand, ApiError> {
        let Operation::Mutate { number, action } = self.operation else {
            return Err(ApiError::bad("not_a_mutation"));
        };
        let fields = form(body, MAX_LABELS + 4)?;
        let (mut title, mut text, mut version, mut clear_labels) = (None, None, None, None);
        let mut labels = Vec::new();
        for (key, value) in fields {
            match key.as_str() {
                "expected_version" => set_once(&mut version, decimal(&value)?)?,
                "title" if matches!(action, "open" | "edit") => set_once(&mut title, value)?,
                "body" if matches!(action, "open" | "edit" | "comment") => {
                    set_once(&mut text, value)?;
                }
                "label" if matches!(action, "open" | "edit") => {
                    if labels.len() == MAX_LABELS {
                        return Err(ApiError::too_large());
                    }
                    labels.push(value);
                }
                "clear_labels" if action == "edit" && value == "true" => {
                    set_once(&mut clear_labels, true)?;
                }
                _ => return Err(ApiError::bad("unknown_or_inapplicable_field")),
            }
        }
        let version = version.ok_or_else(|| ApiError::bad("expected_version_required"))?;
        if (action == "open") != (version == 0) {
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
        if clear_labels.is_some() && !labels.is_empty() {
            return Err(ApiError::bad("conflicting_label_fields"));
        }
        labels.sort();
        if labels.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ApiError::bad("duplicate_label"));
        }
        let action = match action {
            "open" => IssueAction::Open {
                title: title.ok_or_else(|| ApiError::bad("title_required"))?,
                body: text.ok_or_else(|| ApiError::bad("body_required"))?,
                labels,
            },
            "edit" => IssueAction::Edit(IssueEdit {
                title,
                body: text,
                labels: if clear_labels.is_some() || !labels.is_empty() {
                    Some(labels)
                } else {
                    None
                },
            }),
            "comment" => IssueAction::Comment {
                body: text.ok_or_else(|| ApiError::bad("body_required"))?,
            },
            "close" => IssueAction::Close,
            "reopen" => IssueAction::Reopen,
            _ => return Err(ApiError::not_found()),
        };
        action
            .validate()
            .map_err(|_| ApiError::bad("invalid_issue_content"))?;
        Ok(IssueCommand {
            number,
            expected_version,
            action,
        })
    }
}

fn issue_number(text: &str) -> Result<IssueNumber, ApiError> {
    IssueNumber::try_new(decimal(text)?).ok_or_else(|| ApiError::bad("invalid_issue_number"))
}
fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), ApiError> {
    if slot.replace(value).is_some() {
        return Err(ApiError::bad("duplicate_field"));
    }
    Ok(())
}
pub(super) fn decimal(text: &str) -> Result<u64, ApiError> {
    if text.is_empty()
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(ApiError::bad("invalid_integer"));
    }
    text.parse().map_err(|_| ApiError::bad("integer_overflow"))
}
pub(super) fn page(query: Option<&str>, cursor: &str) -> Result<Page, ApiError> {
    let (mut after, mut limit, mut expected) = (None, None, None);
    for (name, value) in form(query.unwrap_or("").as_bytes(), 3)? {
        if name == cursor {
            set_once(&mut after, decimal(&value)?)?;
        } else if name == "limit" {
            set_once(&mut limit, decimal(&value)?)?;
        } else if name == "expected_head" {
            set_once(&mut expected, parse_head_token(&value)?)?;
        } else {
            return Err(ApiError::bad("unknown_query_field"));
        }
    }
    let (after, limit) = (after.unwrap_or(0), limit.unwrap_or(50));
    if !(1..=100).contains(&limit) {
        return Err(ApiError::bad("invalid_page_limit"));
    }
    if after != 0 && expected.is_none() {
        return Err(ApiError::bad("snapshot_required"));
    }
    Ok(Page {
        after,
        limit: limit as u16,
        expected_head: expected,
    })
}

pub(super) fn form(bytes: &[u8], maximum_fields: usize) -> Result<Vec<(String, String)>, ApiError> {
    if bytes.len() > MAX_FORM_BYTES {
        return Err(ApiError::too_large());
    }
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    for field in bytes.split(|&b| b == b'&') {
        if result.len() == maximum_fields {
            return Err(ApiError::too_large());
        }
        let equals = field
            .iter()
            .position(|&b| b == b'=')
            .ok_or_else(|| ApiError::bad("invalid_form"))?;
        let key = decode(&field[..equals], 32)?;
        // A lowercase letter, then lowercase letters, digits or underscores:
        // documented names such as `artifact_sha256` must parse.
        if !key.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
            || !key
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(ApiError::bad("invalid_field_name"));
        }
        let value = decode(&field[equals + 1..], MAX_BODY_BYTES)?;
        result.try_reserve(1).map_err(|_| ApiError::unavailable())?;
        result.push((key, value));
    }
    Ok(result)
}
fn decode(bytes: &[u8], maximum: usize) -> Result<String, ApiError> {
    let mut out = Vec::new();
    out.try_reserve_exact(bytes.len().min(maximum))
        .map_err(|_| ApiError::unavailable())?;
    let mut cursor = 0;
    while cursor < bytes.len() {
        if out.len() == maximum {
            return Err(ApiError::too_large());
        }
        let byte = match bytes[cursor] {
            b'+' => b' ',
            b'%' => {
                let first = *bytes
                    .get(cursor + 1)
                    .ok_or_else(|| ApiError::bad("invalid_percent_escape"))?;
                let second = *bytes
                    .get(cursor + 2)
                    .ok_or_else(|| ApiError::bad("invalid_percent_escape"))?;
                cursor += 2;
                (digit(first)? << 4) | digit(second)?
            }
            byte => byte,
        };
        if byte == 0 {
            return Err(ApiError::bad("nul_not_allowed"));
        }
        out.push(byte);
        cursor += 1;
    }
    String::from_utf8(out).map_err(|_| ApiError::bad("invalid_utf8"))
}
fn digit(byte: u8) -> Result<u8, ApiError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(ApiError::bad("invalid_percent_escape")),
    }
}
pub(super) fn parse_head_token(text: &str) -> Result<RepositoryAuthorityHeadId, ApiError> {
    let (algorithm, digest) = text
        .strip_prefix("alg:")
        .and_then(|text| text.split_once(':'))
        .ok_or_else(|| ApiError::bad("invalid_snapshot_token"))?;
    let algorithm = DigestAlgorithmId::try_new(
        u16::try_from(decimal(algorithm)?).map_err(|_| ApiError::bad("invalid_snapshot_token"))?,
    )
    .map_err(|_| ApiError::bad("invalid_snapshot_token"))?;
    if digest.is_empty()
        || digest.len() > 128
        || digest.len() % 2 != 0
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ApiError::bad("invalid_snapshot_token"));
    }
    let bytes = digest
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok((digit(pair[0])? << 4) | digit(pair[1])?))
        .collect::<Result<Vec<_>, ApiError>>()?;
    let digest =
        DigestBytes::try_new(&bytes).map_err(|_| ApiError::bad("invalid_snapshot_token"))?;
    Ok(RepositoryAuthorityHeadId::from_digest(
        algorithm,
        CANONICAL_CODEC_VERSION,
        digest,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use fgit_wire::smart_http::{HttpLimits, head};

    #[test]
    fn field_names_admit_digits_after_a_leading_lowercase_letter() {
        let fields = form(b"object_format=sha1&artifact_sha256=ab", 4).unwrap();
        assert_eq!(fields[1].0, "artifact_sha256");
        for rejected in [
            b"=x".as_slice(),
            b"2fa=x",
            b"_hidden=x",
            b"Upper=x",
            b"dash-name=x",
        ] {
            assert_eq!(
                form(rejected, 4).unwrap_err().code,
                "invalid_field_name",
                "{}",
                String::from_utf8_lossy(rejected)
            );
        }
    }

    fn command(action: &str, form: &[u8]) -> Result<IssueCommand, ApiError> {
        let bytes = format!(
            "POST /repo.git/api/v1/issues/1/{action} HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n",
            form.len()
        );
        let head = head::parse(bytes.as_bytes(), HttpLimits::default())
            .unwrap()
            .unwrap();
        Request::parse(&head)?.unwrap().command(form)
    }

    #[test]
    fn versioned_forms_preserve_utf8_empty_replacements_and_literal_escapes() {
        let open = command(
            "open",
            b"expected_version=0&title=Hello+%F0%9F%A6%80&body=%252f%0A%22&label=z&label=a",
        )
        .unwrap();
        let IssueAction::Open {
            title,
            body,
            labels,
        } = open.action
        else {
            panic!("open")
        };
        assert_eq!(title, "Hello 🦀");
        assert_eq!(body, "%2f\n\"");
        assert_eq!(labels, ["a", "z"]);
        let edit = command("edit", b"expected_version=1&body=&clear_labels=true").unwrap();
        let IssueAction::Edit(edit) = edit.action else {
            panic!("edit")
        };
        assert_eq!(edit.title, None);
        assert_eq!(edit.body, Some(String::new()));
        assert_eq!(edit.labels, Some(Vec::new()));
    }

    #[test]
    fn credentials_versions_and_ambiguous_fields_cannot_be_smuggled_in_text() {
        for body in [
            b"expected_version=0&title=t&body=b&principal=admin".as_slice(),
            b"expected_version=0&expected_version=1&title=t&body=b",
            b"expected_version=00&title=t&body=b",
            b"expected_version=1&title=t&body=b",
            b"expected_version=0&title=t&body=%FF",
            b"expected_version=0&title=t&body=%00",
            b"expected_version=0&title=t&body=%",
            b"expected_version=0&title=t&body=b&label=a&label=a",
        ] {
            assert!(command("open", body).is_err());
        }
        assert!(command("close", b"expected_version=1&body=ignored").is_err());
        assert!(command("edit", b"expected_version=1").is_err());
        assert!(command("edit", b"expected_version=1&clear_labels=true&label=a").is_err());
        assert!(command("comment", b"expected_version=18446744073709551615&body=x").is_err());
    }

    #[test]
    fn paging_requires_an_explicit_basis_and_rejects_unknown_or_duplicate_parameters() {
        for query in [
            "after=1",
            "limit=0",
            "limit=101",
            "limit=1&limit=2",
            "principal=admin",
            "after_version=1",
        ] {
            assert!(page(Some(query), "after").is_err());
        }
        assert_eq!(page(Some("limit=2"), "after").unwrap().limit, 2);
        assert_eq!(page(None, "after_version").unwrap().after, 0);
    }
}
