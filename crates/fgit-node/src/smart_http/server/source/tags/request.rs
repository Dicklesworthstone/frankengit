//! Closed tag commands. Raw ref/message bytes have explicit hex encodings;
//! target kind and tagger metadata are claims to verify, never credentials.

use super::super::super::issues::{
    ApiError, MAX_FORM_BYTES, parse_decimal, parse_form, parse_snapshot,
};
use fgit_crypto::GitObjectKind;
use fgit_forge::tags::{
    MAX_TAG_MESSAGE_BYTES, MAX_TAG_NAME_BYTES, TagCommand, TagMetadata, TagReadLimits,
    validate_tag_name,
};
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RepositoryAuthorityHeadId};
use fgit_wire::smart_http::{BodyFraming, head::Envelope};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Operation {
    Lightweight,
    Annotated,
    Delete,
    Inspect,
}
impl Operation {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Lightweight => "lightweight",
            Self::Annotated => "annotated",
            Self::Delete => "delete",
            Self::Inspect => "inspect",
        }
    }
}
#[derive(Debug)]
pub(super) struct Request<'a> {
    pub repository_route: &'a str,
    pub operation: Operation,
}
#[derive(Debug)]
pub(super) struct Inspection {
    pub reference: RefName,
    pub expected_head: Option<RepositoryAuthorityHeadId>,
    pub expected_object: Option<GitOid>,
    pub limits: TagReadLimits,
}
#[derive(Debug)]
pub(super) enum Command {
    Mutate(TagCommand),
    Inspect(Inspection),
}

impl<'a> Request<'a> {
    pub(super) fn parse(head: &Envelope<'a>) -> Result<Option<Self>, ApiError> {
        let (path, query) = head
            .target
            .split_once('?')
            .map_or((head.target, None), |(path, query)| (path, Some(query)));
        let Some((repository_route, action)) = path.split_once("/api/v1/source/tags/") else {
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
        let operation = match action {
            "lightweight" => Operation::Lightweight,
            "annotated" => Operation::Annotated,
            "delete" => Operation::Delete,
            "inspect" => Operation::Inspect,
            _ => return Err(ApiError::not_found()),
        };
        if head.method != "POST" {
            return Err(ApiError::method());
        }
        if query.is_some()
            || head.git_protocol.is_some()
            || matches!(
                head.body,
                BodyFraming::Empty | BodyFraming::ContentLength(0)
            )
        {
            return Err(ApiError::bad("invalid_tag_envelope"));
        }
        if !head.content_type.is_some_and(|media| {
            media.eq_ignore_ascii_case("application/x-www-form-urlencoded")
                || media.eq_ignore_ascii_case("application/x-www-form-urlencoded; charset=utf-8")
        }) {
            return Err(ApiError::media());
        }
        if matches!(head.body, BodyFraming::ContentLength(length) if length > MAX_FORM_BYTES as u64)
        {
            return Err(ApiError::too_large());
        }
        Ok(Some(Self {
            repository_route,
            operation,
        }))
    }

    pub(super) fn is_mutation(&self) -> bool {
        self.operation != Operation::Inspect
    }

    pub(super) fn command(
        &self,
        bytes: &[u8],
        format: GitHashAlgorithm,
    ) -> Result<Command, ApiError> {
        let mut fields = BTreeMap::new();
        for (name, value) in parse_form(bytes, 10)? {
            let common = matches!(name.as_str(), "object_format" | "ref" | "ref_hex");
            let applicable = match self.operation {
                Operation::Lightweight => name == "target",
                Operation::Annotated => matches!(
                    name.as_str(),
                    "target" | "target_kind" | "tagger" | "timestamp" | "message_hex"
                ),
                Operation::Delete => name == "expected_object",
                Operation::Inspect => matches!(
                    name.as_str(),
                    "expected_head"
                        | "expected_object"
                        | "max_tags"
                        | "max_object_bytes"
                        | "max_total_bytes"
                ),
            };
            if !common && !applicable {
                return Err(ApiError::bad("unknown_or_inapplicable_field"));
            }
            if fields.insert(name, value).is_some() {
                return Err(ApiError::bad("duplicate_field"));
            }
        }
        if take(&mut fields, "object_format")? != format.as_str() {
            return Err(ApiError::bad("object_format_mismatch"));
        }
        let name = match (fields.remove("ref"), fields.remove("ref_hex")) {
            (Some(text), None) => text.into_bytes(),
            (None, Some(text)) => unhex(&text, MAX_TAG_NAME_BYTES)?,
            _ => return Err(ApiError::bad("one_tag_reference_required")),
        };
        let name = RefName::try_new(&name).map_err(|_| ApiError::bad("invalid_tag_name"))?;
        validate_tag_name(&name).map_err(|_| ApiError::bad("invalid_tag_name"))?;
        if self.operation == Operation::Inspect {
            let expected_head = fields
                .remove("expected_head")
                .map(|text| parse_snapshot(&text))
                .transpose()?;
            let expected_object = fields
                .remove("expected_object")
                .map(|text| oid(&text, format))
                .transpose()?;
            let defaults = TagReadLimits::default();
            let limits = TagReadLimits {
                max_tags: bound(&mut fields, "max_tags", defaults.max_tags)?,
                max_object_bytes: bound(
                    &mut fields,
                    "max_object_bytes",
                    defaults.max_object_bytes,
                )?,
                max_total_bytes: bound(&mut fields, "max_total_bytes", defaults.max_total_bytes)?,
            };
            limits
                .validate()
                .map_err(|_| ApiError::bad("invalid_tag_limits"))?;
            return Ok(Command::Inspect(Inspection {
                reference: name,
                expected_head,
                expected_object,
                limits,
            }));
        }
        let command = match self.operation {
            Operation::Lightweight => TagCommand::Lightweight {
                name,
                target: oid(&take(&mut fields, "target")?, format)?,
            },
            Operation::Delete => TagCommand::Delete {
                name,
                expected: oid(&take(&mut fields, "expected_object")?, format)?,
            },
            Operation::Annotated => TagCommand::Annotated {
                name,
                target: oid(&take(&mut fields, "target")?, format)?,
                target_kind: match take(&mut fields, "target_kind")?.as_str() {
                    "commit" => GitObjectKind::Commit,
                    "tree" => GitObjectKind::Tree,
                    "blob" => GitObjectKind::Blob,
                    "tag" => GitObjectKind::Tag,
                    _ => return Err(ApiError::bad("invalid_target_kind")),
                },
                metadata: TagMetadata {
                    tagger: take(&mut fields, "tagger")?,
                    timestamp: parse_decimal(&take(&mut fields, "timestamp")?)?,
                    message: unhex(&take(&mut fields, "message_hex")?, MAX_TAG_MESSAGE_BYTES)?,
                },
            },
            Operation::Inspect => return Err(ApiError::bad("invalid_tag_operation")),
        };
        // Native validation owns metadata and native object construction. This
        // pure check neither validates target visibility/kind nor stages bytes.
        command
            .prepare(format)
            .map_err(|_| ApiError::bad("invalid_tag_command"))?;
        Ok(Command::Mutate(command))
    }
}
fn take(fields: &mut BTreeMap<String, String>, name: &str) -> Result<String, ApiError> {
    fields
        .remove(name)
        .ok_or_else(|| ApiError::bad("missing_field"))
}
fn bound(
    fields: &mut BTreeMap<String, String>,
    name: &str,
    maximum: usize,
) -> Result<usize, ApiError> {
    let Some(text) = fields.remove(name) else {
        return Ok(maximum);
    };
    let value =
        usize::try_from(parse_decimal(&text)?).map_err(|_| ApiError::bad("invalid_tag_limits"))?;
    if value == 0 || value > maximum {
        return Err(ApiError::bad("invalid_tag_limits"));
    }
    Ok(value)
}
fn oid(text: &str, format: GitHashAlgorithm) -> Result<GitOid, ApiError> {
    if text.len() != format.digest_len() * 2
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApiError::bad("invalid_object_id"));
    }
    let id = GitOid::from_hex(format, text).map_err(|_| ApiError::bad("invalid_object_id"))?;
    if id.is_zero() {
        return Err(ApiError::bad("zero_object_id"));
    }
    Ok(id)
}
fn unhex(text: &str, maximum: usize) -> Result<Vec<u8>, ApiError> {
    if text.len() > maximum * 2 {
        return Err(ApiError::too_large());
    }
    if !text.len().is_multiple_of(2) {
        return Err(ApiError::bad("invalid_hex"));
    }
    let digit = |byte| match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(ApiError::bad("invalid_hex")),
    };
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok((digit(pair[0])? << 4) | digit(pair[1])?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(operation: Operation, body: &str) -> Result<Command, ApiError> {
        Request {
            repository_route: "/repo.git",
            operation,
        }
        .command(body.as_bytes(), GitHashAlgorithm::Sha256)
    }
    fn basic() -> String {
        format!(
            "object_format=sha256&ref=refs/tags/v1&target={}",
            "a".repeat(64)
        )
    }
    #[test]
    fn annotations_preserve_raw_names_messages_and_explicit_zero_timestamp() {
        let body = basic().replace("ref=refs/tags/v1", "ref_hex=726566732f746167732f76ff")
            + "&target_kind=commit&tagger=Author+%3Ca%40b%3E&timestamp=0&message_hex=ff0d0a78";
        let Command::Mutate(TagCommand::Annotated { name, metadata, .. }) =
            parse(Operation::Annotated, &body).unwrap()
        else {
            panic!("annotation")
        };
        assert_eq!(name.as_bytes(), b"refs/tags/v\xff");
        assert_eq!(metadata.timestamp, 0);
        assert_eq!(metadata.message, b"\xff\r\nx");
        assert!(
            parse(
                Operation::Annotated,
                &body.replace("message_hex=ff0d0a78", "message_hex=")
            )
            .is_ok()
        );
    }
    #[test]
    fn creation_deletion_and_inspection_have_disjoint_expectations() {
        assert!(parse(Operation::Lightweight, &basic()).is_ok());
        assert!(
            parse(
                Operation::Delete,
                &basic().replace("target=", "expected_object=")
            )
            .is_ok()
        );
        assert!(parse(Operation::Inspect, "object_format=sha256&ref=refs/tags/v1").is_ok());
        for suffix in [
            "&force=true",
            "&expected_object=absent",
            "&principal=owner",
            "&tagger=a",
            "&ref_hex=78",
        ] {
            assert!(parse(Operation::Lightweight, &(basic() + suffix)).is_err());
        }
        assert!(parse(Operation::Delete, &basic()).is_err());
        assert!(parse(Operation::Annotated, &basic()).is_err());
    }
    #[test]
    fn wrong_domains_duplicate_fields_and_non_tag_names_refuse() {
        for body in [
            basic().replace("sha256", "sha1"),
            basic().replace("refs/tags/v1", "refs/heads/main"),
            basic().replace(&"a".repeat(64), &"0".repeat(64)),
            basic().replace(&"a".repeat(64), &"A".repeat(64)),
            basic() + "&target=" + &"b".repeat(64),
        ] {
            assert!(parse(Operation::Lightweight, &body).is_err());
        }
        assert!(unhex("aa0", 4).is_err());
        assert!(unhex("AA", 4).is_err());
        assert!(unhex("aaaa", 1).is_err());
    }
    #[test]
    fn inspection_limits_can_only_narrow() {
        let base = "object_format=sha256&ref=refs/tags/v1";
        assert!(
            parse(
                Operation::Inspect,
                &(base.to_owned() + "&max_tags=1&max_total_bytes=16")
            )
            .is_ok()
        );
        for field in [
            "max_tags=65",
            "max_tags=0",
            "max_tags=01",
            "max_total_bytes=4194305",
            "max_object_bytes=1048577",
        ] {
            assert!(parse(Operation::Inspect, &format!("{base}&{field}")).is_err());
        }
    }
    #[test]
    fn invalid_envelopes_refuse_before_body_intake() {
        for (path, method, headers) in [
            ("/repo.git/api/v1/source/tags/inspect", "GET", ""),
            ("/repo.git/api/v1/source/tags/delete?force=true", "POST", ""),
            (
                "/repo.git/api/v1/source/tags/annotated",
                "POST",
                "Git-Protocol: version=2\r\n",
            ),
        ] {
            let bytes = format!(
                "{method} {path} HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n{headers}\r\n"
            );
            let head = fgit_wire::smart_http::head::parse(bytes.as_bytes(), Default::default())
                .unwrap()
                .unwrap();
            assert!(Request::parse(&head).is_err());
        }
    }
}
