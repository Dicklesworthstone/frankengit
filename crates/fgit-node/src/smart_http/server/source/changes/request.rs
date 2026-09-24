//! Explicit source-edit coordinates. No implicit current branch, author,
//! timestamp, expected-old refresh, force flag, or caller-supplied identity.

use super::super::super::issues::{ApiError, parse_decimal, parse_form};
use super::super::super::pulls::{SourceUploadKind, source_upload_boundary};
use fgit_forge::preparation::MergeMetadata;
use fgit_types::{GitHashAlgorithm, GitOid, RefName};
use fgit_wire::smart_http::{BodyFraming, head::Envelope};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Operation {
    Prepare,
    Inspect,
    Apply,
}
#[derive(Debug)]
pub(in crate::smart_http::server::source) struct Request<'a> {
    pub(in crate::smart_http::server::source) repository_route: &'a str,
    pub(super) operation: Operation,
    pub(super) boundary: &'a str,
}
impl<'a> Request<'a> {
    pub(in crate::smart_http::server::source) fn parse(
        head: &Envelope<'a>,
    ) -> Result<Option<Self>, ApiError> {
        let (path, query) = head
            .target
            .split_once('?')
            .map_or((head.target, None), |(path, query)| (path, Some(query)));
        let Some((repository_route, action)) = path.split_once("/api/v1/source/") else {
            return Ok(None);
        };
        let operation = match action {
            "prepare" => Operation::Prepare,
            "inspect" => Operation::Inspect,
            "apply" => Operation::Apply,
            _ => return Ok(None),
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
        if head.method != "POST" {
            return Err(ApiError::method());
        }
        if query.is_some() || head.body == BodyFraming::Empty {
            return Err(ApiError::bad("invalid_source_change_envelope"));
        }
        if head.git_protocol.is_some() {
            return Err(ApiError::bad("git_protocol_not_applicable"));
        }
        let boundary = source_upload_boundary(head.content_type.ok_or_else(ApiError::media)?)?;
        let request = Self {
            repository_route,
            operation,
            boundary,
        };
        if matches!(head.body, BodyFraming::ContentLength(n) if n > request.kind().maximum() as u64)
        {
            return Err(ApiError::too_large());
        }
        Ok(Some(request))
    }
    pub(in crate::smart_http::server::source) fn is_mutation(&self) -> bool {
        self.operation == Operation::Apply
    }
    pub(super) const fn kind(&self) -> SourceUploadKind {
        match self.operation {
            Operation::Prepare => SourceUploadKind::Patch,
            _ => SourceUploadKind::Bundle,
        }
    }
    pub(super) fn command(
        &self,
        bytes: &[u8],
        format: GitHashAlgorithm,
    ) -> Result<Command, ApiError> {
        let mut fields = BTreeMap::new();
        for (name, value) in parse_form(bytes, 7)? {
            let common = matches!(name.as_str(), "ref" | "object_format" | "expected_commit");
            let applicable = match self.operation {
                Operation::Prepare => matches!(
                    name.as_str(),
                    "author" | "committer" | "timestamp" | "message"
                ),
                Operation::Inspect | Operation::Apply => name == "candidate_commit",
            };
            if !common && !applicable {
                return Err(ApiError::bad("unknown_source_change_field"));
            }
            if fields.insert(name, value).is_some() {
                return Err(ApiError::bad("duplicate_field"));
            }
        }
        if take(&mut fields, "object_format")? != format.as_str() {
            return Err(ApiError::bad("object_format_mismatch"));
        }
        let reference = RefName::try_new(take(&mut fields, "ref")?.as_bytes())
            .map_err(|_| ApiError::bad("invalid_ref"))?;
        if !reference.as_bytes().starts_with(b"refs/heads/") || reference.as_bytes().len() > 4096 {
            return Err(ApiError::bad("source_change_requires_branch"));
        }
        let base = oid(&take(&mut fields, "expected_commit")?, format)?;
        match self.operation {
            Operation::Prepare => {
                let metadata = MergeMetadata {
                    author: take(&mut fields, "author")?,
                    committer: take(&mut fields, "committer")?,
                    timestamp: parse_decimal(&take(&mut fields, "timestamp")?)?,
                    message: take(&mut fields, "message")?.into_bytes(),
                };
                metadata
                    .validate()
                    .map_err(|_| ApiError::bad("invalid_commit_metadata"))?;
                Ok(Command::Prepare {
                    reference,
                    base,
                    metadata,
                })
            }
            Operation::Inspect | Operation::Apply => {
                let candidate = oid(&take(&mut fields, "candidate_commit")?, format)?;
                if candidate == base {
                    return Err(ApiError::bad("candidate_equals_parent"));
                }
                Ok(Command::Candidate {
                    reference,
                    base,
                    candidate,
                })
            }
        }
    }
}
#[derive(Debug)]
pub(super) enum Command {
    Prepare {
        reference: RefName,
        base: GitOid,
        metadata: MergeMetadata,
    },
    Candidate {
        reference: RefName,
        base: GitOid,
        candidate: GitOid,
    },
}
fn take(fields: &mut BTreeMap<String, String>, name: &str) -> Result<String, ApiError> {
    fields
        .remove(name)
        .ok_or_else(|| ApiError::bad("missing_source_change_field"))
}
fn oid(text: &str, format: GitHashAlgorithm) -> Result<GitOid, ApiError> {
    if text.len() != format.digest_len() * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ApiError::bad("invalid_oid"));
    }
    let id = GitOid::from_hex(format, text).map_err(|_| ApiError::bad("invalid_oid"))?;
    if id.is_zero() {
        return Err(ApiError::bad("invalid_oid"));
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_wire::smart_http::{HttpLimits, head};
    fn request(operation: Operation) -> Request<'static> {
        Request {
            repository_route: "/repo.git",
            operation,
            boundary: "source",
        }
    }
    fn form(format: GitHashAlgorithm) -> String {
        format!(
            "object_format={}&ref=refs/heads/main&expected_commit={}",
            format.as_str(),
            "a".repeat(format.digest_len() * 2)
        )
    }
    #[test]
    fn explicit_metadata_and_candidate_hash_domains_are_preserved() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let body = form(format)
                + "&author=Alice+%3Ca%40example.invalid%3E&committer=Bot+%3Cb%40example.invalid%3E&timestamp=1&message=Exact%0D%0A%252f";
            let Command::Prepare { base, metadata, .. } = request(Operation::Prepare)
                .command(body.as_bytes(), format)
                .unwrap()
            else {
                panic!("prepare");
            };
            assert_eq!(base.algorithm(), format);
            assert_eq!(metadata.message, b"Exact\r\n%2f");
            let body = form(format) + "&candidate_commit=" + &"b".repeat(format.digest_len() * 2);
            for operation in [Operation::Inspect, Operation::Apply] {
                assert!(matches!(
                    request(operation).command(body.as_bytes(), format),
                    Ok(Command::Candidate { .. })
                ));
            }
        }
    }
    #[test]
    fn commands_cannot_infer_identity_force_or_missing_preconditions() {
        let valid = form(GitHashAlgorithm::Sha1) + "&candidate_commit=" + &"b".repeat(40);
        for body in [
            valid.clone() + "&force=true",
            valid.clone() + "&principal=admin",
            valid.clone() + "&expected_commit=" + &"a".repeat(40),
            valid.replace("refs/heads/main", "refs/tags/tag"),
            valid.replace(&"b".repeat(40), &"a".repeat(40)),
            valid.replace("object_format=sha1", "object_format=sha256"),
            valid.replace("expected_commit=", "ignored="),
            valid.replace(&"b".repeat(40), &"0".repeat(40)),
        ] {
            assert!(
                request(Operation::Apply)
                    .command(body.as_bytes(), GitHashAlgorithm::Sha1)
                    .is_err()
            );
        }
        assert!(
            request(Operation::Prepare)
                .command(
                    form(GitHashAlgorithm::Sha1).as_bytes(),
                    GitHashAlgorithm::Sha1
                )
                .is_err()
        );
    }
    #[test]
    fn source_changes_have_closed_multipart_routes_and_explicit_mutation_semantics() {
        for (action, mutation) in [("prepare", false), ("inspect", false), ("apply", true)] {
            let bytes = format!(
                "POST /repo.git/api/v1/source/{action} HTTP/1.1\r\nHost: local\r\nContent-Type: multipart/form-data; boundary=x\r\nContent-Length: 1\r\n\r\n"
            );
            let envelope = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert_eq!(
                Request::parse(&envelope).unwrap().unwrap().is_mutation(),
                mutation
            );
            for invalid in [
                bytes.replace("POST ", "GET "),
                bytes.replace(&format!("/{action} HTTP"), &format!("/{action}?x=y HTTP")),
                bytes.replace(
                    "multipart/form-data; boundary=x",
                    "application/x-www-form-urlencoded",
                ),
            ] {
                assert_ne!(invalid, bytes);
                let head = head::parse(invalid.as_bytes(), HttpLimits::default())
                    .unwrap()
                    .unwrap();
                assert!(Request::parse(&head).is_err());
            }
        }
    }
}
