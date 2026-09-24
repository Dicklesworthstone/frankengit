//! Initial history has no synthetic parent or implicit branch lease. The
//! caller selects branch absence explicitly and supplies all Git metadata.

use super::super::super::issues::{ApiError, parse_decimal, parse_form, parse_snapshot};
use super::super::super::pulls::{SourceUploadKind, source_upload_boundary};
use fgit_forge::preparation::MergeMetadata;
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RepositoryAuthorityHeadId};
use fgit_wire::smart_http::{BodyFraming, head::Envelope};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Prepare,
    Apply,
}

#[derive(Debug)]
pub struct Request<'a> {
    pub repository_route: &'a str,
    pub boundary: &'a str,
    pub operation: Operation,
}
impl<'a> Request<'a> {
    pub(crate) fn parse(envelope: &Envelope<'a>) -> Result<Option<Self>, ApiError> {
        let (path, query) = envelope
            .target
            .split_once('?')
            .map_or((envelope.target, None), |(path, query)| (path, Some(query)));
        let Some((repository_route, action)) = path.split_once("/api/v1/source/initial/") else {
            return Ok(None);
        };
        let operation = match action {
            "prepare" => Operation::Prepare,
            "apply" => Operation::Apply,
            _ => return Err(ApiError::not_found()),
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
        if envelope.method != "POST" {
            return Err(ApiError::method());
        }
        if query.is_some()
            || envelope.git_protocol.is_some()
            || matches!(
                envelope.body,
                BodyFraming::Empty | BodyFraming::ContentLength(0)
            )
        {
            return Err(ApiError::bad("invalid_initial_envelope"));
        }
        let boundary = source_upload_boundary(envelope.content_type.ok_or_else(ApiError::media)?)?;
        let request = Self {
            repository_route,
            boundary,
            operation,
        };
        if matches!(envelope.body, BodyFraming::ContentLength(n) if n > request.kind().maximum() as u64)
        {
            return Err(ApiError::too_large());
        }
        Ok(Some(request))
    }

    pub(crate) fn is_mutation(&self) -> bool {
        self.operation == Operation::Apply
    }
    pub(super) const fn kind(&self) -> SourceUploadKind {
        match self.operation {
            Operation::Prepare => SourceUploadKind::Patch,
            Operation::Apply => SourceUploadKind::Bundle,
        }
    }

    pub(super) fn command(
        &self,
        bytes: &[u8],
        format: GitHashAlgorithm,
    ) -> Result<Command, ApiError> {
        let mut fields = BTreeMap::new();
        for (name, value) in parse_form(bytes, 9)? {
            let common = matches!(name.as_str(), "object_format" | "ref" | "expected_absent");
            let applicable = match self.operation {
                Operation::Prepare => matches!(
                    name.as_str(),
                    "author" | "committer" | "timestamp" | "message" | "expected_head"
                ),
                Operation::Apply => name == "candidate_commit",
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
        if take(&mut fields, "expected_absent")? != "true" {
            return Err(ApiError::bad("explicit_branch_absence_required"));
        }
        let name = take(&mut fields, "ref")?;
        if name.len() > 4096 || !name.starts_with("refs/heads/") {
            return Err(ApiError::bad("full_branch_required"));
        }
        let reference =
            RefName::try_new(name.as_bytes()).map_err(|_| ApiError::bad("invalid_ref"))?;
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
                let expected_head = fields
                    .remove("expected_head")
                    .map(|value| parse_snapshot(&value))
                    .transpose()?;
                Ok(Command::Prepare {
                    reference,
                    metadata,
                    expected_head,
                })
            }
            Operation::Apply => {
                let text = take(&mut fields, "candidate_commit")?;
                if text.len() != format.digest_len() * 2
                    || !text
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(ApiError::bad("invalid_candidate_commit"));
                }
                let candidate = GitOid::from_hex(format, &text)
                    .map_err(|_| ApiError::bad("invalid_candidate_commit"))?;
                if candidate.is_zero() {
                    return Err(ApiError::bad("invalid_candidate_commit"));
                }
                Ok(Command::Apply {
                    reference,
                    candidate,
                })
            }
        }
    }
}
fn take(fields: &mut BTreeMap<String, String>, key: &str) -> Result<String, ApiError> {
    fields
        .remove(key)
        .ok_or_else(|| ApiError::bad("missing_required_field"))
}

#[derive(Debug)]
pub(super) enum Command {
    Prepare {
        reference: RefName,
        metadata: MergeMetadata,
        expected_head: Option<RepositoryAuthorityHeadId>,
    },
    Apply {
        reference: RefName,
        candidate: GitOid,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_wire::smart_http::{HttpLimits, head};
    const PREPARE: &[u8] = b"object_format=sha1&ref=refs/heads/main&expected_absent=true&author=A+%3Ca%40example.invalid%3E&committer=C+%3Cc%40example.invalid%3E&timestamp=1&message=first%0A";
    fn command(
        operation: Operation,
        bytes: &[u8],
        format: GitHashAlgorithm,
    ) -> Result<Command, ApiError> {
        Request {
            repository_route: "/repo.git",
            boundary: "x",
            operation,
        }
        .command(bytes, format)
    }
    #[test]
    fn preparation_has_explicit_metadata_and_no_parent() {
        let Command::Prepare {
            reference,
            metadata,
            expected_head,
        } = command(Operation::Prepare, PREPARE, GitHashAlgorithm::Sha1).unwrap()
        else {
            panic!("prepare")
        };
        assert_eq!(reference.as_bytes(), b"refs/heads/main");
        assert_eq!(metadata.message, b"first\n");
        assert_eq!(metadata.timestamp, 1);
        assert!(expected_head.is_none());
        for extra in [
            "&expected_commit=0",
            "&principal=owner",
            "&force=true",
            "&expected_absent=true",
            "&candidate_commit=abc",
        ] {
            let mut bytes = PREPARE.to_vec();
            bytes.extend_from_slice(extra.as_bytes());
            assert!(command(Operation::Prepare, &bytes, GitHashAlgorithm::Sha1).is_err());
        }
    }
    #[test]
    fn application_is_creation_only_in_the_exact_native_domain() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let body = format!(
                "object_format={}&ref=refs/heads/new&expected_absent=true&candidate_commit={}",
                format.as_str(),
                "a".repeat(format.digest_len() * 2)
            );
            assert!(command(Operation::Apply, body.as_bytes(), format).is_ok());
            for bad in [
                body.replace("=true", "=false"),
                body.replace("refs/heads/", "refs/tags/"),
                body.replace(
                    &"a".repeat(format.digest_len() * 2),
                    &"0".repeat(format.digest_len() * 2),
                ),
                format!("{body}&expected_head=ignored"),
                format!("{body}&author=ignored"),
            ] {
                assert!(command(Operation::Apply, bad.as_bytes(), format).is_err());
            }
        }
    }
    #[test]
    fn snapshot_pins_are_preparation_preconditions_not_publication_leases() {
        let token = format!("alg:1:{}", "a".repeat(64));
        let mut pinned = PREPARE.to_vec();
        pinned.extend_from_slice(format!("&expected_head={token}").as_bytes());
        let Command::Prepare { expected_head, .. } =
            command(Operation::Prepare, &pinned, GitHashAlgorithm::Sha1).unwrap()
        else {
            panic!("prepare")
        };
        assert_eq!(expected_head, Some(parse_snapshot(&token).unwrap()));
        pinned.extend_from_slice(format!("&expected_head={token}").as_bytes());
        assert!(command(Operation::Prepare, &pinned, GitHashAlgorithm::Sha1).is_err());
        let apply = format!(
            "object_format=sha1&ref=refs/heads/main&expected_absent=true&candidate_commit={}&expected_head={token}",
            "a".repeat(40)
        );
        assert!(command(Operation::Apply, apply.as_bytes(), GitHashAlgorithm::Sha1).is_err());
    }
    #[test]
    fn initial_routes_do_not_steal_existing_source_operations() {
        for (path, mutation) in [
            ("initial/prepare", Some(false)),
            ("initial/apply", Some(true)),
            ("prepare", None),
            ("refs", None),
        ] {
            let bytes = format!(
                "POST /repo.git/api/v1/source/{path} HTTP/1.1\r\nHost: local\r\nContent-Type: multipart/form-data; boundary=x\r\nContent-Length: 1\r\n\r\n"
            );
            let envelope = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert_eq!(
                Request::parse(&envelope)
                    .unwrap()
                    .map(|request| request.is_mutation()),
                mutation
            );
        }
    }
}
