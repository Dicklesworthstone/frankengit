//! Preparation and resolution are body-bearing reads. Client-selected PR
//! coordinates and commit metadata are explicit; file parts are bytes only.

use super::super::super::issues::{ApiError, MAX_FORM_BYTES, parse_decimal, parse_form};
use super::super::collaboration::resolution_upload::{self, FileParts};
use fgit_forge::event::review::ReviewSubject;
use fgit_forge::preparation::resolution::{
    ConflictResolution, ResolutionChoice, ResolutionError, validate_resolutions,
};
use fgit_forge::preparation::{MergeMetadata, PreparationLimits};
use fgit_forge::{AggregateVersion, PullRequestNumber};
use fgit_types::{GitHashAlgorithm, GitOid, PolicyEpoch, RefName};
use fgit_wire::smart_http::{BodyFraming, head::Envelope};
use std::collections::BTreeMap;

#[derive(Debug)]
pub(crate) struct Request<'a> {
    pub repository_route: &'a str,
    pub number: PullRequestNumber,
    pub resolution: bool,
    pub boundary: Option<&'a str>,
}

#[derive(Debug)]
pub(super) struct ResolutionCommand {
    pub subject: ReviewSubject,
    pub metadata: MergeMetadata,
    pub base: GitOid,
    pub choices: Vec<ConflictResolution>,
}

impl<'a> Request<'a> {
    pub(crate) fn parse(head: &Envelope<'a>) -> Result<Option<Self>, ApiError> {
        let (path, query) = head
            .target
            .split_once('?')
            .map_or((head.target, None), |(p, q)| (p, Some(q)));
        let Some((repository_route, suffix)) = path.split_once("/api/v1/pulls/") else {
            return Ok(None);
        };
        let Some((number, action)) = suffix.split_once('/') else {
            return Ok(None);
        };
        if !matches!(action, "prepare" | "resolve")
            && !action.starts_with("prepare/")
            && !action.starts_with("resolve/")
        {
            return Ok(None);
        }
        if !matches!(action, "prepare" | "resolve")
            || repository_route.len() < 2
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
            return Err(ApiError::bad("invalid_preparation_envelope"));
        }
        if head.git_protocol.is_some() {
            return Err(ApiError::bad("git_protocol_not_applicable"));
        }
        let resolution = action == "resolve";
        let content = head.content_type.ok_or_else(ApiError::media)?;
        let boundary = if content.eq_ignore_ascii_case("application/x-www-form-urlencoded")
            || content.eq_ignore_ascii_case("application/x-www-form-urlencoded; charset=utf-8")
        {
            None
        } else if resolution {
            Some(resolution_upload::boundary(content)?)
        } else {
            return Err(ApiError::media());
        };
        let maximum = if boundary.is_some() {
            resolution_upload::MAX_UPLOAD_BYTES
        } else {
            MAX_FORM_BYTES
        };
        if matches!(head.body, BodyFraming::ContentLength(n) if n > maximum as u64) {
            return Err(ApiError::too_large());
        }
        let number = PullRequestNumber::try_new(parse_decimal(number)?)
            .ok_or_else(|| ApiError::bad("invalid_pull_request_number"))?;
        Ok(Some(Self {
            repository_route,
            number,
            resolution,
            boundary,
        }))
    }

    pub(super) fn command(
        &self,
        bytes: &[u8],
        format: GitHashAlgorithm,
    ) -> Result<(ReviewSubject, MergeMetadata), ApiError> {
        // A resolution can never fall back to automatic construction.
        if self.resolution {
            return Err(ApiError::bad("resolution_choices_required"));
        }
        let (fields, _) = self.fields(bytes)?;
        self.subject_and_metadata(fields, format)
    }

    pub(super) fn resolved_command(
        &self,
        bytes: &[u8],
        mut files: FileParts<'_>,
        format: GitHashAlgorithm,
    ) -> Result<ResolutionCommand, ApiError> {
        if !self.resolution {
            return Err(ApiError::bad("not_a_resolution_request"));
        }
        let (mut fields, descriptors) = self.fields(bytes)?;
        let base = oid(&take(&mut fields, "merge_base")?, format)?;
        let (subject, metadata) = self.subject_and_metadata(fields, format)?;
        let mut choices = Vec::new();
        let mut retained_bytes = 0usize;
        for descriptor in descriptors {
            let mut fields = descriptor.split(':');
            let path = path_bytes(
                fields
                    .next()
                    .ok_or_else(|| ApiError::bad("invalid_resolution"))?,
            )?;
            let action = fields
                .next()
                .ok_or_else(|| ApiError::bad("invalid_resolution"))?;
            retained_bytes = retained_bytes
                .checked_add(path.len())
                .ok_or_else(ApiError::too_large)?;
            let choice = match action {
                "base" => ResolutionChoice::Base,
                "ours" => ResolutionChoice::Ours,
                "theirs" => ResolutionChoice::Theirs,
                "delete" => ResolutionChoice::Delete,
                "file" => {
                    let mode = match fields.next() {
                        Some("100644") => 0o100644,
                        Some("100755") => 0o100755,
                        _ => return Err(ApiError::bad("invalid_resolution_mode")),
                    };
                    let name = fields
                        .next()
                        .ok_or_else(|| ApiError::bad("resolution_file_required"))?;
                    if !resolution_upload::file_name(name) {
                        return Err(ApiError::bad("invalid_resolution_file"));
                    }
                    let content = files
                        .remove(name)
                        .ok_or_else(|| ApiError::bad("missing_or_reused_resolution_file"))?;
                    retained_bytes = retained_bytes
                        .checked_add(content.len())
                        .ok_or_else(ApiError::too_large)?;
                    if content.len() > resolution_upload::MAX_FILE_BYTES
                        || retained_bytes > resolution_upload::MAX_CONTENT_BYTES
                    {
                        return Err(ApiError::too_large());
                    }
                    let mut bytes = Vec::new();
                    bytes
                        .try_reserve_exact(content.len())
                        .map_err(|_| ApiError::unavailable())?;
                    bytes.extend_from_slice(content);
                    ResolutionChoice::File { mode, bytes }
                }
                _ => return Err(ApiError::bad("invalid_resolution_choice")),
            };
            if fields.next().is_some() {
                return Err(ApiError::bad("invalid_resolution"));
            }
            if retained_bytes > resolution_upload::MAX_CONTENT_BYTES {
                return Err(ApiError::too_large());
            }
            choices
                .try_reserve(1)
                .map_err(|_| ApiError::unavailable())?;
            choices.push(ConflictResolution { path, choice });
        }
        if !files.is_empty() {
            return Err(ApiError::bad("unreferenced_resolution_file"));
        }
        choices.sort_by(|left, right| left.path.cmp(&right.path));
        validate_resolutions(&choices, PreparationLimits::default()).map_err(
            |error| match error {
                ResolutionError::Budget => ApiError::too_large(),
                _ => ApiError::bad("invalid_resolution_set"),
            },
        )?;
        Ok(ResolutionCommand {
            subject,
            metadata,
            base,
            choices,
        })
    }

    fn fields(&self, bytes: &[u8]) -> Result<(BTreeMap<String, String>, Vec<String>), ApiError> {
        let mut fields = BTreeMap::new();
        let mut resolutions = Vec::new();
        let maximum = if self.resolution {
            12 + resolution_upload::MAX_FILES
        } else {
            11
        };
        for (name, value) in parse_form(bytes, maximum)? {
            if name == "resolution" && self.resolution {
                if resolutions.len() == resolution_upload::MAX_FILES {
                    return Err(ApiError::too_large());
                }
                resolutions.push(value);
                continue;
            }
            if !matches!(
                name.as_str(),
                "object_format"
                    | "pull_request_version"
                    | "policy_epoch"
                    | "source_ref"
                    | "target_ref"
                    | "source_tip"
                    | "target_tip"
                    | "author"
                    | "committer"
                    | "timestamp"
                    | "message"
            ) && !(name == "merge_base" && self.resolution)
            {
                return Err(ApiError::bad("unknown_preparation_field"));
            }
            if fields.insert(name, value).is_some() {
                return Err(ApiError::bad("duplicate_field"));
            }
        }
        Ok((fields, resolutions))
    }

    fn subject_and_metadata(
        &self,
        mut fields: BTreeMap<String, String>,
        format: GitHashAlgorithm,
    ) -> Result<(ReviewSubject, MergeMetadata), ApiError> {
        if take(&mut fields, "object_format")? != format.as_str() {
            return Err(ApiError::bad("object_format_mismatch"));
        }
        let version =
            AggregateVersion::try_new(parse_decimal(&take(&mut fields, "pull_request_version")?)?)
                .ok_or_else(|| ApiError::bad("invalid_pull_request_version"))?;
        version
            .next()
            .map_err(|_| ApiError::bad("version_exhausted"))?;
        let subject = ReviewSubject {
            pull_request: self.number,
            pull_request_version: version,
            policy_epoch: PolicyEpoch::try_new(parse_decimal(&take(&mut fields, "policy_epoch")?)?)
                .map_err(|_| ApiError::bad("invalid_policy_epoch"))?,
            source_ref: RefName::try_new(take(&mut fields, "source_ref")?.as_bytes())
                .map_err(|_| ApiError::bad("invalid_ref"))?,
            target_ref: RefName::try_new(take(&mut fields, "target_ref")?.as_bytes())
                .map_err(|_| ApiError::bad("invalid_ref"))?,
            source_tip: oid(&take(&mut fields, "source_tip")?, format)?,
            target_tip: oid(&take(&mut fields, "target_tip")?, format)?,
        };
        subject
            .validate()
            .map_err(|_| ApiError::bad("invalid_preparation_subject"))?;
        let metadata = MergeMetadata {
            author: take(&mut fields, "author")?,
            committer: take(&mut fields, "committer")?,
            timestamp: parse_decimal(&take(&mut fields, "timestamp")?)?,
            message: take(&mut fields, "message")?.into_bytes(),
        };
        metadata
            .validate()
            .map_err(|_| ApiError::bad("invalid_commit_metadata"))?;
        if !fields.is_empty() {
            return Err(ApiError::bad("unknown_preparation_field"));
        }
        Ok((subject, metadata))
    }
}
fn take(fields: &mut BTreeMap<String, String>, name: &str) -> Result<String, ApiError> {
    fields
        .remove(name)
        .ok_or_else(|| ApiError::bad("missing_preparation_field"))
}
fn oid(text: &str, format: GitHashAlgorithm) -> Result<GitOid, ApiError> {
    if text.len() != format.digest_len() * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ApiError::bad("invalid_oid"));
    }
    let oid = GitOid::from_hex(format, text).map_err(|_| ApiError::bad("invalid_oid"))?;
    if oid.is_zero() {
        return Err(ApiError::bad("invalid_oid"));
    }
    Ok(oid)
}
fn path_bytes(text: &str) -> Result<Vec<u8>, ApiError> {
    if text.is_empty()
        || text.len() > 2 * PreparationLimits::default().max_path_bytes
        || text.len() % 2 != 0
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ApiError::bad("invalid_resolution_path"));
    }
    let digit = |byte: u8| {
        if byte <= b'9' {
            byte - b'0'
        } else {
            byte - b'a' + 10
        }
    };
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(text.len() / 2)
        .map_err(|_| ApiError::unavailable())?;
    for pair in text.as_bytes().chunks_exact(2) {
        bytes.push((digit(pair[0]) << 4) | digit(pair[1]));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_wire::smart_http::{HttpLimits, head};
    fn request(resolution: bool) -> Request<'static> {
        Request {
            repository_route: "/r.git",
            number: PullRequestNumber::FIRST,
            resolution,
            boundary: None,
        }
    }
    fn form(format: GitHashAlgorithm) -> String {
        format!(
            "object_format={}&pull_request_version=1&policy_epoch=1&source_ref=refs/heads/topic&target_ref=refs/heads/main&source_tip={}&target_tip={}&author=Alice+%3Ca%40example.invalid%3E&committer=Bot+%3Cb%40example.invalid%3E&timestamp=1&message=Exact+%F0%9F%A6%80%0A%252f",
            format.as_str(),
            "a".repeat(format.digest_len() * 2),
            "b".repeat(format.digest_len() * 2)
        )
    }
    #[test]
    fn deterministic_metadata_and_hash_domains_are_explicit() {
        let request = request(false);
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let input = form(format);
            let (subject, metadata) = request.command(input.as_bytes(), format).unwrap();
            assert_eq!(subject.source_tip.algorithm(), format);
            assert_eq!(metadata.author, "Alice <a@example.invalid>");
            assert_eq!(metadata.message, "Exact 🦀\n%2f".as_bytes());
            assert_eq!(
                request.command(input.as_bytes(), format).unwrap(),
                (subject, metadata)
            );
        }
    }
    #[test]
    fn missing_fields_ambient_identity_and_header_injection_are_not_defaults() {
        let request = request(false);
        let valid = form(GitHashAlgorithm::Sha1);
        for invalid in [
            valid.replace("&timestamp=1", ""),
            valid.replace("timestamp=1", "timestamp=0"),
            valid.replace("timestamp=1", "timestamp=01"),
            valid.replace("message=Exact", "principal=Exact"),
            valid.replace("author=Alice", "author=Alice%0Aparent+fake"),
            valid.replace("message=Exact", "message=%00Exact"),
            valid.replace("message=Exact", "message=%FFExact"),
            valid.replace("policy_epoch=1", "policy_epoch=0"),
            valid.replace("source_ref=refs/heads/topic", "source_ref=refs/heads/main"),
            valid.replace("object_format=sha1", "object_format=sha256"),
            valid.clone() + "&timestamp=2",
        ] {
            assert!(
                request
                    .command(invalid.as_bytes(), GitHashAlgorithm::Sha1)
                    .is_err()
            );
        }
    }
    #[test]
    fn preparation_has_a_closed_body_bearing_route_not_a_mutation_fallback() {
        for (method, suffix, headers) in [
            ("GET", "/1/prepare", ""),
            ("POST", "/1/prepare?message=secret", "Content-Length: 1\r\n"),
            ("POST", "/01/prepare", "Content-Length: 1\r\n"),
            ("POST", "/1/prepare/merge", "Content-Length: 1\r\n"),
            ("POST", "/1/resolve/merge", "Content-Length: 1\r\n"),
            ("POST", "/1/prepare", "Content-Length: 262145\r\n"),
            (
                "POST",
                "/1/prepare",
                "Content-Length: 1\r\nGit-Protocol: version=2\r\n",
            ),
        ] {
            let bytes = format!(
                "{method} /r.git/api/v1/pulls{suffix} HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\n{headers}\r\n"
            );
            let envelope = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert!(Request::parse(&envelope).is_err());
        }
    }
    #[test]
    fn raw_paths_empty_files_and_binary_modes_survive_exactly() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let input = form(format)
                + &format!(
                    "&merge_base={}&resolution=ff:file:100755:file_7&resolution=61:delete",
                    "c".repeat(format.digest_len() * 2)
                );
            let files = BTreeMap::from([("file_7", b"\0\xff\r\nno-normalization".as_slice())]);
            let parsed = request(true)
                .resolved_command(input.as_bytes(), files, format)
                .unwrap();
            assert_eq!(parsed.choices[0].path, b"a");
            assert_eq!(
                parsed.choices[1],
                ConflictResolution {
                    path: vec![255],
                    choice: ResolutionChoice::File {
                        mode: 0o100755,
                        bytes: b"\0\xff\r\nno-normalization".to_vec()
                    }
                }
            );
            let empty = request(true)
                .resolved_command(
                    input.as_bytes(),
                    BTreeMap::from([("file_7", b"".as_slice())]),
                    format,
                )
                .unwrap();
            assert!(
                matches!(&empty.choices[1].choice, ResolutionChoice::File { bytes, .. } if bytes.is_empty())
            );
            assert!(request(false).command(input.as_bytes(), format).is_err());
            assert!(request(true).command(input.as_bytes(), format).is_err());
        }
    }
    #[test]
    fn ambiguous_paths_missing_unused_files_and_non_regular_modes_refuse() {
        let base = form(GitHashAlgorithm::Sha1) + &format!("&merge_base={}", "c".repeat(40));
        for suffix in [
            "&resolution=61:ours&resolution=61:theirs",
            "&resolution=61:ours&resolution=612f62:theirs",
            "&resolution=2e2e2f61:delete",
            "&resolution=2e6769742f61:delete",
            "&resolution=00:delete",
            "&resolution=FF:ours",
            "&resolution=61:ours:ignored",
            "&resolution=61:file:120000:file_0",
            "&resolution=61:file:100644:file_0",
            "&resolution=61:unknown",
        ] {
            assert!(
                request(true)
                    .resolved_command(
                        (base.clone() + suffix).as_bytes(),
                        BTreeMap::new(),
                        GitHashAlgorithm::Sha1
                    )
                    .is_err(),
                "{suffix}"
            );
        }
        let input = base.clone() + "&resolution=61:ours";
        assert!(
            request(true)
                .resolved_command(
                    input.as_bytes(),
                    BTreeMap::from([("file_0", b"unused".as_slice())]),
                    GitHashAlgorithm::Sha1
                )
                .is_err()
        );
        let input = base + "&resolution=61:file:100644:file_0&resolution=62:file:100644:file_0";
        assert!(
            request(true)
                .resolved_command(
                    input.as_bytes(),
                    BTreeMap::from([("file_0", b"once".as_slice())]),
                    GitHashAlgorithm::Sha1
                )
                .is_err()
        );
    }
}
