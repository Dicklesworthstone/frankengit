//! Preparation is a body-bearing read, not a mutation or implicit latest-tip
//! merge. All PR coordinates and Git commit metadata are client-selected.

use std::collections::BTreeMap;
use fgit_forge::{AggregateVersion, PullRequestNumber};
use fgit_forge::event::review::ReviewSubject;
use fgit_forge::preparation::MergeMetadata;
use fgit_types::{GitHashAlgorithm, GitOid, PolicyEpoch, RefName};
use fgit_wire::smart_http::{BodyFraming, head::Envelope};
use super::super::super::issues::{ApiError, MAX_FORM_BYTES, parse_decimal, parse_form};

#[derive(Debug)]
pub(crate) struct Request<'a> {
    pub repository_route: &'a str,
    pub number: PullRequestNumber,
}
impl<'a> Request<'a> {
    pub(crate) fn parse(head: &Envelope<'a>) -> Result<Option<Self>, ApiError> {
        let (path, query) = head.target.split_once('?').map_or((head.target, None), |(p, q)| (p, Some(q)));
        let Some((repository_route, suffix)) = path.split_once("/api/v1/pulls/") else { return Ok(None); };
        let Some((number, action)) = suffix.split_once('/') else { return Ok(None); };
        if action != "prepare" && !action.starts_with("prepare/") { return Ok(None); }
        if action != "prepare" || repository_route.len() < 2 || !repository_route.starts_with('/')
            || repository_route[1..].split('/').any(|part| part.is_empty() || matches!(part, "." | "..")
                || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b)))
        { return Err(ApiError::not_found()); }
        if head.method != "POST" { return Err(ApiError::method()); }
        if query.is_some() || head.body == BodyFraming::Empty {
            return Err(ApiError::bad("invalid_preparation_envelope"));
        }
        if head.git_protocol.is_some() { return Err(ApiError::bad("git_protocol_not_applicable")); }
        if !head.content_type.is_some_and(|content| content.eq_ignore_ascii_case("application/x-www-form-urlencoded")
            || content.eq_ignore_ascii_case("application/x-www-form-urlencoded; charset=utf-8"))
        { return Err(ApiError::media()); }
        if matches!(head.body, BodyFraming::ContentLength(n) if n > MAX_FORM_BYTES as u64) {
            return Err(ApiError::too_large());
        }
        let number = PullRequestNumber::try_new(parse_decimal(number)?)
            .ok_or_else(|| ApiError::bad("invalid_pull_request_number"))?;
        Ok(Some(Self { repository_route, number }))
    }

    pub(super) fn command(&self, bytes: &[u8], format: GitHashAlgorithm)
        -> Result<(ReviewSubject, MergeMetadata), ApiError>
    {
        let mut fields = BTreeMap::new();
        for (name, value) in parse_form(bytes, 11)? {
            if !matches!(name.as_str(), "object_format" | "pull_request_version" | "policy_epoch"
                | "source_ref" | "target_ref" | "source_tip" | "target_tip"
                | "author" | "committer" | "timestamp" | "message")
            { return Err(ApiError::bad("unknown_preparation_field")); }
            if fields.insert(name, value).is_some() { return Err(ApiError::bad("duplicate_field")); }
        }
        if take(&mut fields, "object_format")? != format.as_str() {
            return Err(ApiError::bad("object_format_mismatch"));
        }
        let version = AggregateVersion::try_new(parse_decimal(&take(&mut fields, "pull_request_version")?)?)
            .ok_or_else(|| ApiError::bad("invalid_pull_request_version"))?;
        version.next().map_err(|_| ApiError::bad("version_exhausted"))?;
        let subject = ReviewSubject {
            pull_request: self.number, pull_request_version: version,
            policy_epoch: PolicyEpoch::try_new(parse_decimal(&take(&mut fields, "policy_epoch")?)?)
                .map_err(|_| ApiError::bad("invalid_policy_epoch"))?,
            source_ref: RefName::try_new(take(&mut fields, "source_ref")?.as_bytes())
                .map_err(|_| ApiError::bad("invalid_ref"))?,
            target_ref: RefName::try_new(take(&mut fields, "target_ref")?.as_bytes())
                .map_err(|_| ApiError::bad("invalid_ref"))?,
            source_tip: oid(&take(&mut fields, "source_tip")?, format)?,
            target_tip: oid(&take(&mut fields, "target_tip")?, format)?,
        };
        subject.validate().map_err(|_| ApiError::bad("invalid_preparation_subject"))?;
        let metadata = MergeMetadata {
            author: take(&mut fields, "author")?, committer: take(&mut fields, "committer")?,
            timestamp: parse_decimal(&take(&mut fields, "timestamp")?)?,
            message: take(&mut fields, "message")?.into_bytes(),
        };
        metadata.validate().map_err(|_| ApiError::bad("invalid_commit_metadata"))?;
        Ok((subject, metadata))
    }
}
fn take(fields: &mut BTreeMap<String, String>, name: &str) -> Result<String, ApiError> {
    fields.remove(name).ok_or_else(|| ApiError::bad("missing_preparation_field"))
}
fn oid(text: &str, format: GitHashAlgorithm) -> Result<GitOid, ApiError> {
    if text.len() != format.digest_len() * 2
        || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    { return Err(ApiError::bad("invalid_oid")); }
    let oid = GitOid::from_hex(format, text).map_err(|_| ApiError::bad("invalid_oid"))?;
    if oid.is_zero() { return Err(ApiError::bad("invalid_oid")); }
    Ok(oid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_wire::smart_http::{HttpLimits, head};

    fn form(format: GitHashAlgorithm) -> String {
        format!("object_format={}&pull_request_version=1&policy_epoch=1&source_ref=refs/heads/topic&target_ref=refs/heads/main&source_tip={}&target_tip={}&author=Alice+%3Ca%40example.invalid%3E&committer=Bot+%3Cb%40example.invalid%3E&timestamp=1&message=Exact+%F0%9F%A6%80%0A%252f",
            format.as_str(), "a".repeat(format.digest_len() * 2), "b".repeat(format.digest_len() * 2))
    }
    #[test]
    fn deterministic_metadata_and_hash_domains_are_explicit() {
        let request = Request { repository_route: "/r.git", number: PullRequestNumber::FIRST };
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let input = form(format);
            let (subject, metadata) = request.command(input.as_bytes(), format).unwrap();
            assert_eq!(subject.source_tip.algorithm(), format);
            assert_eq!(metadata.author, "Alice <a@example.invalid>");
            assert_eq!(metadata.message, "Exact 🦀\n%2f".as_bytes());
            assert_eq!(request.command(input.as_bytes(), format).unwrap(), (subject, metadata));
        }
    }
    #[test]
    fn missing_fields_ambient_identity_and_header_injection_are_not_defaults() {
        let request = Request { repository_route: "/r.git", number: PullRequestNumber::FIRST };
        let valid = form(GitHashAlgorithm::Sha1);
        for invalid in [
            valid.replace("&timestamp=1", ""), valid.replace("timestamp=1", "timestamp=0"),
            valid.replace("timestamp=1", "timestamp=01"), valid.replace("message=Exact", "principal=Exact"),
            valid.replace("author=Alice", "author=Alice%0Aparent+fake"),
            valid.replace("message=Exact", "message=%00Exact"), valid.replace("message=Exact", "message=%FFExact"),
            valid.replace("policy_epoch=1", "policy_epoch=0"), valid.replace("source_ref=refs/heads/topic", "source_ref=refs/heads/main"),
            valid.replace("object_format=sha1", "object_format=sha256"), valid.clone() + "&timestamp=2",
        ] { assert!(request.command(invalid.as_bytes(), GitHashAlgorithm::Sha1).is_err()); }
    }
    #[test]
    fn preparation_has_a_closed_body_bearing_route_not_a_mutation_fallback() {
        for (method, suffix, headers) in [
            ("GET", "/1/prepare", ""), ("POST", "/1/prepare?message=secret", "Content-Length: 1\r\n"),
            ("POST", "/01/prepare", "Content-Length: 1\r\n"), ("POST", "/1/prepare/merge", "Content-Length: 1\r\n"),
            ("POST", "/1/prepare", "Content-Length: 262145\r\n"),
            ("POST", "/1/prepare", "Content-Length: 1\r\nGit-Protocol: version=2\r\n"),
        ] {
            let bytes = format!("{method} /r.git/api/v1/pulls{suffix} HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\n{headers}\r\n");
            let envelope = head::parse(bytes.as_bytes(), HttpLimits::default()).unwrap().unwrap();
            assert!(Request::parse(&envelope).is_err());
        }
    }
}
