//! Inspection binds an independently supplied PR subject and candidate. The
//! upload cannot choose a principal, hide paths or switch to a source-side diff.

use std::collections::BTreeMap;
use fgit_forge::{AggregateVersion, PullRequestNumber};
use fgit_forge::event::review::{CandidateBinding, ReviewSubject};
use fgit_types::{GitHashAlgorithm, GitOid, PolicyEpoch, RefName};
use fgit_wire::smart_http::{BodyFraming, head::Envelope};
use super::super::collaboration::{CANDIDATE_UPLOAD_BYTES, candidate_boundary};
use super::super::super::issues::{ApiError, parse_decimal, parse_form};

#[derive(Debug)]
pub(crate) struct Request<'a> {
    pub repository_route: &'a str,
    pub number: PullRequestNumber,
    pub boundary: &'a str,
}
impl<'a> Request<'a> {
    pub(crate) fn parse(head: &Envelope<'a>) -> Result<Option<Self>, ApiError> {
        let (path, query) = head.target.split_once('?').map_or((head.target, None), |(p, q)| (p, Some(q)));
        let Some((repository_route, suffix)) = path.split_once("/api/v1/pulls/") else { return Ok(None); };
        let Some((number, action)) = suffix.split_once('/') else { return Ok(None); };
        if action != "inspect" && !action.starts_with("inspect/") { return Ok(None); }
        if action != "inspect" || repository_route.len() < 2 || !repository_route.starts_with('/')
            || repository_route[1..].split('/').any(|part| part.is_empty() || matches!(part, "." | "..")
                || !part.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)))
        { return Err(ApiError::not_found()); }
        if head.method != "POST" { return Err(ApiError::method()); }
        if query.is_some() || head.git_protocol.is_some()
            || matches!(head.body, BodyFraming::Empty | BodyFraming::ContentLength(0))
        { return Err(ApiError::bad("invalid_inspection_envelope")); }
        let boundary = candidate_boundary(head.content_type.ok_or_else(ApiError::media)?)?;
        if matches!(head.body, BodyFraming::ContentLength(bytes) if bytes > CANDIDATE_UPLOAD_BYTES as u64) {
            return Err(ApiError::too_large());
        }
        let number = PullRequestNumber::try_new(parse_decimal(number)?)
            .ok_or_else(|| ApiError::bad("invalid_pull_request_number"))?;
        Ok(Some(Self { repository_route, number, boundary }))
    }

    pub(super) fn command(&self, bytes: &[u8], format: GitHashAlgorithm)
        -> Result<(ReviewSubject, CandidateBinding), ApiError>
    {
        let mut fields = BTreeMap::new();
        for (name, value) in parse_form(bytes, 9)? {
            if !matches!(name.as_str(), "object_format" | "pull_request_version" | "policy_epoch"
                | "source_ref" | "target_ref" | "source_tip" | "target_tip" | "merge_base" | "candidate_commit")
            { return Err(ApiError::bad("unknown_inspection_field")); }
            if fields.insert(name, value).is_some() { return Err(ApiError::bad("duplicate_field")); }
        }
        if take(&mut fields, "object_format")? != format.as_str() { return Err(ApiError::bad("object_format_mismatch")); }
        let subject = ReviewSubject {
            pull_request: self.number,
            pull_request_version: AggregateVersion::try_new(parse_decimal(&take(&mut fields, "pull_request_version")?)?)
                .ok_or_else(|| ApiError::bad("invalid_pull_request_version"))?,
            policy_epoch: PolicyEpoch::try_new(parse_decimal(&take(&mut fields, "policy_epoch")?)?)
                .map_err(|_| ApiError::bad("invalid_policy_epoch"))?,
            source_ref: RefName::try_new(take(&mut fields, "source_ref")?.as_bytes()).map_err(|_| ApiError::bad("invalid_ref"))?,
            target_ref: RefName::try_new(take(&mut fields, "target_ref")?.as_bytes()).map_err(|_| ApiError::bad("invalid_ref"))?,
            source_tip: oid(&take(&mut fields, "source_tip")?, format)?,
            target_tip: oid(&take(&mut fields, "target_tip")?, format)?,
        };
        let candidate = CandidateBinding { merge_base: oid(&take(&mut fields, "merge_base")?, format)?,
            commit: oid(&take(&mut fields, "candidate_commit")?, format)? };
        candidate.validate(&subject).map_err(|_| ApiError::bad("invalid_candidate_subject"))?;
        Ok((subject, candidate))
    }
}
fn take(fields: &mut BTreeMap<String, String>, name: &str) -> Result<String, ApiError> {
    fields.remove(name).ok_or_else(|| ApiError::bad("missing_inspection_field"))
}
fn oid(text: &str, format: GitHashAlgorithm) -> Result<GitOid, ApiError> {
    if text.len() != format.digest_len() * 2
        || !text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
        let width = format.digest_len() * 2;
        format!("object_format={}&pull_request_version=1&policy_epoch=1&source_ref=refs/heads/topic&target_ref=refs/heads/main&source_tip={}&target_tip={}&merge_base={}&candidate_commit={}",
            format.as_str(), "a".repeat(width), "b".repeat(width), "c".repeat(width), "d".repeat(width))
    }
    #[test]
    fn subjects_are_explicit_and_cannot_hide_paths_or_supply_identity() {
        let request = Request { repository_route: "/r.git", number: PullRequestNumber::FIRST, boundary: "x" };
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let valid = form(format);
            let (subject, candidate) = request.command(valid.as_bytes(), format).unwrap();
            assert_eq!(subject.source_tip.algorithm(), format);
            assert_eq!(candidate.commit.algorithm(), format);
            for invalid in [valid.replace("&policy_epoch=1", ""), valid.replace("policy_epoch=1", "policy_epoch=0"),
                valid.replace("source_ref=refs/heads/topic", "source_ref=refs/heads/main"),
                valid.replace("candidate_commit=", "principal="), valid.clone() + "&path=only-clean.txt",
                valid.clone() + "&pull_request_version=2"]
            { assert!(request.command(invalid.as_bytes(), format).is_err()); }
        }
    }
    #[test]
    fn inspection_requires_a_complete_binary_upload_not_a_get_or_vote() {
        for (method, suffix, media, framing) in [
            ("GET", "1/inspect", "multipart/form-data; boundary=x", "Content-Length: 1"),
            ("POST", "1/inspect?path=x", "multipart/form-data; boundary=x", "Content-Length: 1"),
            ("POST", "01/inspect", "multipart/form-data; boundary=x", "Content-Length: 1"),
            ("POST", "1/inspect/approve", "multipart/form-data; boundary=x", "Content-Length: 1"),
            ("POST", "1/inspect", "application/x-www-form-urlencoded", "Content-Length: 1"),
            ("POST", "1/inspect", "multipart/form-data; boundary=x", "Content-Length: 0"),
        ] {
            let wire = format!("{method} /r.git/api/v1/pulls/{suffix} HTTP/1.1\r\nHost: local\r\nContent-Type: {media}\r\n{framing}\r\n\r\n");
            let head = head::parse(wire.as_bytes(), HttpLimits::default()).unwrap().unwrap();
            assert!(Request::parse(&head).is_err());
        }
    }
}
