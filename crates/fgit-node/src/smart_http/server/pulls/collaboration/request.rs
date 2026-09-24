//! Exact client-selected review subjects and merge requirements. No current
//! version/tip refresh, caller-supplied reviewer identity or inferred hash domain.

use super::super::super::issues::{parse_decimal, parse_form, parse_snapshot};
use super::{ApiError, multipart};
use fgit_admission::merge::native::pull_request::reviews::gate::ReviewRequirements;
use fgit_forge::event::review::{
    CandidateBinding, CandidateReviewCommand, ReviewCommand, ReviewDecision, ReviewSubject,
};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_types::{
    GitHashAlgorithm, GitOid, PolicyEpoch, PrincipalId, RefName, RepositoryAuthorityHeadId,
};
use fgit_wire::smart_http::{BodyFraming, head::Envelope};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug)]
pub struct Page {
    pub after: Option<PrincipalId>,
    pub limit: u16,
    pub expected_head: Option<RepositoryAuthorityHeadId>,
}
#[derive(Clone, Copy, Debug)]
pub enum Operation {
    List(Page),
    Review(ReviewDecision),
    Merge,
}
#[derive(Clone, Copy, Debug)]
pub enum Encoding<'a> {
    Form,
    Multipart(&'a str),
}
#[derive(Debug)]
pub struct Request<'a> {
    pub repository_route: &'a str,
    pub number: PullRequestNumber,
    pub operation: Operation,
    pub encoding: Encoding<'a>,
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
        if action != "merge" && action != "reviews" && !action.starts_with("reviews/") {
            return Ok(None);
        }
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
        let number = PullRequestNumber::try_new(parse_decimal(number)?)
            .ok_or_else(|| ApiError::bad("invalid_pull_request_number"))?;
        if head.git_protocol.is_some() {
            return Err(ApiError::bad("git_protocol_not_applicable"));
        }
        let operation = match action {
            "reviews" => {
                if head.method != "GET" {
                    return Err(ApiError::method());
                }
                if !matches!(
                    head.body,
                    BodyFraming::Empty | BodyFraming::ContentLength(0)
                ) || head.expect_continue
                {
                    return Err(ApiError::bad("body_not_allowed"));
                }
                Operation::List(page(query)?)
            }
            action => {
                if head.method != "POST" {
                    return Err(ApiError::method());
                }
                if query.is_some() || head.body == BodyFraming::Empty {
                    return Err(ApiError::bad("invalid_mutation_envelope"));
                }
                match action {
                    "reviews/approve" => Operation::Review(ReviewDecision::Approve),
                    "reviews/request-changes" => Operation::Review(ReviewDecision::RequestChanges),
                    "reviews/withdraw" => Operation::Review(ReviewDecision::Withdraw),
                    "merge" => Operation::Merge,
                    _ => return Err(ApiError::not_found()),
                }
            }
        };
        let encoding = if matches!(operation, Operation::List(_)) {
            Encoding::Form
        } else {
            let content_type = head.content_type.ok_or_else(ApiError::media)?;
            let encoding = if content_type.eq_ignore_ascii_case("application/x-www-form-urlencoded")
                || content_type
                    .eq_ignore_ascii_case("application/x-www-form-urlencoded; charset=utf-8")
            {
                Encoding::Form
            } else {
                if matches!(operation, Operation::Review(ReviewDecision::Withdraw)) {
                    return Err(ApiError::media());
                }
                Encoding::Multipart(
                    multipart::boundary(content_type).map_err(|_| ApiError::media())?,
                )
            };
            let maximum = match encoding {
                Encoding::Form => multipart::MAX_COMMAND_BYTES,
                Encoding::Multipart(_) => multipart::MAX_UPLOAD_BYTES,
            };
            if matches!(head.body, BodyFraming::ContentLength(n) if n > maximum as u64) {
                return Err(ApiError::too_large());
            }
            encoding
        };
        Ok(Some(Self {
            repository_route,
            number,
            operation,
            encoding,
        }))
    }
    pub(crate) const fn is_mutation(&self) -> bool {
        !matches!(self.operation, Operation::List(_))
    }

    pub(super) fn command(
        &self,
        bytes: &[u8],
        format: GitHashAlgorithm,
        principal: PrincipalId,
    ) -> Result<Command, ApiError> {
        let mut fields = BTreeMap::new();
        let mut reviewers = Vec::new();
        for (name, value) in parse_form(bytes, 41)? {
            if name == "required_reviewer" && matches!(self.operation, Operation::Merge) {
                reviewers.push(principal_id(&value)?);
            } else {
                let common = matches!(
                    name.as_str(),
                    "object_format"
                        | "pull_request_version"
                        | "policy_epoch"
                        | "source_ref"
                        | "target_ref"
                        | "source_tip"
                        | "target_tip"
                        | "merge_base"
                        | "candidate_commit"
                );
                let review = matches!(self.operation, Operation::Review(_))
                    && matches!(name.as_str(), "expected_version" | "reason");
                if !common && !review {
                    return Err(ApiError::bad("unknown_or_inapplicable_field"));
                }
                if fields.insert(name, value).is_some() {
                    return Err(ApiError::bad("duplicate_field"));
                }
            }
        }
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
        let candidate = CandidateBinding {
            merge_base: oid(&take(&mut fields, "merge_base")?, format)?,
            commit: oid(&take(&mut fields, "candidate_commit")?, format)?,
        };
        candidate
            .validate(&subject)
            .map_err(|_| ApiError::bad("invalid_candidate_subject"))?;
        match self.operation {
            Operation::Review(decision) => {
                let version = parse_decimal(&take(&mut fields, "expected_version")?)?;
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
                let command = CandidateReviewCommand {
                    candidate,
                    review: ReviewCommand {
                        expected_version,
                        subject,
                        decision,
                        reason: take(&mut fields, "reason")?,
                    },
                };
                command
                    .proposed_event(principal, format)
                    .map_err(|_| ApiError::bad("invalid_review_command"))?;
                Ok(Command::Review(command))
            }
            Operation::Merge => {
                if reviewers.contains(&principal) {
                    return Err(ApiError::bad("submitter_cannot_review_own_merge"));
                }
                let required = ReviewRequirements::new(subject.policy_epoch, reviewers)
                    .map_err(|_| ApiError::bad("invalid_required_reviewers"))?;
                Ok(Command::Merge {
                    subject,
                    candidate,
                    required,
                })
            }
            Operation::List(_) => Err(ApiError::bad("not_a_mutation")),
        }
    }
}

pub(super) enum Command {
    Review(CandidateReviewCommand),
    Merge {
        subject: ReviewSubject,
        candidate: CandidateBinding,
        required: ReviewRequirements,
    },
}
fn take(fields: &mut BTreeMap<String, String>, name: &'static str) -> Result<String, ApiError> {
    fields
        .remove(name)
        .ok_or_else(|| ApiError::bad("required_field_missing"))
}
fn oid(text: &str, format: GitHashAlgorithm) -> Result<GitOid, ApiError> {
    if text.len() != format.digest_len() * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ApiError::bad("invalid_object_id"));
    }
    let oid = GitOid::from_hex(format, text).map_err(|_| ApiError::bad("invalid_object_id"))?;
    if oid.is_zero() {
        return Err(ApiError::bad("invalid_object_id"));
    }
    Ok(oid)
}
fn principal_id(text: &str) -> Result<PrincipalId, ApiError> {
    if text.len() != 32
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ApiError::bad("invalid_reviewer"));
    }
    PrincipalId::from_hex(text).map_err(|_| ApiError::bad("invalid_reviewer"))
}
fn page(query: Option<&str>) -> Result<Page, ApiError> {
    let (mut after, mut limit, mut expected_head) = (None, None, None);
    for (name, value) in parse_form(query.unwrap_or("").as_bytes(), 3)? {
        match name.as_str() {
            "after" if after.is_none() => after = Some(principal_id(&value)?),
            "limit" if limit.is_none() => limit = Some(parse_decimal(&value)?),
            "expected_head" if expected_head.is_none() => {
                expected_head = Some(parse_snapshot(&value)?);
            }
            _ => return Err(ApiError::bad("unknown_or_duplicate_query_field")),
        }
    }
    let limit = limit.unwrap_or(50);
    if !(1..=100).contains(&limit) {
        return Err(ApiError::bad("invalid_page_limit"));
    }
    if after.is_some() && expected_head.is_none() {
        return Err(ApiError::bad("snapshot_required"));
    }
    Ok(Page {
        after,
        limit: limit as u16,
        expected_head,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fields() -> String {
        format!(
            "object_format=sha1&pull_request_version=1&policy_epoch=1&source_ref=refs%2Fheads%2Ftopic&target_ref=refs%2Fheads%2Fmain&source_tip={}&target_tip={}&merge_base={}&candidate_commit={}",
            "a".repeat(40),
            "b".repeat(40),
            "c".repeat(40),
            "d".repeat(40)
        )
    }
    fn request(operation: Operation) -> Request<'static> {
        Request {
            repository_route: "/repo.git",
            number: PullRequestNumber::FIRST,
            operation,
            encoding: Encoding::Form,
        }
    }
    #[test]
    fn reviewer_identity_is_credential_owned_and_subject_is_not_refreshed() {
        let actor = PrincipalId::from_bytes([3; 16]);
        let request = request(Operation::Review(ReviewDecision::Approve));
        let body = fields() + "&expected_version=0&reason=exact%0Acandidate";
        let Command::Review(command) = request
            .command(body.as_bytes(), GitHashAlgorithm::Sha1, actor)
            .unwrap()
        else {
            panic!("review");
        };
        assert_eq!(command.review.reason, "exact\ncandidate");
        assert_eq!(
            command.review.subject.pull_request_version,
            AggregateVersion::FIRST
        );
        for extra in [
            "&reviewer=admin",
            "&force=true",
            "&expected_version=1",
            "&required_reviewer=admin",
        ] {
            assert!(
                request
                    .command(
                        (body.clone() + extra).as_bytes(),
                        GitHashAlgorithm::Sha1,
                        actor
                    )
                    .is_err()
            );
        }
        assert!(
            request
                .command(body.as_bytes(), GitHashAlgorithm::Sha256, actor)
                .is_err()
        );
    }
    #[test]
    fn merge_requires_a_nonempty_distinct_non_submitter_reviewer_set() {
        let actor = PrincipalId::from_bytes([3; 16]);
        let request = request(Operation::Merge);
        for extra in [
            String::new(),
            format!("&required_reviewer={actor}"),
            format!(
                "&required_reviewer={0}&required_reviewer={0}",
                "44".repeat(16)
            ),
        ] {
            assert!(
                request
                    .command(
                        (fields() + &extra).as_bytes(),
                        GitHashAlgorithm::Sha1,
                        actor
                    )
                    .is_err()
            );
        }
        let body = fields() + &format!("&required_reviewer={}", "44".repeat(16));
        assert!(matches!(
            request
                .command(body.as_bytes(), GitHashAlgorithm::Sha1, actor)
                .unwrap(),
            Command::Merge { .. }
        ));
    }
    #[test]
    fn withdrawal_version_and_review_pagination_are_explicit() {
        let request = request(Operation::Review(ReviewDecision::Withdraw));
        let actor = PrincipalId::from_bytes([3; 16]);
        assert!(
            request
                .command(
                    (fields() + "&expected_version=0&reason=withdraw").as_bytes(),
                    GitHashAlgorithm::Sha1,
                    actor
                )
                .is_err()
        );
        assert!(
            request
                .command(
                    (fields() + "&expected_version=1&reason=withdraw").as_bytes(),
                    GitHashAlgorithm::Sha1,
                    actor
                )
                .is_ok()
        );
        assert!(page(Some(&format!("after={actor}"))).is_err());
        assert!(page(Some("limit=0")).is_err());
        assert!(page(Some("limit=1&limit=2")).is_err());
        assert_eq!(page(None).unwrap().limit, 50);
    }
}
