//! Explicit linear-history selection and publication leases. No implicit
//! upstream, empty-commit policy, identity, force flag or moving expectation.

use super::super::super::issues::{ApiError, parse_decimal, parse_form, parse_snapshot};
use fgit_forge::preparation::PreparationLimits;
use fgit_forge::preparation::rebase::{EmptyCommitPolicy, RebaseCommitter, RebaseRequest};
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RepositoryAuthorityHeadId};
use std::collections::BTreeMap;

pub(super) const MAX_COMMITS: usize = 256;

#[derive(Debug)]
pub(super) struct Prepare {
    pub source: RefName,
    pub onto_ref: RefName,
    pub inputs: RebaseRequest,
    pub expected_head: Option<RepositoryAuthorityHeadId>,
    pub committer: RebaseCommitter,
    pub limits: PreparationLimits,
}
#[derive(Debug)]
pub(super) struct Apply {
    pub reference: RefName,
    pub expected_source: GitOid,
    pub onto: GitOid,
    pub candidate: GitOid,
}

impl Prepare {
    pub(super) fn parse(bytes: &[u8], format: GitHashAlgorithm) -> Result<Self, ApiError> {
        let fields = fields(bytes, true)?;
        Self::from_fields(fields, format)
    }
    pub(super) fn from_fields(
        mut fields: BTreeMap<String, String>,
        format: GitHashAlgorithm,
    ) -> Result<Self, ApiError> {
        profile(&mut fields, format)?;
        let source = reference(&mut fields, "source_ref", "source_ref_hex")?;
        let onto_ref = reference(&mut fields, "onto_ref", "onto_ref_hex")?;
        if source == onto_ref {
            return Err(ApiError::bad("rebase_requires_distinct_branches"));
        }
        let inputs = RebaseRequest {
            source_tip: oid(&take(&mut fields, "expected_source")?, format)?,
            upstream: oid(&take(&mut fields, "upstream")?, format)?,
            onto: oid(&take(&mut fields, "expected_onto")?, format)?,
            empty: match take(&mut fields, "empty")?.as_str() {
                "stop" => EmptyCommitPolicy::Stop,
                "drop" => EmptyCommitPolicy::Drop,
                "keep" => EmptyCommitPolicy::Keep,
                _ => return Err(ApiError::bad("invalid_empty_commit_policy")),
            },
        };
        let expected_head = fields
            .remove("expected_head")
            .map(|s| parse_snapshot(&s))
            .transpose()?;
        let committer = RebaseCommitter {
            identity: take(&mut fields, "committer")?,
            timestamp: parse_decimal(&take(&mut fields, "timestamp")?)?,
        };
        committer
            .validate()
            .map_err(|_| ApiError::bad("invalid_rebase_committer"))?;
        let mut limits = PreparationLimits {
            max_commits: MAX_COMMITS,
            ..PreparationLimits::default()
        };
        for (name, field) in [
            ("max_commits", &mut limits.max_commits),
            ("max_edges", &mut limits.max_edges),
            ("max_tree_entries", &mut limits.max_tree_entries),
            ("max_depth", &mut limits.max_depth),
            ("max_path_bytes", &mut limits.max_path_bytes),
            ("max_content_merges", &mut limits.max_content_merges),
            ("max_text_bytes", &mut limits.max_text_bytes),
            ("max_conflicts", &mut limits.max_conflicts),
            ("max_objects", &mut limits.max_objects),
            ("max_output_bytes", &mut limits.max_output_bytes),
        ] {
            if let Some(text) = fields.remove(name) {
                *field = usize::try_from(parse_decimal(&text)?)
                    .map_err(|_| ApiError::bad("invalid_rebase_limit"))?;
            }
        }
        limits
            .validate()
            .map_err(|_| ApiError::bad("invalid_rebase_limits"))?;
        // The publication owner accepts at most 256 rewritten commits. Do not
        // advertise a larger HTTP preparation profile than can be published.
        if limits.max_commits > MAX_COMMITS {
            return Err(ApiError::bad("invalid_rebase_limits"));
        }
        if !fields.is_empty() {
            return Err(ApiError::bad("unknown_rebase_field"));
        }
        Ok(Self {
            source,
            onto_ref,
            inputs,
            expected_head,
            committer,
            limits,
        })
    }
}
impl Apply {
    pub(super) fn parse(bytes: &[u8], format: GitHashAlgorithm) -> Result<Self, ApiError> {
        let mut fields = fields(bytes, false)?;
        profile(&mut fields, format)?;
        let reference = reference(&mut fields, "ref", "ref_hex")?;
        let expected_source = oid(&take(&mut fields, "expected_source")?, format)?;
        let onto = oid(&take(&mut fields, "onto")?, format)?;
        let candidate = oid(&take(&mut fields, "candidate_commit")?, format)?;
        if !fields.is_empty() {
            return Err(ApiError::bad("unknown_rebase_field"));
        }
        Ok(Self {
            reference,
            expected_source,
            onto,
            candidate,
        })
    }
}
pub(super) fn prepare_field(name: &str) -> bool {
    matches!(
        name,
        "object_format"
            | "profile"
            | "source_ref"
            | "source_ref_hex"
            | "onto_ref"
            | "onto_ref_hex"
            | "expected_source"
            | "upstream"
            | "expected_onto"
            | "expected_head"
            | "empty"
            | "committer"
            | "timestamp"
            | "max_commits"
            | "max_edges"
            | "max_tree_entries"
            | "max_depth"
            | "max_path_bytes"
            | "max_content_merges"
            | "max_text_bytes"
            | "max_conflicts"
            | "max_objects"
            | "max_output_bytes"
    )
}
fn fields(bytes: &[u8], prepare: bool) -> Result<BTreeMap<String, String>, ApiError> {
    let mut fields = BTreeMap::new();
    for (name, value) in parse_form(bytes, 24)? {
        let accepted = if prepare {
            prepare_field(&name)
        } else {
            matches!(
                name.as_str(),
                "object_format"
                    | "profile"
                    | "ref"
                    | "ref_hex"
                    | "expected_source"
                    | "onto"
                    | "candidate_commit"
            )
        };
        if !accepted {
            return Err(ApiError::bad("unknown_rebase_field"));
        }
        if fields.insert(name, value).is_some() {
            return Err(ApiError::bad("duplicate_field"));
        }
    }
    Ok(fields)
}
fn profile(
    fields: &mut BTreeMap<String, String>,
    format: GitHashAlgorithm,
) -> Result<(), ApiError> {
    if take(fields, "object_format")? != format.as_str() {
        return Err(ApiError::bad("object_format_mismatch"));
    }
    if take(fields, "profile")? != "linear-v1" {
        return Err(ApiError::bad("unsupported_rebase_profile"));
    }
    Ok(())
}
fn take(fields: &mut BTreeMap<String, String>, name: &str) -> Result<String, ApiError> {
    fields
        .remove(name)
        .ok_or_else(|| ApiError::bad("missing_rebase_field"))
}
fn reference(
    fields: &mut BTreeMap<String, String>,
    name: &str,
    hex_name: &str,
) -> Result<RefName, ApiError> {
    let bytes = match (fields.remove(name), fields.remove(hex_name)) {
        (Some(text), None) => text.into_bytes(),
        (None, Some(text)) => unhex(&text, 4096)?,
        _ => return Err(ApiError::bad("exactly_one_reference_encoding_required")),
    };
    if bytes.len() > 4096 || !bytes.starts_with(b"refs/heads/") {
        return Err(ApiError::bad("rebase_requires_branch"));
    }
    RefName::try_new(&bytes).map_err(|_| ApiError::bad("invalid_ref"))
}
pub(super) fn oid(text: &str, format: GitHashAlgorithm) -> Result<GitOid, ApiError> {
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
pub(super) fn unhex(text: &str, maximum: usize) -> Result<Vec<u8>, ApiError> {
    if text.is_empty()
        || !text.len().is_multiple_of(2)
        || text.len() > maximum * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ApiError::bad("invalid_hex_bytes"));
    }
    let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    Ok(text
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| (digit(p[0]) << 4) | digit(p[1]))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn form(format: GitHashAlgorithm) -> String {
        format!(
            "object_format={}&profile=linear-v1&source_ref=refs/heads/topic&onto_ref=refs/heads/main&expected_source={}&upstream={}&expected_onto={}&empty=stop&committer=Bot+%3Cbot%40example.invalid%3E&timestamp=1",
            format.as_str(),
            "a".repeat(format.digest_len() * 2),
            "b".repeat(format.digest_len() * 2),
            "c".repeat(format.digest_len() * 2)
        )
    }
    #[test]
    fn exact_hash_domains_byte_refs_and_all_empty_policies_parse() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            for (text, policy) in [
                ("stop", EmptyCommitPolicy::Stop),
                ("drop", EmptyCommitPolicy::Drop),
                ("keep", EmptyCommitPolicy::Keep),
            ] {
                let command = Prepare::parse(
                    form(format)
                        .replace("empty=stop", &format!("empty={text}"))
                        .as_bytes(),
                    format,
                )
                .unwrap();
                assert_eq!(command.inputs.empty, policy);
                assert_eq!(command.inputs.onto.algorithm(), format);
                assert_eq!(command.limits.max_commits, MAX_COMMITS);
            }
            let body = form(format).replace(
                "source_ref=refs/heads/topic",
                "source_ref_hex=726566732f68656164732fff",
            );
            assert_eq!(
                Prepare::parse(body.as_bytes(), format)
                    .unwrap()
                    .source
                    .as_bytes(),
                b"refs/heads/\xff"
            );
        }
    }
    #[test]
    fn no_ambient_policy_identity_or_widened_limits_are_accepted() {
        let valid = form(GitHashAlgorithm::Sha1);
        for bad in [
            valid.clone() + "&force=true",
            valid.clone() + "&principal=admin",
            valid.clone() + "&timestamp=2",
            valid.clone() + "&max_commits=257",
            valid.clone() + "&max_objects=0",
            valid.clone() + "&max_text_bytes=1048577",
            valid.replace("&empty=stop", ""),
            valid.replace("timestamp=1", "timestamp=01"),
            valid.replace("source_ref=refs/heads/topic", "source_ref=refs/heads/main"),
            valid.clone() + "&source_ref_hex=61",
            valid.replace("committer=Bot", "committer=Bot%0Aparent+bad"),
        ] {
            assert!(
                Prepare::parse(bad.as_bytes(), GitHashAlgorithm::Sha1).is_err(),
                "{bad}"
            );
        }
    }
    #[test]
    fn publication_source_lease_is_not_the_pack_prerequisite() {
        let input = format!(
            "object_format=sha1&profile=linear-v1&ref=refs/heads/topic&expected_source={}&onto={}&candidate_commit={}",
            "a".repeat(40),
            "b".repeat(40),
            "c".repeat(40)
        );
        let command = Apply::parse(input.as_bytes(), GitHashAlgorithm::Sha1).unwrap();
        assert_ne!(command.expected_source, command.onto);
        // A fully dropped suffix legitimately advertises onto with an empty pack.
        assert!(
            Apply::parse(
                input.replace(&"c".repeat(40), &"b".repeat(40)).as_bytes(),
                GitHashAlgorithm::Sha1
            )
            .is_ok()
        );
        for extra in [
            "&force=true",
            "&expected_head=latest",
            "&empty=drop",
            "&committer=admin",
        ] {
            assert!(
                Apply::parse((input.clone() + extra).as_bytes(), GitHashAlgorithm::Sha1).is_err()
            );
        }
    }
}
