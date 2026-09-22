//! Closed source-reference operations. An OID is an explicit expected/new
//! value, not an object-read capability. Rename lowers to one atomic delete
//! plus absent-destination create; no force or implicit-current-tip option.

use std::collections::BTreeMap;

use fgit_authority::{ExpectedOld, ProposedNew, RefCommand};
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RepositoryAuthorityHeadId};
use fgit_wire::smart_http::{BodyFraming, head::Envelope};

use super::super::super::issues::{
    ApiError, MAX_FORM_BYTES, parse_decimal, parse_form, parse_snapshot,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Operation {
    List,
    Create,
    Update,
    Delete,
    Rename,
}
impl Operation {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::List => "list",
            Self::Create => "create",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Rename => "rename",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Namespace {
    All,
    Branches,
    Tags,
}
impl Namespace {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Branches => "branches",
            Self::Tags => "tags",
        }
    }
    pub(super) const fn prefix(self) -> &'static [u8] {
        match self {
            Self::All => b"refs/",
            Self::Branches => b"refs/heads/",
            Self::Tags => b"refs/tags/",
        }
    }
}

#[derive(Debug)]
pub(super) struct Page {
    pub namespace: Namespace,
    pub after: Option<RefName>,
    pub limit: u16,
    pub expected_head: Option<RepositoryAuthorityHeadId>,
}

#[derive(Debug)]
pub(super) enum Command {
    List(Page),
    Mutate(Vec<RefCommand>),
}

#[derive(Debug)]
pub(super) struct Request<'a> {
    pub repository_route: &'a str,
    pub operation: Operation,
}
impl<'a> Request<'a> {
    pub(super) fn parse(head: &Envelope<'a>) -> Result<Option<Self>, ApiError> {
        let (path, query) = head
            .target
            .split_once('?')
            .map_or((head.target, None), |(path, query)| (path, Some(query)));
        let Some((repository_route, action)) = path.split_once("/api/v1/source/") else {
            return Ok(None);
        };
        let operation = match action {
            "refs" => Operation::List,
            "branches/create" => Operation::Create,
            "branches/update" => Operation::Update,
            "branches/delete" => Operation::Delete,
            "branches/rename" => Operation::Rename,
            _ if action.starts_with("branches/") || action == "branches" => {
                return Err(ApiError::not_found());
            }
            _ => return Ok(None),
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
        if head.method != "POST" {
            return Err(ApiError::method());
        }
        if query.is_some() || head.git_protocol.is_some() {
            return Err(ApiError::bad("unexpected_reference_parameters"));
        }
        let media = head.content_type.ok_or_else(ApiError::media)?;
        if !media.eq_ignore_ascii_case("application/x-www-form-urlencoded")
            && !media.eq_ignore_ascii_case("application/x-www-form-urlencoded; charset=utf-8")
        {
            return Err(ApiError::media());
        }
        match head.body {
            BodyFraming::ContentLength(length) if length > MAX_FORM_BYTES as u64 => {
                return Err(ApiError::too_large());
            }
            BodyFraming::Empty | BodyFraming::ContentLength(0) => {
                return Err(ApiError::bad("reference_command_required"));
            }
            _ => {}
        }
        Ok(Some(Self {
            repository_route,
            operation,
        }))
    }

    pub(super) fn is_mutation(&self) -> bool {
        self.operation != Operation::List
    }

    pub(super) fn command(
        &self,
        bytes: &[u8],
        format: GitHashAlgorithm,
    ) -> Result<Command, ApiError> {
        let mut fields = BTreeMap::new();
        for (name, value) in parse_form(bytes, 6)? {
            if fields.insert(name, value).is_some() {
                return Err(ApiError::bad("duplicate_field"));
            }
        }
        if take(&mut fields, "object_format")? != format.as_str() {
            return Err(ApiError::bad("object_format_mismatch"));
        }
        let result = match self.operation {
            Operation::List => {
                let namespace = match fields.remove("namespace").as_deref().unwrap_or("all") {
                    "all" => Namespace::All,
                    "branches" => Namespace::Branches,
                    "tags" => Namespace::Tags,
                    _ => return Err(ApiError::bad("invalid_ref_namespace")),
                };
                let after = fields
                    .remove("after")
                    .map(|name| reference(&name, namespace.prefix()))
                    .transpose()?;
                let expected_head = fields
                    .remove("expected_head")
                    .map(|text| parse_snapshot(&text))
                    .transpose()?;
                let limit = fields
                    .remove("limit")
                    .map(|text| parse_decimal(&text))
                    .transpose()?
                    .unwrap_or(50);
                if !(1..=100).contains(&limit) {
                    return Err(ApiError::bad("invalid_page_limit"));
                }
                if after.is_some() && expected_head.is_none() {
                    return Err(ApiError::bad("snapshot_required"));
                }
                Command::List(Page {
                    namespace,
                    after,
                    limit: limit as u16,
                    expected_head,
                })
            }
            operation => {
                let name = reference(&take(&mut fields, "ref")?, b"refs/heads/")?;
                let old = if operation == Operation::Create {
                    None
                } else {
                    Some(oid(&take(&mut fields, "expected_commit")?, format)?)
                };
                let new = match operation {
                    Operation::Create | Operation::Update => {
                        Some(oid(&take(&mut fields, "new_commit")?, format)?)
                    }
                    Operation::Rename => old,
                    _ => None,
                };
                let mut commands =
                    Vec::with_capacity(if operation == Operation::Rename { 2 } else { 1 });
                commands.push(RefCommand {
                    name: name.clone(),
                    expected_old: old.map_or(ExpectedOld::Absent, ExpectedOld::Exactly),
                    proposed_new: if operation == Operation::Rename {
                        ProposedNew::Delete
                    } else {
                        new.map_or(ProposedNew::Delete, ProposedNew::Update)
                    },
                    force: false,
                });
                if operation == Operation::Rename {
                    let destination = reference(&take(&mut fields, "new_ref")?, b"refs/heads/")?;
                    if destination == name {
                        return Err(ApiError::bad("rename_requires_distinct_branches"));
                    }
                    commands.push(RefCommand {
                        name: destination,
                        expected_old: ExpectedOld::Absent,
                        proposed_new: ProposedNew::Update(
                            new.ok_or_else(|| ApiError::bad("expected_commit_required"))?,
                        ),
                        force: false,
                    });
                }
                Command::Mutate(commands)
            }
        };
        if !fields.is_empty() {
            return Err(ApiError::bad("unknown_reference_field"));
        }
        Ok(result)
    }
}
fn take(fields: &mut BTreeMap<String, String>, name: &str) -> Result<String, ApiError> {
    fields
        .remove(name)
        .ok_or_else(|| ApiError::bad("missing_reference_field"))
}
fn reference(text: &str, prefix: &[u8]) -> Result<RefName, ApiError> {
    if text.len() > 4096 || !text.as_bytes().starts_with(prefix) {
        return Err(ApiError::bad("invalid_reference_namespace"));
    }
    RefName::try_new(text.as_bytes()).map_err(|_| ApiError::bad("invalid_reference"))
}
fn oid(text: &str, format: GitHashAlgorithm) -> Result<GitOid, ApiError> {
    if text.len() != format.digest_len() * 2
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApiError::bad("invalid_native_commit"));
    }
    let oid = GitOid::from_hex(format, text).map_err(|_| ApiError::bad("invalid_native_commit"))?;
    if oid.is_zero() {
        return Err(ApiError::bad("nonzero_native_commit_required"));
    }
    Ok(oid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_wire::smart_http::{HttpLimits, head};

    fn parse(action: &str, form: &str, format: GitHashAlgorithm) -> Result<Command, ApiError> {
        Request {
            repository_route: "/repo.git",
            operation: match action {
                "create" => Operation::Create,
                "update" => Operation::Update,
                "delete" => Operation::Delete,
                "rename" => Operation::Rename,
                _ => Operation::List,
            },
        }
        .command(form.as_bytes(), format)
    }
    #[test]
    fn rename_is_one_exact_delete_and_absent_destination_create_in_both_formats() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let id = "a".repeat(format.digest_len() * 2);
            let form = format!(
                "object_format={}&ref=refs/heads/z&expected_commit={id}&new_ref=refs/heads/a",
                format.as_str()
            );
            let Command::Mutate(commands) = parse("rename", &form, format).unwrap() else {
                panic!("mutation");
            };
            assert_eq!(commands.len(), 2);
            assert_eq!(
                commands[0].expected_old,
                ExpectedOld::Exactly(GitOid::from_hex(format, &id).unwrap())
            );
            assert_eq!(commands[0].proposed_new, ProposedNew::Delete);
            assert_eq!(commands[1].expected_old, ExpectedOld::Absent);
            assert_eq!(
                commands[1].proposed_new,
                ProposedNew::Update(GitOid::from_hex(format, &id).unwrap())
            );
            assert!(commands.iter().all(|command| !command.force));
        }
    }
    #[test]
    fn missing_leases_force_identity_overrides_and_duplicate_fields_are_rejected() {
        let format = GitHashAlgorithm::Sha256;
        let create = format!(
            "object_format=sha256&ref=refs/heads/new&new_commit={}",
            "a".repeat(64)
        );
        assert!(parse("create", &create, format).is_ok());
        for extra in [
            "&force=true",
            "&principal=admin",
            "&ref=refs/heads/other",
            "&expected_commit=absent",
            "&atomic=false",
        ] {
            assert!(parse("create", &(create.clone() + extra), format).is_err());
        }
        assert!(parse("update", &create, format).is_err());
        assert!(
            parse(
                "create",
                &create.replace("refs/heads/new", "refs/tags/new"),
                format
            )
            .is_err()
        );
        assert!(
            parse(
                "create",
                &create.replace(&"a".repeat(64), &"0".repeat(64)),
                format
            )
            .is_err()
        );
        assert!(
            parse(
                "create",
                &create.replace(&"a".repeat(64), &"A".repeat(64)),
                format
            )
            .is_err()
        );
        assert!(parse("create", &create, GitHashAlgorithm::Sha1).is_err());
        let rename = format!(
            "object_format=sha256&ref=refs/heads/same&expected_commit={}&new_ref=refs/heads/same",
            "a".repeat(64)
        );
        assert!(parse("rename", &rename, format).is_err());
    }
    #[test]
    fn ref_pages_require_pinned_continuations_and_namespace_appropriate_cursors() {
        let format = GitHashAlgorithm::Sha1;
        let base = "object_format=sha1&namespace=branches";
        assert!(parse("list", base, format).is_ok());
        for extra in [
            "&after=refs/heads/a",
            "&limit=0",
            "&limit=101",
            "&limit=01",
            "&namespace=all",
            "&ref=refs/heads/a",
        ] {
            assert!(parse("list", &(base.to_owned() + extra), format).is_err());
        }
        let pinned = format!(
            "{base}&after=refs/heads/a&expected_head=alg:1:{}",
            "a".repeat(64)
        );
        assert!(parse("list", &pinned, format).is_ok());
        assert!(
            parse(
                "list",
                &pinned.replace("after=refs/heads/a", "after=refs/tags/a"),
                format
            )
            .is_err()
        );
    }
    #[test]
    fn only_declared_routes_and_bounded_form_envelopes_are_accepted() {
        for (action, mutation) in [
            ("refs", false),
            ("branches/create", true),
            ("branches/update", true),
            ("branches/delete", true),
            ("branches/rename", true),
        ] {
            let raw = format!(
                "POST /repo.git/api/v1/source/{action} HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n\r\n"
            );
            let parsed = head::parse(raw.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert_eq!(
                Request::parse(&parsed).unwrap().unwrap().is_mutation(),
                mutation
            );
            for invalid in [
                raw.replace("POST ", "GET "),
                raw.replace(" HTTP/1.1", "?force=true HTTP/1.1"),
                raw.replace("Content-Length: 1", "Content-Length: 262145"),
                raw.replace("Content-Length: 1", "Content-Length: 0"),
                raw.replace("application/x-www-form-urlencoded", "application/json"),
            ] {
                let parsed = head::parse(invalid.as_bytes(), HttpLimits::default())
                    .unwrap()
                    .unwrap();
                assert!(Request::parse(&parsed).is_err());
            }
        }
    }
}
