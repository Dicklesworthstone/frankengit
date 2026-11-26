#![forbid(unsafe_code)]
//! Repeated form operands lower to one ordinary native atomic receive request.
//! Reference names are exact lowercase hex bytes, never client-side identities.
use super::super::super::issues::{ApiError, parse_form};
use super::request::oid;
use crate::OneNode;
use fgit_authority::{ExpectedOld, ProposedNew, RefCommand};
use fgit_types::{
    GitHashAlgorithm, PrincipalId, RefName, RepositoryId, RepositoryIncarnationId, TenantId,
};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WriterScope {
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub incarnation: RepositoryIncarnationId,
    pub principal: PrincipalId,
}

impl WriterScope {
    fn parse(value: &str) -> Result<Self, ApiError> {
        let bad_scope = || ApiError::bad("invalid_branch_transaction_scope");
        let mut parts = value.split(':');
        let scope = Self {
            tenant: TenantId::from_hex(parts.next().ok_or_else(bad_scope)?)
                .map_err(|_| bad_scope())?,
            repository: RepositoryId::from_hex(parts.next().ok_or_else(bad_scope)?)
                .map_err(|_| bad_scope())?,
            incarnation: RepositoryIncarnationId::from_hex(parts.next().ok_or_else(bad_scope)?)
                .map_err(|_| bad_scope())?,
            principal: PrincipalId::from_hex(parts.next().ok_or_else(bad_scope)?)
                .map_err(|_| bad_scope())?,
        };
        if parts.next().is_some() {
            return Err(bad_scope());
        }
        Ok(scope)
    }
}

pub(super) fn parse(
    bytes: &[u8],
    format: GitHashAlgorithm,
) -> Result<(Vec<RefCommand>, Option<WriterScope>), ApiError> {
    let fields = parse_form(bytes, OneNode::MAX_BRANCH_TRANSACTION_COMMANDS + 2)?;
    let mut selected_format = false;
    let mut expected_scope = None;
    let mut names = BTreeSet::new();
    let mut commands = Vec::new();
    for (field, value) in fields {
        if field == "object_format" {
            if selected_format {
                return Err(ApiError::bad("duplicate_field"));
            }
            if value != format.as_str() {
                return Err(ApiError::bad("object_format_mismatch"));
            }
            selected_format = true;
            continue;
        }
        if field == "expected_scope" {
            if expected_scope.is_some() {
                return Err(ApiError::bad("duplicate_field"));
            }
            expected_scope = Some(WriterScope::parse(&value)?);
            continue;
        }
        if !matches!(field.as_str(), "create" | "update" | "delete") {
            return Err(ApiError::bad("unknown_reference_field"));
        }
        if commands.len() == OneNode::MAX_BRANCH_TRANSACTION_COMMANDS {
            return Err(ApiError::too_large());
        }
        let mut parts = value.split(':');
        let name = reference(
            parts
                .next()
                .ok_or_else(|| ApiError::bad("invalid_transaction_operand"))?,
        )?;
        let first = oid(
            parts
                .next()
                .ok_or_else(|| ApiError::bad("invalid_transaction_operand"))?,
            format,
        )?;
        let (expected_old, proposed_new) = match field.as_str() {
            "create" => (ExpectedOld::Absent, ProposedNew::Update(first)),
            "delete" => (ExpectedOld::Exactly(first), ProposedNew::Delete),
            _ => (
                ExpectedOld::Exactly(first),
                ProposedNew::Update(oid(
                    parts
                        .next()
                        .ok_or_else(|| ApiError::bad("invalid_transaction_operand"))?,
                    format,
                )?),
            ),
        };
        if parts.next().is_some() {
            return Err(ApiError::bad("invalid_transaction_operand"));
        }
        if !names.insert(name.clone()) {
            return Err(ApiError::bad("duplicate_branch_target"));
        }
        commands
            .try_reserve(1)
            .map_err(|_| ApiError::unavailable())?;
        commands.push(RefCommand {
            name,
            expected_old,
            proposed_new,
            force: false,
        });
    }
    if !selected_format {
        return Err(ApiError::bad("missing_reference_field"));
    }
    if commands.is_empty() {
        return Err(ApiError::bad("reference_command_required"));
    }
    Ok((commands, expected_scope))
}
fn reference(text: &str) -> Result<RefName, ApiError> {
    if text.is_empty()
        || text.len() > 8192
        || !text.len().is_multiple_of(2)
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ApiError::bad("invalid_reference_hex"));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(text.len() / 2)
        .map_err(|_| ApiError::unavailable())?;
    let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    for pair in text.as_bytes().as_chunks::<2>().0 {
        bytes.push(digit(pair[0]) * 16 + digit(pair[1]));
    }
    if !bytes.starts_with(b"refs/heads/") {
        return Err(ApiError::bad("invalid_reference_namespace"));
    }
    RefName::try_new(&bytes).map_err(|_| ApiError::bad("invalid_reference"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn form(format: GitHashAlgorithm, count: usize) -> String {
        let mut form = format!("object_format={}", format.as_str());
        for i in 0..count {
            write!(
                form,
                "&create={}:{}",
                hex(format!("refs/heads/a{i}").as_bytes()),
                "a".repeat(format.digest_len() * 2)
            )
            .expect("writing to a String cannot fail");
        }
        form
    }
    #[test]
    fn mixed_transaction_retains_exact_bytes_and_conditions_in_both_domains() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let old = "a".repeat(format.digest_len() * 2);
            let new = "b".repeat(format.digest_len() * 2);
            let body = format!(
                "create={}:{new}&object_format={}&update={}:{old}:{new}&delete={}:{old}",
                hex(b"refs/heads/raw-\xff"),
                format.as_str(),
                hex(b"refs/heads/update"),
                hex(b"refs/heads/delete")
            );
            let (commands, scope) = parse(body.as_bytes(), format).unwrap();
            assert!(scope.is_none());
            assert_eq!(commands.len(), 3);
            assert_eq!(commands[0].name.as_bytes(), b"refs/heads/raw-\xff");
            assert_eq!(commands[0].expected_old, ExpectedOld::Absent);
            assert_eq!(
                commands[1].expected_old,
                ExpectedOld::Exactly(oid(&old, format).unwrap())
            );
            assert_eq!(commands[2].proposed_new, ProposedNew::Delete);
            assert!(commands.iter().all(|c| !c.force));
        }
    }
    #[test]
    fn count_and_payload_limits_refuse_without_truncation() {
        let f = GitHashAlgorithm::Sha256;
        for count in [64, 65, 1024] {
            assert_eq!(parse(form(f, count).as_bytes(), f).unwrap().0.len(), count);
        }
        // The independent form-byte bound can reject before the native count
        // ceiling; never truncate a large transaction into a permitted prefix.
        assert!(
            parse(
                form(f, OneNode::MAX_BRANCH_TRANSACTION_COMMANDS).as_bytes(),
                f
            )
            .is_err()
        );
        assert!(
            parse(
                form(f, OneNode::MAX_BRANCH_TRANSACTION_COMMANDS + 1).as_bytes(),
                f
            )
            .is_err()
        );
        assert!(parse(b"object_format=sha256", f).is_err());
        assert!(parse(&vec![b'x'; 262145], f).is_err());
        assert!(reference(&"aa".repeat(4097)).is_err());
    }
    #[test]
    fn duplicate_targets_and_implicit_or_extra_authority_fields_refuse() {
        let f = GitHashAlgorithm::Sha1;
        let good = form(f, 1);
        for extra in [
            "&force=true",
            "&principal=admin",
            "&atomic=false",
            "&object_format=sha1",
            "&create=bad",
            "&rename=bad",
        ] {
            assert!(
                parse((good.clone() + extra).as_bytes(), f).is_err(),
                "{extra}"
            );
        }
        let repeated = format!("{good}&delete={}:{}", hex(b"refs/heads/a0"), "a".repeat(40));
        assert!(parse(repeated.as_bytes(), f).is_err());
        assert!(parse(good.replace("object_format=sha1&", "").as_bytes(), f).is_err());
        assert!(parse(good.as_bytes(), GitHashAlgorithm::Sha256).is_err());
        assert_eq!(parse(good.as_bytes(), f).unwrap().0.len(), 1);
    }
    #[test]
    fn optional_writer_scope_requires_all_four_canonical_identities_exactly_once() {
        let f = GitHashAlgorithm::Sha256;
        let body = form(f, 1);
        let [tenant, repository, incarnation, principal] =
            [1, 2, 3, 0xa].map(|v| format!("{v:02x}").repeat(16));
        let scope = format!("{tenant}:{repository}:{incarnation}:{principal}");
        let scoped = format!("{body}&expected_scope={scope}");
        let (commands, expected) = parse(scoped.as_bytes(), f).unwrap();
        assert_eq!(commands, parse(body.as_bytes(), f).unwrap().0);
        assert_eq!(
            expected,
            Some(WriterScope {
                tenant: TenantId::from_bytes([1; 16]),
                repository: RepositoryId::from_bytes([2; 16]),
                incarnation: RepositoryIncarnationId::from_bytes([3; 16]),
                principal: PrincipalId::from_bytes([0xa; 16]),
            })
        );
        for invalid in [
            format!("{body}&expected_scope={tenant}:{repository}:{incarnation}"),
            format!("{scoped}:{tenant}"),
            scoped.replace(&principal, &principal.to_uppercase()),
            format!("{scoped}&expected_scope={scope}"),
        ] {
            assert!(parse(invalid.as_bytes(), f).is_err(), "{invalid}");
        }
    }
    #[test]
    fn operand_shapes_and_noncanonical_ids_are_closed() {
        let prefix = format!("object_format=sha1&update={}", hex(b"refs/heads/a"));
        let a = "a".repeat(40);
        let b = "b".repeat(40);
        assert!(
            parse(
                format!("{prefix}:{a}:{b}").as_bytes(),
                GitHashAlgorithm::Sha1
            )
            .is_ok()
        );
        for rest in [
            format!(":{a}"),
            format!(":{a}:{b}:extra"),
            format!(":{}:{b}", "0".repeat(40)),
            format!(":{a}:{}", "B".repeat(40)),
        ] {
            assert!(parse(format!("{prefix}{rest}").as_bytes(), GitHashAlgorithm::Sha1).is_err());
        }
        for name in [
            "",
            "abc",
            "GG",
            "726566732f746167732f61",
            "726566732f68656164732f2e2e",
        ] {
            assert!(reference(name).is_err(), "{name}");
        }
    }
}
