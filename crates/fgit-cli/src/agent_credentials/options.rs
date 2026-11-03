use super::USAGE;
use fgit_authority::IdempotencyKey;
use fgit_forge::{AggregateVersion, ExpectedVersion};
use fgit_identity::agent::{
    AgentCredentialGrant, AgentCredentialId, DISCUSSIONS_READ, DISCUSSIONS_WRITE, ISSUES_READ,
    ISSUES_WRITE, OUTCOMES_READ, PULLS_READ, PULLS_WRITE, SOURCE_READ, SponsorKind,
};
use fgit_types::{GitHashAlgorithm, PrincipalId, RepositoryId, RepositoryIncarnationId, TenantId};
use std::{collections::BTreeMap, path::PathBuf};

pub(super) enum Options {
    Generate { output: PathBuf },
    Repository(RepositoryOptions),
}
pub(super) struct RepositoryOptions {
    pub storage: PathBuf,
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub incarnation: RepositoryIncarnationId,
    pub format: GitHashAlgorithm,
    pub operation: Operation,
}
pub(super) enum Operation {
    Show {
        id: Option<AgentCredentialId>,
    },
    Issue {
        principal: PrincipalId,
        key: IdempotencyKey,
        grant: AgentCredentialGrant,
        token_file: PathBuf,
    },
    Revoke {
        principal: PrincipalId,
        key: IdempotencyKey,
        id: AgentCredentialId,
        expected_version: ExpectedVersion,
    },
}

fn integer(value: &str) -> Result<u64, String> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("expected a canonical unsigned integer".into());
    }
    value.parse().map_err(|_| "integer overflow".into())
}

fn credential_id(value: &str) -> Result<AgentCredentialId, String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("credential ID must be 64 lowercase hexadecimal digits".into());
    }
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * index..2 * index + 2], 16)
            .map_err(|_| "invalid credential ID")?;
    }
    AgentCredentialId::try_new(bytes).ok_or_else(|| "credential ID must be nonzero".into())
}

fn operations(value: &str) -> Result<u16, String> {
    let mut result = 0u16;
    for operation in value.split(',') {
        let bit = match operation {
            "issues-read" => ISSUES_READ,
            "issues-write" => ISSUES_WRITE,
            "pulls-read" => PULLS_READ,
            "pulls-write" => PULLS_WRITE,
            "discussions-read" => DISCUSSIONS_READ,
            "discussions-write" => DISCUSSIONS_WRITE,
            "outcomes-read" => OUTCOMES_READ,
            "source-read" => SOURCE_READ,
            _ => return Err("unknown or unsupported agent credential operation".into()),
        };
        if result & bit != 0 {
            return Err("duplicate agent credential operation".into());
        }
        result |= bit;
    }
    Ok(result)
}

pub(super) fn parse(args: &[String]) -> Result<Options, String> {
    if args.is_empty()
        || args.len() > 40
        || args.iter().any(|arg| arg.len() > 4096)
        || args.iter().map(String::len).sum::<usize>() > 32768
    {
        return Err(USAGE.into());
    }
    if args[0] == "generate-token" {
        return if args.len() == 3 && args[1] == "--output" && !args[2].is_empty() {
            Ok(Options::Generate {
                output: args[2].clone().into(),
            })
        } else {
            Err(USAGE.into())
        };
    }
    if args.len() < 7
        || args[1].is_empty()
        || !matches!(args[0].as_str(), "issue" | "revoke" | "show")
    {
        return Err(USAGE.into());
    }
    let tenant = TenantId::from_hex(&args[2]).map_err(|_| "invalid tenant ID")?;
    let repository = RepositoryId::from_hex(&args[3]).map_err(|_| "invalid repository ID")?;
    let operation = args[0].as_str();
    let mut fields = BTreeMap::new();
    let mut trusted = false;
    let mut index = 4;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        if flag == "--trusted-local" {
            if trusted {
                return Err("duplicate --trusted-local".into());
            }
            trusted = true;
            continue;
        }
        let allowed = matches!(flag, "--incarnation" | "--object-format")
            || (operation == "show" && flag == "--credential-id")
            || (operation != "show" && matches!(flag, "--principal" | "--idempotency-key"))
            || (operation == "revoke" && matches!(flag, "--credential-id" | "--expected-version"))
            || (operation == "issue"
                && matches!(
                    flag,
                    "--agent"
                        | "--sponsor-kind"
                        | "--token-file"
                        | "--issued-at"
                        | "--expires-at"
                        | "--operations"
                ));
        if !allowed {
            return Err("unknown or inapplicable agent-credential option".into());
        }
        let value = args
            .get(index)
            .ok_or("missing agent-credential option value")?;
        index += 1;
        if value.is_empty() || fields.insert(flag, value.as_str()).is_some() {
            return Err("empty or duplicate agent-credential option".into());
        }
    }
    if !trusted {
        return Err("--trusted-local is required".into());
    }
    let get = |flag| {
        fields
            .get(flag)
            .copied()
            .ok_or_else(|| format!("{flag} is required"))
    };
    let incarnation = RepositoryIncarnationId::from_hex(get("--incarnation")?)
        .map_err(|_| "invalid incarnation ID")?;
    let format = match fields.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1,
        "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("object format must be sha1 or sha256".into()),
    };
    let operation = if operation == "show" {
        Operation::Show {
            id: fields
                .get("--credential-id")
                .map(|value| credential_id(value))
                .transpose()?,
        }
    } else {
        let principal =
            PrincipalId::from_hex(get("--principal")?).map_err(|_| "invalid principal ID")?;
        if principal.as_bytes().iter().all(|byte| *byte == 0) {
            return Err("principal ID must be nonzero".into());
        }
        let key = IdempotencyKey::new(get("--idempotency-key")?.as_bytes().to_vec())
            .map_err(|_| "invalid idempotency key")?;
        if operation == "issue" {
            let grant = AgentCredentialGrant {
                agent: PrincipalId::from_hex(get("--agent")?).map_err(|_| "invalid agent ID")?,
                sponsor: principal,
                sponsor_kind: match get("--sponsor-kind")? {
                    "human" => SponsorKind::Human,
                    "service" => SponsorKind::Service,
                    _ => return Err("sponsor kind must be explicit human or service".into()),
                },
                tenant,
                repository,
                incarnation,
                issued_at: integer(get("--issued-at")?)?,
                expires_at: integer(get("--expires-at")?)?,
                operations: operations(get("--operations")?)?,
            };
            grant
                .validate()
                .map_err(|error| format!("invalid agent grant: {error}"))?;
            Operation::Issue {
                principal,
                key,
                grant,
                token_file: get("--token-file")?.into(),
            }
        } else {
            if integer(get("--expected-version")?)? != 1 {
                return Err(
                    "revocation requires --expected-version 1; the grant is immutable".into(),
                );
            }
            Operation::Revoke {
                principal,
                key,
                id: credential_id(get("--credential-id")?)?,
                expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
            }
        }
    };
    Ok(Options::Repository(RepositoryOptions {
        storage: args[1].clone().into(),
        tenant,
        repository,
        incarnation,
        format,
        operation,
    }))
}
