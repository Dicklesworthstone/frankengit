use super::USAGE;
use fgit_object_fabric::{ArtifactIdentity, ArtifactPayloadKind, MediaType, RetentionProfile};
use fgit_types::{
    Digest, DigestAlgorithmId, DigestBytes, RepositoryId, RepositoryIncarnationId, TenantId,
};
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

#[derive(Debug)]
pub(super) enum Selection {
    Put {
        source: PathBuf,
        identity: ArtifactIdentity,
    },
    Inspect {
        id: Digest,
    },
    Export {
        id: Digest,
        output: PathBuf,
    },
}
#[derive(Debug)]
pub(super) struct Options {
    pub root: PathBuf,
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub incarnation: RepositoryIncarnationId,
    pub trust: String,
    pub maximum: u64,
    pub selection: Selection,
}
pub(super) fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 8
        || args.len() > 40
        || args.iter().any(|s| s.len() > 4096 || s.contains('\0'))
        || args.iter().map(String::len).sum::<usize>() > 32768
    {
        return Err(USAGE.into());
    }
    let operation = args[0].as_str();
    if !matches!(operation, "put" | "inspect" | "export") {
        return Err(USAGE.into());
    }
    let root = absolute(&args[1])?;
    for value in &args[2..5] {
        if value.len() != 32
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("scope IDs must be 32 lowercase hexadecimal digits".into());
        }
    }
    let tenant = TenantId::from_hex(&args[2]).map_err(|e| e.to_string())?;
    let repository = RepositoryId::from_hex(&args[3]).map_err(|e| e.to_string())?;
    let incarnation = RepositoryIncarnationId::from_hex(&args[4]).map_err(|e| e.to_string())?;
    let mut fields = BTreeMap::new();
    let mut cursor = 5;
    while cursor < args.len() {
        let name = args[cursor].as_str();
        cursor += 1;
        let allowed = matches!(
            name,
            "--trusted-local" | "--trust-domain" | "--max-payload-mib"
        ) || match operation {
            "put" => matches!(
                name,
                "--source"
                    | "--payload-sha256"
                    | "--payload-bytes"
                    | "--kind"
                    | "--media-type"
                    | "--ttl-secs"
                    | "--expected-id"
                    | "--source-rcr"
                    | "--build-capsule"
                    | "--check-receipt"
            ),
            "inspect" => name == "--id",
            _ => matches!(name, "--id" | "--output"),
        };
        if !allowed {
            return Err(format!("unsupported {operation} option {name:?}"));
        }
        let value = if name == "--trusted-local" {
            "true"
        } else {
            let value = args
                .get(cursor)
                .ok_or_else(|| format!("missing value for {name}"))?;
            cursor += 1;
            if value.is_empty() || value.starts_with("--") {
                return Err(format!("missing value for {name}"));
            }
            value
        };
        if fields.insert(name, value).is_some() {
            return Err(format!("duplicate {name}"));
        }
    }
    let required = |name| {
        fields
            .get(name)
            .copied()
            .ok_or_else(|| format!("{name} is required"))
    };
    required("--trusted-local")?;
    let trust = required("--trust-domain")?;
    if trust.is_empty()
        || trust.len() > 256
        || !trust
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err("trust domain must contain 1..256 ASCII identifier bytes".into());
    }
    let maximum = fields
        .get("--max-payload-mib")
        .map_or(Ok(64), |s| decimal(s, 1, 512))?
        * 1024
        * 1024;
    let selection = if operation == "put" {
        let source = absolute(required("--source")?)?;
        let length = decimal(required("--payload-bytes")?, 0, maximum)?;
        let kind = match required("--kind")? {
            "ci_artifact" => ArtifactPayloadKind::CiArtifact,
            "build_log" => ArtifactPayloadKind::BuildLog,
            "release_asset" => ArtifactPayloadKind::ReleaseAsset,
            "sbom" => ArtifactPayloadKind::Sbom,
            "signature" => ArtifactPayloadKind::Signature,
            "provenance" => ArtifactPayloadKind::Provenance,
            "git_lfs" => ArtifactPayloadKind::GitLfs,
            _ => return Err("unsupported artifact kind".into()),
        };
        let optional = |name| fields.get(name).map(|s| digest(s)).transpose();
        let identity = ArtifactIdentity::new(
            digest(required("--payload-sha256")?)?,
            length,
            MediaType::parse(required("--media-type")?).map_err(|e| format!("{e:?}"))?,
            kind,
            optional("--build-capsule")?,
            optional("--check-receipt")?,
            optional("--source-rcr")?,
            RetentionProfile::HotEphemeral {
                ttl_seconds: fields
                    .get("--ttl-secs")
                    .map_or(Ok(86400), |s| decimal(s, 1, u64::MAX))?,
            },
        );
        if optional("--expected-id")?
            .as_ref()
            .is_some_and(|id| id != identity.artifact_id())
        {
            return Err("artifact identity differs from --expected-id; no storage opened".into());
        }
        Selection::Put { source, identity }
    } else {
        let id = digest(required("--id")?)?;
        if operation == "inspect" {
            Selection::Inspect { id }
        } else {
            Selection::Export {
                id,
                output: absolute(required("--output")?)?,
            }
        }
    };
    Ok(Options {
        root,
        tenant,
        repository,
        incarnation,
        trust: trust.into(),
        maximum,
        selection,
    })
}
fn decimal(value: &str, low: u64, high: u64) -> Result<u64, String> {
    if value.is_empty()
        || value.len() > 20
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("expected canonical unsigned decimal".into());
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|n| (low..=high).contains(n))
        .ok_or_else(|| "decimal outside selected bounds".into())
}
pub(super) fn digest(value: &str) -> Result<Digest, String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("SHA-256 must have 64 lowercase hexadecimal digits".into());
    }
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(Digest::new(
        DigestAlgorithmId::try_new(2).expect("registered SHA-256"),
        DigestBytes::try_new(&bytes).expect("SHA-256 width"),
    ))
}
fn absolute(value: &str) -> Result<PathBuf, String> {
    let path = Path::new(value);
    if !path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        || path.components().collect::<PathBuf>().as_os_str() != path.as_os_str()
    {
        return Err("path must be normalized and absolute".into());
    }
    Ok(path.into())
}
