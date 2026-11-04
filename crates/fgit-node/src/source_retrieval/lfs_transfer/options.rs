//! Explicit local authorization, namespace pins and finite independent budgets.
use super::*;
use fgit_runtime::{BudgetClass, BudgetPolicy, ClassLimits};

pub(super) const USAGE: &str = "usage: fg lfs inventory <storage-root> <tenant-id> <repository-id>
       fg lfs export <storage-root> <lfs-root> <new-archive-file> <tenant-id> <repository-id>
       fg lfs import <storage-root> <lfs-root> <archive-file> <tenant-id> <repository-id>
         --expected-sha256 <archive-sha256> --expected-incarnation <id>
         --expected-head-sha256 <head-body-sha256>

All operations require --trusted-local and whole-repository authorization.
All paths must be absolute without symlinks or parent traversal. Archive files
must live in existing private (0700) directories. Import takes a private spool,
verifies the entire archive and independent checksum, then copies only payloads
referenced by the exact target native inventory. Every target pointer must be
covered; valid extra archive objects are skipped. Source and target namespaces
may differ. No refs, aliases, authority heads, or retention roots are published.

Options: --object-format sha1|sha256 (default sha1)
         --expected-incarnation <id> (optional for inventory/export)
         --expected-head-sha256 <head-body-sha256> (optional for inventory/export)
         --max-objects <1..1000000> (LFS records; default 100000)
         --max-source-objects <1..1000000> (native inventory; default 100000)
         --max-source-bytes <1..1099511627776> (default 1073741824)
         --max-payload-bytes <1..1099511627776> (default 1073741824)
         --max-archive-bytes <1..1099511627776> (default 1073741824)
         --timeout-secs <1..3600> (default 300; global timeout only narrows)

Only canonical extension-free v1 LFS pointers and SHA-256 LFS payloads up to
64 MiB each are supported. Every selected native object is verified, including
retained history, under the source scan budget. Missing/corrupt/unsupported
pointer custody refuses export. Physical orphan payloads are never enumerated.
Import is idempotent immutable custody, not an atomic multi-object transaction.
On interruption or a moved head, earlier valid puts remain and identical retry
can recover them. Keep the archive, checksum and explicit destination pins.
This is a source-backup companion, not a complete service backup. Deadlines are
cooperative between filesystem operations, which can themselves block.";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Action {
    Inventory,
    Export,
    Import,
}

#[derive(Clone, Debug)]
pub(super) struct Options {
    pub action: Action,
    pub root: PathBuf,
    pub custody: Option<PathBuf>,
    pub archive: Option<PathBuf>,
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub format: GitHashAlgorithm,
    pub incarnation: Option<RepositoryIncarnationId>,
    pub head_sha256: Option<[u8; 32]>,
    pub archive_sha256: Option<[u8; 32]>,
    pub limits: TransferLimits,
    pub source_objects: usize,
    pub source_bytes: u64,
    pub timeout: Duration,
}

pub(super) fn digest(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("digest must be 64 lowercase hexadecimal characters".into());
    }
    let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    let mut result = [0; 32];
    for (out, pair) in result.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        *out = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(result)
}

fn positive(value: &str, maximum: u64) -> Result<u64, String> {
    if value.is_empty() || value.starts_with('0') || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("limit must be a canonical positive decimal".into());
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|n| *n <= maximum)
        .ok_or_else(|| "limit exceeds the supported profile".into())
}

impl Options {
    pub fn parse(args: &[String], cap: Option<Duration>) -> Result<Self, String> {
        if args.len() > 32
            || args.iter().any(|s| s.len() > 8192)
            || args.iter().map(String::len).sum::<usize>() > 32768
        {
            return Err("LFS command argument limit".into());
        }
        let action = match args.first().map(String::as_str) {
            Some("inventory") => Action::Inventory,
            Some("export") => Action::Export,
            Some("import") => Action::Import,
            _ => return Err(USAGE.into()),
        };
        let (prefix, custody, archive, tenant, repository) = if action == Action::Inventory {
            if args.len() < 5 {
                return Err(USAGE.into());
            }
            (4, None, None, &args[2], &args[3])
        } else {
            if args.len() < 7 {
                return Err(USAGE.into());
            }
            (
                6,
                Some(PathBuf::from(&args[2])),
                Some(PathBuf::from(&args[3])),
                &args[4],
                &args[5],
            )
        };
        let mut options = Self {
            action,
            root: args[1].clone().into(),
            custody,
            archive,
            tenant: TenantId::from_hex(tenant).map_err(|e| e.to_string())?,
            repository: RepositoryId::from_hex(repository).map_err(|e| e.to_string())?,
            format: GitHashAlgorithm::Sha1,
            incarnation: None,
            head_sha256: None,
            archive_sha256: None,
            limits: TransferLimits::default(),
            source_objects: 100_000,
            source_bytes: 1 << 30,
            timeout: Duration::from_secs(300),
        };
        let mut seen = BTreeSet::new();
        let mut cursor = prefix;
        while let Some(flag) = args.get(cursor) {
            cursor += 1;
            if !seen.insert(flag.as_str()) {
                return Err("duplicate LFS option".into());
            }
            if flag == "--trusted-local" {
                continue;
            }
            let value = args.get(cursor).ok_or("missing LFS option value")?;
            cursor += 1;
            match flag.as_str() {
                "--object-format" => {
                    options.format = match value.as_str() {
                        "sha1" => GitHashAlgorithm::Sha1,
                        "sha256" => GitHashAlgorithm::Sha256,
                        _ => return Err("object format must be sha1 or sha256".into()),
                    }
                }
                "--expected-incarnation" => {
                    options.incarnation =
                        Some(RepositoryIncarnationId::from_hex(value).map_err(|e| e.to_string())?)
                }
                "--expected-head-sha256" => options.head_sha256 = Some(digest(value)?),
                "--expected-sha256" if action == Action::Import => {
                    options.archive_sha256 = Some(digest(value)?)
                }
                "--max-objects" => {
                    options.limits.max_objects = positive(value, 1_000_000)? as usize
                }
                "--max-source-objects" => {
                    options.source_objects = positive(value, 1_000_000)? as usize
                }
                "--max-source-bytes" => options.source_bytes = positive(value, 1 << 40)?,
                "--max-payload-bytes" => {
                    options.limits.max_payload_bytes = positive(value, 1 << 40)?
                }
                "--max-archive-bytes" => {
                    options.limits.max_archive_bytes = positive(value, 1 << 40)?
                }
                "--timeout-secs" => options.timeout = Duration::from_secs(positive(value, 3600)?),
                _ => return Err("unknown or inapplicable LFS option".into()),
            }
        }
        if !seen.contains("--trusted-local") {
            return Err(
                "LFS transfer requires --trusted-local and whole-repository authorization".into(),
            );
        }
        if action == Action::Import
            && (options.incarnation.is_none()
                || options.head_sha256.is_none()
                || options.archive_sha256.is_none())
        {
            return Err("LFS import requires exact destination incarnation/head and independently trusted archive SHA-256".into());
        }
        if let Some(cap) = cap {
            if cap.is_zero() {
                return Err("LFS timeout cap must be positive".into());
            }
            options.timeout = options.timeout.min(cap);
        }
        Ok(options)
    }

    pub fn config(&self) -> Result<NodeConfig, String> {
        let budget = ClassLimits::finite(self.timeout, 1_000_000, 50_000_000);
        let budgets = BudgetPolicy::finite_defaults()
            .with_class_limits(BudgetClass::Database, budget)
            .and_then(|p| p.with_class_limits(BudgetClass::Request, budget))
            .map_err(|e| e.to_string())?;
        let bytes =
            usize::try_from(self.source_bytes).map_err(|_| "source budget exceeds host width")?;
        Ok(
            NodeConfig::new(self.root.clone(), self.tenant, self.repository)
                .with_object_format(self.format)
                .with_selected_pack_blob_limit(bytes)
                .with_runtime_budgets(budgets),
        )
    }
}

#[derive(Clone, Copy)]
pub(super) struct Deadline(Instant);
impl Deadline {
    pub fn new(timeout: Duration) -> Self {
        Self(Instant::now() + timeout)
    }
    pub fn check(self) -> Result<(), String> {
        if Instant::now() >= self.0 {
            Err("LFS operation deadline exceeded".into())
        } else {
            Ok(())
        }
    }
    pub fn live(self, request: &NodeRequestContext) -> bool {
        if self.check().is_err() {
            request.cancel();
            return false;
        }
        request.is_live()
    }
    pub fn request(self, request: &NodeRequestContext) -> Result<(), String> {
        if self.live(request) {
            Ok(())
        } else {
            Err("LFS operation cancelled or resource budget exhausted".into())
        }
    }
    pub fn remaining(self) -> Result<Duration, String> {
        self.check()?;
        Ok(self.0.saturating_duration_since(Instant::now()))
    }
}
