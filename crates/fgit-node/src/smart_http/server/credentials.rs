//! Operator-owned credential grants for the loopback HTTP deployment profile.
//!
//! This is an authentication-boundary configuration, NOT a repository-state
//! database, account directory, organization model, or forge authority. Only
//! token digests are stored. Each request reads one complete file, checks its
//! tenant/repository/incarnation binding, and selects an explicit principal
//! and service scopes. Missing/corrupt configuration never falls back to a
//! previously accepted grant. Revocation applies to subsequent authentication;
//! already authenticated in-flight requests retain their bounded grant.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};

use fgit_crypto::{sha256_digest, verify_mac};
use fgit_types::{PrincipalId, RepositoryId, RepositoryIncarnationId, TenantId};
use fgit_wire::smart_http::Service;

const MAX_FILE_BYTES: usize = 64 * 1024;
const MAX_GRANTS: usize = 256;
const HEADER: &str = "frankengit-http-credentials-v1";

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct Binding {
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub incarnation: RepositoryIncarnationId,
}

// No Debug implementation: credentials must not be printed in diagnostics.
#[derive(Clone)]
pub(super) enum CredentialSource {
    Static { digest: [u8; 32], principal: PrincipalId },
    File { path: PathBuf, binding: Binding },
}

#[derive(Clone, Copy)]
pub(super) struct Grant {
    pub principal: PrincipalId,
    read: bool,
    receive: bool,
    issues_read: bool,
    issues_write: bool,
}
impl Grant {
    pub fn permits(self, service: Service) -> bool {
        match service {
            Service::UploadPack => self.read,
            Service::ReceivePack => self.receive,
        }
    }
    pub fn permits_issues(self, mutation: bool) -> bool {
        if mutation { self.issues_write } else { self.issues_read }
    }
}

struct Entry {
    digest: [u8; 32],
    grant: Grant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CredentialFailure {
    UnknownCredential,
    Unavailable,
    InvalidFile,
    WrongRepository,
    UnsafeFile,
}
impl Display for CredentialFailure {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnknownCredential => "HTTP credential is not accepted",
            Self::Unavailable => "HTTP credential file is unavailable",
            Self::InvalidFile => "HTTP credential file is invalid or exceeds its bounds",
            Self::WrongRepository => "HTTP credential file selects a different repository incarnation",
            Self::UnsafeFile => "HTTP credential file must be a stable private regular file",
        })
    }
}
impl Error for CredentialFailure {}

impl CredentialSource {
    pub fn validate(&self) -> Result<(), CredentialFailure> {
        match self {
            Self::Static { .. } => Ok(()),
            Self::File { path, binding } => load(path, *binding).map(|_| ()),
        }
    }

    pub fn authenticate(&self, authorization: Option<&str>) -> Result<Grant, CredentialFailure> {
        let (scheme, token) = authorization.and_then(|value| value.split_once(' '))
            .ok_or(CredentialFailure::UnknownCredential)?;
        if !scheme.eq_ignore_ascii_case("bearer") || token.len() != 64
            || !token.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(CredentialFailure::UnknownCredential);
        }
        let candidate = sha256_digest(token.as_bytes());
        match self {
            Self::Static { digest, principal } => {
                if !verify_mac(digest, &candidate) {
                    return Err(CredentialFailure::UnknownCredential);
                }
                // Preserve the static Git profile without silently granting any
                // newly added metadata authority to an existing credential.
                Ok(Grant { principal: *principal, read: true, receive: true,
                    issues_read: false, issues_write: false })
            }
            Self::File { path, binding } => {
                let entries = load(path, *binding)?;
                let mut selected = None;
                // Inspect the complete bounded table. No prefix comparison and
                // no early return based on where the matching token is stored.
                // This is not a measured whole-request constant-time guarantee.
                for entry in entries {
                    if verify_mac(&entry.digest, &candidate) {
                        selected = Some(entry.grant);
                    }
                }
                selected.ok_or(CredentialFailure::UnknownCredential)
            }
        }
    }
}

fn safe_metadata(metadata: &Metadata) -> Result<(), CredentialFailure> {
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES as u64 {
        return Err(CredentialFailure::UnsafeFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            return Err(CredentialFailure::UnsafeFile);
        }
    }
    Ok(())
}

fn load(path: &Path, binding: Binding) -> Result<Vec<Entry>, CredentialFailure> {
    // Operator-controlled local path, not a hostile-filesystem containment API.
    // Update it with atomic rename, not in-place edits. The opened file owns
    // this request's snapshot; a later replacement applies to the next request.
    let before = fs::symlink_metadata(path).map_err(|_| CredentialFailure::Unavailable)?;
    safe_metadata(&before)?;
    let mut file = File::open(path).map_err(|_| CredentialFailure::Unavailable)?;
    let opened = file.metadata().map_err(|_| CredentialFailure::Unavailable)?;
    safe_metadata(&opened)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(CredentialFailure::UnsafeFile);
        }
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(MAX_FILE_BYTES + 1).map_err(|_| CredentialFailure::Unavailable)?;
    (&mut file).take((MAX_FILE_BYTES + 1) as u64).read_to_end(&mut bytes)
        .map_err(|_| CredentialFailure::Unavailable)?;
    let after = file.metadata().map_err(|_| CredentialFailure::Unavailable)?;
    safe_metadata(&after)?;
    if opened.len() != after.len() || after.len() != bytes.len() as u64
        || opened.modified().ok() != after.modified().ok()
    {
        return Err(CredentialFailure::UnsafeFile);
    }
    parse(&bytes, binding)
}

fn lower_hex<const N: usize>(text: &str) -> Result<[u8; N], CredentialFailure> {
    if text.len() != N * 2 || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(CredentialFailure::InvalidFile);
    }
    let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    let mut result = [0; N];
    for (out, pair) in result.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *out = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    Ok(result)
}

fn grant(principal: PrincipalId, scopes: &str) -> Result<Grant, CredentialFailure> {
    let mut grant = Grant { principal, read: false, receive: false, issues_read: false, issues_write: false };
    let mut previous = 0;
    for scope in scopes.split(',') {
        // Canonical order extends the original read,receive grammar. An old
        // deployment rejecting these new explicit scopes fails closed.
        let (rank, flag) = match scope {
            "read" => (1, &mut grant.read),
            "receive" => (2, &mut grant.receive),
            "issues-read" => (3, &mut grant.issues_read),
            "issues-write" => (4, &mut grant.issues_write),
            _ => return Err(CredentialFailure::InvalidFile),
        };
        if rank <= previous { return Err(CredentialFailure::InvalidFile); }
        *flag = true;
        previous = rank;
    }
    Ok(grant)
}

fn parse(bytes: &[u8], binding: Binding) -> Result<Vec<Entry>, CredentialFailure> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(CredentialFailure::InvalidFile);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| CredentialFailure::InvalidFile)?;
    let mut lines = text.lines();
    let mut header = lines.next().ok_or(CredentialFailure::InvalidFile)?.split(' ');
    if header.next() != Some(HEADER) {
        return Err(CredentialFailure::InvalidFile);
    }
    let selected = Binding {
        tenant: TenantId::from_bytes(lower_hex(header.next().ok_or(CredentialFailure::InvalidFile)?)?),
        repository: RepositoryId::from_bytes(lower_hex(header.next().ok_or(CredentialFailure::InvalidFile)?)?),
        incarnation: RepositoryIncarnationId::from_bytes(lower_hex(header.next().ok_or(CredentialFailure::InvalidFile)?)?),
    };
    if header.next().is_some() {
        return Err(CredentialFailure::InvalidFile);
    }
    if selected != binding {
        return Err(CredentialFailure::WrongRepository);
    }
    let mut entries = Vec::new();
    let mut digests = BTreeSet::new();
    for line in lines {
        if entries.len() == MAX_GRANTS {
            return Err(CredentialFailure::InvalidFile);
        }
        let mut fields = line.split(' ');
        let digest = lower_hex(fields.next().ok_or(CredentialFailure::InvalidFile)?)?;
        let principal = PrincipalId::from_bytes(lower_hex(fields.next().ok_or(CredentialFailure::InvalidFile)?)?);
        let grant = grant(principal, fields.next().ok_or(CredentialFailure::InvalidFile)?)?;
        if fields.next().is_some() || !digests.insert(digest) {
            return Err(CredentialFailure::InvalidFile);
        }
        entries.try_reserve(1).map_err(|_| CredentialFailure::Unavailable)?;
        entries.push(Entry { digest, grant });
    }
    // A header with zero entries is a valid revoke-all configuration.
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    fn binding() -> Binding {
        Binding { tenant: TenantId::from_bytes([1; 16]), repository: RepositoryId::from_bytes([2; 16]),
            incarnation: RepositoryIncarnationId::from_bytes([3; 16]) }
    }
    fn header() -> String {
        let b = binding();
        format!("{HEADER} {} {} {}\n", b.tenant, b.repository, b.incarnation)
    }
    fn row(token: &str, principal: u8, scope: &str) -> String {
        let digest: String = sha256_digest(token.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
        format!("{digest} {} {scope}\n", PrincipalId::from_bytes([principal; 16]))
    }
    fn private_write(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    #[test]
    fn scopes_are_explicit_and_receive_does_not_imply_fetch() {
        let text = header() + &row(&"a".repeat(64), 4, "read")
            + &row(&"b".repeat(64), 5, "receive") + &row(&"c".repeat(64), 6, "read,receive");
        let entries = parse(text.as_bytes(), binding()).unwrap();
        assert_eq!(entries.len(), 3);
        assert!(entries[0].grant.permits(Service::UploadPack));
        assert!(!entries[0].grant.permits(Service::ReceivePack));
        assert!(!entries[1].grant.permits(Service::UploadPack));
        assert!(entries[1].grant.permits(Service::ReceivePack));
        assert!(entries[2].grant.permits(Service::UploadPack));
        assert!(entries[2].grant.permits(Service::ReceivePack));
        assert_ne!(entries[0].grant.principal, entries[1].grant.principal);
        for entry in entries {
            assert!(!entry.grant.permits_issues(false));
            assert!(!entry.grant.permits_issues(true));
        }
    }
    #[test]
    fn issue_grants_never_imply_git_or_each_other() {
        let principal = PrincipalId::from_bytes([7; 16]);
        let read = grant(principal, "issues-read").unwrap();
        let write = grant(principal, "issues-write").unwrap();
        assert!(read.permits_issues(false));
        assert!(!read.permits_issues(true));
        assert!(write.permits_issues(true));
        assert!(!write.permits_issues(false));
        for grant in [read, write] {
            assert!(!grant.permits(Service::UploadPack));
            assert!(!grant.permits(Service::ReceivePack));
        }
        assert!(grant(principal, "issues-read,issues-write").unwrap().permits_issues(true));
        assert!(grant(principal, "issues-write,read").is_err());
        assert!(grant(principal, "issues-read,issues-read").is_err());
        let token = "a".repeat(64);
        let source = CredentialSource::Static { digest: sha256_digest(token.as_bytes()), principal };
        let legacy = source.authenticate(Some(&format!("Bearer {token}"))).unwrap();
        assert!(!legacy.permits_issues(false) && !legacy.permits_issues(true));
    }
    #[test]
    fn duplicate_tokens_bad_scopes_and_foreign_bindings_fail_closed() {
        let row = row(&"a".repeat(64), 4, "read");
        for text in [header() + &row + &row, header() + &row.replace(" read", " write"),
            header() + &row.replace(" read", " read,read"), header() + "\n", String::new()]
        {
            assert!(parse(text.as_bytes(), binding()).is_err());
        }
        let mut foreign = binding();
        foreign.incarnation = RepositoryIncarnationId::from_bytes([9; 16]);
        assert!(matches!(parse((header() + &row).as_bytes(), foreign), Err(CredentialFailure::WrongRepository)));
        assert!(parse(header().as_bytes(), binding()).unwrap().is_empty());
        assert!(parse(&vec![b'x'; MAX_FILE_BYTES + 1], binding()).is_err());
    }
    #[test]
    fn grants_reload_for_rotation_revocation_and_invalid_configuration() {
        let path = std::env::temp_dir().join(format!("fg-http-grants-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        let source = CredentialSource::File { path: path.clone(), binding: binding() };
        let first = format!("Bearer {}", "a".repeat(64));
        let rotated = format!("Bearer {}", "b".repeat(64));
        private_write(&path, (header() + &row(&"a".repeat(64), 4, "receive")).as_bytes());
        let principal = source.authenticate(Some(&first)).unwrap().principal;
        private_write(&path, (header() + &row(&"b".repeat(64), 4, "receive")).as_bytes());
        assert!(matches!(source.authenticate(Some(&first)), Err(CredentialFailure::UnknownCredential)));
        assert_eq!(source.authenticate(Some(&rotated)).unwrap().principal, principal);
        private_write(&path, b"malformed");
        assert!(matches!(source.authenticate(Some(&rotated)), Err(CredentialFailure::InvalidFile)));
        private_write(&path, header().as_bytes());
        assert!(matches!(source.authenticate(Some(&rotated)), Err(CredentialFailure::UnknownCredential)));
        fs::remove_file(&path).unwrap();
        assert!(matches!(source.authenticate(Some(&rotated)), Err(CredentialFailure::Unavailable)));
    }
    #[cfg(unix)]
    #[test]
    fn public_files_and_symlinks_are_refused() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let path = std::env::temp_dir().join(format!("fg-http-grant-perms-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        private_write(&path, header().as_bytes());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(load(&path, binding()), Err(CredentialFailure::UnsafeFile)));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = path.with_extension("link");
        symlink(&path, &link).unwrap();
        assert!(matches!(load(&link, binding()), Err(CredentialFailure::UnsafeFile)));
        fs::remove_file(link).unwrap();
        fs::remove_file(path).unwrap();
    }
}
