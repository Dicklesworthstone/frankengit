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
use std::sync::Arc;

use fgit_authority::IdempotencyKey;
use fgit_crypto::{sha256_digest, verify_mac};
use fgit_types::{PrincipalId, RepositoryId, RepositoryIncarnationId, TenantId};
use fgit_wire::smart_http::Service;

use crate::ref_write_scope::RefWriteScope;
use crate::{AuthenticatedReceiveSession, LoopbackReceiveSession};
use fgit_admission::evidence::AdmissionAuthentication;

const MAX_FILE_BYTES: usize = 64 * 1024;
const MAX_GRANTS: usize = 256;
const HEADER: &str = "frankengit-http-credentials-v1";
const HEADER_V2: &str = "frankengit-http-credentials-v2";

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct Binding {
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub incarnation: RepositoryIncarnationId,
}

// No Debug implementation: credentials must not be printed in diagnostics.
#[derive(Clone)]
pub(super) enum CredentialSource {
    Static {
        digest: [u8; 32],
        principal: PrincipalId,
    },
    File {
        path: PathBuf,
        binding: Binding,
    },
}

// Declaration order is the existing credential grammar's canonical scope order.
// These positions are private memory representation, never serialized evidence.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum Scope {
    Read,
    Receive,
    IssuesRead,
    IssuesWrite,
    OutcomesRead,
    PullsRead,
    PullsWrite,
    ReviewsRead,
    ReviewsWrite,
    MergesWrite,
    ProtectionRead,
    ProtectionWrite,
    LfsRead,
    LfsWrite,
    ArtifactRead,
    QueuesRead,
    QueuesWrite,
    QueuesLand,
}

impl Scope {
    fn parse(text: &str) -> Result<Self, CredentialFailure> {
        match text {
            "read" => Ok(Self::Read),
            "receive" => Ok(Self::Receive),
            "issues-read" => Ok(Self::IssuesRead),
            "issues-write" => Ok(Self::IssuesWrite),
            "outcomes-read" => Ok(Self::OutcomesRead),
            "pulls-read" => Ok(Self::PullsRead),
            "pulls-write" => Ok(Self::PullsWrite),
            "reviews-read" => Ok(Self::ReviewsRead),
            "reviews-write" => Ok(Self::ReviewsWrite),
            "merges-write" => Ok(Self::MergesWrite),
            "protection-read" => Ok(Self::ProtectionRead),
            "protection-write" => Ok(Self::ProtectionWrite),
            "lfs-read" => Ok(Self::LfsRead),
            "lfs-write" => Ok(Self::LfsWrite),
            "artifact-read" => Ok(Self::ArtifactRead),
            "queues-read" => Ok(Self::QueuesRead),
            "queues-write" => Ok(Self::QueuesWrite),
            "queues-land" => Ok(Self::QueuesLand),
            _ => Err(CredentialFailure::InvalidFile),
        }
    }

    const fn mask(self) -> u32 {
        1 << self as u8
    }
}

#[derive(Clone, Copy, Default)]
struct Scopes(u32);

impl Scopes {
    const fn git_transport() -> Self {
        Self(Scope::Read.mask() | Scope::Receive.mask())
    }

    const fn contains(self, scope: Scope) -> bool {
        self.0 & scope.mask() != 0
    }

    const fn insert(&mut self, scope: Scope) {
        self.0 |= scope.mask();
    }
}

#[derive(Clone)]
pub(super) struct Grant {
    pub principal: PrincipalId,
    scopes: Scopes,
    ref_write_scope: Option<Arc<RefWriteScope>>,
}
impl Grant {
    pub const fn permits(&self, service: Service) -> bool {
        match service {
            Service::UploadPack => self.scopes.contains(Scope::Read),
            Service::ReceivePack => self.scopes.contains(Scope::Receive),
        }
    }
    pub const fn permits_issues(&self, mutation: bool) -> bool {
        if mutation {
            self.scopes.contains(Scope::IssuesWrite)
        } else {
            self.scopes.contains(Scope::IssuesRead)
        }
    }
    /// PR metadata authority is separate from code publication and reviews.
    pub const fn permits_pulls(&self, mutation: bool) -> bool {
        if mutation {
            self.scopes.contains(Scope::PullsWrite)
        } else {
            self.scopes.contains(Scope::PullsRead)
        }
    }
    /// Queue intent is independent of PR, review and code publication authority.
    pub const fn permits_queues(&self, mutation: bool) -> bool {
        if mutation {
            self.scopes.contains(Scope::QueuesWrite)
        } else {
            self.scopes.contains(Scope::QueuesRead)
        }
    }
    /// Queue-head code publication is independent of membership and PR merges.
    /// The target's reference ceiling and canonical protection remain mandatory.
    pub const fn permits_queue_landing(&self) -> bool {
        self.scopes.contains(Scope::QueuesLand)
    }
    /// A vote always uses this credential's principal, not a form field.
    pub const fn permits_reviews(&self, mutation: bool) -> bool {
        if mutation {
            self.scopes.contains(Scope::ReviewsWrite)
        } else {
            self.scopes.contains(Scope::ReviewsRead)
        }
    }
    /// Allows reviewed code publication and selection of additional named
    /// reviewers. Mandatory repository protection remains enforced at CAS.
    pub const fn permits_reviewed_merge(&self) -> bool {
        self.scopes.contains(Scope::MergesWrite)
    }
    /// Policy inspection and administration require independent explicit grants.
    pub const fn permits_protection(&self, mutation: bool) -> bool {
        if mutation {
            self.scopes.contains(Scope::ProtectionWrite)
        } else {
            self.scopes.contains(Scope::ProtectionRead)
        }
    }
    /// Recovery is separately grantable after write access has been withdrawn.
    /// It never permits inspecting another principal's transaction namespace.
    pub const fn permits_outcomes(&self) -> bool {
        self.scopes.contains(Scope::OutcomesRead)
    }
    /// Reads the complete explicitly selected workflow artifact custody namespace.
    /// This separate grant does not inherit Git visibility or grant a check.
    pub const fn permits_artifact_read(&self) -> bool {
        self.scopes.contains(Scope::ArtifactRead)
    }
    /// Artifact custody is independent from Git ref publication and metadata.
    pub const fn permits_lfs(&self, mutation: bool) -> bool {
        if mutation {
            self.scopes.contains(Scope::LfsWrite)
        } else {
            self.scopes.contains(Scope::LfsRead)
        }
    }

    /// Carry the selected write ceiling across Git and native API dispatch.
    /// No request payload may replace it or widen another service grant.
    pub(super) fn session(&self, key: IdempotencyKey) -> LoopbackReceiveSession {
        LoopbackReceiveSession::Authenticated(
            AuthenticatedReceiveSession::new(self.principal, key)
                .with_authentication(AdmissionAuthentication::HttpToken)
                .with_ref_write_scope(self.ref_write_scope.clone()),
        )
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
            Self::WrongRepository => {
                "HTTP credential file selects a different repository incarnation"
            }
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
        let candidate = credential_digest(authorization)?;
        match self {
            Self::Static { digest, principal } => {
                if !verify_mac(digest, &candidate) {
                    return Err(CredentialFailure::UnknownCredential);
                }
                // Preserve the static Git profile without silently granting any
                // newly added metadata authority to an existing credential.
                Ok(Grant {
                    principal: *principal,
                    scopes: Scopes::git_transport(),
                    ref_write_scope: None,
                })
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

// Basic transports the existing token as the password for ordinary Git
// credential helpers. The username is syntax only: it MUST NOT select a
// principal or widen a grant. This remains the loopback/TLS-proxy profile;
// base64 does not protect a credential on an unencrypted network.
const MAX_BASIC_USERNAME_BYTES: usize = 256;
const MAX_BASIC_BYTES: usize = MAX_BASIC_USERNAME_BYTES + 1 + 64;

fn credential_digest(authorization: Option<&str>) -> Result<[u8; 32], CredentialFailure> {
    let (scheme, value) = authorization
        .and_then(|value| value.split_once(' '))
        .ok_or(CredentialFailure::UnknownCredential)?;
    if scheme.eq_ignore_ascii_case("bearer") {
        return token_digest(value.as_bytes());
    }
    if !scheme.eq_ignore_ascii_case("basic") {
        return Err(CredentialFailure::UnknownCredential);
    }
    let mut decoded = [0_u8; MAX_BASIC_BYTES];
    let length =
        decode_basic(value.as_bytes(), &mut decoded).ok_or(CredentialFailure::UnknownCredential)?;
    let user_pass = &decoded[..length];
    let separator = user_pass
        .iter()
        .position(|byte| *byte == b':')
        .ok_or(CredentialFailure::UnknownCredential)?;
    if separator == 0
        || separator > MAX_BASIC_USERNAME_BYTES
        || user_pass[..separator].iter().any(u8::is_ascii_control)
        || std::str::from_utf8(&user_pass[..separator]).is_err()
    {
        return Err(CredentialFailure::UnknownCredential);
    }
    token_digest(&user_pass[separator + 1..])
}

fn token_digest(token: &[u8]) -> Result<[u8; 32], CredentialFailure> {
    if token.len() != 64
        || !token
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(CredentialFailure::UnknownCredential);
    }
    Ok(sha256_digest(token))
}

// A fixed-size RFC 4648 decoder for the bounded Basic user-pass field only.
// Reject truncated input, whitespace, URL-safe alphabets, internal/extra
// padding and nonzero unused bits. No allocation depends on hostile input.
fn decode_basic(input: &[u8], output: &mut [u8; MAX_BASIC_BYTES]) -> Option<usize> {
    if input.is_empty()
        || input.len() > MAX_BASIC_BYTES.div_ceil(3) * 4
        || !input.len().is_multiple_of(4)
    {
        return None;
    }
    const fn sextet(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut written = 0;
    for (index, quartet) in input.as_chunks::<4>().0.iter().enumerate() {
        let a = sextet(quartet[0])?;
        let b = sextet(quartet[1])?;
        let last = index + 1 == input.len() / 4;
        let (c, d, count) = match (quartet[2], quartet[3]) {
            (b'=', b'=') if last && b.is_multiple_of(16) => (0, 0, 1),
            (c, b'=') if last => {
                let c = sextet(c)?;
                if c & 3 != 0 {
                    return None;
                }
                (c, 0, 2)
            }
            (c, d) => (sextet(c)?, sextet(d)?, 3),
        };
        if written + count > output.len() {
            return None;
        }
        output[written] = (a << 2) | (b >> 4);
        if count > 1 {
            output[written + 1] = (b << 4) | (c >> 2);
        }
        if count > 2 {
            output[written + 2] = (c << 6) | d;
        }
        written += count;
    }
    Some(written)
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
    let opened = file
        .metadata()
        .map_err(|_| CredentialFailure::Unavailable)?;
    safe_metadata(&opened)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(CredentialFailure::UnsafeFile);
        }
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(MAX_FILE_BYTES + 1)
        .map_err(|_| CredentialFailure::Unavailable)?;
    (&mut file)
        .take((MAX_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| CredentialFailure::Unavailable)?;
    let after = file
        .metadata()
        .map_err(|_| CredentialFailure::Unavailable)?;
    safe_metadata(&after)?;
    if opened.len() != after.len()
        || after.len() != bytes.len() as u64
        || opened.modified().ok() != after.modified().ok()
    {
        return Err(CredentialFailure::UnsafeFile);
    }
    parse(&bytes, binding)
}

fn lower_hex<const N: usize>(text: &str) -> Result<[u8; N], CredentialFailure> {
    if text.len() != N * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(CredentialFailure::InvalidFile);
    }
    let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    let mut result = [0; N];
    for (out, pair) in result
        .iter_mut()
        .zip(text.as_bytes().as_chunks::<2>().0.iter())
    {
        *out = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    Ok(result)
}

fn grant(principal: PrincipalId, scopes: &str) -> Result<Grant, CredentialFailure> {
    let mut grant = Grant {
        principal,
        scopes: Scopes::default(),
        ref_write_scope: None,
    };
    let mut previous = None;
    for name in scopes.split(',') {
        // Preserve strict canonical order and refusal of duplicate/unknown scopes.
        let scope = Scope::parse(name)?;
        if previous.is_some_and(|previous| scope <= previous) {
            return Err(CredentialFailure::InvalidFile);
        }
        grant.scopes.insert(scope);
        previous = Some(scope);
    }
    Ok(grant)
}

fn parse(bytes: &[u8], binding: Binding) -> Result<Vec<Entry>, CredentialFailure> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(CredentialFailure::InvalidFile);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| CredentialFailure::InvalidFile)?;
    let mut lines = text.lines();
    let mut header = lines
        .next()
        .ok_or(CredentialFailure::InvalidFile)?
        .split(' ');
    let scoped_refs = match header.next() {
        Some(HEADER) => false,
        Some(HEADER_V2) => true,
        _ => return Err(CredentialFailure::InvalidFile),
    };
    let selected = Binding {
        tenant: TenantId::from_bytes(lower_hex(
            header.next().ok_or(CredentialFailure::InvalidFile)?,
        )?),
        repository: RepositoryId::from_bytes(lower_hex(
            header.next().ok_or(CredentialFailure::InvalidFile)?,
        )?),
        incarnation: RepositoryIncarnationId::from_bytes(lower_hex(
            header.next().ok_or(CredentialFailure::InvalidFile)?,
        )?),
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
        let principal = PrincipalId::from_bytes(lower_hex(
            fields.next().ok_or(CredentialFailure::InvalidFile)?,
        )?);
        let mut grant = grant(
            principal,
            fields.next().ok_or(CredentialFailure::InvalidFile)?,
        )?;
        if scoped_refs {
            grant.ref_write_scope =
                RefWriteScope::parse(fields.next().ok_or(CredentialFailure::InvalidFile)?)
                    .map_err(|_| CredentialFailure::InvalidFile)?
                    .map(Arc::new);
        }
        if fields.next().is_some() || !digests.insert(digest) {
            return Err(CredentialFailure::InvalidFile);
        }
        entries
            .try_reserve(1)
            .map_err(|_| CredentialFailure::Unavailable)?;
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
        Binding {
            tenant: TenantId::from_bytes([1; 16]),
            repository: RepositoryId::from_bytes([2; 16]),
            incarnation: RepositoryIncarnationId::from_bytes([3; 16]),
        }
    }
    fn header() -> String {
        let b = binding();
        format!("{HEADER} {} {} {}\n", b.tenant, b.repository, b.incarnation)
    }
    fn row(token: &str, principal: u8, scope: &str) -> String {
        let digest: String = sha256_digest(token.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!(
            "{digest} {} {scope}\n",
            PrincipalId::from_bytes([principal; 16])
        )
    }
    fn private_write(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    fn scoped_header() -> String {
        header().replacen(HEADER, HEADER_V2, 1)
    }
    fn scoped_row(token: &str, scope: &str, references: &str) -> String {
        let legacy = row(token, 4, scope);
        format!("{} {references}\n", legacy.trim_end())
    }
    fn selected_session(grant: &Grant) -> AuthenticatedReceiveSession {
        let LoopbackReceiveSession::Authenticated(session) =
            grant.session(IdempotencyKey::new(b"stable-retry-key".to_vec()).unwrap())
        else {
            panic!("credential must supply authentication");
        };
        session
    }

    #[test]
    fn v2_ref_ceiling_is_explicit_and_independent_from_service_permissions() {
        let token = "a".repeat(64);
        let reference = fgit_types::RefName::try_new(b"refs/heads/main").unwrap();
        for field in ["all", "none", "exact:726566732f68656164732f6d61696e"] {
            let text = scoped_header() + &scoped_row(&token, "read,receive,issues-write", field);
            let entries = parse(text.as_bytes(), binding()).unwrap();
            let selected = &entries[0].grant;
            assert!(selected.permits(Service::UploadPack));
            assert!(selected.permits(Service::ReceivePack));
            assert!(selected.permits_issues(true));
            assert!(!selected.permits_reviewed_merge());
            let session = selected_session(selected);
            assert_eq!(session.principal_id(), PrincipalId::from_bytes([4; 16]));
            assert_eq!(
                session.client_idempotency_key().as_bytes(),
                b"stable-retry-key"
            );
            assert_eq!(session.permits_ref_write(&reference), field != "none");
            assert_eq!(
                session.permits_ref_write_bytes(b"refs/heads/elsewhere"),
                field == "all"
            );
        }
        let legacy = parse(
            (header() + &row(&token, 4, "receive")).as_bytes(),
            binding(),
        )
        .unwrap();
        assert!(selected_session(&legacy[0].grant).permits_ref_write(&reference));
        // A matching selector never manufactures receive/merge or read access.
        let read_only = parse(
            (scoped_header() + &scoped_row(&token, "issues-write", "all")).as_bytes(),
            binding(),
        )
        .unwrap();
        assert!(!read_only[0].grant.permits(Service::UploadPack));
        assert!(!read_only[0].grant.permits(Service::ReceivePack));
        assert!(!read_only[0].grant.permits_reviewed_merge());
    }

    #[test]
    fn malformed_v2_ref_fields_refuse_the_complete_table_without_legacy_fallback() {
        let token = "a".repeat(64);
        let first = scoped_row(&token, "receive", "all");
        for bad in [
            scoped_row(&"b".repeat(64), "receive", ""),
            row(&"b".repeat(64), 4, "receive"),
            scoped_row(&"b".repeat(64), "receive", "all extra"),
            scoped_row(
                &"b".repeat(64),
                "receive",
                "prefix:726566732f68656164732f6167656e74",
            ),
            scoped_row(&"b".repeat(64), "receive", "exact:48454144"),
        ] {
            assert!(matches!(
                parse((scoped_header() + &first + &bad).as_bytes(), binding()),
                Err(CredentialFailure::InvalidFile)
            ));
        }
        assert!(matches!(
            parse((header() + &first).as_bytes(), binding()),
            Err(CredentialFailure::InvalidFile)
        ));
        assert!(
            parse(scoped_header().as_bytes(), binding())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn v2_atomic_reload_narrows_future_sessions_and_revokes_without_changing_identity() {
        let path = std::env::temp_dir().join(format!(
            "fg-http-scoped-grants-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let source = CredentialSource::File {
            path: path.clone(),
            binding: binding(),
        };
        let token = "a".repeat(64);
        let authorization = format!("Bearer {token}");
        private_write(
            &path,
            (scoped_header() + &scoped_row(&token, "read,receive,outcomes-read", "all")).as_bytes(),
        );
        let original = selected_session(&source.authenticate(Some(&authorization)).unwrap());
        let replacement = path.with_extension("replacement");
        private_write(
            &replacement,
            (scoped_header() + &scoped_row(&token, "read,receive,outcomes-read", "none"))
                .as_bytes(),
        );
        fs::rename(&replacement, &path).unwrap();
        let narrowed = source.authenticate(Some(&authorization)).unwrap();
        let current = selected_session(&narrowed);
        assert_eq!(current.principal_id(), original.principal_id());
        assert_eq!(
            current.client_idempotency_key(),
            original.client_idempotency_key()
        );
        assert!(original.permits_ref_write_bytes(b"refs/heads/main"));
        assert!(!current.permits_ref_write_bytes(b"refs/heads/main"));
        assert!(narrowed.permits(Service::UploadPack) && narrowed.permits_outcomes());
        private_write(&replacement, b"broken replacement");
        fs::rename(&replacement, &path).unwrap();
        assert!(matches!(
            source.authenticate(Some(&authorization)),
            Err(CredentialFailure::InvalidFile)
        ));
        private_write(&replacement, scoped_header().as_bytes());
        fs::rename(&replacement, &path).unwrap();
        assert!(matches!(
            source.authenticate(Some(&authorization)),
            Err(CredentialFailure::UnknownCredential)
        ));
        fs::remove_file(path).unwrap();
    }
    fn basic(user_pass: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut encoded = String::from("Basic ");
        for chunk in user_pass.chunks(3) {
            let first = chunk[0];
            let second = chunk.get(1).copied().unwrap_or(0);
            let third = chunk.get(2).copied().unwrap_or(0);
            encoded.push(char::from(ALPHABET[usize::from(first >> 2)]));
            encoded.push(char::from(
                ALPHABET[usize::from(((first & 3) << 4) | (second >> 4))],
            ));
            encoded.push(if chunk.len() > 1 {
                char::from(ALPHABET[usize::from(((second & 15) << 2) | (third >> 6))])
            } else {
                '='
            });
            encoded.push(if chunk.len() > 2 {
                char::from(ALPHABET[usize::from(third & 63)])
            } else {
                '='
            });
        }
        encoded
    }

    #[test]
    fn queue_scopes_are_independent_and_preserve_all_existing_scope_meanings() {
        let principal = PrincipalId::from_bytes([7; 16]);
        let old = "read,receive,issues-read,issues-write,outcomes-read,pulls-read,pulls-write,reviews-read,reviews-write,merges-write,protection-read,protection-write,lfs-read,lfs-write,artifact-read";
        let legacy = grant(principal, old).unwrap();
        assert!(!legacy.permits_queues(false) && !legacy.permits_queues(true));
        assert!(!legacy.permits_queue_landing());
        for (scope, read, write) in [
            ("queues-read", true, false),
            ("queues-write", false, true),
            ("queues-read,queues-write", true, true),
        ] {
            let selected = grant(principal, scope).unwrap();
            assert_eq!(selected.permits_queues(false), read);
            assert_eq!(selected.permits_queues(true), write);
            assert_eq!(
                selected_session(&selected).authentication(),
                AdmissionAuthentication::HttpToken
            );
            assert!(
                !selected.permits(Service::UploadPack) && !selected.permits(Service::ReceivePack)
            );
            assert!(!selected.permits_issues(false) && !selected.permits_issues(true));
            assert!(!selected.permits_pulls(false) && !selected.permits_pulls(true));
            assert!(!selected.permits_reviews(false) && !selected.permits_reviews(true));
            assert!(!selected.permits_protection(false) && !selected.permits_protection(true));
            assert!(!selected.permits_lfs(false) && !selected.permits_lfs(true));
            assert!(!selected.permits_outcomes() && !selected.permits_reviewed_merge());
            assert!(!selected.permits_artifact_read());
            assert!(!selected.permits_queue_landing());
        }
        let all = grant(principal, &format!("{old},queues-read,queues-write")).unwrap();
        assert!(all.permits_queues(false) && all.permits_queues(true));
        assert!(all.permits(Service::UploadPack) && all.permits(Service::ReceivePack));
        assert!(all.permits_artifact_read());
        for invalid in [
            "queues-write,queues-read",
            "queues-read,queues-read",
            "queues-write,read",
            "queue-write",
            "queue-land",
            "queues-land,queues-write",
            "queues-land,queues-land",
        ] {
            assert!(matches!(
                grant(principal, invalid),
                Err(CredentialFailure::InvalidFile)
            ));
        }
        let token = "a".repeat(64);
        let source = CredentialSource::Static {
            digest: sha256_digest(token.as_bytes()),
            principal,
        };
        let static_grant = source
            .authenticate(Some(&format!("Bearer {token}")))
            .unwrap();
        assert!(!static_grant.permits_queues(false) && !static_grant.permits_queues(true));
        assert!(!static_grant.permits_queue_landing());
        let landing = grant(principal, "queues-land").unwrap();
        assert!(landing.permits_queue_landing());
        assert!(!landing.permits_queues(false) && !landing.permits_queues(true));
        assert!(!landing.permits(Service::UploadPack) && !landing.permits(Service::ReceivePack));
        assert!(!landing.permits_pulls(false) && !landing.permits_pulls(true));
        assert!(!landing.permits_reviews(false) && !landing.permits_reviews(true));
        assert!(!landing.permits_protection(false) && !landing.permits_protection(true));
        assert!(!landing.permits_outcomes() && !landing.permits_reviewed_merge());
        assert!(!landing.permits_issues(false) && !landing.permits_issues(true));
        assert!(!landing.permits_lfs(false) && !landing.permits_lfs(true));
        assert!(!landing.permits_artifact_read());
        assert_eq!(
            selected_session(&landing).authentication(),
            AdmissionAuthentication::HttpToken
        );
        assert!(
            grant(
                principal,
                &format!("{old},queues-read,queues-write,queues-land")
            )
            .unwrap()
            .permits_queue_landing()
        );
    }

    #[test]
    fn artifact_reads_require_their_own_scope_without_widening_existing_grants() {
        let principal = PrincipalId::from_bytes([7; 16]);
        let old_scopes = "read,receive,issues-read,issues-write,outcomes-read,pulls-read,pulls-write,reviews-read,reviews-write,merges-write,protection-read,protection-write,lfs-read,lfs-write";
        assert!(
            !grant(principal, old_scopes)
                .unwrap()
                .permits_artifact_read()
        );
        let selected = grant(principal, "artifact-read").unwrap();
        assert!(selected.permits_artifact_read());
        assert_eq!(selected.principal, principal);
        assert!(!selected.permits(Service::UploadPack) && !selected.permits(Service::ReceivePack));
        assert!(!selected.permits_issues(false) && !selected.permits_issues(true));
        assert!(!selected.permits_pulls(false) && !selected.permits_pulls(true));
        assert!(!selected.permits_reviews(false) && !selected.permits_reviews(true));
        assert!(!selected.permits_protection(false) && !selected.permits_protection(true));
        assert!(!selected.permits_outcomes() && !selected.permits_reviewed_merge());
        assert!(!selected.permits_lfs(false) && !selected.permits_lfs(true));
        assert!(
            grant(principal, &format!("{old_scopes},artifact-read"))
                .unwrap()
                .permits_artifact_read()
        );
        for invalid in [
            "artifact-read,artifact-read",
            "artifact-read,read",
            "artifact-write",
            "artifacts-read",
        ] {
            assert!(matches!(
                grant(principal, invalid),
                Err(CredentialFailure::InvalidFile)
            ));
        }
        let token = "a".repeat(64);
        let source = CredentialSource::Static {
            digest: sha256_digest(token.as_bytes()),
            principal,
        };
        assert!(
            !source
                .authenticate(Some(&format!("Bearer {token}")))
                .unwrap()
                .permits_artifact_read()
        );
    }

    #[test]
    fn basic_decoder_matches_rfc_vectors_and_checks_all_padding_forms() {
        let mut output = [0; MAX_BASIC_BYTES];
        for (encoded, decoded) in [
            ("Zg==", "f"),
            ("Zm8=", "fo"),
            ("Zm9v", "foo"),
            ("Zm9vYg==", "foob"),
            ("Zm9vYmE=", "fooba"),
            ("Zm9vYmFy", "foobar"),
            ("QWxhZGRpbjpvcGVuIHNlc2FtZQ==", "Aladdin:open sesame"),
        ] {
            let length = decode_basic(encoded.as_bytes(), &mut output).unwrap();
            assert_eq!(&output[..length], decoded.as_bytes());
        }
        for invalid in [
            "",
            "Zg",
            "Zg=",
            "Zg===",
            "Zh==",
            "Zm9=",
            "Zg==AAAA",
            "Zm=8",
            "=m9v",
            "Zm9v\n",
            "Zm9v YmFy",
            "____",
            "----",
            "====",
        ] {
            assert!(decode_basic(invalid.as_bytes(), &mut output).is_none());
        }
        // Exercise every byte value and every possible final-quantum length.
        for length in 1..=MAX_BASIC_BYTES {
            let original: Vec<u8> = (0..length).map(|index| index.to_le_bytes()[0]).collect();
            let encoded = basic(&original);
            let size = decode_basic(&encoded.as_bytes()[6..], &mut output).unwrap();
            assert_eq!(&output[..size], original);
        }
        assert!(
            decode_basic(
                &basic(&vec![b'x'; MAX_BASIC_BYTES + 1]).as_bytes()[6..],
                &mut output
            )
            .is_none()
        );
    }

    #[test]
    fn basic_and_bearer_select_the_same_token_not_the_supplied_username() {
        let token = "a".repeat(64);
        let principal = PrincipalId::from_bytes([7; 16]);
        let source = CredentialSource::Static {
            digest: sha256_digest(token.as_bytes()),
            principal,
        };
        for username in [
            "git".to_owned(),
            "admin".to_owned(),
            PrincipalId::from_bytes([9; 16]).to_string(),
            "u".repeat(MAX_BASIC_USERNAME_BYTES),
            "utilisateur-é".to_owned(),
        ] {
            let authorization = basic(format!("{username}:{token}").as_bytes());
            let selected = source.authenticate(Some(&authorization)).unwrap();
            assert_eq!(selected.principal, principal);
            assert_eq!(
                selected_session(&selected).authentication(),
                AdmissionAuthentication::HttpToken,
            );
            assert!(
                selected.permits(Service::UploadPack) && selected.permits(Service::ReceivePack)
            );
            assert!(!selected.permits_issues(false) && !selected.permits_issues(true));
            assert!(!selected.permits_pulls(false) && !selected.permits_pulls(true));
            assert!(!selected.permits_reviews(false) && !selected.permits_reviews(true));
            assert!(!selected.permits_outcomes() && !selected.permits_reviewed_merge());
            assert_eq!(
                credential_digest(Some(&authorization)),
                credential_digest(Some(&format!("bEaReR {token}")))
            );
            assert!(
                source
                    .authenticate(Some(&authorization.replacen("Basic", "bAsIc", 1)))
                    .is_ok()
            );
        }
        for user_pass in [
            format!(":{token}"),
            format!("{}:{token}", "u".repeat(MAX_BASIC_USERNAME_BYTES + 1)),
            format!("user\n:{token}"),
            format!("user\0:{token}"),
            format!("user\u{7f}:{token}"),
            format!("user:{token}:extra"),
            format!("user:{}", "a".repeat(63)),
            format!("user:{}", "A".repeat(64)),
            token,
            format!("user:{}", "b".repeat(64)),
        ] {
            assert!(matches!(
                source.authenticate(Some(&basic(user_pass.as_bytes()))),
                Err(CredentialFailure::UnknownCredential)
            ));
        }
        assert!(matches!(
            source.authenticate(Some(&basic(&[0xff, b':', b'a']))),
            Err(CredentialFailure::UnknownCredential)
        ));
        for authorization in [
            None,
            Some(""),
            Some("Basic"),
            Some("Digest token"),
            Some("Basic  Zg=="),
            Some("Bearer invalid"),
        ] {
            assert!(matches!(
                source.authenticate(authorization),
                Err(CredentialFailure::UnknownCredential)
            ));
        }
    }

    #[test]
    fn basic_file_grants_preserve_scopes_rotation_revocation_and_incarnation_binding() {
        let path = std::env::temp_dir().join(format!(
            "fg-http-basic-grants-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let source = CredentialSource::File {
            path: path.clone(),
            binding: binding(),
        };
        let first = basic(format!("admin:{}", "a".repeat(64)).as_bytes());
        let rotated = basic(format!("other:{}", "b".repeat(64)).as_bytes());
        private_write(
            &path,
            (header() + &row(&"a".repeat(64), 4, "read")).as_bytes(),
        );
        let selected = source.authenticate(Some(&first)).unwrap();
        assert_eq!(selected.principal, PrincipalId::from_bytes([4; 16]));
        assert!(selected.permits(Service::UploadPack));
        assert!(!selected.permits(Service::ReceivePack) && !selected.permits_reviewed_merge());
        let mut foreign = binding();
        foreign.incarnation = RepositoryIncarnationId::from_bytes([9; 16]);
        assert!(matches!(
            CredentialSource::File {
                path: path.clone(),
                binding: foreign
            }
            .authenticate(Some(&first)),
            Err(CredentialFailure::WrongRepository)
        ));
        private_write(
            &path,
            (header() + &row(&"b".repeat(64), 4, "outcomes-read")).as_bytes(),
        );
        assert!(matches!(
            source.authenticate(Some(&first)),
            Err(CredentialFailure::UnknownCredential)
        ));
        let recovery = source.authenticate(Some(&rotated)).unwrap();
        assert_eq!(recovery.principal, selected.principal);
        assert!(recovery.permits_outcomes());
        assert!(!recovery.permits(Service::UploadPack) && !recovery.permits(Service::ReceivePack));
        private_write(&path, b"malformed");
        assert!(matches!(
            source.authenticate(Some(&rotated)),
            Err(CredentialFailure::InvalidFile)
        ));
        private_write(&path, header().as_bytes());
        assert!(matches!(
            source.authenticate(Some(&rotated)),
            Err(CredentialFailure::UnknownCredential)
        ));
        fs::remove_file(path).unwrap();
        assert!(matches!(
            source.authenticate(Some(&rotated)),
            Err(CredentialFailure::Unavailable)
        ));
    }

    #[test]
    fn scopes_are_explicit_and_receive_does_not_imply_fetch() {
        let text = header()
            + &row(&"a".repeat(64), 4, "read")
            + &row(&"b".repeat(64), 5, "receive")
            + &row(&"c".repeat(64), 6, "read,receive");
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
            assert!(!entry.grant.permits_outcomes());
        }
    }
    #[test]
    fn every_named_scope_grants_only_its_own_service_operation() {
        let names = [
            "read",
            "receive",
            "issues-read",
            "issues-write",
            "outcomes-read",
            "pulls-read",
            "pulls-write",
            "reviews-read",
            "reviews-write",
            "merges-write",
            "protection-read",
            "protection-write",
            "lfs-read",
            "lfs-write",
            "artifact-read",
        ];
        let principal = PrincipalId::from_bytes([7; 16]);
        for (index, name) in names.iter().enumerate() {
            let selected = grant(principal, name).unwrap();
            let observed = [
                selected.permits(Service::UploadPack),
                selected.permits(Service::ReceivePack),
                selected.permits_issues(false),
                selected.permits_issues(true),
                selected.permits_outcomes(),
                selected.permits_pulls(false),
                selected.permits_pulls(true),
                selected.permits_reviews(false),
                selected.permits_reviews(true),
                selected.permits_reviewed_merge(),
                selected.permits_protection(false),
                selected.permits_protection(true),
                selected.permits_lfs(false),
                selected.permits_lfs(true),
                selected.permits_artifact_read(),
            ];
            let mut expected = [false; 15];
            expected[index] = true;
            assert_eq!(
                observed, expected,
                "scope {name} must not imply another grant"
            );
            assert!(matches!(
                grant(principal, &format!("{name},{name}")),
                Err(CredentialFailure::InvalidFile)
            ));
        }
        assert!(grant(principal, &names.join(",")).is_ok());
        let mut reversed = names;
        reversed.reverse();
        assert!(matches!(
            grant(principal, &reversed.join(",")),
            Err(CredentialFailure::InvalidFile)
        ));
    }

    #[test]
    fn lfs_grants_are_independent_and_never_implicit() {
        let principal = PrincipalId::from_bytes([7; 16]);
        let read = grant(principal, "lfs-read").unwrap();
        assert!(read.permits_lfs(false));
        assert!(!read.permits_lfs(true));
        let write = grant(principal, "lfs-write").unwrap();
        assert!(!write.permits_lfs(false));
        assert!(write.permits_lfs(true));
        let both = grant(principal, "lfs-read,lfs-write").unwrap();
        assert!(both.permits_lfs(false) && both.permits_lfs(true));
        for selected in [read, write, both] {
            assert!(!selected.permits(Service::UploadPack));
            assert!(!selected.permits(Service::ReceivePack));
            assert!(!selected.permits_reviewed_merge());
            assert!(!selected.permits_protection(true));
        }
        for scopes in ["read", "receive", "read,receive", "protection-write"] {
            let selected = grant(principal, scopes).unwrap();
            assert!(!selected.permits_lfs(false) && !selected.permits_lfs(true));
        }
        for scopes in ["lfs-write,lfs-read", "lfs-read,lfs-read", "lfs-read,read"] {
            assert!(grant(principal, scopes).is_err());
        }
        let token = "a".repeat(64);
        let selected = CredentialSource::Static {
            digest: sha256_digest(token.as_bytes()),
            principal,
        }
        .authenticate(Some(&format!("Bearer {token}")))
        .unwrap();
        assert!(!selected.permits_lfs(false) && !selected.permits_lfs(true));
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
            assert!(!grant.permits_outcomes());
        }
        assert!(
            grant(principal, "issues-read,issues-write")
                .unwrap()
                .permits_issues(true)
        );
        assert!(grant(principal, "issues-write,read").is_err());
        assert!(grant(principal, "issues-read,issues-read").is_err());
        let token = "a".repeat(64);
        let source = CredentialSource::Static {
            digest: sha256_digest(token.as_bytes()),
            principal,
        };
        let legacy = source
            .authenticate(Some(&format!("Bearer {token}")))
            .unwrap();
        assert!(!legacy.permits_issues(false) && !legacy.permits_issues(true));
        assert!(!legacy.permits_outcomes());
    }
    #[test]
    fn recovery_scope_can_survive_write_withdrawal_without_restoring_other_access() {
        let principal = PrincipalId::from_bytes([7; 16]);
        let recovery = grant(principal, "outcomes-read").unwrap();
        assert!(recovery.permits_outcomes());
        assert!(!recovery.permits(Service::UploadPack));
        assert!(!recovery.permits(Service::ReceivePack));
        assert!(!recovery.permits_issues(false));
        assert!(!recovery.permits_issues(true));
        let full = grant(
            principal,
            "read,receive,issues-read,issues-write,outcomes-read",
        )
        .unwrap();
        assert!(full.permits_outcomes() && full.permits_issues(true));
        assert!(grant(principal, "outcomes-read,read").is_err());
        assert!(grant(principal, "outcomes-read,outcomes-read").is_err());
    }
    #[test]
    fn pull_request_scopes_do_not_imply_each_other_or_any_existing_service() {
        let principal = PrincipalId::from_bytes([7; 16]);
        for scope in [
            "read",
            "receive",
            "issues-read",
            "issues-write",
            "outcomes-read",
        ] {
            let old = grant(principal, scope).unwrap();
            assert!(!old.permits_pulls(false) && !old.permits_pulls(true));
        }
        for (scope, write) in [("pulls-read", false), ("pulls-write", true)] {
            let selected = grant(principal, scope).unwrap();
            assert!(selected.permits_pulls(write));
            assert!(!selected.permits_pulls(!write));
            assert!(
                !selected.permits(Service::UploadPack) && !selected.permits(Service::ReceivePack)
            );
            assert!(!selected.permits_issues(false) && !selected.permits_issues(true));
            assert!(!selected.permits_outcomes());
        }
        assert!(grant(principal, "outcomes-read,pulls-read,pulls-write").is_ok());
        for scopes in [
            "pulls-write,pulls-read",
            "pulls-read,pulls-read",
            "pulls-read,read",
            "pulls-merge",
        ] {
            assert!(grant(principal, scopes).is_err());
        }
        let token = "a".repeat(64);
        let source = CredentialSource::Static {
            digest: sha256_digest(token.as_bytes()),
            principal,
        };
        let legacy = source
            .authenticate(Some(&format!("Bearer {token}")))
            .unwrap();
        assert!(!legacy.permits_pulls(false) && !legacy.permits_pulls(true));
    }
    #[test]
    fn review_and_merge_grants_are_independent_of_each_other_and_all_old_scopes() {
        let principal = PrincipalId::from_bytes([7; 16]);
        let old = grant(
            principal,
            "read,receive,issues-read,issues-write,outcomes-read,pulls-read,pulls-write",
        )
        .unwrap();
        assert!(
            !old.permits_reviews(false)
                && !old.permits_reviews(true)
                && !old.permits_reviewed_merge()
        );
        for scope in ["reviews-read", "reviews-write", "merges-write"] {
            let selected = grant(principal, scope).unwrap();
            assert_eq!(selected.permits_reviews(false), scope == "reviews-read");
            assert_eq!(selected.permits_reviews(true), scope == "reviews-write");
            assert_eq!(selected.permits_reviewed_merge(), scope == "merges-write");
            assert!(!selected.permits_pulls(false) && !selected.permits_pulls(true));
            assert!(
                !selected.permits(Service::UploadPack) && !selected.permits(Service::ReceivePack)
            );
            assert!(
                !selected.permits_issues(false)
                    && !selected.permits_issues(true)
                    && !selected.permits_outcomes()
            );
        }
        assert!(grant(principal, "reviews-read,reviews-write,merges-write").is_ok());
        assert!(grant(principal, "merges-write,reviews-write").is_err());
        assert!(grant(principal, "reviews-read,reviews-read").is_err());
        let token = "a".repeat(64);
        let legacy = CredentialSource::Static {
            digest: sha256_digest(token.as_bytes()),
            principal,
        }
        .authenticate(Some(&format!("Bearer {token}")))
        .unwrap();
        assert!(
            !legacy.permits_reviews(false)
                && !legacy.permits_reviews(true)
                && !legacy.permits_reviewed_merge()
        );
    }
    #[test]
    fn protection_grants_are_explicit_independent_and_do_not_grant_other_services() {
        let principal = PrincipalId::from_bytes([7; 16]);
        let old = grant(
            principal,
            "read,receive,issues-read,issues-write,outcomes-read,pulls-read,pulls-write,reviews-read,reviews-write,merges-write",
        )
        .unwrap();
        assert!(!old.permits_protection(false) && !old.permits_protection(true));
        for (scope, mutation) in [("protection-read", false), ("protection-write", true)] {
            let selected = grant(principal, scope).unwrap();
            assert!(selected.permits_protection(mutation));
            assert!(!selected.permits_protection(!mutation));
            assert!(
                !selected.permits(Service::UploadPack) && !selected.permits(Service::ReceivePack)
            );
            assert!(!selected.permits_issues(false) && !selected.permits_issues(true));
            assert!(!selected.permits_pulls(false) && !selected.permits_pulls(true));
            assert!(!selected.permits_reviews(false) && !selected.permits_reviews(true));
            assert!(!selected.permits_outcomes() && !selected.permits_reviewed_merge());
        }
        let both = grant(principal, "protection-read,protection-write").unwrap();
        assert!(both.permits_protection(false) && both.permits_protection(true));
        assert!(grant(principal, "merges-write,protection-read,protection-write").is_ok());
        for scopes in [
            "protection-write,protection-read",
            "protection-read,protection-read",
            "protection-write,protection-write",
            "protection-read,read",
            "protection",
        ] {
            assert!(grant(principal, scopes).is_err());
        }
        let token = "a".repeat(64);
        let legacy = CredentialSource::Static {
            digest: sha256_digest(token.as_bytes()),
            principal,
        }
        .authenticate(Some(&format!("Bearer {token}")))
        .unwrap();
        assert!(!legacy.permits_protection(false) && !legacy.permits_protection(true));
    }
    #[test]
    fn duplicate_tokens_bad_scopes_and_foreign_bindings_fail_closed() {
        let row = row(&"a".repeat(64), 4, "read");
        for text in [
            header() + &row + &row,
            header() + &row.replace(" read", " write"),
            header() + &row.replace(" read", " read,read"),
            header() + "\n",
            String::new(),
        ] {
            assert!(parse(text.as_bytes(), binding()).is_err());
        }
        let mut foreign = binding();
        foreign.incarnation = RepositoryIncarnationId::from_bytes([9; 16]);
        assert!(matches!(
            parse((header() + &row).as_bytes(), foreign),
            Err(CredentialFailure::WrongRepository)
        ));
        assert!(parse(header().as_bytes(), binding()).unwrap().is_empty());
        assert!(parse(&vec![b'x'; MAX_FILE_BYTES + 1], binding()).is_err());
    }
    #[test]
    fn grants_reload_for_rotation_revocation_and_invalid_configuration() {
        let path = std::env::temp_dir().join(format!(
            "fg-http-grants-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let source = CredentialSource::File {
            path: path.clone(),
            binding: binding(),
        };
        let first = format!("Bearer {}", "a".repeat(64));
        let rotated = format!("Bearer {}", "b".repeat(64));
        private_write(
            &path,
            (header() + &row(&"a".repeat(64), 4, "receive")).as_bytes(),
        );
        let principal = source.authenticate(Some(&first)).unwrap().principal;
        private_write(
            &path,
            (header() + &row(&"b".repeat(64), 4, "receive")).as_bytes(),
        );
        assert!(matches!(
            source.authenticate(Some(&first)),
            Err(CredentialFailure::UnknownCredential)
        ));
        assert_eq!(
            source.authenticate(Some(&rotated)).unwrap().principal,
            principal
        );
        private_write(&path, b"malformed");
        assert!(matches!(
            source.authenticate(Some(&rotated)),
            Err(CredentialFailure::InvalidFile)
        ));
        private_write(&path, header().as_bytes());
        assert!(matches!(
            source.authenticate(Some(&rotated)),
            Err(CredentialFailure::UnknownCredential)
        ));
        fs::remove_file(&path).unwrap();
        assert!(matches!(
            source.authenticate(Some(&rotated)),
            Err(CredentialFailure::Unavailable)
        ));
    }
    #[cfg(unix)]
    #[test]
    fn public_files_and_symlinks_are_refused() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let path = std::env::temp_dir().join(format!(
            "fg-http-grant-perms-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        private_write(&path, header().as_bytes());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            load(&path, binding()),
            Err(CredentialFailure::UnsafeFile)
        ));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = path.with_extension("link");
        symlink(&path, &link).unwrap();
        assert!(matches!(
            load(&link, binding()),
            Err(CredentialFailure::UnsafeFile)
        ));
        fs::remove_file(link).unwrap();
        fs::remove_file(path).unwrap();
    }
}
