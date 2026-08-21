#![forbid(unsafe_code)]

//! One-process FrankenGit node assembly.
//!
//! This crate composes published subsystem boundaries only.  It opens the
//! admitted embedded `FrankenSQLite` authority profile on the node-owned
//! Asupersync runtime and places Git object bodies through the local immutable
//! object-fabric backend. Neither backend is represented by a node-owned map.
//!
//! Database opening and clean shutdown run through the owned runtime during
//! node lifecycle transitions. Authority operations themselves remain async:
//! no synchronous request-path adapter is introduced around the async engine.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener};
use std::path::{Path, PathBuf};
use std::time::Duration;

use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityLimits, AuthorityVersionToken, HeadInit,
    HeadKey, HeadRead, PublicationOutcome, StoreInstanceId, body_key, publish_decisions_async,
};
use fgit_authority_fsqlite::{EngineError, FsqliteAuthorityStore};
use fgit_codec::{
    schema::{RepositoryAuthorityHeadBody, RepositoryDecisionBatchBody},
    wire::encode_body,
};
use fgit_crypto::{GitObjectKind, IdentityDomain, git_object_id, git_payload_commitment};
use fgit_git_object::ObjectType;
use fgit_object_fabric::fabric::{
    ImmutableObjectFabric, PlacementAdmission, PutIfAbsent, StoreRefusal, VerifiedObject,
};
use fgit_object_fabric::local::{LocalFilesystemConfig, LocalFilesystemFabric};
use fgit_object_fabric::{ObjectEnvelope, ObjectKind, SegmentLimits};
use fgit_resource::{
    Grade, LeakDisposition, ObligationLedger, RegionCloseOutcome, RegionId, ResourceError,
    ResourceVector,
};
use fgit_runtime::{BudgetClass, NodeRuntime, RuntimeProfile, RuntimeRefusal};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, GitHashAlgorithm, GitOid, HeadGeneration, PolicyEpoch,
    RegistryEpoch, RepositoryId, TenantId,
};
use fgit_wire::{
    Capabilities, LegacyUploadPack, PackPayloadSource, PackRequest, Packet, PktLineDecoder,
    UploadPackRepository, UploadPackVersion, V1Advertisement, WireError, WireEvent, WireLimits,
    encode_packets, sideband_pack_chunk,
};
use fsqlite_types::cx::Cx as FsqliteCx;

const OBJECT_CODEC_NAMESPACE: &[u8] = b"git-object-body/v1";
const HEAD_KEY_PREFIX: &[u8] = b"frankengit/node/head/";
const FABRIC_NAMESPACE_PREFIX: &[u8] = b"frankengit/node/object/";
const DEFAULT_MAX_OBJECT_BYTES: u64 = 32 * 1024 * 1024;
const AUTHORITY_DATABASE_FILE: &str = "authority.fsqlite";
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Typed refusal from the node assembly boundary.
#[derive(Debug)]
pub enum NodeRefusal {
    /// An empty filesystem root would make the storage target ambiguous.
    EmptyStorageRoot,
    /// A caller-selected worker count was outside this slice's finite profile.
    InvalidWorkerCount,
    /// The runtime could not establish its finite production profile.
    Runtime(RuntimeRefusal),
    /// Authority-head staging or initialization refused or was ambiguous.
    Authority(fgit_authority::OutcomeFailure),
    /// A non-initializing open found no canonical authority head.
    AuthorityHeadAbsent,
    /// A supplied authority materialization names another repository.
    RepositoryMismatch,
    /// The operator-selected storage root cannot name the embedded database.
    StoragePathEncoding,
    /// The derived authority-head key was outside the bounded key vocabulary.
    HeadKey(fgit_authority::KeyError),
    /// A newly constructed durable authority unexpectedly held another head.
    HeadInitializationConflict,
    /// Authority initialization failed and its explicit worker cleanup failed too.
    AuthorityInitializationCleanup {
        /// The initialization failure observed before cleanup.
        initialization: Box<NodeRefusal>,
        /// The failure while awaiting the authority worker's close.
        cleanup: Box<NodeRefusal>,
    },
    /// A non-initializing open failed and then could not prove clean teardown.
    ExistingOpenCleanup {
        /// The refusal observed while opening or authenticating the head.
        opening: Box<NodeRefusal>,
        /// The refusal while draining the partially opened node.
        cleanup: Box<NodeRefusal>,
    },
    /// The local immutable object fabric refused the requested operation.
    Fabric(StoreRefusal),
    /// Object bytes exceeded this node's configured storage bound.
    ObjectTooLarge { offered: u64, maximum: u64 },
    /// A platform-sized object length could not be represented canonically.
    ObjectLengthOverflow,
    /// Resource custody could not issue the bounded placement grant.
    Resource(ResourceError),
    /// A storage effect failed to settle its obligation region.
    ResourceContainment,
    /// The node root did not quiesce within its bounded shutdown interval.
    RuntimeContainment,
    /// A fixed node identity handle failed its bounded representation.
    Identity(fgit_resource::IdentityError),
}

impl Display for NodeRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyStorageRoot => formatter.write_str("node storage root is empty"),
            Self::InvalidWorkerCount => formatter.write_str("node worker count must be non-zero"),
            Self::Runtime(error) => Display::fmt(error, formatter),
            Self::Authority(error) => Display::fmt(error, formatter),
            Self::AuthorityHeadAbsent => {
                formatter.write_str("node authority head is absent; run fg init before doctor")
            }
            Self::RepositoryMismatch => formatter
                .write_str("authority materialization does not belong to this node repository"),
            Self::StoragePathEncoding => formatter.write_str(
                "node storage root cannot be represented as a UTF-8 embedded authority path",
            ),
            Self::HeadKey(error) => Display::fmt(error, formatter),
            Self::HeadInitializationConflict => {
                formatter.write_str("durable authority head conflicts during initialization")
            }
            Self::AuthorityInitializationCleanup {
                initialization,
                cleanup,
            } => write!(
                formatter,
                "authority initialization failed ({initialization}) and explicit cleanup failed ({cleanup})"
            ),
            Self::ExistingOpenCleanup { opening, cleanup } => write!(
                formatter,
                "non-initializing node open failed ({opening}) and explicit cleanup failed ({cleanup})"
            ),
            Self::Fabric(error) => Display::fmt(error, formatter),
            Self::ObjectTooLarge { offered, maximum } => {
                write!(
                    formatter,
                    "object is {offered} bytes but node limit is {maximum}"
                )
            }
            Self::ObjectLengthOverflow => {
                formatter.write_str("object length exceeds canonical range")
            }
            Self::Resource(error) => Display::fmt(error, formatter),
            Self::ResourceContainment => {
                formatter.write_str("object placement region did not reach quiescence")
            }
            Self::RuntimeContainment => {
                formatter.write_str("node runtime did not reach quiescence during shutdown")
            }
            Self::Identity(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for NodeRefusal {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
            Self::Authority(error) => Some(error),
            Self::HeadKey(error) => Some(error),
            Self::AuthorityInitializationCleanup { initialization, .. } => Some(initialization),
            Self::ExistingOpenCleanup { opening, .. } => Some(opening),
            Self::Fabric(error) => Some(error),
            Self::Resource(error) => Some(error),
            Self::Identity(error) => Some(error),
            Self::EmptyStorageRoot
            | Self::InvalidWorkerCount
            | Self::AuthorityHeadAbsent
            | Self::RepositoryMismatch
            | Self::HeadInitializationConflict
            | Self::StoragePathEncoding
            | Self::ObjectTooLarge { .. }
            | Self::ObjectLengthOverflow
            | Self::ResourceContainment
            | Self::RuntimeContainment => None,
        }
    }
}

/// A repository path accepted by the git-daemon transport boundary.
///
/// This is an opaque authority lookup key, never a filesystem path.  The
/// daemon grammar requires an absolute slash-prefixed path, while the path
/// validator rejects empty, dot, parent, and control-byte components before a
/// future authority-backed resolver sees it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitDaemonRepositoryPath(Vec<u8>);

impl GitDaemonRepositoryPath {
    /// Returns the exact wire bytes of the validated authority lookup key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn parse(path: &[u8]) -> Result<Self, GitDaemonTransportRefusal> {
        if path.is_empty() {
            return Err(GitDaemonTransportRefusal::InvalidRepositoryPath {
                reason: GitDaemonPathRefusal::Empty,
            });
        }
        if !path.starts_with(b"/") {
            return Err(GitDaemonTransportRefusal::InvalidRepositoryPath {
                reason: GitDaemonPathRefusal::NotAbsolute,
            });
        }
        for component in path[1..].split(|byte| *byte == b'/') {
            if component.is_empty() {
                return Err(GitDaemonTransportRefusal::InvalidRepositoryPath {
                    reason: GitDaemonPathRefusal::EmptyComponent,
                });
            }
            if component == b"." {
                return Err(GitDaemonTransportRefusal::InvalidRepositoryPath {
                    reason: GitDaemonPathRefusal::DotComponent,
                });
            }
            if component == b".." {
                return Err(GitDaemonTransportRefusal::InvalidRepositoryPath {
                    reason: GitDaemonPathRefusal::ParentComponent,
                });
            }
            if component.iter().any(|byte| byte.is_ascii_control()) {
                return Err(GitDaemonTransportRefusal::InvalidRepositoryPath {
                    reason: GitDaemonPathRefusal::ControlByte,
                });
            }
        }
        Ok(Self(path.to_vec()))
    }
}

/// Why a git-daemon repository lookup key was refused before authority lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitDaemonPathRefusal {
    /// The service request did not name a repository.
    Empty,
    /// Git-daemon requires the repository name to begin with `/`.
    NotAbsolute,
    /// A repeated slash or trailing slash created an empty path component.
    EmptyComponent,
    /// A `.` component would admit an alternate spelling of the same key.
    DotComponent,
    /// A `..` component could be interpreted as a filesystem traversal.
    ParentComponent,
    /// A path component included an ASCII control byte.
    ControlByte,
}

impl Display for GitDaemonPathRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("repository path is empty"),
            Self::NotAbsolute => formatter.write_str("repository path is not absolute"),
            Self::EmptyComponent => formatter.write_str("repository path has an empty component"),
            Self::DotComponent => formatter.write_str("repository path has a dot component"),
            Self::ParentComponent => formatter.write_str("repository path has a parent component"),
            Self::ControlByte => formatter.write_str("repository path has a control byte"),
        }
    }
}

impl Error for GitDaemonPathRefusal {}

/// The parsed git-daemon opening request for the supported upload-pack lane.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitDaemonRequest {
    repository_path: GitDaemonRepositoryPath,
}

impl GitDaemonRequest {
    /// Returns the canonical authority lookup key requested by the client.
    #[must_use]
    pub const fn repository_path(&self) -> &GitDaemonRepositoryPath {
        &self.repository_path
    }
}

/// Typed failure at the git-daemon transport boundary.
#[derive(Debug)]
pub enum GitDaemonTransportRefusal {
    /// The byte stream could not be read or written at a named transport step.
    Io {
        /// The operation that encountered the I/O failure.
        operation: &'static str,
        /// The source I/O failure.
        source: io::Error,
    },
    /// The service-request pkt-line had malformed length syntax.
    InvalidGreetingLength,
    /// The service-request pkt-line used a control record instead of data.
    GreetingControlPacket,
    /// The service-request pkt-line was shorter than its four-byte framing header.
    GreetingPacketTooSmall { declared: usize },
    /// The service-request pkt-line exceeds the declared bounded wire profile.
    GreetingPacketTooLarge { declared: usize, maximum: usize },
    /// The complete request did not decode to exactly one pkt-line data record.
    InvalidGreetingPacketSequence { packets: usize },
    /// The service request omitted the NUL separator after the command and path.
    MissingGreetingTerminator,
    /// The command/path record had no ASCII-space separator.
    MalformedServiceRequest,
    /// The requested daemon service is not upload-pack.
    UnsupportedService { service_bytes: usize },
    /// The client requested a protocol generation outside this V0 milestone.
    UnsupportedProtocolVersion { version_bytes: usize },
    /// More than one version parameter appeared in the service request.
    DuplicateProtocolVersion,
    /// The path cannot name a canonical repository lookup key.
    InvalidRepositoryPath {
        /// The precise lexical refusal.
        reason: GitDaemonPathRefusal,
    },
    /// A complete pkt-line negotiation was not supplied before transport EOF.
    IncompleteNegotiation,
    /// The existing wire state machine rejected a bounded protocol input/output.
    Wire(WireError),
}

impl Display for GitDaemonTransportRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, source } => write!(formatter, "git-daemon {operation}: {source}"),
            Self::InvalidGreetingLength => {
                formatter.write_str("git-daemon greeting has a non-hex pkt-line length")
            }
            Self::GreetingControlPacket => {
                formatter.write_str("git-daemon greeting must be one data pkt-line")
            }
            Self::GreetingPacketTooSmall { declared } => {
                write!(
                    formatter,
                    "git-daemon greeting packet is too short: {declared}"
                )
            }
            Self::GreetingPacketTooLarge { declared, maximum } => write!(
                formatter,
                "git-daemon greeting packet is {declared} bytes, above {maximum}"
            ),
            Self::InvalidGreetingPacketSequence { packets } => write!(
                formatter,
                "git-daemon greeting must contain one data packet, found {packets}"
            ),
            Self::MissingGreetingTerminator => {
                formatter.write_str("git-daemon greeting lacks the NUL service terminator")
            }
            Self::MalformedServiceRequest => {
                formatter.write_str("git-daemon greeting lacks a command/path separator")
            }
            Self::UnsupportedService { service_bytes } => write!(
                formatter,
                "git-daemon requested an unsupported service ({service_bytes} bytes)"
            ),
            Self::UnsupportedProtocolVersion { version_bytes } => write!(
                formatter,
                "git-daemon requested an unsupported protocol version ({version_bytes} bytes)"
            ),
            Self::DuplicateProtocolVersion => {
                formatter.write_str("git-daemon greeting specifies protocol version more than once")
            }
            Self::InvalidRepositoryPath { reason } => Display::fmt(reason, formatter),
            Self::IncompleteNegotiation => formatter
                .write_str("git-daemon transport ended before a complete upload-pack request"),
            Self::Wire(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for GitDaemonTransportRefusal {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::InvalidRepositoryPath { reason } => Some(reason),
            Self::Wire(error) => Some(error),
            Self::InvalidGreetingLength
            | Self::GreetingControlPacket
            | Self::GreetingPacketTooSmall { .. }
            | Self::GreetingPacketTooLarge { .. }
            | Self::InvalidGreetingPacketSequence { .. }
            | Self::MissingGreetingTerminator
            | Self::MalformedServiceRequest
            | Self::UnsupportedService { .. }
            | Self::UnsupportedProtocolVersion { .. }
            | Self::DuplicateProtocolVersion
            | Self::IncompleteNegotiation => None,
        }
    }
}

/// A transport or canonical-pack-construction failure from one served session.
#[derive(Debug)]
pub enum GitDaemonServeError<PackError> {
    /// The socket/stdin transport or wire protocol was refused.
    Transport(GitDaemonTransportRefusal),
    /// The authority-backed canonical pack builder declined the selected request.
    Pack(PackError),
}

impl<PackError: Display> Display for GitDaemonServeError<PackError> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => Display::fmt(error, formatter),
            Self::Pack(error) => Display::fmt(error, formatter),
        }
    }
}

impl<PackError: Error + 'static> Error for GitDaemonServeError<PackError> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Pack(error) => Some(error),
        }
    }
}

/// Evidence that one legacy upload-pack request was completely emitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitDaemonSessionReceipt {
    request: GitDaemonRequest,
    pack_request: PackRequest,
}

impl GitDaemonSessionReceipt {
    /// Returns the parsed git-daemon service request.
    #[must_use]
    pub const fn request(&self) -> &GitDaemonRequest {
        &self.request
    }

    /// Returns the exact wire-validated fetch request sent to the pack builder.
    #[must_use]
    pub const fn pack_request(&self) -> &PackRequest {
        &self.pack_request
    }
}

/// Parses one complete git-daemon opening pkt-line.
///
/// Only legacy V0 `git-upload-pack` is accepted for the first-clone vertical
/// slice. Service selection and repository path validation belong here; pkt
/// line syntax remains owned by `fgit-wire`'s published decoder.
pub fn parse_git_daemon_request(
    frame: &[u8],
    limits: WireLimits,
) -> Result<GitDaemonRequest, GitDaemonTransportRefusal> {
    let mut decoder = PktLineDecoder::new(limits).map_err(GitDaemonTransportRefusal::Wire)?;
    let packets = decoder
        .push(frame)
        .map_err(GitDaemonTransportRefusal::Wire)?;
    decoder.finish().map_err(GitDaemonTransportRefusal::Wire)?;
    let [Packet::Data(payload)] = packets.as_slice() else {
        if packets
            .iter()
            .any(|packet| !matches!(packet, Packet::Data(_)))
        {
            return Err(GitDaemonTransportRefusal::GreetingControlPacket);
        }
        return Err(GitDaemonTransportRefusal::InvalidGreetingPacketSequence {
            packets: packets.len(),
        });
    };
    parse_git_daemon_request_payload(payload)
}

/// Serves one bounded legacy V0 git-daemon upload-pack session.
///
/// The caller supplies an authority-backed `UploadPackRepository` snapshot and
/// constructs the pack only after the verified wire machine emits
/// [`WireEvent::PackRequested`]. This adapter deliberately owns neither a ref
/// map nor an object catalog: a future `OneNode` binding must resolve the
/// requested path through the authenticated authority head and use the
/// canonical pack planner/writer for `build_pack`.
///
/// The first-clone lane advertises exactly the supplied capabilities. Its
/// intended caller passes an empty capability set, yielding raw `PACK` bytes
/// after the final negotiated ACK/NAK. When a later caller explicitly enables
/// `side-band-64k`, this adapter preserves the wire crate's bounded
/// pull/write ordering and emits a terminal flush after the payload.
pub fn serve_git_daemon_upload_pack<R, W, BuildPack, Payload, PackError>(
    reader: &mut R,
    writer: &mut W,
    repository: &impl UploadPackRepository,
    capabilities: Capabilities,
    limits: WireLimits,
    mut build_pack: BuildPack,
) -> Result<GitDaemonSessionReceipt, GitDaemonServeError<PackError>>
where
    R: Read,
    W: Write,
    BuildPack: FnMut(&GitDaemonRequest, &PackRequest) -> Result<Payload, PackError>,
    Payload: PackPayloadSource,
{
    let request =
        read_git_daemon_request(reader, &limits).map_err(GitDaemonServeError::Transport)?;
    let advertisement = V1Advertisement::new(
        repository.advertised_refs().to_vec(),
        capabilities.clone(),
        repository.object_format(),
        &limits,
    )
    .map_err(|error| GitDaemonServeError::Transport(GitDaemonTransportRefusal::Wire(error)))?;
    write_packet_group(
        writer,
        &advertisement.encode(&limits).map_err(|error| {
            GitDaemonServeError::Transport(GitDaemonTransportRefusal::Wire(error))
        })?,
        &limits,
    )
    .map_err(GitDaemonServeError::Transport)?;

    let mut machine = LegacyUploadPack::new(UploadPackVersion::V0, capabilities, limits.clone())
        .map_err(|error| GitDaemonServeError::Transport(GitDaemonTransportRefusal::Wire(error)))?;
    let mut input = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut input).map_err(|source| {
            GitDaemonServeError::Transport(GitDaemonTransportRefusal::Io {
                operation: "read upload-pack negotiation",
                source,
            })
        })?;
        if read == 0 {
            machine.finish().map_err(|error| {
                GitDaemonServeError::Transport(GitDaemonTransportRefusal::Wire(error))
            })?;
            return Err(GitDaemonServeError::Transport(
                GitDaemonTransportRefusal::IncompleteNegotiation,
            ));
        }

        let transition = machine
            .push_bytes(&input[..read], repository)
            .map_err(|error| {
                GitDaemonServeError::Transport(GitDaemonTransportRefusal::Wire(error))
            })?;
        write_packet_group(writer, &transition.output, &limits)
            .map_err(GitDaemonServeError::Transport)?;

        for event in transition.events {
            let WireEvent::PackRequested(pack_request) = event else {
                continue;
            };
            if !machine.is_complete() {
                return Err(GitDaemonServeError::Transport(
                    GitDaemonTransportRefusal::IncompleteNegotiation,
                ));
            }
            let mut payload =
                build_pack(&request, &pack_request).map_err(GitDaemonServeError::Pack)?;
            emit_pack_payload(writer, &mut payload, &pack_request, &limits)
                .map_err(GitDaemonServeError::Transport)?;
            return Ok(GitDaemonSessionReceipt {
                request,
                pack_request,
            });
        }
    }
}

/// Accepts and completes one git-daemon upload-pack connection.
///
/// A node-owned listener loop owns repetition, shutdown requests, and the
/// in-flight-session drain. This one-shot primitive performs the protocol
/// session and sends the server write-half EOF after raw V0 pack bytes, which
/// is the completion marker required by legacy clients.
pub fn serve_git_daemon_tcp_once<BuildPack, Payload, PackError>(
    listener: &TcpListener,
    repository: &impl UploadPackRepository,
    capabilities: Capabilities,
    limits: WireLimits,
    build_pack: BuildPack,
) -> Result<GitDaemonSessionReceipt, GitDaemonServeError<PackError>>
where
    BuildPack: FnMut(&GitDaemonRequest, &PackRequest) -> Result<Payload, PackError>,
    Payload: PackPayloadSource,
{
    let (mut stream, _) = listener.accept().map_err(|source| {
        GitDaemonServeError::Transport(GitDaemonTransportRefusal::Io {
            operation: "accept git-daemon connection",
            source,
        })
    })?;
    let mut writer = stream.try_clone().map_err(|source| {
        GitDaemonServeError::Transport(GitDaemonTransportRefusal::Io {
            operation: "duplicate git-daemon connection for response writes",
            source,
        })
    })?;
    let receipt = serve_git_daemon_upload_pack(
        &mut stream,
        &mut writer,
        repository,
        capabilities,
        limits,
        build_pack,
    )?;
    writer.shutdown(Shutdown::Write).map_err(|source| {
        GitDaemonServeError::Transport(GitDaemonTransportRefusal::Io {
            operation: "send git-daemon response EOF",
            source,
        })
    })?;
    Ok(receipt)
}

fn parse_git_daemon_request_payload(
    payload: &[u8],
) -> Result<GitDaemonRequest, GitDaemonTransportRefusal> {
    let Some(terminator) = payload.iter().position(|byte| *byte == 0) else {
        return Err(GitDaemonTransportRefusal::MissingGreetingTerminator);
    };
    let service_and_path = &payload[..terminator];
    let parameters = &payload[terminator + 1..];
    if !parameters.is_empty() && !parameters.ends_with(&[0]) {
        return Err(GitDaemonTransportRefusal::MissingGreetingTerminator);
    }
    let Some(separator) = service_and_path.iter().position(|byte| *byte == b' ') else {
        return Err(GitDaemonTransportRefusal::MalformedServiceRequest);
    };
    let service = &service_and_path[..separator];
    if service != b"git-upload-pack" {
        return Err(GitDaemonTransportRefusal::UnsupportedService {
            service_bytes: service.len(),
        });
    }
    let repository_path = GitDaemonRepositoryPath::parse(&service_and_path[separator + 1..])?;

    let mut requested_version_bytes = None;
    for parameter in parameters.split(|byte| *byte == 0) {
        if parameter.is_empty() {
            continue;
        }
        let Some(version) = parameter.strip_prefix(b"version=") else {
            continue;
        };
        if requested_version_bytes.is_some() {
            return Err(GitDaemonTransportRefusal::DuplicateProtocolVersion);
        }
        requested_version_bytes = Some(version.len());
    }
    if let Some(version_bytes) = requested_version_bytes {
        return Err(GitDaemonTransportRefusal::UnsupportedProtocolVersion { version_bytes });
    }
    Ok(GitDaemonRequest { repository_path })
}

fn read_git_daemon_request(
    reader: &mut impl Read,
    limits: &WireLimits,
) -> Result<GitDaemonRequest, GitDaemonTransportRefusal> {
    let mut header = [0_u8; 4];
    reader
        .read_exact(&mut header)
        .map_err(|source| GitDaemonTransportRefusal::Io {
            operation: "read git-daemon greeting header",
            source,
        })?;
    let declared = git_daemon_packet_length(header)?;
    if declared < 4 {
        return Err(GitDaemonTransportRefusal::GreetingControlPacket);
    }
    if declared > limits.max_packet_bytes {
        return Err(GitDaemonTransportRefusal::GreetingPacketTooLarge {
            declared,
            maximum: limits.max_packet_bytes,
        });
    }
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(declared)
        .map_err(|_| GitDaemonTransportRefusal::Wire(WireError::AllocationFailure))?;
    frame.extend_from_slice(&header);
    let payload_length = declared
        .checked_sub(header.len())
        .ok_or(GitDaemonTransportRefusal::GreetingPacketTooSmall { declared })?;
    let original_length = frame.len();
    frame.resize(declared, 0);
    reader
        .read_exact(&mut frame[original_length..original_length + payload_length])
        .map_err(|source| GitDaemonTransportRefusal::Io {
            operation: "read git-daemon greeting payload",
            source,
        })?;
    parse_git_daemon_request(&frame, limits.clone())
}

fn git_daemon_packet_length(header: [u8; 4]) -> Result<usize, GitDaemonTransportRefusal> {
    let mut declared = 0_usize;
    for byte in header {
        let digit = match byte {
            b'0'..=b'9' => usize::from(byte - b'0'),
            b'a'..=b'f' => usize::from(byte - b'a') + 10,
            b'A'..=b'F' => usize::from(byte - b'A') + 10,
            _ => return Err(GitDaemonTransportRefusal::InvalidGreetingLength),
        };
        declared = declared
            .checked_mul(16)
            .and_then(|value| value.checked_add(digit))
            .ok_or(GitDaemonTransportRefusal::InvalidGreetingLength)?;
    }
    Ok(declared)
}

fn write_packet_group(
    writer: &mut impl Write,
    packets: &[Packet],
    limits: &WireLimits,
) -> Result<(), GitDaemonTransportRefusal> {
    let bytes = encode_packets(packets, limits).map_err(GitDaemonTransportRefusal::Wire)?;
    writer
        .write_all(&bytes)
        .map_err(|source| GitDaemonTransportRefusal::Io {
            operation: "write git-daemon pkt-line response",
            source,
        })?;
    writer
        .flush()
        .map_err(|source| GitDaemonTransportRefusal::Io {
            operation: "flush git-daemon pkt-line response",
            source,
        })
}

fn emit_pack_payload(
    writer: &mut impl Write,
    payload: &mut impl PackPayloadSource,
    request: &PackRequest,
    limits: &WireLimits,
) -> Result<(), GitDaemonTransportRefusal> {
    let maximum_chunk_bytes = if request.options.sideband_64k() {
        limits
            .max_packet_bytes
            .checked_sub(5)
            .ok_or(GitDaemonTransportRefusal::Wire(WireError::InvalidLimit {
                field: "max_packet_bytes for sideband pack source",
            }))?
    } else {
        limits.max_packet_bytes
    };
    loop {
        let Some(chunk) = payload
            .next_chunk(maximum_chunk_bytes)
            .map_err(GitDaemonTransportRefusal::Wire)?
        else {
            break;
        };
        if chunk.len() > maximum_chunk_bytes {
            return Err(GitDaemonTransportRefusal::Wire(
                WireError::PackChunkTooLarge {
                    observed: chunk.len(),
                    limit: maximum_chunk_bytes,
                },
            ));
        }
        if request.options.sideband_64k() {
            let packets =
                sideband_pack_chunk(&chunk, limits).map_err(GitDaemonTransportRefusal::Wire)?;
            write_packet_group(writer, &packets, limits)?;
        } else {
            writer
                .write_all(&chunk)
                .map_err(|source| GitDaemonTransportRefusal::Io {
                    operation: "write raw git pack payload",
                    source,
                })?;
            writer
                .flush()
                .map_err(|source| GitDaemonTransportRefusal::Io {
                    operation: "flush raw git pack payload",
                    source,
                })?;
        }
    }
    if request.options.sideband_64k() {
        write_packet_group(writer, &[Packet::Flush], limits)?;
    }
    Ok(())
}

/// Explicit inputs for initializing one embedded node.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    storage_root: PathBuf,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    store_instance: StoreInstanceId,
    worker_threads: usize,
    object_format: GitHashAlgorithm,
    max_object_bytes: u64,
    segment_limits: SegmentLimits,
}

impl NodeConfig {
    /// Creates the bounded SHA-1 Git compatibility profile used in this slice.
    #[must_use]
    pub fn new(storage_root: PathBuf, tenant_id: TenantId, repository_id: RepositoryId) -> Self {
        Self {
            storage_root,
            tenant_id,
            repository_id,
            store_instance: StoreInstanceId::from_raw(1),
            worker_threads: 1,
            object_format: GitHashAlgorithm::Sha1,
            max_object_bytes: DEFAULT_MAX_OBJECT_BYTES,
            segment_limits: SegmentLimits::default(),
        }
    }

    /// Selects the explicit one-process authority instance identity.
    #[must_use]
    pub const fn with_store_instance(mut self, store_instance: StoreInstanceId) -> Self {
        self.store_instance = store_instance;
        self
    }

    /// Selects a finite production runtime worker count.
    #[must_use]
    pub const fn with_worker_threads(mut self, worker_threads: usize) -> Self {
        self.worker_threads = worker_threads;
        self
    }

    /// Selects the native Git object identity domain.
    #[must_use]
    pub const fn with_object_format(mut self, object_format: GitHashAlgorithm) -> Self {
        self.object_format = object_format;
        self
    }

    /// Selects the pre-allocation object byte ceiling.
    #[must_use]
    pub const fn with_max_object_bytes(mut self, max_object_bytes: u64) -> Self {
        self.max_object_bytes = max_object_bytes;
        self
    }
}

/// The idempotent result of creating the initial authority head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeInitialization {
    /// The head slot was absent and this call created it.
    Created,
    /// The requested genesis head was already installed byte-for-byte.
    IdenticalRetry,
}

/// Bounded, authenticated observations made by [`OneNode::doctor`].
///
/// This is deliberately narrower than a replay proof. It authenticates the
/// current authority receipt and, when the caller names one native object,
/// re-verifies that object's immutable envelope, native identity, and payload
/// commitment. It neither enumerates physical storage nor reconstructs an RCR
/// chain; those capabilities remain owned by the future materializer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorReport {
    authority_head: AuthenticatedHead,
    sampled_object: Option<GitOid>,
}

/// Request-owned authority context for one node operation.
///
/// The embedded authority binding requires FrankenSQLite's capability context,
/// while node request cancellation and budget ownership come from the
/// node-owned Asupersync runtime. This wrapper keeps that bridge alive for the
/// whole request without storing it on [`FsqliteAuthorityStore`] or reusing a
/// node-lifetime database context for request work.
///
/// It intentionally exposes no direct database operation: node operations
/// take this value explicitly, so a future raw-socket gateway can carry the
/// same bounded request context through authenticated authority reads and the
/// canonical admission projection. It does not itself materialize refs.
pub struct NodeRequestContext {
    authority: FsqliteCx,
}

impl NodeRequestContext {
    fn authority(&self) -> &FsqliteCx {
        &self.authority
    }
}

impl DoctorReport {
    /// The current authority receipt authenticated by the embedded store.
    #[must_use]
    pub const fn authority_head(&self) -> &AuthenticatedHead {
        &self.authority_head
    }

    /// The exact object independently re-verified by this invocation, if any.
    #[must_use]
    pub const fn sampled_object(&self) -> Option<GitOid> {
        self.sampled_object
    }
}

/// In-process authority/fabric bootstrap for the future one-node server assembly.
///
/// This type deliberately does not claim a transport service: the currently
/// published wire crate is SANS-I/O and the canonical ref projection required
/// for receive admission has not yet been published as a production surface.
#[derive(Debug)]
pub struct OneNode {
    authority: FsqliteAuthorityStore,
    head_key: HeadKey,
    fabric: LocalFilesystemFabric,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    namespace: Vec<u8>,
    object_format: GitHashAlgorithm,
    max_object_bytes: u64,
    segment_limits: SegmentLimits,
    runtime: NodeRuntime,
}

impl OneNode {
    /// Opens the durable authority store and initializes its first head when absent.
    ///
    /// Runtime blocking here is only node lifecycle work. Request operations
    /// such as [`Self::read_authority_head`] remain async over the runtime-owned
    /// database context.
    pub fn init(config: NodeConfig) -> Result<(Self, NodeInitialization), NodeRefusal> {
        let genesis = genesis_head(config.repository_id);
        let node = Self::open_components(config)?;
        let initialization_cx = node.authority_context();
        let initialization = match initialize_embedded_repository(
            &node.runtime,
            &node.authority,
            &initialization_cx,
            &node.head_key,
            &genesis,
        ) {
            Ok(HeadInit::Created(_)) => Ok(NodeInitialization::Created),
            Ok(HeadInit::IdenticalRetry(_)) => Ok(NodeInitialization::IdenticalRetry),
            Ok(HeadInit::Conflict) => Err(NodeRefusal::HeadInitializationConflict),
            Err(error) => Err(error),
        };
        match initialization {
            Ok(initialization) => Ok((node, initialization)),
            Err(initialization) => {
                let cleanup = node.shutdown();
                match cleanup {
                    Ok(()) => Err(initialization),
                    Err(cleanup) => Err(NodeRefusal::AuthorityInitializationCleanup {
                        initialization: Box::new(initialization),
                        cleanup: Box::new(cleanup),
                    }),
                }
            }
        }
    }

    /// Opens an already initialized node without synthesizing a canonical head.
    ///
    /// The embedded engine must establish its fixed local schema before it can
    /// read, but this method never calls `initialize_head`: an absent head is a
    /// typed refusal. A successful return has authenticated the current head
    /// receipt against the store's issuance record.
    pub fn open_existing(config: NodeConfig) -> Result<Self, NodeRefusal> {
        let node = Self::open_components(config)?;
        let opened = node.runtime().block_on(node.authenticate_authority_head());
        match opened {
            Ok(_) => Ok(node),
            Err(opening) => Err(close_after_existing_open_failure(node, opening)),
        }
    }

    fn open_components(config: NodeConfig) -> Result<Self, NodeRefusal> {
        if config.storage_root.as_os_str().is_empty() {
            return Err(NodeRefusal::EmptyStorageRoot);
        }
        if config.worker_threads == 0 {
            return Err(NodeRefusal::InvalidWorkerCount);
        }

        let runtime = RuntimeProfile::production(config.worker_threads)
            .build()
            .map_err(NodeRefusal::Runtime)?;
        let authority_path = authority_database_path(&config.storage_root)?;
        let namespace = object_namespace(config.repository_id);
        let failure_domain = fgit_resource::OpaqueHandle::new(b"node-local-filesystem")
            .map_err(NodeRefusal::Identity)?;
        let encryption_dependency =
            fgit_resource::OpaqueHandle::new(b"node-local-key").map_err(NodeRefusal::Identity)?;
        let fabric = LocalFilesystemFabric::open(LocalFilesystemConfig::new(
            config.storage_root,
            namespace.clone(),
            failure_domain,
            encryption_dependency,
            config.max_object_bytes,
            config.segment_limits.clone(),
        ))
        .map_err(NodeRefusal::Fabric)?;

        let head_key = head_key(config.repository_id)?;
        let opening_cx = authority_context_for(&runtime);
        let authority = runtime
            .block_on(FsqliteAuthorityStore::open(
                &opening_cx,
                authority_path,
                config.store_instance,
                AuthorityLimits::default(),
            ))
            .map_err(authority_engine_refusal)?;
        Ok(Self {
            runtime,
            authority,
            head_key,
            fabric,
            tenant_id: config.tenant_id,
            repository_id: config.repository_id,
            namespace,
            object_format: config.object_format,
            max_object_bytes: config.max_object_bytes,
            segment_limits: config.segment_limits,
        })
    }

    /// Returns the runtime responsible for request contexts and lifecycle.
    #[must_use]
    pub const fn runtime(&self) -> &NodeRuntime {
        &self.runtime
    }

    /// Returns the repository tenant identity.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Returns the repository identity governed by this node's authority head.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Mints the bounded authority context for one node request.
    ///
    /// Each call creates a new FrankenSQLite context attached to a fresh
    /// `BudgetClass::Database` Asupersync context. The returned value must stay
    /// alive while its matching node operations are awaited; it is never saved
    /// in the authority store or shared with another request.
    #[must_use]
    pub fn request_context(&self) -> NodeRequestContext {
        NodeRequestContext {
            authority: self.authority_context(),
        }
    }

    /// Reads the current authority-selected head in `request`.
    ///
    /// The authority call is made through the production async contract. The
    /// object fabric is not authority, and this does not decode the head body
    /// into refs or provide an upload-pack repository.
    pub async fn read_authority_head_in(
        &self,
        request: &NodeRequestContext,
    ) -> Result<HeadRead, NodeRefusal> {
        AsyncAuthorityStore::read_head(&self.authority, request.authority(), &self.head_key)
            .await
            .map_err(authority_failure_refusal)
    }

    /// Reads the current authority-selected head with a fresh bounded context.
    ///
    /// Services that execute more than one authority operation for the same
    /// request should call [`Self::request_context`] once and use
    /// [`Self::read_authority_head_in`] instead.
    pub async fn read_authority_head(&self) -> Result<HeadRead, NodeRefusal> {
        let request = self.request_context();
        self.read_authority_head_in(&request).await
    }

    /// Re-reads and authenticates the current authority-head receipt.
    ///
    /// Authentication proves the store issued the exact key, token,
    /// generation, and body presented in the read receipt. It does not prove
    /// that this receipt is current after the read, so callers still need CAS
    /// for publication.
    pub async fn authenticate_authority_head_in(
        &self,
        request: &NodeRequestContext,
    ) -> Result<AuthenticatedHead, NodeRefusal> {
        let HeadRead::Present(receipt) = self.read_authority_head_in(request).await? else {
            return Err(NodeRefusal::AuthorityHeadAbsent);
        };
        AsyncAuthorityStore::authenticate_head_receipt(
            &self.authority,
            request.authority(),
            &receipt,
        )
        .await
        .map_err(authority_failure_refusal)
    }

    /// Re-reads and authenticates the current authority-head receipt with a
    /// fresh bounded request context.
    pub async fn authenticate_authority_head(&self) -> Result<AuthenticatedHead, NodeRefusal> {
        let request = self.request_context();
        self.authenticate_authority_head_in(&request).await
    }

    /// Publishes one already-materialized decision batch through this node's
    /// durable production authority path.
    ///
    /// `batch` and `successor` must come from the canonical transaction/ref
    /// materializer. This boundary never synthesizes them from connection-local
    /// state: the shared authority core verifies their binding, walks the
    /// authenticated decision history, and atomically publishes the terminal
    /// outcomes with the successor head. `expected` is the token from the
    /// materializer's authenticated predecessor read. Materializations for a
    /// different repository are refused before any immutable staging work.
    pub async fn publish_decisions_in(
        &self,
        request: &NodeRequestContext,
        expected: AuthorityVersionToken,
        batch: &RepositoryDecisionBatchBody,
        successor: &RepositoryAuthorityHeadBody,
    ) -> Result<PublicationOutcome, NodeRefusal> {
        if batch.repository_id != self.repository_id
            || successor.repository_id != self.repository_id
        {
            return Err(NodeRefusal::RepositoryMismatch);
        }
        publish_decisions_async(
            &self.authority,
            request.authority(),
            &self.head_key,
            expected,
            batch,
            successor,
            self.tenant_id,
        )
        .await
        .map_err(NodeRefusal::Authority)
    }

    /// Performs the currently published bounded doctor checks.
    ///
    /// `sampled_object` is caller-selected rather than discovered from a
    /// directory listing. It is accepted only in this node's declared native
    /// Git identity domain, then read through fabric's verified-whole-read
    /// boundary. No sample means authority-head authentication only.
    pub async fn doctor_in(
        &self,
        request: &NodeRequestContext,
        sampled_object: Option<GitOid>,
    ) -> Result<DoctorReport, NodeRefusal> {
        let authority_head = self.authenticate_authority_head_in(request).await?;
        if let Some(identity) = sampled_object {
            let _ = self.read_git_object(identity)?;
        }
        Ok(DoctorReport {
            authority_head,
            sampled_object,
        })
    }

    /// Performs the currently published bounded doctor checks with a fresh
    /// bounded request context.
    pub async fn doctor(
        &self,
        sampled_object: Option<GitOid>,
    ) -> Result<DoctorReport, NodeRefusal> {
        let request = self.request_context();
        self.doctor_in(&request, sampled_object).await
    }

    /// Awaits authority-worker closure and then joins the owning runtime.
    ///
    /// Callers that obtain a node must use this before dropping it so a clean
    /// stop has an observed quiescence result instead of relying on the
    /// database driver's drop-time backstop.
    pub fn shutdown(mut self) -> Result<(), NodeRefusal> {
        let shutdown_cx = self.authority_context();
        self.runtime
            .block_on(self.authority.close(&shutdown_cx))
            .map_err(authority_engine_refusal)?;
        if self.runtime.join_root(SHUTDOWN_TIMEOUT) {
            Ok(())
        } else {
            Err(NodeRefusal::RuntimeContainment)
        }
    }

    fn authority_context(&self) -> FsqliteCx {
        authority_context_for(&self.runtime)
    }

    /// Validates and immutably places one native Git object through object fabric.
    pub fn put_git_object(
        &self,
        object_type: ObjectType,
        body: Vec<u8>,
    ) -> Result<StoredObject, NodeRefusal> {
        let offered = u64::try_from(body.len()).map_err(|_| NodeRefusal::ObjectLengthOverflow)?;
        if offered > self.max_object_bytes {
            return Err(NodeRefusal::ObjectTooLarge {
                offered,
                maximum: self.max_object_bytes,
            });
        }
        let object_kind = fabric_object_kind(object_type);
        let crypto_kind = crypto_object_kind(object_type);
        let identity = git_object_id(self.object_format, crypto_kind, &body);
        let commitment = git_payload_commitment(crypto_kind, &body, CANONICAL_CODEC_VERSION);
        let mut commitment_bytes = [0_u8; 32];
        commitment_bytes.copy_from_slice(commitment.digest().as_bytes());
        let envelope = ObjectEnvelope::new(
            self.namespace.clone(),
            identity,
            object_kind,
            offered,
            commitment_bytes,
            OBJECT_CODEC_NAMESPACE.to_vec(),
            commitment_bytes,
            None,
            &self.segment_limits,
        )
        .map_err(|error| NodeRefusal::Fabric(StoreRefusal::Fabric(error)))?;
        let verified = VerifiedObject::new(envelope, body).map_err(NodeRefusal::Fabric)?;
        let ledger = ObligationLedger::root(
            RegionId::new(1),
            LeakDisposition::RecordAndContinue,
            placement_resources(offered),
        );
        let grant = ledger
            .grant(placement_resources(offered))
            .map_err(NodeRefusal::Resource)?;
        let outcome = self
            .fabric
            .put_if_absent(verified, PlacementAdmission::new(&ledger, grant));
        let closed = ledger.close();
        if !matches!(closed, RegionCloseOutcome::Quiescent(_)) {
            return Err(NodeRefusal::ResourceContainment);
        }
        match outcome.map_err(NodeRefusal::Fabric)? {
            PutIfAbsent::Created { .. } => Ok(StoredObject::Created(identity)),
            PutIfAbsent::AlreadyPresent { .. } => Ok(StoredObject::AlreadyPresent(identity)),
        }
    }

    /// Reads one exact immutable Git object from the local fabric.
    pub fn read_git_object(&self, identity: GitOid) -> Result<VerifiedObject, NodeRefusal> {
        if identity.algorithm() != self.object_format {
            return Err(NodeRefusal::Fabric(
                StoreRefusal::NativeObjectIdentityMismatch,
            ));
        }
        self.fabric
            .read_whole(identity)
            .map(|read| read.object)
            .map_err(NodeRefusal::Fabric)
    }
}

fn close_after_existing_open_failure(node: OneNode, opening: NodeRefusal) -> NodeRefusal {
    match node.shutdown() {
        Ok(()) => opening,
        Err(cleanup) => NodeRefusal::ExistingOpenCleanup {
            opening: Box::new(opening),
            cleanup: Box::new(cleanup),
        },
    }
}

/// Observable immutable-placement outcome; neither case is an authority publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredObject {
    /// The exact immutable object was newly placed.
    Created(GitOid),
    /// An identical immutable object was already present.
    AlreadyPresent(GitOid),
}

impl StoredObject {
    /// The native object identity named by either placement outcome.
    #[must_use]
    pub const fn identity(self) -> GitOid {
        match self {
            Self::Created(identity) | Self::AlreadyPresent(identity) => identity,
        }
    }
}

fn head_key(repository_id: RepositoryId) -> Result<HeadKey, NodeRefusal> {
    let mut bytes = Vec::with_capacity(HEAD_KEY_PREFIX.len() + repository_id.as_bytes().len());
    bytes.extend_from_slice(HEAD_KEY_PREFIX);
    bytes.extend_from_slice(repository_id.as_bytes());
    HeadKey::new(bytes).map_err(NodeRefusal::HeadKey)
}

fn authority_database_path(storage_root: &Path) -> Result<String, NodeRefusal> {
    storage_root
        .join(AUTHORITY_DATABASE_FILE)
        .into_os_string()
        .into_string()
        .map_err(|_| NodeRefusal::StoragePathEncoding)
}

fn authority_context_for(runtime: &NodeRuntime) -> FsqliteCx {
    let authority = FsqliteCx::new();
    authority.set_native_cx(runtime.request_cx(BudgetClass::Database));
    authority
}

fn authority_engine_refusal(error: EngineError) -> NodeRefusal {
    NodeRefusal::Authority(error.into_failure().into())
}

fn authority_failure_refusal(error: fgit_authority::AuthorityFailure) -> NodeRefusal {
    NodeRefusal::Authority(error.into())
}

fn initialize_embedded_repository(
    runtime: &NodeRuntime,
    authority: &FsqliteAuthorityStore,
    authority_cx: &FsqliteCx,
    head_key: &HeadKey,
    genesis: &RepositoryAuthorityHeadBody,
) -> Result<HeadInit, NodeRefusal> {
    let immutable_key = body_key(IdentityDomain::RepositoryAuthorityHead, genesis)
        .map_err(|error| NodeRefusal::Authority(error.into()))?;
    let body = encode_body(genesis).map_err(|error| NodeRefusal::Authority(error.into()))?;
    runtime
        .block_on(authority.put_if_absent(authority_cx, &immutable_key, &body))
        .map_err(authority_engine_refusal)?;
    let generation = HeadGeneration::try_new(genesis.generation.get()).map_err(|error| {
        NodeRefusal::Authority(fgit_authority::OutcomeFailure::Codec(error.into()))
    })?;
    runtime
        .block_on(authority.initialize_head(authority_cx, head_key, generation, &body))
        .map_err(authority_engine_refusal)
}

fn object_namespace(repository_id: RepositoryId) -> Vec<u8> {
    let mut namespace =
        Vec::with_capacity(FABRIC_NAMESPACE_PREFIX.len() + repository_id.as_bytes().len());
    namespace.extend_from_slice(FABRIC_NAMESPACE_PREFIX);
    namespace.extend_from_slice(repository_id.as_bytes());
    namespace
}

fn genesis_head(repository_id: RepositoryId) -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id,
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: genesis_root(repository_id, b"refs"),
        forge_position_root: genesis_root(repository_id, b"forge-position"),
        outcome_index_root: genesis_root(repository_id, b"outcome-index"),
        retention_root: genesis_root(repository_id, b"retention"),
        outbox_root: genesis_root(repository_id, b"outbox"),
        configuration_root: genesis_root(repository_id, b"configuration"),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

fn genesis_root(repository_id: RepositoryId, label: &[u8]) -> Digest {
    let mut bytes = Vec::with_capacity(label.len() + repository_id.as_bytes().len());
    bytes.extend_from_slice(label);
    bytes.extend_from_slice(repository_id.as_bytes());
    let commitment = git_payload_commitment(GitObjectKind::Blob, &bytes, CANONICAL_CODEC_VERSION);
    Digest::new(
        IdentityDomain::GitPayloadCommitment.algorithm().id(),
        *commitment.digest(),
    )
}

const fn fabric_object_kind(object_type: ObjectType) -> ObjectKind {
    match object_type {
        ObjectType::Commit => ObjectKind::Commit,
        ObjectType::Tree => ObjectKind::Tree,
        ObjectType::Blob => ObjectKind::Blob,
        ObjectType::Tag => ObjectKind::Tag,
    }
}

const fn crypto_object_kind(object_type: ObjectType) -> GitObjectKind {
    match object_type {
        ObjectType::Commit => GitObjectKind::Commit,
        ObjectType::Tree => GitObjectKind::Tree,
        ObjectType::Blob => GitObjectKind::Blob,
        ObjectType::Tag => GitObjectKind::Tag,
    }
}

fn placement_resources(object_bytes: u64) -> ResourceVector {
    ResourceVector::from_grades(&[(Grade::Bytes, object_bytes.max(1)), (Grade::Objects, 1)])
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::fs;
    use std::io::{Cursor, Read};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::Duration;

    use fgit_authority::HeadRead;
    use fgit_codec::harness::{advanced_head, decision_batch};
    use fgit_types::{RepositoryId, TenantId};
    use fgit_wire::{
        AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, PackPayloadSource, Packet,
        UploadPackRepository, WireError, WireLimits, encode_packets,
    };

    use super::{
        GitDaemonServeError, GitDaemonTransportRefusal, NodeConfig, NodeInitialization,
        NodeRefusal, OneNode, parse_git_daemon_request, serve_git_daemon_tcp_once,
        serve_git_daemon_upload_pack,
    };

    static NEXT_SCRATCH_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct ScratchDirectory {
        root: PathBuf,
    }

    impl ScratchDirectory {
        fn new() -> Self {
            let sequence = NEXT_SCRATCH_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "frankengit-node-authority-{}-{sequence}",
                std::process::id()
            ));
            Self { root }
        }

        fn path(&self) -> &Path {
            &self.root
        }
    }

    impl Drop for ScratchDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn test_config(root: PathBuf) -> NodeConfig {
        NodeConfig::new(
            root,
            TenantId::from_bytes([0x11; 16]),
            RepositoryId::from_bytes([0x22; 16]),
        )
    }

    #[derive(Clone, Debug)]
    struct FixtureRepository {
        refs: Vec<AdvertisedRef>,
    }

    impl FixtureRepository {
        fn single_main_ref() -> Self {
            let limits = WireLimits::default();
            let oid = AnyGitOid::from_hex(
                GitObjectFormat::Sha1,
                "1111111111111111111111111111111111111111",
            )
            .expect("fixed SHA-1 object id");
            let reference =
                AdvertisedRef::new(oid, b"refs/heads/main", &limits).expect("fixed valid ref");
            Self {
                refs: vec![reference],
            }
        }
    }

    impl UploadPackRepository for FixtureRepository {
        fn object_format(&self) -> GitObjectFormat {
            GitObjectFormat::Sha1
        }

        fn advertised_refs(&self) -> &[AdvertisedRef] {
            &self.refs
        }

        fn contains_want(&self, oid: AnyGitOid) -> bool {
            self.refs.iter().any(|reference| reference.oid == oid)
        }

        fn is_common(&self, _oid: AnyGitOid) -> bool {
            false
        }
    }

    struct FixturePack {
        bytes: Option<Vec<u8>>,
    }

    impl PackPayloadSource for FixturePack {
        fn next_chunk(&mut self, maximum_chunk_bytes: usize) -> Result<Option<Vec<u8>>, WireError> {
            let Some(chunk) = self.bytes.take() else {
                return Ok(None);
            };
            if chunk.len() > maximum_chunk_bytes {
                return Err(WireError::PackChunkTooLarge {
                    observed: chunk.len(),
                    limit: maximum_chunk_bytes,
                });
            }
            Ok(Some(chunk))
        }
    }

    struct FragmentedReader {
        bytes: Vec<u8>,
        offset: usize,
        fragment_bytes: usize,
    }

    impl FragmentedReader {
        fn new(bytes: Vec<u8>, fragment_bytes: usize) -> Self {
            Self {
                bytes,
                offset: 0,
                fragment_bytes,
            }
        }
    }

    impl Read for FragmentedReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.offset == self.bytes.len() {
                return Ok(0);
            }
            let available = self.bytes.len() - self.offset;
            let length = available.min(self.fragment_bytes).min(buffer.len());
            buffer[..length].copy_from_slice(&self.bytes[self.offset..self.offset + length]);
            self.offset += length;
            Ok(length)
        }
    }

    fn daemon_greeting(payload: &[u8]) -> Vec<u8> {
        encode_packets(&[Packet::Data(payload.to_vec())], &WireLimits::default())
            .expect("fixed greeting encodes")
    }

    #[test]
    fn git_daemon_parser_accepts_a_v0_upload_pack_path() {
        let greeting = daemon_greeting(b"git-upload-pack /demo.git\0host=example.test\0");
        let request = parse_git_daemon_request(&greeting, WireLimits::default())
            .expect("v0 upload-pack greeting is accepted");

        assert_eq!(request.repository_path().as_bytes(), b"/demo.git");
    }

    #[test]
    fn git_daemon_parser_refuses_a_non_upload_pack_service() {
        let greeting = daemon_greeting(b"git-receive-pack /demo.git\0host=example.test\0");

        assert!(matches!(
            parse_git_daemon_request(&greeting, WireLimits::default()),
            Err(GitDaemonTransportRefusal::UnsupportedService { .. })
        ));
    }

    #[test]
    fn git_daemon_parser_refuses_a_truncated_pkt_line() {
        assert!(matches!(
            parse_git_daemon_request(b"0033git-upload-pack /demo.git", WireLimits::default()),
            Err(GitDaemonTransportRefusal::Wire(
                WireError::TruncatedPacket { .. }
            ))
        ));
    }

    #[test]
    fn git_daemon_session_writes_advertisement_ack_then_raw_pack_after_done() {
        let repository = FixtureRepository::single_main_ref();
        let want = repository.refs[0].oid.to_string();
        let mut client_bytes = daemon_greeting(b"git-upload-pack /demo.git\0host=example.test\0");
        client_bytes.extend(
            encode_packets(
                &[
                    Packet::Data(format!("want {want}\n").into_bytes()),
                    Packet::Flush,
                    Packet::Data(b"done\n".to_vec()),
                ],
                &WireLimits::default(),
            )
            .expect("fixed upload-pack negotiation encodes"),
        );
        let mut reader = FragmentedReader::new(client_bytes, 3);
        let mut writer = Cursor::new(Vec::new());

        let receipt = serve_git_daemon_upload_pack(
            &mut reader,
            &mut writer,
            &repository,
            Capabilities::default(),
            WireLimits::default(),
            |request, pack_request| -> Result<FixturePack, Infallible> {
                assert_eq!(request.repository_path().as_bytes(), b"/demo.git");
                assert_eq!(pack_request.wants, vec![repository.refs[0].oid]);
                Ok(FixturePack {
                    bytes: Some(b"PACK\0fixture".to_vec()),
                })
            },
        )
        .expect("complete V0 negotiation emits the canonical-pack payload");

        assert_eq!(receipt.request().repository_path().as_bytes(), b"/demo.git");
        assert_eq!(receipt.pack_request().wants, vec![repository.refs[0].oid]);
        let bytes = writer.into_inner();
        let pack_offset = bytes
            .windows(b"PACK".len())
            .position(|window| window == b"PACK")
            .expect("raw pack follows the upload-pack negotiation");
        assert_eq!(&bytes[pack_offset..], b"PACK\0fixture");
        assert_eq!(
            bytes[..pack_offset]
                .windows(b"NAK\n".len())
                .filter(|window| *window == b"NAK\n")
                .count(),
            1,
            "the want-phase flush emits the sole negotiated NAK before raw pack bytes; the final done transition delegates fgit-wire's non-duplicating Git 2.54 behavior"
        );
    }

    #[test]
    fn git_daemon_session_refuses_eof_before_done_without_constructing_a_pack() {
        let repository = FixtureRepository::single_main_ref();
        let mut reader = Cursor::new(daemon_greeting(b"git-upload-pack /demo.git\0"));
        let mut writer = Cursor::new(Vec::new());

        let result = serve_git_daemon_upload_pack(
            &mut reader,
            &mut writer,
            &repository,
            Capabilities::default(),
            WireLimits::default(),
            |_request, _pack_request| -> Result<FixturePack, Infallible> {
                panic!("a pack must not be constructed before a complete request")
            },
        );

        assert!(matches!(
            result,
            Err(GitDaemonServeError::Transport(
                GitDaemonTransportRefusal::IncompleteNegotiation
            ))
        ));
    }

    #[test]
    fn git_daemon_tcp_once_signals_eof_after_the_raw_pack_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener binds");
        let address = listener
            .local_addr()
            .expect("listener address is available");
        let repository = FixtureRepository::single_main_ref();
        let server = thread::spawn(move || {
            serve_git_daemon_tcp_once(
                &listener,
                &repository,
                Capabilities::default(),
                WireLimits::default(),
                |_request, _pack_request| -> Result<FixturePack, Infallible> {
                    Ok(FixturePack {
                        bytes: Some(b"PACK\0tcp".to_vec()),
                    })
                },
            )
        });

        let mut client = TcpStream::connect(address).expect("loopback client connects");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("client read timeout configures");
        let want = "1111111111111111111111111111111111111111";
        let mut request = daemon_greeting(b"git-upload-pack /demo.git\0host=loopback\0");
        request.extend(
            encode_packets(
                &[
                    Packet::Data(format!("want {want}\n").into_bytes()),
                    Packet::Flush,
                    Packet::Data(b"done\n".to_vec()),
                ],
                &WireLimits::default(),
            )
            .expect("fixed TCP negotiation encodes"),
        );
        std::io::Write::write_all(&mut client, &request).expect("client request writes");
        client
            .shutdown(Shutdown::Write)
            .expect("client closes request half after done");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .expect("server response reaches write-half EOF");
        let receipt = server
            .join()
            .expect("server thread joins")
            .expect("server accepts the complete V0 request");
        assert_eq!(receipt.request().repository_path().as_bytes(), b"/demo.git");
        assert!(response.ends_with(b"PACK\0tcp"));
    }

    #[test]
    fn clean_restart_uses_the_same_durable_authority_head() {
        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf());

        let (first, first_init) = OneNode::init(config.clone()).expect("first node opens");
        assert_eq!(first_init, NodeInitialization::Created);
        let first_request = first.request_context();
        let first_head = first
            .runtime()
            .block_on(first.read_authority_head_in(&first_request))
            .expect("first head reads");
        assert!(matches!(&first_head, HeadRead::Present(_)));
        first.shutdown().expect("first node closes cleanly");

        let (second, second_init) = OneNode::init(config).expect("reopened node opens");
        assert_eq!(second_init, NodeInitialization::IdenticalRetry);
        let second_request = second.request_context();
        let second_head = second
            .runtime()
            .block_on(second.read_authority_head_in(&second_request))
            .expect("reopened head reads");
        assert_eq!(second_head, first_head);
        second.shutdown().expect("reopened node closes cleanly");
    }

    #[test]
    fn doctor_authenticates_the_head_and_rechecks_a_named_object() {
        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf());
        let (node, _) = OneNode::init(config.clone()).expect("node opens");
        let stored = node
            .put_git_object(fgit_git_object::ObjectType::Blob, b"doctor sample".to_vec())
            .expect("sample stores");
        let request = node.request_context();
        let report = node
            .runtime()
            .block_on(node.doctor_in(&request, Some(stored.identity())))
            .expect("doctor authenticates and verifies the named sample");
        assert_eq!(report.sampled_object(), Some(stored.identity()));
        assert_eq!(
            report.authority_head().receipt().generation(),
            fgit_types::HeadGeneration::FIRST
        );
        node.shutdown().expect("node closes cleanly");

        let reopened = OneNode::open_existing(config).expect("existing head opens");
        let reopened_request = reopened.request_context();
        let reopened_report = reopened
            .runtime()
            .block_on(reopened.doctor_in(&reopened_request, None))
            .expect("doctor authenticates reopened head");
        assert_eq!(
            reopened_report.authority_head().receipt().generation(),
            fgit_types::HeadGeneration::FIRST
        );
        reopened.shutdown().expect("reopened node closes cleanly");
    }

    #[test]
    fn durable_publication_refuses_another_repository_before_staging() {
        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf());
        let (node, _) = OneNode::init(config).expect("node opens");
        let request = node.request_context();
        let before = node
            .runtime()
            .block_on(node.read_authority_head_in(&request))
            .expect("genesis head reads");
        let HeadRead::Present(before_receipt) = before else {
            panic!("node initialization creates its authority head");
        };

        let other_repository = RepositoryId::from_bytes([0x44; 16]);
        let mut batch = decision_batch();
        batch.repository_id = other_repository;
        let mut successor = advanced_head();
        successor.repository_id = other_repository;

        let refusal = node.runtime().block_on(node.publish_decisions_in(
            &request,
            before_receipt.token(),
            &batch,
            &successor,
        ));
        assert!(matches!(refusal, Err(NodeRefusal::RepositoryMismatch)));

        let after = node
            .runtime()
            .block_on(node.read_authority_head_in(&request))
            .expect("rejected publication leaves head readable");
        assert_eq!(after, HeadRead::Present(before_receipt));
        node.shutdown().expect("node closes cleanly");
    }

    #[test]
    fn open_existing_refuses_an_absent_authority_head() {
        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf());

        assert!(matches!(
            OneNode::open_existing(config),
            Err(NodeRefusal::AuthorityHeadAbsent)
        ));
    }
}
