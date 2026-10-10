#![forbid(unsafe_code)]
//! Create-only local materialization of bytes supplied by the native verifier.
//!
//! This module does not interpret Git or establish source authenticity. Its only
//! production caller supplies a verified native layout. The directory must be
//! quiescent and operator controlled; path-based std I/O is not a hostile-host
//! descriptor-relative sandbox. No file is truncated or replaced.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

const RECORD: &str = ".frankengit-native-source-recovery";
const PART: &str = ".fg-recovery-part";
const CHUNK: usize = 64 * 1024;

/// A replayable pack bound to an already verified native plan. Every complete
/// replay must check that binding before returning EOF, including replays used
/// to compare a shorter existing stage. The writer always reads through EOF.
/// Git interpretation and the cryptographic binding belong to the native caller.
pub(super) trait VerifiedPackSource {
    fn len(&self) -> u64;
    fn rewind(&mut self) -> std::io::Result<()>;
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize>;
}

pub(super) enum Pack<'a> {
    Bytes(&'a [u8]),
    Stream(&'a mut dyn VerifiedPackSource),
}
impl Pack<'_> {
    fn len(&self) -> u64 {
        match self {
            Self::Bytes(bytes) => bytes.len() as u64,
            Self::Stream(source) => source.len(),
        }
    }
    fn within_limit(&self) -> bool {
        let maximum = match self {
            Self::Bytes(_) => 128 * 1024 * 1024,
            Self::Stream(_) => 16 * 1024 * 1024 * 1024,
        };
        self.len() > 0 && self.len() <= maximum
    }
}

/// Borrowed metadata and a bounded replayable pack, constructed from the native
/// recovery plan. Only the pack may be file backed; metadata remains bounded.
pub(super) struct Layout<'a> {
    pub record: &'a [u8],
    pub pack_stem: &'a str,
    pub pack: Pack<'a>,
    pub index: &'a [u8],
    pub packed_refs: &'a [u8],
    pub config: &'a [u8],
    pub head: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum State {
    Unchanged,
    Staged,
    PublicationUncertain,
    Published,
    Durable,
}
impl State {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::Staged => "staged",
            Self::PublicationUncertain => "publication_uncertain",
            Self::Published => "published",
            Self::Durable => "durable",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Code {
    Stopped,
    UnsupportedPlatform,
    InvalidLayout,
    InvalidDestination,
    ExistingDestination,
    MissingRecoveryRecord,
    UnexpectedEntry,
    InvalidFile,
    NamespaceChanged,
    BodyMismatch,
    SourceChanged,
    Io,
}
impl Code {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::UnsupportedPlatform => "directory_sync_profile_unsupported",
            Self::InvalidLayout => "invalid_layout",
            Self::InvalidDestination => "invalid_destination",
            Self::ExistingDestination => "destination_exists",
            Self::MissingRecoveryRecord => "missing_recovery_record",
            Self::UnexpectedEntry => "unexpected_directory_entry",
            Self::InvalidFile => "non_private_regular_file",
            Self::NamespaceChanged => "namespace_changed",
            Self::BodyMismatch => "existing_body_mismatch",
            Self::SourceChanged => "verified_source_changed",
            Self::Io => "filesystem_error",
        }
    }
}

#[derive(Debug)]
pub(super) struct Error {
    pub state: State,
    pub code: Code,
    detail: String,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "native_bundle_recovery_refused: state={} code={} detail={:?}; preserve the destination and use explicit --resume with the same verified input and head",
            self.state.as_str(),
            self.code.as_str(),
            self.detail
        )
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Completed {
    pub resumed: bool,
    pub already_published: bool,
}

struct Body<'a> {
    name: String,
    content: Content<'a>,
}
enum Content<'a> {
    Bytes(Cursor<&'a [u8]>),
    Stream(&'a mut dyn VerifiedPackSource),
}
impl<'a> Content<'a> {
    fn bytes(bytes: &'a [u8]) -> Self {
        Self::Bytes(Cursor::new(bytes))
    }
    fn len(&self) -> u64 {
        match self {
            Self::Bytes(cursor) => cursor.get_ref().len() as u64,
            Self::Stream(source) => source.len(),
        }
    }
    fn rewind(&mut self) -> std::io::Result<()> {
        match self {
            Self::Bytes(cursor) => {
                cursor.set_position(0);
                Ok(())
            }
            Self::Stream(source) => source.rewind(),
        }
    }
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Bytes(cursor) => cursor.read(output),
            Self::Stream(source) => source.read(output),
        }
    }
}
struct Directory {
    path: PathBuf,
    identity: Metadata,
}
struct Writer<'a, F> {
    state: State,
    stopped: bool,
    live: &'a mut F,
    directories: Vec<Directory>,
}
impl<F: FnMut() -> bool> Writer<'_, F> {
    fn error(&self, code: Code, detail: impl Into<String>) -> Error {
        Error {
            state: self.state,
            code,
            detail: detail.into(),
        }
    }
    fn io(&self, action: &str, error: std::io::Error) -> Error {
        self.error(Code::Io, format!("{action}: {error}"))
    }
    fn source_error(&self, action: &str, error: std::io::Error) -> Error {
        let code = match error.kind() {
            std::io::ErrorKind::InvalidData | std::io::ErrorKind::UnexpectedEof => {
                Code::SourceChanged
            }
            _ => Code::Io,
        };
        self.error(code, format!("{action}: {error}"))
    }
    fn checkpoint(&mut self) -> Result<(), Error> {
        if !self.stopped && !(self.live)() {
            self.stopped = true;
        }
        if self.stopped {
            Err(self.error(Code::Stopped, "cooperative cancellation or deadline"))
        } else {
            Ok(())
        }
    }
    fn check_directories(&mut self) -> Result<(), Error> {
        self.checkpoint()?;
        for directory in &self.directories {
            let current = fs::symlink_metadata(&directory.path)
                .map_err(|error| self.io("recheck directory", error))?;
            if !current.is_dir() || !same_identity(&directory.identity, &current) {
                return Err(
                    self.error(Code::NamespaceChanged, directory.path.display().to_string())
                );
            }
        }
        self.checkpoint()
    }
    fn remember_directory(&mut self, path: PathBuf, private: bool) -> Result<(), Error> {
        self.checkpoint()?;
        let identity =
            fs::symlink_metadata(&path).map_err(|error| self.io("inspect directory", error))?;
        if !identity.is_dir() || (private && !private_directory(&identity)) {
            return Err(self.error(Code::InvalidDestination, path.display().to_string()));
        }
        self.directories.push(Directory { path, identity });
        Ok(())
    }
    fn sync_directory(&mut self, path: &Path) -> Result<(), Error> {
        self.check_directories()?;
        let named =
            fs::symlink_metadata(path).map_err(|error| self.io("inspect sync directory", error))?;
        let file = File::open(path).map_err(|error| self.io("open sync directory", error))?;
        let opened = file
            .metadata()
            .map_err(|error| self.io("inspect open directory", error))?;
        if !named.is_dir() || !same_identity(&named, &opened) {
            return Err(self.error(Code::NamespaceChanged, "directory changed while opening"));
        }
        file.sync_all()
            .map_err(|error| self.io("synchronize directory", error))?;
        self.check_directories()
    }
    fn inspect_file(
        &mut self,
        path: &Path,
        expected: &mut Content<'_>,
        prefix: bool,
    ) -> Result<Option<Metadata>, Error> {
        self.check_directories()?;
        let Some(named) =
            metadata_optional(path).map_err(|error| self.io("inspect body", error))?
        else {
            return Ok(None);
        };
        if !private_file(&named)
            || named.len() > expected.len()
            || (!prefix && named.len() != expected.len())
        {
            return Err(self.error(
                if !private_file(&named) {
                    Code::InvalidFile
                } else {
                    Code::BodyMismatch
                },
                path.display().to_string(),
            ));
        }
        let mut file = File::open(path).map_err(|error| self.io("open existing body", error))?;
        let before = file
            .metadata()
            .map_err(|error| self.io("inspect open body", error))?;
        if !same_file(&named, &before) {
            return Err(self.error(Code::NamespaceChanged, "body changed while opening"));
        }
        expected
            .rewind()
            .map_err(|error| self.source_error("rewind verified body", error))?;
        let mut buffer = [0_u8; CHUNK];
        let mut source = [0_u8; CHUNK];
        let mut at = 0_u64;
        loop {
            self.checkpoint()?;
            let count = match expected.read(&mut source) {
                Ok(count) => count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(self.source_error("read verified body", error)),
            };
            self.checkpoint()?;
            let end = at
                .checked_add(count as u64)
                .filter(|end| count <= CHUNK && *end <= expected.len())
                .ok_or_else(|| self.error(Code::SourceChanged, "verified body grew"))?;
            let compare = (named.len().saturating_sub(at)).min(count as u64) as usize;
            let mut read = 0;
            while read < compare {
                self.checkpoint()?;
                match file.read(&mut buffer[read..compare]) {
                    Ok(0) => {
                        return Err(self.error(Code::BodyMismatch, "existing body shortened"));
                    }
                    Ok(count) => read += count,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(self.io("read existing body", error)),
                }
            }
            if buffer[..compare] != source[..compare] {
                return Err(self.error(Code::BodyMismatch, path.display().to_string()));
            }
            // Even a short stage prefix must be compared to a fully replayed,
            // binding-checked source. An unchecked prefix never authorizes append.
            at = end;
            if count == 0 {
                break;
            }
        }
        if at != expected.len() {
            return Err(self.error(Code::SourceChanged, "verified body shortened"));
        }
        self.checkpoint()?;
        loop {
            match file.read(&mut buffer[..1]) {
                Ok(0) => break,
                Ok(_) => return Err(self.error(Code::BodyMismatch, "existing body grew")),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                    self.checkpoint()?;
                }
                Err(error) => return Err(self.io("check existing body EOF", error)),
            }
        }
        let after = file
            .metadata()
            .map_err(|error| self.io("inspect read body", error))?;
        let current =
            fs::symlink_metadata(path).map_err(|error| self.io("recheck read body", error))?;
        if !same_file(&before, &after) || !same_file(&after, &current) {
            return Err(self.error(Code::NamespaceChanged, "body changed while reading"));
        }
        self.check_directories()?;
        Ok(Some(current))
    }
    fn inspect_body(&mut self, root: &Path, body: &mut Body<'_>) -> Result<bool, Error> {
        let final_path = root.join(&body.name);
        let part_path = root.join(format!("{}{PART}", body.name));
        let final_file = self.inspect_file(&final_path, &mut body.content, false)?;
        let part_file = self.inspect_file(&part_path, &mut body.content, true)?;
        match (&final_file, &part_file) {
            (Some(final_file), Some(part_file))
                if !same_identity(final_file, part_file)
                    || part_file.len() != body.content.len()
                    || links(part_file) != 2 =>
            {
                return Err(self.error(
                    Code::InvalidFile,
                    "published body and retained stage are not the same exact link",
                ));
            }
            (Some(final_file), None) if links(final_file) != 1 => {
                return Err(self.error(Code::InvalidFile, "final body has an unowned hard link"));
            }
            (None, Some(part_file)) if links(part_file) != 1 => {
                return Err(self.error(Code::InvalidFile, "stage has an unowned hard link"));
            }
            _ => {}
        }
        Ok(final_file.is_some())
    }
    fn stage_body(&mut self, root: &Path, body: &mut Body<'_>) -> Result<bool, Error> {
        if self.inspect_body(root, body)? {
            return Ok(true);
        }
        let part_path = root.join(format!("{}{PART}", body.name));
        self.check_directories()?;
        let before =
            metadata_optional(&part_path).map_err(|error| self.io("inspect stage", error))?;
        let mut options = OpenOptions::new();
        options.read(true).append(true);
        if before.is_none() {
            options.create_new(true);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&part_path)
            .map_err(|error| self.io("open private stage", error))?;
        let opened = file
            .metadata()
            .map_err(|error| self.io("inspect stage descriptor", error))?;
        if !private_file(&opened)
            || links(&opened) != 1
            || before
                .as_ref()
                .is_some_and(|before| !same_file(before, &opened))
        {
            return Err(self.error(Code::NamespaceChanged, "stage changed while opening"));
        }
        // inspect_body verified the complete existing prefix before this append.
        // The trusted-local profile requires no concurrent writer to this path.
        let prefix = opened.len();
        if prefix > body.content.len() {
            return Err(self.error(Code::BodyMismatch, "stage is longer than expected"));
        }
        body.content
            .rewind()
            .map_err(|error| self.source_error("rewind verified stage source", error))?;
        let mut buffer = [0_u8; CHUNK];
        let mut at = 0_u64;
        loop {
            self.check_directories()?;
            let count = match body.content.read(&mut buffer) {
                Ok(count) => count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(self.source_error("read verified stage source", error)),
            };
            self.checkpoint()?;
            let end = at
                .checked_add(count as u64)
                .filter(|end| count <= CHUNK && *end <= body.content.len())
                .ok_or_else(|| self.error(Code::SourceChanged, "verified body grew"))?;
            let skip = prefix.saturating_sub(at).min(count as u64) as usize;
            if skip < count {
                file.write_all(&buffer[skip..count])
                    .map_err(|error| self.io("append verified stage", error))?;
                self.checkpoint()?;
            }
            at = end;
            if count == 0 {
                break;
            }
        }
        if at != body.content.len() {
            return Err(self.error(Code::SourceChanged, "verified body shortened"));
        }
        file.sync_all()
            .map_err(|error| self.io("synchronize stage", error))?;
        drop(file);
        self.inspect_file(&part_path, &mut body.content, false)?;
        Ok(false)
    }
    fn install_body(
        &mut self,
        root: &Path,
        body: &mut Body<'_>,
        is_head: bool,
    ) -> Result<(), Error> {
        let present = self.stage_body(root, body)?;
        let final_path = root.join(&body.name);
        let part_path = root.join(format!("{}{PART}", body.name));
        if !present {
            self.check_directories()?;
            if is_head {
                self.state = State::PublicationUncertain;
            }
            fs::hard_link(&part_path, &final_path)
                .map_err(|error| self.io("create-only body publication", error))?;
            if is_head {
                self.state = State::Published;
            }
            self.checkpoint()?;
        }
        self.inspect_body(root, body)?;
        let file =
            File::open(&final_path).map_err(|error| self.io("open published body", error))?;
        file.sync_all()
            .map_err(|error| self.io("synchronize published body", error))?;
        drop(file);
        if metadata_optional(&part_path)
            .map_err(|error| self.io("inspect linked stage", error))?
            .is_some()
        {
            self.check_directories()?;
            self.inspect_body(root, body)?;
            fs::remove_file(&part_path)
                .map_err(|error| self.io("remove exact staging link", error))?;
        }
        self.check_directories()
    }
}

fn metadata_optional(path: &Path) -> std::io::Result<Option<Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}
fn same_identity(a: &Metadata, b: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.mode() == b.mode()
            && a.uid() == b.uid()
            && a.gid() == b.gid()
    }
    #[cfg(not(unix))]
    {
        let _ = (a, b);
        false
    }
}
fn same_file(a: &Metadata, b: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        same_identity(a, b)
            && a.len() == b.len()
            && a.nlink() == b.nlink()
            && a.mtime() == b.mtime()
            && a.mtime_nsec() == b.mtime_nsec()
            && a.ctime() == b.ctime()
            && a.ctime_nsec() == b.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        let _ = (a, b);
        false
    }
}
fn links(metadata: &Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.nlink()
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        0
    }
}
fn private_file(metadata: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.is_file()
            && metadata.mode() & 0o7777 == 0o600
            && (1..=2).contains(&metadata.nlink())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}
fn private_directory(metadata: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.is_dir() && metadata.mode() & 0o7777 == 0o700
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

fn normal_destination(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        // Path::components, equality and parent() normalize trailing `/.`.
        // Inspect the original byte spelling before selecting the parent/name.
        !path
            .as_os_str()
            .as_bytes()
            .split(|byte| *byte == b'/')
            .any(|component| matches!(component, b"." | b".."))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

/// Verify every preexisting entry before any resume mutation. All names are
/// generated locally, never expanded from the bundle's ref names.
fn inspect_namespace<F: FnMut() -> bool>(
    writer: &mut Writer<'_, F>,
    root: &Path,
    bodies: &[Body<'_>],
) -> Result<(), Error> {
    let mut allowed = BTreeSet::from([
        "objects".to_owned(),
        "objects/pack".to_owned(),
        "refs".to_owned(),
    ]);
    for body in bodies {
        allowed.insert(body.name.clone());
        allowed.insert(format!("{}{PART}", body.name));
    }
    for directory in ["", "objects", "objects/pack", "refs"] {
        writer.check_directories()?;
        let path = root.join(directory);
        let Some(metadata) = metadata_optional(&path)
            .map_err(|error| writer.io("inspect recovery namespace", error))?
        else {
            continue;
        };
        if !private_directory(&metadata) {
            return Err(writer.error(Code::InvalidDestination, "non-private recovery directory"));
        }
        let entries = fs::read_dir(&path)
            .map_err(|error| writer.io("enumerate recovery directory", error))?;
        for entry in entries {
            writer.checkpoint()?;
            let entry = entry.map_err(|error| writer.io("read recovery directory entry", error))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(writer.error(Code::UnexpectedEntry, "non-UTF8 host filename"));
            };
            let relative = if directory.is_empty() {
                name.to_owned()
            } else {
                format!("{directory}/{name}")
            };
            if !allowed.contains(&relative) {
                return Err(writer.error(Code::UnexpectedEntry, relative));
            }
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| writer.io("inspect recovery entry", error))?;
            if matches!(relative.as_str(), "objects" | "objects/pack" | "refs") {
                if !private_directory(&metadata) {
                    return Err(writer.error(Code::InvalidDestination, relative));
                }
            } else if !private_file(&metadata) {
                return Err(writer.error(Code::InvalidFile, relative));
            }
        }
    }
    Ok(())
}

/// Materialize a complete native layout. HEAD is the only Git-visible root and
/// is linked last. A crash before the exact recovery record is installed leaves
/// an unidentified directory which resume refuses; it is never guessed owned.
pub(super) fn materialize(
    destination: &Path,
    layout: &mut Layout<'_>,
    resume: bool,
    allow_work: &mut impl FnMut() -> bool,
) -> Result<Completed, Error> {
    let mut writer = Writer {
        // Before inspecting a resumed destination, no refusal may imply that
        // an earlier attempt did not publish HEAD.
        state: if resume {
            State::PublicationUncertain
        } else {
            State::Unchanged
        },
        stopped: false,
        live: allow_work,
        directories: Vec::new(),
    };
    writer.checkpoint()?;
    if !cfg!(unix) {
        return Err(writer.error(
            Code::UnsupportedPlatform,
            "requires Unix regular-file and directory synchronization",
        ));
    }
    if !normal_destination(destination) {
        return Err(writer.error(
            Code::InvalidDestination,
            "destination components must not be . or ..",
        ));
    }
    let digest = layout.pack_stem.strip_prefix("pack-").unwrap_or("");
    if !matches!(digest.len(), 40 | 64)
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || layout.record.is_empty()
        || layout.record.len() > 16 * 1024
        || !layout.pack.within_limit()
        || layout.index.is_empty()
        || layout.index.len() > 16 * 1024 * 1024
        || layout.packed_refs.is_empty()
        || layout.packed_refs.len() > 1024 * 1024 + 64
        || layout.config.is_empty()
        || layout.config.len() > 4096
        || layout.head.is_empty()
        || layout.head.len() > 8192
    {
        return Err(writer.error(Code::InvalidLayout, "native layout framing or byte limits"));
    }
    let name = destination.file_name().ok_or_else(|| {
        writer.error(
            Code::InvalidDestination,
            "destination must name a new directory",
        )
    })?;
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if destination
        .parent()
        .is_some_and(|parent| parent.join(name) != destination)
    {
        return Err(writer.error(Code::InvalidDestination, "ambiguous destination components"));
    }
    writer.remember_directory(parent.to_owned(), false)?;
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|error| writer.io("resolve trusted destination parent", error))?;
    writer.check_directories()?;
    let root = canonical_parent.join(name);
    if resume {
        writer.remember_directory(root.clone(), true)?;
    } else {
        if metadata_optional(&root)
            .map_err(|error| writer.io("inspect destination", error))?
            .is_some()
        {
            return Err(writer.error(
                Code::ExistingDestination,
                "fresh recovery never reuses any existing path",
            ));
        }
        create_private_directory(&root)
            .map_err(|error| writer.io("create private destination", error))?;
        writer.state = State::Staged;
        writer.remember_directory(root.clone(), true)?;
    }
    // Observe a preexisting publication root before any namespace or identity
    // refusal. A bad record cannot turn an already visible HEAD into "unchanged".
    let already_published = metadata_optional(&root.join("HEAD"))
        .map_err(|error| writer.io("inspect publication root", error))?
        .is_some();
    writer.state = if already_published {
        State::PublicationUncertain
    } else {
        State::Staged
    };
    let pack = match &mut layout.pack {
        Pack::Bytes(bytes) => Content::bytes(bytes),
        Pack::Stream(source) => Content::Stream(&mut **source),
    };
    let mut bodies = [
        Body {
            name: RECORD.to_owned(),
            content: Content::bytes(layout.record),
        },
        Body {
            name: format!("objects/pack/{}.pack", layout.pack_stem),
            content: pack,
        },
        Body {
            name: format!("objects/pack/{}.idx", layout.pack_stem),
            content: Content::bytes(layout.index),
        },
        Body {
            name: "packed-refs".to_owned(),
            content: Content::bytes(layout.packed_refs),
        },
        Body {
            name: "config".to_owned(),
            content: Content::bytes(layout.config),
        },
        Body {
            name: "HEAD".to_owned(),
            content: Content::bytes(layout.head),
        },
    ];
    inspect_namespace(&mut writer, &root, &bodies)?;
    if resume && !writer.inspect_body(&root, &mut bodies[0])? {
        return Err(writer.error(
            Code::MissingRecoveryRecord,
            "only a complete exact recovery record identifies an interrupted target",
        ));
    }
    if already_published {
        for relative in ["objects", "objects/pack", "refs"] {
            if metadata_optional(&root.join(relative))
                .map_err(|error| writer.io("inspect published directory", error))?
                .is_none()
            {
                return Err(writer.error(
                    Code::BodyMismatch,
                    "HEAD exists but a required directory is absent",
                ));
            }
        }
    }
    // On resume, reject all corruption before creating/appending any body. A
    // visible HEAD may never be repaired around absent/incomplete dependencies.
    for body in &mut bodies {
        let present = writer.inspect_body(&root, body)?;
        if already_published && !present {
            return Err(writer.error(
                Code::BodyMismatch,
                "HEAD exists but a required complete body is absent",
            ));
        }
    }
    if already_published {
        writer.state = State::Published;
    }
    writer.install_body(&root, &mut bodies[0], false)?;
    writer.sync_directory(&root)?;
    writer.sync_directory(&canonical_parent)?;
    for relative in ["objects", "objects/pack", "refs"] {
        writer.check_directories()?;
        let path = root.join(relative);
        if metadata_optional(&path)
            .map_err(|error| writer.io("inspect fixed directory", error))?
            .is_none()
        {
            if already_published {
                return Err(writer.error(
                    Code::BodyMismatch,
                    "published layout lacks a required directory",
                ));
            }
            create_private_directory(&path)
                .map_err(|error| writer.io("create fixed private directory", error))?;
        }
        writer.remember_directory(path, true)?;
    }
    for body in &mut bodies[1..5] {
        writer.install_body(&root, body, false)?;
    }
    for directory in ["objects/pack", "objects", "refs", ""] {
        writer.sync_directory(&root.join(directory))?;
    }
    // All native dependencies are immutable and synchronized before HEAD.
    inspect_namespace(&mut writer, &root, &bodies)?;
    for body in &mut bodies[..5] {
        if !writer.inspect_body(&root, body)? {
            return Err(writer.error(
                Code::BodyMismatch,
                "required body disappeared before HEAD publication",
            ));
        }
    }
    writer.install_body(&root, &mut bodies[5], true)?;
    writer.sync_directory(&root)?;
    writer.sync_directory(&canonical_parent)?;
    writer.state = State::Durable;
    writer.checkpoint()?;
    Ok(Completed {
        resumed: resume,
        already_published,
    })
}

#[cfg(test)]
#[path = "filesystem_tests.rs"]
mod tests;
