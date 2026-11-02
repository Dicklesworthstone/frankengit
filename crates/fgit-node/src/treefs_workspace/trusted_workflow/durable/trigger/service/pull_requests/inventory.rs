//! Bounded local responsibility inventory, never repository authority.
//! Pending membership is durable before child custody; initialized membership
//! is durable before dispatch. Records only grow and never release a child.
use super::super::super::{Owner, check_directory, hex};
use super::{WorkflowWatchError, checkpoint};
use fgit_crypto::sha256_digest;
use fgit_types::RefName;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 8] = b"FGPRCOL1";
const MAX_MEMBERS: usize = 64;
const MAX_REFERENCE: usize = 4096;
// One complete record and one fixed staging name bound disk custody to less
// than 514 KiB, excluding the separate native member event/run histories.
const MAX_BYTES: usize = 8 + 32 + 32 + 2 + MAX_MEMBERS * (8 + 1 + 2 + MAX_REFERENCE) + 32;
const READ_FLAGS: i32 = 0o400000 | 0o4000 | 0o2000000; // Linux NOFOLLOW|NONBLOCK|CLOEXEC.

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Entry {
    pub number: u64,
    pub reference: RefName,
    pub initialized: bool,
}

pub(super) struct Inventory {
    parent: PathBuf,
    parent_meta: fs::Metadata,
    root: PathBuf,
    root_meta: fs::Metadata,
    owner: Owner,
    scope: [u8; 32],
    binding: [u8; 32],
    entries: Vec<Entry>,
    bytes: Vec<u8>,
    maximum: usize,
}

fn bad(detail: impl Into<String>) -> WorkflowWatchError {
    WorkflowWatchError::Custody(format!("PR collection inventory: {}", detail.into()))
}
fn io_error(error: io::Error) -> WorkflowWatchError {
    bad(error.to_string())
}
fn directory(path: &Path) -> Result<fs::Metadata, WorkflowWatchError> {
    check_directory(path).map_err(|e| bad(e.to_string()))?;
    fs::symlink_metadata(path).map_err(io_error)
}
fn same(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    (a.dev(), a.ino()) == (b.dev(), b.ino())
}
fn regular(meta: &fs::Metadata) -> bool {
    meta.is_file()
        && meta.mode() & 0o777 == 0o600
        && meta.nlink() == 1
        && meta.len() <= MAX_BYTES as u64
}
fn unchanged(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    same(a, b)
        && a.len() == b.len()
        && (a.mtime(), a.mtime_nsec(), a.ctime(), a.ctime_nsec())
            == (b.mtime(), b.mtime_nsec(), b.ctime(), b.ctime_nsec())
}
fn read(path: &Path, live: &dyn Fn() -> bool) -> Result<Vec<u8>, WorkflowWatchError> {
    checkpoint(live)?;
    let named = fs::symlink_metadata(path).map_err(io_error)?;
    if !regular(&named) {
        return Err(bad("record is not a bounded private regular file"));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(READ_FLAGS)
        .open(path)
        .map_err(io_error)?;
    let selected = file.metadata().map_err(io_error)?;
    if !regular(&selected) || !unchanged(&named, &selected) {
        return Err(bad("record changed during open"));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(selected.len() as usize)
        .map_err(|_| bad("record allocation refused"))?;
    let mut buffer = [0u8; 8192];
    loop {
        checkpoint(live)?;
        let n = file.read(&mut buffer).map_err(io_error)?;
        checkpoint(live)?;
        if n == 0 {
            break;
        }
        if bytes.len().checked_add(n).is_none_or(|n| n > MAX_BYTES) {
            return Err(bad("record grew beyond bound"));
        }
        bytes.extend_from_slice(&buffer[..n]);
    }
    let after = file.metadata().map_err(io_error)?;
    let current = fs::symlink_metadata(path).map_err(io_error)?;
    if !regular(&after)
        || !regular(&current)
        || !unchanged(&selected, &after)
        || !unchanged(&after, &current)
        || bytes.len() as u64 != selected.len()
    {
        return Err(bad("record changed during read"));
    }
    checkpoint(live)?;
    Ok(bytes)
}

impl Inventory {
    pub(super) fn open(
        parent: &Path,
        scope: [u8; 32],
        binding: [u8; 32],
        maximum: usize,
        live: &dyn Fn() -> bool,
    ) -> Result<Self, WorkflowWatchError> {
        checkpoint(live)?;
        if !(1..=MAX_MEMBERS).contains(&maximum) {
            return Err(bad("member bound must be 1..64"));
        }
        let parent_meta = directory(parent)?;
        let root = parent.join(format!("pull-requests-{}", hex(&scope)));
        let exists = match fs::symlink_metadata(&root) {
            Ok(_) => true,
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(e) => return Err(io_error(e)),
        };
        if exists {
            directory(&root)?;
            let lock = fs::symlink_metadata(root.join("owner.lock")).map_err(io_error)?;
            if !regular(&lock) {
                return Err(bad("original collection owner is missing or invalid"));
            }
        }
        let owner = Owner::open(&root).map_err(|e| bad(e.to_string()))?;
        let root_meta = directory(&root)?;
        // Another owner may have created, initialized and released this scope
        // since the pre-lock observation. Its responsibility must be adopted,
        // never overwritten with an empty record selected before the lock.
        let loaded = load_locked(&root, exists, &scope, &binding, maximum, live)?;
        let initialize = loaded.is_none();
        let (entries, bytes) = loaded.unwrap_or_default();
        let mut inventory = Self {
            parent: parent.to_owned(),
            parent_meta,
            root,
            root_meta,
            owner,
            scope,
            binding,
            entries,
            bytes,
            maximum,
        };
        inventory.check_layout(live)?;
        if initialize {
            inventory.write(Vec::new(), live)?;
        }
        inventory.check(live)?;
        Ok(inventory)
    }
    pub(super) fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn check_layout(&self, live: &dyn Fn() -> bool) -> Result<(), WorkflowWatchError> {
        checkpoint(live)?;
        if !same(&directory(&self.parent)?, &self.parent_meta)
            || !same(&directory(&self.root)?, &self.root_meta)
        {
            return Err(bad("custody directory changed"));
        }
        let named = fs::symlink_metadata(self.root.join("owner.lock")).map_err(io_error)?;
        let held = self.owner.0.metadata().map_err(io_error)?;
        if !regular(&named) || !regular(&held) || !same(&named, &held) {
            return Err(bad("collection owner changed"));
        }
        let mut count = 0;
        for entry in fs::read_dir(&self.root).map_err(io_error)?.take(4) {
            checkpoint(live)?;
            let entry = entry.map_err(io_error)?;
            count += 1;
            if count > 3
                || !matches!(
                    entry.file_name().to_str(),
                    Some("owner.lock" | "inventory" | "inventory.next")
                )
            {
                return Err(bad("unknown collection custody entry"));
            }
            if !regular(&fs::symlink_metadata(entry.path()).map_err(io_error)?) {
                return Err(bad("invalid collection custody entry"));
            }
        }
        checkpoint(live)
    }
    pub(super) fn check(&self, live: &dyn Fn() -> bool) -> Result<(), WorkflowWatchError> {
        self.check_layout(live)?;
        if read(&self.root.join("inventory"), live)? != self.bytes {
            return Err(bad("durable membership changed"));
        }
        Ok(())
    }
    pub(super) fn replace(
        &mut self,
        entries: Vec<Entry>,
        live: &dyn Fn() -> bool,
    ) -> Result<(), WorkflowWatchError> {
        self.check(live)?;
        for previous in &self.entries {
            let Some(next) = entries.iter().find(|next| next.number == previous.number) else {
                return Err(bad("retained member cannot be removed"));
            };
            if previous.reference != next.reference || (previous.initialized && !next.initialized) {
                return Err(bad("member identity or initialization regressed"));
            }
        }
        if entries == self.entries {
            return Ok(());
        }
        self.write(entries, live)
    }
    fn write(
        &mut self,
        entries: Vec<Entry>,
        live: &dyn Fn() -> bool,
    ) -> Result<(), WorkflowWatchError> {
        let bytes = encode(&entries, &self.scope, &self.binding, self.maximum)?;
        self.check_layout(live)?;
        let staged = self.root.join("inventory.next");
        match fs::symlink_metadata(&staged) {
            Ok(meta) if regular(&meta) => fs::remove_file(&staged).map_err(io_error)?,
            Ok(_) => return Err(bad("invalid interrupted staging record")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_error(e)),
        }
        checkpoint(live)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(READ_FLAGS)
            .open(&staged)
            .map_err(io_error)?;
        for chunk in bytes.chunks(8192) {
            checkpoint(live)?;
            file.write_all(chunk).map_err(io_error)?;
        }
        file.sync_all().map_err(io_error)?;
        checkpoint(live)?;
        let named = fs::symlink_metadata(&staged).map_err(io_error)?;
        let held = file.metadata().map_err(io_error)?;
        if !regular(&named)
            || !regular(&held)
            || !same(&named, &held)
            || held.len() != bytes.len() as u64
        {
            return Err(bad("staging record changed"));
        }
        self.check_layout(live)?;
        fs::rename(&staged, self.root.join("inventory")).map_err(io_error)?;
        File::open(&self.root)
            .and_then(|file| file.sync_all())
            .map_err(io_error)?;
        checkpoint(live)?;
        self.entries = entries;
        self.bytes = bytes;
        self.check(live)
    }
}

fn load_locked(
    root: &Path,
    existed_before_lock: bool,
    scope: &[u8; 32],
    binding: &[u8; 32],
    maximum: usize,
    live: &dyn Fn() -> bool,
) -> Result<Option<(Vec<Entry>, Vec<u8>)>, WorkflowWatchError> {
    checkpoint(live)?;
    match fs::symlink_metadata(root.join("inventory")) {
        Ok(_) => {
            let bytes = read(&root.join("inventory"), live)?;
            let entries = decode(&bytes, scope, binding, maximum)?;
            Ok(Some((entries, bytes)))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            checkpoint(live)?;
            if existed_before_lock {
                Err(bad("original membership record is missing"))
            } else {
                Ok(None)
            }
        }
        Err(error) => Err(io_error(error)),
    }
}

fn encode(
    entries: &[Entry],
    scope: &[u8; 32],
    binding: &[u8; 32],
    maximum: usize,
) -> Result<Vec<u8>, WorkflowWatchError> {
    if entries.len() > maximum || entries.len() > MAX_MEMBERS {
        return Err(bad("retained member limit exceeded"));
    }
    let mut bytes = Vec::with_capacity(106 + entries.len() * 80);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(scope);
    bytes.extend_from_slice(binding);
    bytes.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    let mut previous = 0;
    for entry in entries {
        let name = entry.reference.as_bytes();
        if entry.number <= previous
            || name.len() > MAX_REFERENCE
            || !name.starts_with(b"refs/heads/")
        {
            return Err(bad("invalid member identity or ordering"));
        }
        previous = entry.number;
        bytes.extend_from_slice(&entry.number.to_be_bytes());
        bytes.push(u8::from(entry.initialized));
        bytes.extend_from_slice(&(name.len() as u16).to_be_bytes());
        bytes.extend_from_slice(name);
    }
    bytes.extend_from_slice(&sha256_digest(&bytes));
    Ok(bytes)
}
fn decode(
    bytes: &[u8],
    scope: &[u8; 32],
    binding: &[u8; 32],
    maximum: usize,
) -> Result<Vec<Entry>, WorkflowWatchError> {
    if bytes.len() < 106 || bytes.len() > MAX_BYTES {
        return Err(bad("invalid record length"));
    }
    let (body, checksum) = bytes.split_at(bytes.len() - 32);
    if sha256_digest(body) != checksum {
        return Err(bad("record checksum mismatch"));
    }
    if &body[..8] != MAGIC || &body[8..40] != scope || &body[40..72] != binding {
        return Err(bad("scope, publisher or execution configuration differs"));
    }
    let count = usize::from(u16::from_be_bytes([body[72], body[73]]));
    if count > maximum || count > MAX_MEMBERS {
        return Err(bad("retained member limit exceeded"));
    }
    let mut entries = Vec::with_capacity(count);
    let mut offset = 74;
    for _ in 0..count {
        let fixed = body
            .get(offset..offset + 11)
            .ok_or_else(|| bad("truncated member"))?;
        let number = u64::from_be_bytes(
            fixed[..8]
                .try_into()
                .map_err(|_| bad("invalid member number"))?,
        );
        let initialized = match fixed[8] {
            0 => false,
            1 => true,
            _ => return Err(bad("invalid initialization phase")),
        };
        let size = usize::from(u16::from_be_bytes([fixed[9], fixed[10]]));
        offset += 11;
        if size > MAX_REFERENCE {
            return Err(bad("reference limit exceeded"));
        }
        let name = body
            .get(offset..offset + size)
            .ok_or_else(|| bad("truncated reference"))?;
        offset += size;
        let reference = RefName::try_new(name).map_err(|_| bad("invalid member reference"))?;
        entries.push(Entry {
            number,
            reference,
            initialized,
        });
    }
    if offset != body.len() || encode(&entries, scope, binding, maximum)? != bytes {
        return Err(bad("noncanonical member record"));
    }
    Ok(entries)
}

#[cfg(test)]
mod tests;
