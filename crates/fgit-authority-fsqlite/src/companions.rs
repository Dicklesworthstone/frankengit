//! Closed file-backed authority image used by all-heads restore with fsqlite 0.4.10.
//! Only the dedicated private restore directory has this fixed database name.

use std::{fs, io, path::Path};

/// Database linked last, after the complete closed WAL set has reached its destination.
pub const DATABASE: &str = "authority.fsqlite";
/// Primary SQLite write-ahead log.
pub const WAL: &str = "authority.fsqlite-wal";
/// A nonempty rollback journal prevents publication.
pub const JOURNAL: &str = "authority.fsqlite-journal";
/// SQLite shared-memory index, recreated at the destination.
pub const SHM: &str = "authority.fsqlite-shm";
/// Recovery files that travel with the database, in publication order.
pub const WAL_SET: [&str; 2] = [WAL, "authority.fsqlite-wal-fec"];
/// Namespace, locking and certificate records bound to the staging path.
/// Keep them there until the final image has been independently reopened and closed.
pub const LOCAL_STATE: [&str; 10] = [
    "authority.fsqlite-fsqlite-ns-gate",
    "authority.fsqlite-fsqlite-ns-use",
    "authority.fsqlite.fsqlite-migration-state",
    "authority.fsqlite-lock-shared",
    "authority.fsqlite-lock-reserved",
    "authority.fsqlite-lock-pending",
    "authority.fsqlite-wal-cert",
    "authority.fsqlite-wal-cert-head",
    "authority.fsqlite-wal-fec.lock",
    "authority.fsqlite.fsqlite-shm",
];

/// Every admitted filename in the closed image. Individual companions are optional.
pub fn image_files() -> impl Iterator<Item = &'static str> {
    [DATABASE, JOURNAL, SHM]
        .into_iter()
        .chain(WAL_SET)
        .chain(LOCAL_STATE)
}

/// Inspect all entries before moving or unlinking any part of a private restore image.
/// The caller owns custody of this directory and has closed its database connections.
///
/// # Errors
/// Returns an error on a filesystem fault, an unfamiliar name or a non-regular entry.
pub fn validate_closed_image(directory: &Path) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        if !image_files().any(|known| name == known) || !entry.file_type()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unrecognized authority image entry or file type: {name:?}"),
            ));
        }
    }
    Ok(())
}
