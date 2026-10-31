//! Private disk custody for one selected pack (frankengit-8xyq).
//!
//! A selected pack used to be planned and written whole in memory, so every
//! clone held the complete pack and its object bodies, and the upload
//! envelope had to bound them. The streamed writer emits into this sink
//! instead: one exclusive file under the node's storage root, unlinked on Unix
//! as soon as it exists, written through a bounded buffer and read back in
//! bounded chunks. It is scratch, not storage: never synced, never published,
//! and gone when the payload is dropped.
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fgit_pack::{PackArtifactSink, PackWriteError};

/// Pending emitter bytes are flushed to the file in writes of this size.
const SPOOL_BUFFER_BYTES: usize = 256 * 1024;

/// One exclusive scratch file, removed by name on drop while still linked.
#[derive(Debug)]
struct ScratchFile {
    file: File,
    path: PathBuf,
    linked: bool,
}

impl ScratchFile {
    fn create(root: &Path) -> io::Result<Self> {
        for _ in 0..8 {
            let path = root.join(format!(
                ".fg-pack-spool-{:032x}",
                std::random::random::<u128>(..)
            ));
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let file = match options.open(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            };
            #[allow(unused_mut)]
            let mut scratch = Self {
                file,
                path,
                linked: true,
            };
            // On Unix the name goes now: cancellation, panic or process death
            // cannot leave a named pack behind. Elsewhere drop removes it.
            #[cfg(unix)]
            {
                fs::remove_file(&scratch.path)?;
                scratch.linked = false;
            }
            return Ok(scratch);
        }
        Err(io::Error::from(io::ErrorKind::AlreadyExists))
    }
}

impl Drop for ScratchFile {
    fn drop(&mut self) {
        if self.linked {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// A pack being written: the scratch file and its unflushed tail.
#[derive(Debug)]
pub struct SpoolTemporary {
    scratch: Option<ScratchFile>,
    pending: Vec<u8>,
    len: u64,
}

impl SpoolTemporary {
    fn flush(&mut self) -> io::Result<()> {
        let scratch = self
            .scratch
            .as_mut()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        scratch.file.write_all(&self.pending)?;
        self.pending.clear();
        Ok(())
    }
}

/// The streamed writer's sink. A promoted pack becomes a [`SpooledPack`].
pub struct PackSpool<'root> {
    root: &'root Path,
    promoted: Option<SpooledPack>,
}

impl<'root> PackSpool<'root> {
    pub(crate) const fn new(root: &'root Path) -> Self {
        Self {
            root,
            promoted: None,
        }
    }

    /// The completed pack, present only after the writer promoted it.
    pub(crate) fn into_promoted(self) -> Option<SpooledPack> {
        self.promoted
    }
}

impl PackArtifactSink for PackSpool<'_> {
    type Temporary = SpoolTemporary;

    fn create_temporary(&mut self) -> Result<Self::Temporary, PackWriteError> {
        let scratch =
            ScratchFile::create(self.root).map_err(|_| PackWriteError::TemporaryArtifactRefused)?;
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(SPOOL_BUFFER_BYTES)
            .map_err(|_| PackWriteError::TemporaryArtifactRefused)?;
        Ok(SpoolTemporary {
            scratch: Some(scratch),
            pending,
            len: 0,
        })
    }

    fn write_temporary(
        &mut self,
        temporary: &mut Self::Temporary,
        bytes: &[u8],
    ) -> Result<(), PackWriteError> {
        temporary.len = temporary
            .len
            .checked_add(bytes.len() as u64)
            .ok_or(PackWriteError::TemporaryWriteRefused)?;
        if temporary.pending.len() + bytes.len() > SPOOL_BUFFER_BYTES {
            temporary
                .flush()
                .map_err(|_| PackWriteError::TemporaryWriteRefused)?;
        }
        if bytes.len() > SPOOL_BUFFER_BYTES {
            let scratch = temporary
                .scratch
                .as_mut()
                .ok_or(PackWriteError::TemporaryWriteRefused)?;
            return scratch
                .file
                .write_all(bytes)
                .map_err(|_| PackWriteError::TemporaryWriteRefused);
        }
        temporary.pending.extend_from_slice(bytes);
        Ok(())
    }

    fn promote_temporary(&mut self, temporary: &mut Self::Temporary) -> Result<(), PackWriteError> {
        temporary
            .flush()
            .map_err(|_| PackWriteError::PromotionRefused)?;
        let mut scratch = temporary
            .scratch
            .take()
            .ok_or(PackWriteError::PromotionRefused)?;
        scratch
            .file
            .flush()
            .map_err(|_| PackWriteError::PromotionRefused)?;
        self.promoted = Some(SpooledPack {
            scratch,
            len: temporary.len,
            offset: 0,
        });
        Ok(())
    }

    fn abort_temporary(&mut self, temporary: Self::Temporary) {
        drop(temporary);
    }
}

/// A complete pack in scratch custody, read back in bounded chunks.
#[derive(Debug)]
pub struct SpooledPack {
    scratch: ScratchFile,
    len: u64,
    offset: u64,
}

impl SpooledPack {
    /// The next at most `maximum` bytes, or `None` after the trailer.
    pub(crate) fn next_chunk(&mut self, maximum: usize) -> io::Result<Option<Vec<u8>>> {
        if self.offset == self.len {
            return Ok(None);
        }
        let remaining = self.len - self.offset;
        let length = usize::try_from(remaining.min(maximum as u64))
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let mut chunk = Vec::new();
        chunk
            .try_reserve_exact(length)
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        chunk.resize(length, 0);
        self.scratch.file.seek(SeekFrom::Start(self.offset))?;
        self.scratch.file.read_exact(&mut chunk)?;
        self.offset += length as u64;
        Ok(Some(chunk))
    }

    /// The whole pack, for a caller that publishes it as one file.
    pub(crate) fn into_bytes(mut self) -> io::Result<Vec<u8>> {
        let length =
            usize::try_from(self.len).map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        bytes.resize(length, 0);
        self.scratch.file.seek(SeekFrom::Start(0))?;
        self.scratch.file.read_exact(&mut bytes)?;
        Ok(bytes)
    }
}

/// Resolved objects a receive keeps out of memory (frankengit-88fk): its
/// delta resolver's cache past a resident budget, and verified blob bodies
/// until they are staged. Scratch like a spooled pack: one exclusive file
/// under the storage root, unlinked on Unix as soon as it exists, created on
/// the first append, appended to and read back by handle, and gone on drop.
#[derive(Debug)]
pub struct ObjectSpool {
    root: PathBuf,
    scratch: Option<ScratchFile>,
    len: u64,
}

impl ObjectSpool {
    pub(crate) fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            scratch: None,
            len: 0,
        }
    }

    /// Appends `bytes` and returns where they live.
    pub(crate) fn append(&mut self, bytes: &[u8]) -> io::Result<fgit_pack::SpillHandle> {
        if self.scratch.is_none() {
            self.scratch = Some(ScratchFile::create(&self.root)?);
        }
        let scratch = self
            .scratch
            .as_mut()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        let offset = self.len;
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        scratch.file.seek(SeekFrom::Start(offset))?;
        scratch.file.write_all(bytes)?;
        self.len = end;
        Ok(fgit_pack::SpillHandle {
            offset,
            length: bytes.len(),
        })
    }

    /// Exactly the bytes [`Self::append`] wrote for `handle`.
    pub(crate) fn read(&mut self, handle: fgit_pack::SpillHandle) -> io::Result<Vec<u8>> {
        let scratch = self
            .scratch
            .as_mut()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(handle.length)
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        bytes.resize(handle.length, 0);
        scratch.file.seek(SeekFrom::Start(handle.offset))?;
        scratch.file.read_exact(&mut bytes)?;
        Ok(bytes)
    }
}

impl fgit_pack::CacheSpill for ObjectSpool {
    fn spill(&mut self, bytes: &[u8]) -> Result<fgit_pack::SpillHandle, fgit_pack::PackError> {
        self.append(bytes)
            .map_err(|_| fgit_pack::PackError::AllocationFailed {
                requested: bytes.len(),
            })
    }

    fn read(&mut self, handle: fgit_pack::SpillHandle) -> Result<Vec<u8>, fgit_pack::PackError> {
        Self::read(self, handle).map_err(|_| fgit_pack::PackError::AllocationFailed {
            requested: handle.length,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Root(PathBuf);
    impl Root {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "fg-pack-spool-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn names(&self) -> usize {
            fs::read_dir(&self.0).unwrap().count()
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Bytes written in pieces either side of the buffer size read back exactly,
    /// in bounded chunks and whole, and no name is left behind on Unix.
    #[test]
    fn a_spooled_pack_reads_back_exactly_and_leaves_no_name() {
        let root = Root::new();
        let mut spool = PackSpool::new(&root.0);
        let mut temporary = spool.create_temporary().unwrap();
        let mut expected = Vec::new();
        for (index, size) in [
            1_usize,
            7,
            SPOOL_BUFFER_BYTES,
            3 * SPOOL_BUFFER_BYTES + 5,
            13,
        ]
        .into_iter()
        .enumerate()
        {
            let piece: Vec<u8> = (0..size).map(|at| (at * 31 + index) as u8).collect();
            spool.write_temporary(&mut temporary, &piece).unwrap();
            expected.extend_from_slice(&piece);
        }
        if cfg!(unix) {
            assert_eq!(root.names(), 0, "the scratch name is unlinked at once");
        }
        spool.promote_temporary(&mut temporary).unwrap();
        spool.abort_temporary(temporary);
        let mut pack = spool.into_promoted().unwrap();
        let mut read = Vec::new();
        while let Some(chunk) = pack.next_chunk(65_520).unwrap() {
            assert!(chunk.len() <= 65_520);
            read.extend_from_slice(&chunk);
        }
        assert_eq!(read, expected);
        assert_eq!(pack.into_bytes().unwrap(), expected);
        assert_eq!(root.names(), 0);
    }

    /// An object spool creates no file until its first append, reads every
    /// handle back exactly in any order, and leaves no name behind on Unix
    /// (frankengit-88fk).
    #[test]
    fn an_object_spool_reads_each_handle_back_exactly_and_leaves_no_name() {
        let root = Root::new();
        let mut spool = ObjectSpool::new(&root.0);
        assert_eq!(root.names(), 0, "an unused spool creates nothing");
        let pieces: Vec<Vec<u8>> = [0_usize, 1, 4096, 3 * SPOOL_BUFFER_BYTES + 7, 13]
            .into_iter()
            .enumerate()
            .map(|(index, size)| (0..size).map(|at| (at * 17 + index) as u8).collect())
            .collect();
        let handles: Vec<_> = pieces
            .iter()
            .map(|piece| spool.append(piece).unwrap())
            .collect();
        if cfg!(unix) {
            assert_eq!(root.names(), 0, "the scratch name is unlinked at once");
        }
        for (handle, piece) in handles.iter().zip(&pieces).rev() {
            assert_eq!(&spool.read(*handle).unwrap(), piece);
        }
        // Reads move the file position; a later append still lands at the end.
        let late = spool.append(b"after reads").unwrap();
        assert_eq!(spool.read(late).unwrap(), b"after reads");
        assert_eq!(spool.read(handles[3]).unwrap(), pieces[3]);
        drop(spool);
        assert_eq!(root.names(), 0);
    }

    /// An aborted pack is never promoted and leaves nothing behind.
    #[test]
    fn an_aborted_spool_promotes_nothing() {
        let root = Root::new();
        let mut spool = PackSpool::new(&root.0);
        let mut temporary = spool.create_temporary().unwrap();
        spool.write_temporary(&mut temporary, b"partial").unwrap();
        spool.abort_temporary(temporary);
        assert!(spool.into_promoted().is_none());
        assert_eq!(root.names(), 0);
    }
}
