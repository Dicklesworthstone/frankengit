//! Optional, separately pinned LFS custody for the exact native source snapshot.
//! The existing FGSRC and FGLF formats stay independent; only their verified
//! source identity and complete native pointer inventory join them. Payload
//! custody never publishes repository authority.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub(super) use unix::{Companion, Inventory, export};

/// Complete companion evidence, returned only after actual retained bytes and
/// the exact native pointer selection have verified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Receipt {
    digest: [u8; 32],
    bytes: u64,
    objects: usize,
    payload_bytes: u64,
}
impl Receipt {
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }

    pub fn fields(self) -> String {
        format!(
            concat!(
                ",\"lfs_companion\":{{\"sha256\":\"{}\",\"bytes\":{},",
                "\"objects\":{},\"payload_bytes\":{},\"exact_snapshot\":true}}"
            ),
            super::super::hex(&self.digest),
            self.bytes,
            self.objects,
            self.payload_bytes,
        )
    }
}

// Keep source-only recovery portable. The optional custody lane uses the
// existing Unix artifact store and refuses explicitly on unsupported targets.
#[cfg(not(unix))]
mod unsupported {
    use super::super::archive::stream::{StreamHeader, TransferLimits};
    use super::super::input::PinnedArchive;
    use super::super::profile::Deadline;
    use super::Receipt;
    use std::fs::File;
    use std::io::{Read, Seek};
    use std::path::Path;

    const UNSUPPORTED: &str = "repository backup LFS custody requires a Unix host";

    pub enum Inventory {}
    impl Inventory {
        pub fn collect<R: Read + Seek>(
            _archive: &mut PinnedArchive<R>,
            _deadline: Deadline,
            _limits: TransferLimits,
        ) -> Result<Self, String> {
            Err(UNSUPPORTED.into())
        }
    }

    pub enum Companion {}
    impl Companion {
        pub fn open(
            _path: &Path,
            _expected: [u8; 32],
            _header: &StreamHeader,
            _inventory: &Inventory,
            _limits: TransferLimits,
            _deadline: Deadline,
        ) -> Result<Self, String> {
            Err(UNSUPPORTED.into())
        }

        pub fn install(&mut self, _root: &Path, _deadline: Deadline) -> Result<(), String> {
            Err(UNSUPPORTED.into())
        }

        pub fn verify_stored(&mut self, _root: &Path, _deadline: Deadline) -> Result<(), String> {
            Err(UNSUPPORTED.into())
        }

        pub fn verify_archive(&mut self, _deadline: Deadline) -> Result<(), String> {
            Err(UNSUPPORTED.into())
        }

        pub fn receipt(&self) -> Receipt {
            match *self {}
        }
    }

    pub fn export(
        _root: &Path,
        _header: &StreamHeader,
        _inventory: &Inventory,
        _file: &mut File,
        _limits: TransferLimits,
        _deadline: Deadline,
    ) -> Result<Receipt, String> {
        Err(UNSUPPORTED.into())
    }
}
#[cfg(not(unix))]
pub(super) use unsupported::{Companion, Inventory, export};
