#![forbid(unsafe_code)]
//! Operator-owned progress, NOT repository authority. Pure std so its actual
//! codec, transition rules and file boundary have a standalone test lane.
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub const MAX_REFS: usize = 32;
pub const MAX_STATE_BYTES: usize = 64 * 1024;
const MAGIC: &str = "frankengit-index-worker-v1";

fn invalid(message: &'static str) -> io::Error { io::Error::new(io::ErrorKind::InvalidData, message) }
pub fn hex(bytes: &[u8]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }
pub fn unhex(text: &str, maximum: usize) -> io::Result<Vec<u8>> {
    if text.is_empty() || text.len() % 2 != 0 || text.len() > maximum * 2
        || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    { return Err(invalid("invalid bounded lowercase hex")); }
    let digit = |b| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    Ok(text.as_bytes().chunks_exact(2).map(|p| digit(p[0]) * 16 + digit(p[1])).collect())
}
pub fn decimal(text: &str, maximum: u64) -> io::Result<u64> {
    if text.is_empty() || text.len() > 20 || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0')) { return Err(invalid("invalid decimal")); }
    text.parse::<u64>().ok().filter(|n| *n <= maximum).ok_or_else(|| invalid("decimal exceeds limit"))
}
fn digest(text: &str) -> io::Result<[u8; 32]> {
    let value: [u8; 32] = unhex(text, 32)?.try_into().map_err(|_| invalid("invalid digest width"))?;
    if value == [0; 32] { return Err(invalid("zero generation digest")); }
    Ok(value)
}

/// v1 carries the registered SHA-256 generation digest at codec v1, not a Git ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pin { pub digest: [u8; 32], pub number: u64 }
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Row {
    pub floor: Option<Pin>,
    pub pending: Option<[u8; 32]>,
    /// Durable write-ahead marker. A crash before a candidate was recorded
    /// requires operator investigation, not an automatic reset/retry.
    pub running: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct State { binding: String, pub rows: BTreeMap<Vec<u8>, Row> }
impl State {
    pub fn new(binding: String, refs: &[Vec<u8>]) -> io::Result<Self> {
        if binding.is_empty() || binding.len() > 256 || !binding.bytes().all(|b| b.is_ascii_alphanumeric() || b == b' ')
            || refs.is_empty() || refs.len() > MAX_REFS || refs.iter().map(Vec::len).sum::<usize>() > 16 * 1024
        { return Err(invalid("invalid maintenance binding or scope")); }
        let mut rows = BTreeMap::new();
        for reference in refs {
            if reference.is_empty() || reference.len() > 1024 || rows.insert(reference.clone(), Row::default()).is_some() {
                return Err(invalid("invalid or duplicate reference"));
            }
        }
        Ok(Self { binding, rows })
    }
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let mut out = format!("{MAGIC} {}\n", self.binding);
        for (reference, row) in &self.rows {
            if row.running && row.pending.is_some() { return Err(invalid("contradictory attempt state")); }
            let (floor, number) = row.floor.as_ref().map_or(("-".to_owned(), 0), |p| (hex(&p.digest), p.number));
            if row.floor.as_ref().is_some_and(|p| p.number == 0 || p.digest == [0; 32]) || row.pending == Some([0; 32]) {
                return Err(invalid("invalid progress generation"));
            }
            let pending = row.pending.as_ref().map_or_else(|| "-".to_owned(), |d| hex(d));
            out.push_str(&format!("{} {floor} {number} {pending} {}\n", hex(reference), u8::from(row.running)));
            if out.len() > MAX_STATE_BYTES { return Err(invalid("progress size limit")); }
        }
        Ok(out.into_bytes())
    }
    pub fn decode(bytes: &[u8], expected: &Self) -> io::Result<Self> {
        if bytes.len() > MAX_STATE_BYTES { return Err(invalid("progress size limit")); }
        let text = std::str::from_utf8(bytes).map_err(|_| invalid("progress is not UTF-8"))?;
        let mut lines = text.lines();
        if lines.next() != Some(format!("{MAGIC} {}", expected.binding).as_str()) { return Err(invalid("progress namespace mismatch")); }
        let mut result = expected.clone();
        let mut seen = BTreeMap::new();
        for line in lines {
            let fields: Vec<_> = line.split(' ').collect();
            if fields.len() != 5 { return Err(invalid("invalid progress row")); }
            let reference = unhex(fields[0], 1024)?;
            let number = decimal(fields[2], u64::MAX)?;
            let floor = match (fields[1], number) {
                ("-", 0) => None,
                ("-", _) | (_, 0) => return Err(invalid("incomplete checkpoint")),
                (value, number) => Some(Pin { digest: digest(value)?, number }),
            };
            let pending = if fields[3] == "-" { None } else { Some(digest(fields[3])?) };
            let running = match fields[4] { "0" => false, "1" => true, _ => return Err(invalid("invalid attempt marker")) };
            if !result.rows.contains_key(&reference) || seen.insert(reference.clone(), ()).is_some() {
                return Err(invalid("progress reference set mismatch"));
            }
            result.rows.insert(reference, Row { floor, pending, running });
        }
        if seen.len() != result.rows.len() || result.encode()? != bytes { return Err(invalid("noncanonical or incomplete progress")); }
        Ok(result)
    }
    fn row(&mut self, reference: &[u8]) -> io::Result<&mut Row> {
        self.rows.get_mut(reference).ok_or_else(|| invalid("unconfigured reference"))
    }
    pub fn begin(&mut self, reference: &[u8]) -> io::Result<()> {
        let row = self.row(reference)?;
        if row.running || row.pending.is_some() { return Err(invalid("unresolved previous attempt")); }
        row.running = true; Ok(())
    }
    pub fn refuse(&mut self, reference: &[u8]) -> io::Result<()> {
        let row = self.row(reference)?;
        if !row.running || row.pending.is_some() { return Err(invalid("no running attempt to refuse")); }
        row.running = false; Ok(())
    }
    pub fn uncertain(&mut self, reference: &[u8], candidate: [u8; 32]) -> io::Result<()> {
        let row = self.row(reference)?;
        if !row.running || row.pending.is_some() || candidate == [0; 32] { return Err(invalid("invalid pending transition")); }
        row.running = false; row.pending = Some(candidate); Ok(())
    }
    pub fn acknowledge(&mut self, reference: &[u8], pin: Pin, recovered: Option<[u8; 32]>) -> io::Result<()> {
        let row = self.row(reference)?;
        let allowed = match recovered { None => row.running && row.pending.is_none(), Some(id) => !row.running && row.pending == Some(id) };
        if !allowed || pin.number == 0 || pin.digest == [0; 32] || row.floor.as_ref().is_some_and(|old|
            pin.number < old.number || (pin.number == old.number && pin.digest != old.digest))
        { return Err(invalid("checkpoint regression or unresolved attempt")); }
        row.floor = Some(pin); row.pending = None; row.running = false; Ok(())
    }
}

/// Exclusive operator progress ownership, not a lock on Git refs or authority.
/// No Drop cleanup: abnormal exit leaves run.lock so restart cannot erase an
/// unknown in-flight operation. Release follows explicit native-node shutdown.
pub struct ProgressFile { directory: PathBuf, _lock: File, pub state: State }
impl ProgressFile {
    pub fn open(directory: &Path, initialize: bool, expected: State) -> io::Result<Self> {
        let metadata = fs::symlink_metadata(directory)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() { return Err(invalid("progress directory must be a real directory")); }
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 { return Err(invalid("progress directory must be private (0700)")); }
        }
        if !cfg!(unix) { return Err(io::Error::new(io::ErrorKind::Unsupported, "durable maintenance progress requires the Unix profile")); }
        let lock = private_new(&directory.join("run.lock"))?;
        let mut result = Self { directory: directory.to_path_buf(), _lock: lock, state: expected };
        let load = (|| {
            let path = directory.join("checkpoint");
            if initialize {
                match fs::symlink_metadata(&path) {
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {},
                    Err(e) => return Err(e),
                    Ok(_) => return Err(io::Error::new(io::ErrorKind::AlreadyExists, "checkpoint exists; use resume")),
                }
                result.save()?;
            } else {
                let metadata = fs::symlink_metadata(&path)?;
                if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_STATE_BYTES as u64 {
                    return Err(invalid("invalid checkpoint file"));
                }
                let mut bytes = Vec::new();
                File::open(&path)?.take(MAX_STATE_BYTES as u64 + 1).read_to_end(&mut bytes)?;
                result.state = State::decode(&bytes, &result.state)?;
            }
            // Never automatically overwrite a leftover interrupted replacement.
            match fs::symlink_metadata(directory.join("checkpoint.next")) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e),
                Ok(_) => Err(invalid("interrupted checkpoint replacement requires inspection")),
            }
        })();
        if let Err(error) = load {
            // No native operation has started. Leave suspect checkpoint bytes
            // intact, but do not strand our newly acquired local ownership.
            drop(result._lock);
            let _ = fs::remove_file(directory.join("run.lock"));
            return Err(error);
        }
        Ok(result)
    }
    pub fn save(&self) -> io::Result<()> {
        let bytes = self.state.encode()?;
        let next = self.directory.join("checkpoint.next");
        let mut file = private_new(&next)?;
        file.write_all(&bytes)?; file.sync_all()?; drop(file);
        fs::rename(&next, self.directory.join("checkpoint"))?;
        File::open(&self.directory)?.sync_all()
    }
    pub fn release(self) -> io::Result<()> {
        drop(self._lock);
        fs::remove_file(self.directory.join("run.lock"))?;
        File::open(self.directory)?.sync_all()
    }
}
fn private_new(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new(); options.write(true).create_new(true);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
    options.open(path)
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod tests;
