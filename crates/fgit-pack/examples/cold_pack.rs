#![forbid(unsafe_code)]

//! Reproducible cold pack-writer workload for frankengit-1tl9.
//!
//! Runs the public streamed writer, including native identity verification,
//! delta selection, compression and trailer hashing, without a computation
//! cache. Source generation is outside the measured interval. This measures
//! pack construction in memory, not network clone or object-store latency.
//!
//! Usage: `cold_pack <similar|shifted|unrelated|text> <blob-bytes> <count> <samples>`.
//! Build the same example at the baseline and candidate revisions, alternate
//! their runs with an A/A control, and compare every output checksum/receipt.
//! Remove this workload when a real-repository clone lane covers these input
//! shapes with cold-cache timing and exact pack-byte comparison.

use std::collections::BTreeMap;
use std::error::Error;
use std::time::Instant;

use fgit_git_object::{ObjectType, Sha1, native_object_oid};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, DeterministicPackEncoder, ObjectFormat, ObjectId,
    PackArtifactSink, PackLimits, PackOrderKey, PackPlanner, PackWriteError, PackWriteProfile,
    PackWriter,
};

struct Source(BTreeMap<ObjectId, Vec<u8>>);

impl CanonicalObjectSource for Source {
    fn load(&self, id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
        let body = self
            .0
            .get(id)
            .ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        Ok(CanonicalPackObject::new(
            *id,
            ObjectType::Blob,
            body.clone(),
            Vec::new(),
            0,
            0,
        ))
    }
}

#[derive(Default)]
struct Sink {
    promoted: Option<Vec<u8>>,
}

impl PackArtifactSink for Sink {
    type Temporary = Vec<u8>;

    fn create_temporary(&mut self) -> Result<Self::Temporary, PackWriteError> {
        Ok(Vec::new())
    }

    fn write_temporary(
        &mut self,
        temporary: &mut Self::Temporary,
        bytes: &[u8],
    ) -> Result<(), PackWriteError> {
        temporary.extend_from_slice(bytes);
        Ok(())
    }

    fn promote_temporary(&mut self, temporary: &mut Self::Temporary) -> Result<(), PackWriteError> {
        self.promoted = Some(std::mem::take(temporary));
        Ok(())
    }

    fn abort_temporary(&mut self, _temporary: Self::Temporary) {}
}

fn noise(length: usize, mut state: u64) -> Vec<u8> {
    (0..length)
        .map(|_| {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            (state.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8
        })
        .collect()
}

fn corpus(shape: &str, bytes: usize, count: usize) -> Result<Source, Box<dyn Error>> {
    let seed = 0x0932_6a4f_817c_e5bd;
    let base = noise(bytes, seed);
    let mut objects = BTreeMap::new();
    for version in 0..count {
        let mut body = match shape {
            "similar" => base.clone(),
            "shifted" => {
                let shift = version * 17;
                let mut body = vec![b'#'; shift];
                body.extend_from_slice(&base[..bytes - shift]);
                body
            }
            "unrelated" => noise(bytes, seed ^ (version as u64 + 1)),
            "text" => {
                let row = b"{\"id\":\"record-0001\",\"state\":\"open\",\"description\":\"bounded deterministic repository history\"}\n";
                row.iter().copied().cycle().take(bytes).collect()
            }
            _ => return Err("shape must be similar, shifted, unrelated or text".into()),
        };
        if shape == "similar" || shape == "text" {
            let at = bytes / 2 + version * 19;
            body[at..at + 8].copy_from_slice(&(version as u64).to_le_bytes());
        }
        let id = ObjectId::from(native_object_oid::<Sha1>(ObjectType::Blob, &body));
        if objects.insert(id, body).is_some() {
            return Err("corpus accidentally contains a duplicate native object".into());
        }
    }
    Ok(Source(objects))
}

fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<_> = std::env::args().collect();
    if arguments.len() != 5 {
        return Err(
            "usage: cold_pack <similar|shifted|unrelated|text> <blob-bytes> <count> <samples>"
                .into(),
        );
    }
    let shape = &arguments[1];
    let bytes: usize = arguments[2].parse()?;
    let count: usize = arguments[3].parse()?;
    let samples: usize = arguments[4].parse()?;
    if !(4096..=32 * 1024 * 1024).contains(&bytes)
        || !(2..=32).contains(&count)
        || !(1..=100).contains(&samples)
        || bytes * count > 256 * 1024 * 1024
    {
        return Err(
            "bounds: 4 KiB..32 MiB per blob, 2..32 blobs, <=256 MiB total, 1..100 samples".into(),
        );
    }
    let source = corpus(shape, bytes, count)?;
    let selected: Vec<_> = source
        .0
        .keys()
        .map(|id| PackOrderKey {
            id: *id,
            object_type: ObjectType::Blob,
            recency: 0,
            path_hash: 0,
        })
        .collect();
    let limits = PackLimits {
        max_input_bytes: bytes * count * 2,
        max_total_expanded_bytes: bytes * count,
        ..PackLimits::default()
    };
    let profile = PackWriteProfile::COMPRESSED_V5;
    let planner = PackPlanner::new(ObjectFormat::Sha1, profile, limits.clone());
    let writer = PackWriter::new(limits);
    let mut expected = None;
    for sample in 0..samples {
        let mut sink = Sink::default();
        let mut encoder = DeterministicPackEncoder::for_profile(profile);
        let start = Instant::now();
        let receipt = planner.stream_selected_thin(
            &source,
            &selected,
            &[],
            &writer,
            &mut encoder,
            &mut sink,
            &mut || true,
        )?;
        let elapsed = start.elapsed();
        let pack = sink.promoted.ok_or("writer omitted promotion")?;
        if let Some((expected_receipt, expected_pack)) = &expected
            && (expected_receipt != &receipt || expected_pack != &pack)
        {
            return Err("identical cold computations emitted different bytes or receipts".into());
        }
        let checksum: String = receipt
            .checksum
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        println!(
            "{{\"shape\":\"{shape}\",\"blob_bytes\":{bytes},\"objects\":{count},\"sample\":{sample},\"elapsed_ns\":{},\"pack_bytes\":{},\"deltas\":{},\"checksum\":\"{checksum}\",\"profile\":\"{}\",\"cache\":\"disabled\"}}",
            elapsed.as_nanos(),
            receipt.output_bytes,
            receipt.delta_count,
            profile.id,
        );
        expected = Some((receipt, pack));
    }
    Ok(())
}
