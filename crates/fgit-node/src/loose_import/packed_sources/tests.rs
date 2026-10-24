use super::*;
use fgit_crypto::{git_object_id, sha1_digest, sha256_digest};
use fgit_git_object::ObjectType;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-packed-custody-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("source/objects/pack")).unwrap();
        fs::create_dir(root.join("custody")).unwrap();
        Self(root)
    }
    fn sources(
        &self,
        format: GitHashAlgorithm,
        maximum: u64,
        control: &ImportControl<'_>,
    ) -> PackedObjectSources {
        PackedObjectSources::open_with_profile(
            &self.0.join("source"),
            format,
            1024 * 1024,
            &self.0.join("custody"),
            maximum,
            control,
        )
        .unwrap()
    }
    fn cleaned(&self) {
        assert!(
            fs::read_dir(self.0.join("custody"))
                .unwrap()
                .next()
                .is_none()
        );
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn digest(format: GitHashAlgorithm, data: &[u8]) -> Vec<u8> {
    match format {
        GitHashAlgorithm::Sha1 => sha1_digest(data).to_vec(),
        GitHashAlgorithm::Sha256 => sha256_digest(data).to_vec(),
    }
}
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}
fn stored(bytes: &[u8]) -> Vec<u8> {
    let size = u16::try_from(bytes.len()).unwrap();
    let mut out = vec![0x78, 0x01, 0x01];
    out.extend(size.to_le_bytes());
    out.extend((!size).to_le_bytes());
    out.extend(bytes);
    let (mut a, mut b) = (1_u32, 0_u32);
    for &byte in bytes {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    out.extend(((b << 16) | a).to_be_bytes());
    out
}
fn pack(
    scratch: &Scratch,
    format: GitHashAlgorithm,
    name: &str,
    bodies: &[Vec<u8>],
) -> Vec<GitOid> {
    let objects: BTreeMap<_, _> = bodies
        .iter()
        .map(|body| (git_object_id(format, ObjectType::Blob, body), body))
        .collect();
    let mut pack = b"PACK\0\0\0\x02".to_vec();
    pack.extend((objects.len() as u32).to_be_bytes());
    let mut entries = Vec::new();
    for (id, body) in &objects {
        let offset = pack.len();
        let mut size = body.len();
        let mut byte = 0x30 | (size as u8 & 15);
        size >>= 4;
        while size != 0 {
            pack.push(byte | 128);
            byte = size as u8 & 127;
            size >>= 7;
        }
        pack.push(byte);
        pack.extend(stored(body));
        entries.push((*id, crc32(&pack[offset..]), offset as u32));
    }
    let hash = digest(format, &pack);
    pack.extend(&hash);
    let mut idx = b"\xfftOc\0\0\0\x02".to_vec();
    for byte in 0_u16..256 {
        idx.extend(
            (entries
                .iter()
                .filter(|(id, _, _)| u16::from(id.as_bytes()[0]) <= byte)
                .count() as u32)
                .to_be_bytes(),
        );
    }
    for (id, _, _) in &entries {
        idx.extend(id.as_bytes());
    }
    for (_, crc, _) in &entries {
        idx.extend(crc.to_be_bytes());
    }
    for (_, _, offset) in &entries {
        idx.extend(offset.to_be_bytes());
    }
    idx.extend(hash);
    let hash = digest(format, &idx);
    idx.extend(hash);
    fs::write(
        scratch.0.join(format!("source/objects/pack/{name}.pack")),
        pack,
    )
    .unwrap();
    fs::write(
        scratch.0.join(format!("source/objects/pack/{name}.idx")),
        idx,
    )
    .unwrap();
    objects.keys().copied().collect()
}
#[test]
fn multiple_packs_reuse_exact_disk_custody_after_sources_are_removed() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let mut live = || true;
        let control = ImportControl::new(&mut live);
        let mut expected = BTreeMap::new();
        for ordinal in 0..3 {
            let body = vec![ordinal as u8; 10003];
            let id = pack(
                &scratch,
                format,
                &format!("part-{ordinal}"),
                &[body.clone()],
            )[0];
            expected.insert(id, body);
        }
        let mut sources = scratch.sources(format, 30009, &control);
        for (id, body) in &expected {
            assert_eq!(
                sources.read(*id, &control).unwrap().unwrap().body(),
                body.as_slice()
            );
        }
        assert_eq!(sources.loaded_resolved_bytes, 30009);
        assert_eq!(sources.loaded_objects, 3);
        assert!(std::mem::size_of::<spool::Entry>() <= 32);
        fs::remove_dir_all(scratch.0.join("source")).unwrap();
        for (id, body) in expected.into_iter().rev() {
            assert_eq!(
                sources.read(id, &control).unwrap().unwrap().into_body(),
                body
            );
        }
        assert_eq!(sources.loaded_resolved_bytes, 30009);
        sources.finish().unwrap();
        scratch.cleaned();
    }
}
#[test]
fn aggregate_budget_counts_all_pack_members_and_accepts_the_exact_boundary() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let mut live = || true;
        let control = ImportControl::new(&mut live);
        let a = pack(&scratch, format, "a", &[vec![1; 100]])[0];
        let b = pack(&scratch, format, "b", &[vec![2; 100], vec![3; 100]])[0];
        for maximum in [299, 300] {
            let mut sources = scratch.sources(format, maximum, &control);
            assert!(sources.read(a, &control).unwrap().is_some());
            let result = sources.read(b, &control);
            if maximum == 299 {
                assert!(matches!(
                    result,
                    Err(LooseGitImportRefusal::TotalObjectBytesExceeded {
                        limit: 299,
                        observed: 300
                    })
                ));
                assert!(sources.sources[1].verified_objects.is_none());
                assert_eq!(sources.loaded_objects, 1);
            } else {
                assert!(result.unwrap().is_some());
                assert_eq!(sources.loaded_resolved_bytes, 300);
            }
            sources.finish().unwrap();
            scratch.cleaned();
        }
    }
}
#[test]
fn larger_total_profiles_do_not_weaken_per_pack_decoder_bounds() {
    let scratch = Scratch::new();
    let mut live = || true;
    let control = ImportControl::new(&mut live);
    let id = pack(
        &scratch,
        GitHashAlgorithm::Sha256,
        "bounded",
        &[vec![1; 100]],
    )[0];
    for limit in [99, 100] {
        let mut sources = scratch.sources(GitHashAlgorithm::Sha256, 4096, &control);
        sources.limits.max_total_expanded_bytes = limit;
        let result = sources.read(id, &control);
        if limit == 99 {
            assert!(matches!(
                result,
                Err(LooseGitImportRefusal::PackedObject { .. })
            ));
            assert!(sources.sources[0].verified_objects.is_none());
        } else {
            assert_eq!(result.unwrap().unwrap().body().len(), 100);
        }
        sources.finish().unwrap();
        scratch.cleaned();
    }
}
#[test]
fn reconstruction_work_is_never_renewed_when_another_pack_is_opened() {
    let scratch = Scratch::new();
    let mut live = || true;
    let control = ImportControl::new(&mut live);
    let a = pack(&scratch, GitHashAlgorithm::Sha1, "a", &[vec![1; 100]])[0];
    let b = pack(&scratch, GitHashAlgorithm::Sha1, "b", &[vec![2; 100]])[0];
    let mut sources = scratch.sources(GitHashAlgorithm::Sha1, 1000, &control);
    sources.read(a, &control).unwrap().unwrap();
    // Install a caller-owned exhausted work witness. A fresh per-pack witness
    // would incorrectly let b through, while cached a needs no reconstruction.
    sources.resolution_budget = ResolutionBudget::new();
    sources
        .resolution_budget
        .charge_work(sources.limits.max_delta_work, &sources.limits)
        .unwrap();
    assert!(
        matches!(sources.read(b, &control), Err(LooseGitImportRefusal::PackedObject { source, .. }) if matches!(*source, PackError::DeltaWorkLimit { .. }))
    );
    assert!(sources.sources[1].verified_objects.is_none());
    assert!(sources.read(a, &control).unwrap().is_some());
    sources.finish().unwrap();
    scratch.cleaned();
}
#[test]
fn a_corrupt_later_pack_never_installs_partial_custody() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let mut live = || true;
        let control = ImportControl::new(&mut live);
        let a = pack(&scratch, format, "a", &[vec![1; 100]])[0];
        let b = pack(&scratch, format, "b", &[vec![2; 100]])[0];
        let mut sources = scratch.sources(format, 1000, &control);
        assert!(sources.read(a, &control).unwrap().is_some());
        let path = scratch.0.join("source/objects/pack/b.pack");
        let mut bytes = fs::read(&path).unwrap();
        bytes[20] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            sources.read(b, &control),
            Err(LooseGitImportRefusal::PackedObject { .. })
        ));
        assert!(sources.sources[1].verified_objects.is_none());
        assert_eq!(sources.loaded_objects, 1);
        assert!(sources.read(a, &control).unwrap().is_some());
        sources.finish().unwrap();
        scratch.cleaned();
    }
}
