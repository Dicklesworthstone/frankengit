//! Storage-only framing tests. The opaque payload fixtures below deliberately
//! make no native-object validity claim; node restart tests own canonical
//! revalidation and the actual upload-pack wire result.

use super::*;
use fgit_crypto::sha256_digest;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    store: DurableStore,
}

impl Fixture {
    fn new(format: GitHashAlgorithm, budget: usize) -> Self {
        let root = std::env::temp_dir().join(format!(
            "fgit-received-custody-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed),
        ));
        let store = DurableStore::new(
            root.join("received-pack-cache/v1"),
            TenantId::from_bytes([1; 16]),
            RepositoryId::from_bytes([2; 16]),
            RepositoryIncarnationId::from_bytes([3; 16]),
            format,
            budget,
        );
        Self { root, store }
    }

    fn put(&self, raw: &[u8], objects: &[VerifiedReceivedObject]) {
        self.store
            .persist_parts(raw, objects, sha256_digest(raw), &mut || true)
            .unwrap();
    }

    fn read(&self, objects: &[VerifiedReceivedObject]) -> Vec<Candidate> {
        self.store
            .candidates(
                &ids(objects),
                &BTreeSet::new(),
                &BTreeSet::new(),
                &mut || true,
            )
            .unwrap()
    }

    fn path(&self, index: usize) -> PathBuf {
        self.store.directory.join(slot_name(index))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn objects(format: GitHashAlgorithm, tags: &[u8]) -> Vec<VerifiedReceivedObject> {
    tags.iter()
        .map(|tag| VerifiedReceivedObject {
            id: match format {
                GitHashAlgorithm::Sha1 => GitOid::Sha1(GitOidSha1::from_bytes([*tag; 20])),
                GitHashAlgorithm::Sha256 => GitOid::Sha256(GitOidSha256::from_bytes([*tag; 32])),
            },
            kind: ObjectType::Blob,
            bytes: usize::from(*tag) + 17,
        })
        .collect()
}

fn ids(objects: &[VerifiedReceivedObject]) -> BTreeSet<GitOid> {
    objects.iter().map(|object| object.id).collect()
}

fn charge(raw_bytes: usize, count: usize) -> usize {
    ENTRY_OVERHEAD + count * OBJECT_OVERHEAD + raw_bytes
}

#[test]
fn both_formats_round_trip_exact_bytes_hints_and_versioned_binding() {
    for format in GitHashAlgorithm::ALL {
        let fixture = Fixture::new(*format, 16 * 1024);
        let raw = vec![91; 64];
        let hints = objects(*format, &[10, 20]);
        fixture.put(&raw, &hints);
        let candidates = fixture.read(&hints);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].bytes, raw);
        assert_eq!(candidates[0].objects, hints);
        assert_eq!(candidates[0].sha256, sha256_digest(&raw));
        let encoded = fs::read(fixture.path(0)).unwrap();
        assert_eq!(&encoded[..8], b"FGRP0001");
        assert_eq!(&encoded[8..24], &[1; 16]);
        assert_eq!(&encoded[24..40], &[2; 16]);
        assert_eq!(&encoded[40..56], &[3; 16]);
        assert_eq!(&encoded[56..58], &format.code_point().to_be_bytes());
        assert_eq!(&encoded[58..62], &2u32.to_be_bytes());
        assert_eq!(&encoded[62..70], &64u64.to_be_bytes());
        assert_eq!(&encoded[70..102], &sha256_digest(&raw));
        let width = format.digest_len();
        assert_eq!(&encoded[102..102 + width], hints[0].id.as_bytes());
        assert_eq!(encoded[102 + width], 3);
        assert_eq!(&encoded[103 + width..111 + width], &27u64.to_be_bytes());
        let footer = encoded.len() - FOOTER_BYTES;
        assert_eq!(&encoded[footer..], &sha256_digest(&encoded[..footer]));
        assert_eq!(fs::metadata(fixture.path(0)).unwrap().mode() & 0o777, 0o600);
        assert!(!fixture.store.directory.join(STAGE).exists());
    }
}

#[test]
fn every_truncation_bit_flip_and_trailing_byte_is_an_optional_miss() {
    for format in GitHashAlgorithm::ALL {
        let fixture = Fixture::new(*format, 16 * 1024);
        let hints = objects(*format, &[10]);
        fixture.put(&[31; 64], &hints);
        let original = fs::read(fixture.path(0)).unwrap();
        for length in 0..original.len() {
            fs::write(fixture.path(0), &original[..length]).unwrap();
            assert!(
                fixture.read(&hints).is_empty(),
                "{format} truncation {length}"
            );
        }
        for offset in 0..original.len() {
            let mut altered = original.clone();
            altered[offset] ^= 1;
            fs::write(fixture.path(0), &altered).unwrap();
            assert!(
                fixture.read(&hints).is_empty(),
                "{format} bit flip {offset}"
            );
        }
        let mut trailing = original.clone();
        trailing.push(0);
        fs::write(fixture.path(0), trailing).unwrap();
        assert!(fixture.read(&hints).is_empty());
        fs::write(fixture.path(0), original).unwrap();
        assert_eq!(fixture.read(&hints).len(), 1);
    }
}

#[test]
fn rechecksums_cannot_hide_duplicate_unsorted_or_invalid_hints() {
    for format in GitHashAlgorithm::ALL {
        let fixture = Fixture::new(*format, 16 * 1024);
        let hints = objects(*format, &[10, 20]);
        fixture.put(&[19; 64], &hints);
        let original = fs::read(fixture.path(0)).unwrap();
        let width = format.digest_len();
        let row_bytes = width + 9;
        for mutation in 0..5 {
            let mut altered = original.clone();
            match mutation {
                0 => {
                    // Duplicate the first object identity in the second row.
                    let first = altered[HEADER_BYTES..HEADER_BYTES + width].to_vec();
                    altered[HEADER_BYTES + row_bytes..HEADER_BYTES + row_bytes + width]
                        .copy_from_slice(&first);
                }
                1 => {
                    // Keep distinct authorized identities but reverse their order.
                    let first = altered[HEADER_BYTES..HEADER_BYTES + row_bytes].to_vec();
                    let second =
                        altered[HEADER_BYTES + row_bytes..HEADER_BYTES + 2 * row_bytes].to_vec();
                    altered[HEADER_BYTES..HEADER_BYTES + row_bytes].copy_from_slice(&second);
                    altered[HEADER_BYTES + row_bytes..HEADER_BYTES + 2 * row_bytes]
                        .copy_from_slice(&first);
                }
                2 => altered[HEADER_BYTES + width] = 0,
                3 => altered[HEADER_BYTES..HEADER_BYTES + width].fill(0),
                4 => altered[70] ^= 1, // Wrong raw fingerprint with a valid envelope digest.
                _ => unreachable!(),
            }
            let footer = altered.len() - FOOTER_BYTES;
            let digest = sha256_digest(&altered[..footer]);
            altered[footer..].copy_from_slice(&digest);
            fs::write(fixture.path(0), altered).unwrap();
            assert!(
                fixture.read(&hints).is_empty(),
                "{format} mutation {mutation}"
            );
        }
        fs::write(fixture.path(0), original).unwrap();
        assert_eq!(fixture.read(&hints).len(), 1);
    }
}

#[test]
fn wrong_namespace_and_impossible_lengths_refuse_before_payload_allocation() {
    let format = GitHashAlgorithm::Sha256;
    let fixture = Fixture::new(format, MAX_CAPTURE_BYTES + 8192);
    let raw = [11; 64];
    let hints = objects(format, &[9]);
    fixture.put(&raw, &hints);
    let original = fs::read(fixture.path(0)).unwrap();
    let header: [u8; HEADER_BYTES] = original[..HEADER_BYTES].try_into().unwrap();
    for changed in [
        (4, 2, 3, format),
        (1, 4, 3, format),
        (1, 2, 4, format),
        (1, 2, 3, GitHashAlgorithm::Sha1),
    ] {
        let other = DurableStore::new(
            fixture.root.clone(),
            TenantId::from_bytes([changed.0; 16]),
            RepositoryId::from_bytes([changed.1; 16]),
            RepositoryIncarnationId::from_bytes([changed.2; 16]),
            changed.3,
            fixture.store.max_bytes,
        );
        assert_ne!(
            other.directory.file_name(),
            fixture.store.directory.file_name()
        );
        assert!(
            other
                .decode_header(&header, original.len() as u64)
                .is_none()
        );
    }
    assert!(fixture.store.header(0, 64, [0; 32]).is_none());
    assert!(
        fixture
            .store
            .header(1, MAX_CAPTURE_BYTES + 1, [0; 32])
            .is_none()
    );
    assert!(
        fixture
            .store
            .header(1, MAX_CAPTURE_BYTES, [0; 32])
            .is_some()
    );
    for count in [0, u32::MAX] {
        let mut altered = header;
        altered[58..62].copy_from_slice(&count.to_be_bytes());
        assert!(
            fixture
                .store
                .decode_header(&altered, original.len() as u64)
                .is_none()
        );
    }
    let mut oversized = header;
    oversized[62..70].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(fixture.store.decode_header(&oversized, u64::MAX).is_none());
    assert_eq!(fixture.read(&hints).len(), 1);
}

#[test]
fn authorized_membership_and_live_fingerprint_filter_precede_raw_reads() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256, 512 * 1024);
    let raw = vec![7; 3 * HASH_CHUNK_BYTES];
    let hints = objects(fixture.store.format, &[10, 20]);
    fixture.put(&raw, &hints);
    let directory = open_directory(&fixture.store.directory, false, &mut || true).unwrap();
    let mut all_work = 0usize;
    let successful = fixture
        .store
        .read_candidate(
            &directory,
            0,
            &ids(&hints),
            &BTreeSet::new(),
            &BTreeSet::new(),
            &mut ReadBudget::new(fixture.store.max_bytes),
            &mut || {
                all_work += 1;
                true
            },
        )
        .unwrap();
    assert_eq!(successful.0.bytes, raw);
    let selected = ids(&hints[..1]);
    let held = ids(&hints[1..]);
    assert_eq!(
        fixture
            .store
            .candidates(&selected, &held, &BTreeSet::new(), &mut || true,)
            .unwrap()
            .len(),
        1
    );
    let mut filtered_work = 0usize;
    assert!(matches!(
        fixture.store.read_candidate(
            &directory,
            0,
            &selected,
            &BTreeSet::new(),
            &BTreeSet::new(),
            &mut ReadBudget::new(fixture.store.max_bytes),
            &mut || {
                filtered_work += 1;
                true
            },
        ),
        Err(Miss::Unavailable)
    ));
    assert!(filtered_work < all_work);
    let known = BTreeSet::from([sha256_digest(&raw)]);
    let mut known_work = 0usize;
    assert!(matches!(
        fixture.store.read_candidate(
            &directory,
            0,
            &ids(&hints),
            &BTreeSet::new(),
            &known,
            &mut ReadBudget::new(fixture.store.max_bytes),
            &mut || {
                known_work += 1;
                true
            },
        ),
        Err(Miss::Unavailable)
    ));
    assert!(known_work < filtered_work);
    // A held-only pack never becomes a candidate for a different selection.
    let unrelated = ids(&objects(fixture.store.format, &[30]));
    assert!(
        fixture
            .store
            .candidates(&unrelated, &ids(&hints), &BTreeSet::new(), &mut || true,)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn zero_budget_and_empty_selection_never_create_custody() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1, 0);
    let hints = objects(fixture.store.format, &[9]);
    assert!(fixture.read(&hints).is_empty());
    assert!(matches!(
        fixture
            .store
            .persist_parts(&[1; 64], &hints, sha256_digest(&[1; 64]), &mut || true,),
        Err(Miss::Unavailable)
    ));
    assert!(!fixture.root.exists());
    let enabled = Fixture::new(GitHashAlgorithm::Sha1, 8192);
    assert!(
        enabled
            .store
            .candidates(
                &BTreeSet::new(),
                &ids(&hints),
                &BTreeSet::new(),
                &mut || true,
            )
            .unwrap()
            .is_empty()
    );
    assert!(!enabled.root.exists());
}

#[test]
fn eviction_and_interrupted_staging_share_one_bounded_allowance() {
    let raw_len = 3 * HASH_CHUNK_BYTES;
    let allowance = 2 * charge(raw_len, 1);
    let fixture = Fixture::new(GitHashAlgorithm::Sha256, allowance);
    let first = objects(fixture.store.format, &[10]);
    let second = objects(fixture.store.format, &[20]);
    let third = objects(fixture.store.format, &[30]);
    fixture.put(&vec![1; raw_len], &first);
    let stage = fixture.store.directory.join(STAGE);
    let stopped = fixture.store.persist_parts(
        &vec![2; raw_len],
        &second,
        sha256_digest(&vec![2; raw_len]),
        &mut || fs::metadata(&stage).map_or(true, |metadata| metadata.len() < HEADER_BYTES as u64),
    );
    assert!(matches!(stopped, Err(Miss::Stopped)));
    assert!(stage.is_file());
    assert!(stored_bytes(&fixture) <= allowance as u64);
    assert_eq!(fixture.read(&first).len(), 1);
    fixture.put(&vec![2; raw_len], &second);
    assert!(!stage.exists());
    fixture.put(&vec![3; raw_len], &third);
    let all = [first, second, third].concat();
    let restored = fixture.read(&all);
    assert_eq!(restored.len(), 2);
    assert!(
        restored
            .iter()
            .any(|candidate| candidate.sha256 == sha256_digest(&vec![3; raw_len]))
    );
    assert!(stored_bytes(&fixture) <= allowance as u64);
    // Repeated identical incoming bytes repair/replace one slot, never append
    // additional filenames or evade accounting through a duplicate identity.
    fixture.put(&vec![3; raw_len], &all[2..]);
    assert_eq!(fixture.read(&all).len(), 2);
    assert_eq!(fs::read_dir(&fixture.store.directory).unwrap().count(), 3);
}

fn stored_bytes(fixture: &Fixture) -> u64 {
    fs::read_dir(&fixture.store.directory)
        .unwrap()
        .map(|entry| entry.unwrap().metadata().unwrap().len())
        .sum()
}

#[test]
fn fixed_slot_count_survives_more_writes_than_available_slots() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1, MAX_ENTRIES * charge(64, 1));
    let mut all = Vec::new();
    for tag in 1..=70u8 {
        let hints = objects(fixture.store.format, &[tag]);
        fixture.put(&[tag; 64], &hints);
        all.extend(hints);
    }
    assert_eq!(fixture.read(&all).len(), MAX_ENTRIES);
    assert_eq!(
        fs::read_dir(&fixture.store.directory).unwrap().count(),
        MAX_ENTRIES + 1
    );
    assert!(stored_bytes(&fixture) <= fixture.store.max_bytes as u64);
}

#[test]
fn corrupt_records_are_reclaimed_and_reduced_budgets_cannot_accumulate_old_bytes() {
    let mut fixture = Fixture::new(GitHashAlgorithm::Sha256, 4 * charge(64, 1));
    let hints = objects(fixture.store.format, &[10, 20, 30]);
    for (index, hint) in hints.iter().enumerate() {
        fixture.put(&[index as u8 + 1; 64], &[*hint]);
    }
    fs::write(fixture.path(0), b"torn").unwrap();
    fixture.store.max_bytes = charge(64, 1);
    fixture.put(&[42; 64], &hints[2..]);
    let restored = fixture.read(&hints);
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].bytes, [42; 64]);
    assert!(stored_bytes(&fixture) <= fixture.store.max_bytes as u64);
}

#[test]
fn corrupt_full_records_consume_the_inspection_allowance_without_returning_bytes() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256, charge(64, 1));
    let hints = objects(fixture.store.format, &[10]);
    fixture.put(&[8; 64], &hints);
    let original = fs::read(fixture.path(0)).unwrap();
    let mut corrupt = original.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    // Deliberately exceed what the writer can create, modeling hostile local
    // cache data. Only one full inspection may consume this read allowance.
    for index in 0..3 {
        fs::write(fixture.path(index), &corrupt).unwrap();
        fs::set_permissions(fixture.path(index), fs::Permissions::from_mode(0o600)).unwrap();
    }
    let directory = open_directory(&fixture.store.directory, false, &mut || true).unwrap();
    let mut budget = ReadBudget::new(fixture.store.max_bytes);
    let mut first = 0usize;
    assert!(matches!(
        fixture.store.read_candidate(
            &directory,
            0,
            &ids(&hints),
            &BTreeSet::new(),
            &BTreeSet::new(),
            &mut budget,
            &mut || {
                first += 1;
                true
            },
        ),
        Err(Miss::Unavailable)
    ));
    assert_eq!(budget.inspected, 0);
    assert_eq!(budget.retained, fixture.store.max_bytes);
    let mut later = 0usize;
    assert!(matches!(
        fixture.store.read_candidate(
            &directory,
            1,
            &ids(&hints),
            &BTreeSet::new(),
            &BTreeSet::new(),
            &mut budget,
            &mut || {
                later += 1;
                true
            },
        ),
        Err(Miss::Unavailable)
    ));
    assert!(later < first);
    assert!(fixture.read(&hints).is_empty());
    fs::write(fixture.path(0), original).unwrap();
    assert_eq!(fixture.read(&hints).len(), 1);
}

#[test]
fn links_fifos_nonprivate_files_and_busy_locks_are_misses_without_target_changes() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1, 8192);
    let hints = objects(fixture.store.format, &[10]);
    fixture.put(&[12; 64], &hints);
    let original = fs::read(fixture.path(0)).unwrap();
    let directory = open_directory(&fixture.store.directory, false, &mut || true).unwrap();
    let lock = writer_lock(&directory).unwrap();
    assert!(fixture.read(&hints).is_empty());
    assert!(matches!(
        fixture
            .store
            .persist_parts(&[12; 64], &hints, sha256_digest(&[12; 64]), &mut || true,),
        Err(Miss::Unavailable)
    ));
    drop(lock);
    assert_eq!(fixture.read(&hints).len(), 1);
    let outside = fixture.root.join("must-not-change");
    fs::write(&outside, &original).unwrap();
    fs::remove_file(fixture.path(0)).unwrap();
    symlink(&outside, fixture.path(0)).unwrap();
    assert!(fixture.read(&hints).is_empty());
    assert!(matches!(
        fixture
            .store
            .persist_parts(&[13; 64], &hints, sha256_digest(&[13; 64]), &mut || true,),
        Err(Miss::Unavailable)
    ));
    assert_eq!(fs::read(&outside).unwrap(), original);
    fs::remove_file(fixture.path(0)).unwrap();
    #[cfg(target_os = "linux")]
    {
        rustix::fs::mkfifoat(&directory, slot_name(0), Mode::from_raw_mode(0o600)).unwrap();
        assert!(fixture.read(&hints).is_empty());
        fs::remove_file(fixture.path(0)).unwrap();
    }
    fixture.put(&[12; 64], &hints);
    let hardlink = fixture.root.join("linked-record");
    fs::hard_link(fixture.path(0), &hardlink).unwrap();
    assert!(fixture.read(&hints).is_empty());
    fs::remove_file(hardlink).unwrap();
    fs::set_permissions(fixture.path(0), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(fixture.read(&hints).is_empty());
    fs::set_permissions(fixture.path(0), fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(fixture.read(&hints).len(), 1);
}

#[test]
fn cancellation_remains_explicit_even_at_the_final_optional_miss_checkpoint() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1, 8192);
    let hints = objects(fixture.store.format, &[10]);
    assert_eq!(
        fixture
            .store
            .candidates(
                &ids(&hints),
                &BTreeSet::new(),
                &BTreeSet::new(),
                &mut || false,
            )
            .unwrap_err(),
        PackError::DeadlineExceeded
    );
    assert!(!fixture.root.exists());
    // An absent directory produces an optional I/O miss. Cancel precisely on
    // the final checkpoint after that miss, rather than inside the I/O helper.
    let mut calls = 0usize;
    assert!(
        fixture
            .store
            .candidates(
                &ids(&hints),
                &BTreeSet::new(),
                &BTreeSet::new(),
                &mut || {
                    calls += 1;
                    true
                },
            )
            .unwrap()
            .is_empty()
    );
    let mut observed = 0usize;
    assert_eq!(
        fixture
            .store
            .candidates(
                &ids(&hints),
                &BTreeSet::new(),
                &BTreeSet::new(),
                &mut || {
                    observed += 1;
                    observed < calls
                },
            )
            .unwrap_err(),
        PackError::DeadlineExceeded
    );
    fixture.put(&[14; 64], &hints);
    let directory = open_directory(&fixture.store.directory, false, &mut || true).unwrap();
    let mut total = 0usize;
    fixture
        .store
        .read_candidate(
            &directory,
            0,
            &ids(&hints),
            &BTreeSet::new(),
            &BTreeSet::new(),
            &mut ReadBudget::new(fixture.store.max_bytes),
            &mut || {
                total += 1;
                true
            },
        )
        .unwrap();
    for stop in 1..=total {
        let mut seen = 0usize;
        assert!(
            matches!(
                fixture.store.read_candidate(
                    &directory,
                    0,
                    &ids(&hints),
                    &BTreeSet::new(),
                    &BTreeSet::new(),
                    &mut ReadBudget::new(fixture.store.max_bytes),
                    &mut || {
                        seen += 1;
                        seen < stop
                    },
                ),
                Err(Miss::Stopped)
            ),
            "checkpoint {stop}"
        );
    }
    assert_eq!(fixture.read(&hints).len(), 1);
}
