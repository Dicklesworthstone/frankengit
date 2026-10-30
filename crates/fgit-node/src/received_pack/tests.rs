use super::*;
use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest, sha256_digest};
use fgit_pack::{PackTrailerVerifier, read_verified_pack_owned};
use fgit_types::GitHashAlgorithm;

struct Fixture {
    raw: Vec<u8>,
    pack: QuarantinedPack,
    objects: Vec<VerifiedReceivedObject>,
    offsets: BTreeMap<u64, GitOid>,
    keys: Vec<PackOrderKey>,
}

enum Input {
    Whole(Vec<u8>),
    Ref(GitOid, Vec<u8>, Vec<u8>),
    Ofs(usize, Vec<u8>, Vec<u8>),
}

fn zlib(bytes: &[u8]) -> Vec<u8> {
    let mut output = vec![0x78, 0x01];
    let chunks = bytes.len().max(1).div_ceil(u16::MAX as usize);
    for index in 0..chunks {
        let start = index * u16::MAX as usize;
        let end = bytes.len().min(start + u16::MAX as usize);
        let part = &bytes[start..end];
        output.push(u8::from(index + 1 == chunks));
        let count = u16::try_from(part.len()).unwrap();
        output.extend(count.to_le_bytes());
        output.extend((!count).to_le_bytes());
        output.extend(part);
    }
    let (a, b) = bytes.iter().fold((1u32, 0u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521;
        (a, (b + a) % 65_521)
    });
    output.extend(((b << 16) | a).to_be_bytes());
    output
}

fn fixture(format: GitHashAlgorithm, entries: &[Input]) -> Fixture {
    let mut raw = b"PACK".to_vec();
    raw.extend(2u32.to_be_bytes());
    raw.extend(u32::try_from(entries.len()).unwrap().to_be_bytes());
    let mut wire_offsets = Vec::new();
    let mut offsets = BTreeMap::new();
    let mut objects = Vec::new();
    for entry in entries {
        let at = raw.len();
        wire_offsets.push(at);
        let (kind, encoded, body, base) = match entry {
            Input::Whole(body) => (3, body, body, Vec::new()),
            Input::Ref(base, program, body) => (7, program, body, base.as_bytes().to_vec()),
            Input::Ofs(index, program, body) => {
                let mut distance = at - wire_offsets[*index];
                let mut encoded = vec![(distance & 127) as u8];
                while {
                    distance >>= 7;
                    distance != 0
                } {
                    distance -= 1;
                    encoded.push(0x80 | (distance & 127) as u8);
                }
                encoded.reverse();
                (6, program, body, encoded)
            }
        };
        let id = git_object_id(format, GitObjectKind::Blob, body);
        assert!(offsets.insert(at as u64, id).is_none());
        objects.push(VerifiedReceivedObject {
            id,
            kind: ObjectType::Blob,
            bytes: body.len(),
        });
        let mut size = encoded.len();
        let mut byte = (kind << 4) | (size & 15) as u8;
        size >>= 4;
        while size != 0 {
            raw.push(byte | 128);
            byte = (size & 127) as u8;
            size >>= 7;
        }
        raw.push(byte);
        raw.extend(base);
        raw.extend(zlib(encoded));
    }
    match format {
        GitHashAlgorithm::Sha1 => raw.extend(sha1_digest(&raw)),
        GitHashAlgorithm::Sha256 => raw.extend(sha256_digest(&raw)),
    }
    let pack = read_verified_pack_owned(
        raw.clone(),
        format,
        &PackLimits::default(),
        &mut || true,
        &NativeChecksumVerifier,
        MAX_CAPTURE_BYTES,
    )
    .unwrap();
    objects.sort_by_key(|object| object.id);
    let keys = objects
        .iter()
        .map(|object| PackOrderKey {
            id: object.id,
            object_type: object.kind,
            recency: 0,
            path_hash: 0,
        })
        .collect();
    Fixture { raw, pack, objects, offsets, keys }
}

fn literal_delta(base_len: usize, body: &[u8]) -> Vec<u8> {
    assert!(base_len < 128 && !body.is_empty() && body.len() < 128);
    let mut program = vec![base_len as u8, body.len() as u8, body.len() as u8];
    program.extend_from_slice(body);
    program
}

fn whole(body: &[u8]) -> Fixture {
    fixture(GitHashAlgorithm::Sha1, &[Input::Whole(body.to_vec())])
}

fn retain(cache: &ReceivedPackCache, fixture: &Fixture) {
    cache
        .retain_verified(
            &fixture.pack,
            fixture.objects.iter().copied(),
            &fixture.offsets,
            &PackLimits::default(),
            &mut || true,
        )
        .unwrap();
}

fn payload(cache: &ReceivedPackCache, fixture: &Fixture) -> Option<ReceivedPackPayload> {
    cache
        .try_reuse(&fixture.keys, &PackLimits::default(), true, &mut || true)
        .unwrap()
}

#[test]
fn exact_bytes_receipts_and_independent_cursors_in_both_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = fixture(format, &[Input::Whole(b"first".to_vec()), Input::Whole(b"second".to_vec())]);
        let cache = ReceivedPackCache::new(64 * 1024);
        retain(&cache, &f);
        let mut one = payload(&cache, &f).unwrap();
        let mut two = payload(&cache, &f).unwrap();
        assert_eq!(one.receipt().profile(), "received-pack-v1");
        assert_eq!(one.receipt().checksum(), f.pack.trailer);
        assert_eq!(one.receipt().sha256(), &sha256_digest(&f.raw));
        assert_eq!(one.receipt().object_count(), 2);
        assert_eq!(one.receipt().total_object_bytes(), 11);
        assert_eq!(one.receipt().output_bytes(), f.raw.len());
        assert_eq!(one.next_chunk(7).unwrap().unwrap(), f.raw[..7]);
        assert_eq!(two.next_chunk(3).unwrap().unwrap(), f.raw[..3]);
        let mut collected = f.raw[..7].to_vec();
        while let Some(part) = one.next_chunk(11).unwrap() {
            collected.extend(part);
        }
        assert_eq!(collected, f.raw);
        assert!(one.next_chunk(1).unwrap().is_none());
        assert!(one.next_chunk(0).is_err());
        assert_eq!(two.into_bytes().unwrap(), f.raw);
    }
}

#[test]
fn exact_membership_kinds_and_formats_cannot_be_widened() {
    let f = fixture(GitHashAlgorithm::Sha1, &[Input::Whole(b"a".to_vec()), Input::Whole(b"b".to_vec())]);
    let cache = ReceivedPackCache::new(64 * 1024);
    retain(&cache, &f);
    let mut wrong_kind = f.keys.clone();
    wrong_kind[0].object_type = ObjectType::Tree;
    let mut duplicate = f.keys.clone();
    duplicate[1] = duplicate[0];
    let mut reversed = f.keys.clone();
    reversed.reverse();
    let other = fixture(GitHashAlgorithm::Sha256, &[Input::Whole(b"a".to_vec()), Input::Whole(b"b".to_vec())]);
    for keys in [Vec::new(), f.keys[..1].to_vec(), wrong_kind, duplicate, reversed, other.keys] {
        assert!(cache.try_reuse(&keys, &PackLimits::default(), true, &mut || true).unwrap().is_none());
    }
    let mut hints = f.keys.clone();
    for key in &mut hints {
        key.path_hash = 42;
        key.recency = 17;
    }
    assert!(cache.try_reuse(&hints, &PackLimits::default(), true, &mut || true).unwrap().is_some());
}

#[test]
fn ofs_capability_depth_and_fanout_are_rechecked() {
    let base = b"base";
    let f = fixture(GitHashAlgorithm::Sha1, &[
        Input::Whole(base.to_vec()),
        Input::Ofs(0, literal_delta(base.len(), b"first"), b"first".to_vec()),
        Input::Ofs(0, literal_delta(base.len(), b"second"), b"second".to_vec()),
    ]);
    let cache = ReceivedPackCache::new(64 * 1024);
    retain(&cache, &f);
    let received = payload(&cache, &f).unwrap();
    assert_eq!(received.receipt().ofs_delta_count(), 2);
    assert_eq!(received.receipt().ref_delta_count(), 0);
    assert_eq!(received.receipt().maximum_delta_depth(), 1);
    assert!(cache.try_reuse(&f.keys, &PackLimits::default(), false, &mut || true).unwrap().is_none());
    for limits in [
        PackLimits { max_delta_depth: 0, ..PackLimits::default() },
        PackLimits { max_delta_fanout: 1, ..PackLimits::default() },
    ] {
        assert!(cache.try_reuse(&f.keys, &limits, true, &mut || true).unwrap().is_none());
    }
}

#[test]
fn forward_ref_chains_are_self_contained_without_ofs_negotiation() {
    let format = GitHashAlgorithm::Sha256;
    let base = b"base";
    let middle = b"middle";
    let base_id = git_object_id(format, GitObjectKind::Blob, base);
    let middle_id = git_object_id(format, GitObjectKind::Blob, middle);
    let f = fixture(format, &[
        Input::Ref(middle_id, literal_delta(middle.len(), b"last"), b"last".to_vec()),
        Input::Ref(base_id, literal_delta(base.len(), middle), middle.to_vec()),
        Input::Whole(base.to_vec()),
    ]);
    let cache = ReceivedPackCache::new(64 * 1024);
    retain(&cache, &f);
    let received = cache.try_reuse(&f.keys, &PackLimits::default(), false, &mut || true).unwrap().unwrap();
    assert_eq!(received.receipt().ref_delta_count(), 2);
    assert_eq!(received.receipt().maximum_delta_depth(), 2);
    assert_eq!(received.into_bytes().unwrap(), f.raw);
}

#[test]
fn external_delta_bases_and_cycles_cannot_establish_custody() {
    let format = GitHashAlgorithm::Sha1;
    let base = git_object_id(format, GitObjectKind::Blob, b"outside");
    let thin = fixture(format, &[Input::Ref(base, literal_delta(7, b"inside"), b"inside".to_vec())]);
    let cache = ReceivedPackCache::new(64 * 1024);
    retain(&cache, &thin);
    assert_eq!(cache.retained_entries(), 0);
    let a = git_object_id(format, GitObjectKind::Blob, b"a");
    let b = git_object_id(format, GitObjectKind::Blob, b"b");
    let cyclic = fixture(format, &[
        Input::Ref(b, literal_delta(1, b"a"), b"a".to_vec()),
        Input::Ref(a, literal_delta(1, b"b"), b"b".to_vec()),
    ]);
    retain(&cache, &cyclic);
    assert_eq!(cache.retained_entries(), 0);
}

#[test]
fn current_entry_output_native_object_and_total_limits_are_inclusive() {
    let f = fixture(GitHashAlgorithm::Sha1, &[Input::Whole(b"aaaa".to_vec()), Input::Whole(b"bb".to_vec())]);
    let cache = ReceivedPackCache::new(64 * 1024);
    retain(&cache, &f);
    let exact = PackLimits {
        max_entries: 2,
        max_input_bytes: f.raw.len(),
        max_object_bytes: 4,
        max_total_expanded_bytes: 6,
        ..PackLimits::default()
    };
    assert!(cache.try_reuse(&f.keys, &exact, true, &mut || true).unwrap().is_some());
    for limited in [
        PackLimits { max_entries: 1, ..exact.clone() },
        PackLimits { max_input_bytes: f.raw.len() - 1, ..exact.clone() },
        PackLimits { max_object_bytes: 3, ..exact.clone() },
        PackLimits { max_total_expanded_bytes: 5, ..exact.clone() },
    ] {
        assert!(cache.try_reuse(&f.keys, &limited, true, &mut || true).unwrap().is_none());
    }
}

#[test]
fn inflated_delta_programs_cannot_bypass_smaller_current_envelopes() {
    let base = b"x";
    let result = b"yz";
    let program = literal_delta(1, result); // Five instruction bytes, two result bytes.
    let f = fixture(GitHashAlgorithm::Sha1, &[
        Input::Whole(base.to_vec()),
        Input::Ofs(0, program.clone(), result.to_vec()),
    ]);
    let cache = ReceivedPackCache::new(64 * 1024);
    retain(&cache, &f);
    assert_eq!(payload(&cache, &f).unwrap().receipt().total_object_bytes(), 3);
    let exact = PackLimits {
        max_object_bytes: program.len(),
        max_total_expanded_bytes: base.len() + program.len(),
        ..PackLimits::default()
    };
    assert!(cache.try_reuse(&f.keys, &exact, true, &mut || true).unwrap().is_some());
    for limited in [
        PackLimits { max_object_bytes: result.len(), ..exact.clone() },
        PackLimits { max_total_expanded_bytes: 3, ..exact.clone() },
    ] {
        assert!(cache.try_reuse(&f.keys, &limited, true, &mut || true).unwrap().is_none());
    }
}

#[test]
fn pending_custody_is_invisible_and_abandonment_releases_its_reservation() {
    let f = whole(b"pending");
    let cache = ReceivedPackCache::new(64 * 1024);
    let pending = cache.prepare_verified(&f.pack, f.objects.iter().copied(), &f.offsets, &PackLimits::default(), &mut || true).unwrap().unwrap();
    assert_eq!(cache.retained_entries(), 0);
    assert!(payload(&cache, &f).is_none());
    assert_eq!(cache.state.lock().unwrap().reservations, 1);
    drop(pending);
    assert_eq!(cache.state.lock().unwrap().reserved_bytes, 0);
    assert_eq!(cache.state.lock().unwrap().reservations, 0);
    let pending = cache.prepare_verified(&f.pack, f.objects.iter().copied(), &f.offsets, &PackLimits::default(), &mut || true).unwrap().unwrap();
    pending.commit();
    assert_eq!(cache.retained_entries(), 1);
    assert!(payload(&cache, &f).is_some());
}

#[test]
fn duplicate_speculative_captures_release_extra_charges() {
    let f = whole(b"same");
    let cache = ReceivedPackCache::new(64 * 1024);
    let one = cache.prepare_verified(&f.pack, f.objects.iter().copied(), &f.offsets, &PackLimits::default(), &mut || true).unwrap().unwrap();
    let two = cache.prepare_verified(&f.pack, f.objects.iter().copied(), &f.offsets, &PackLimits::default(), &mut || true).unwrap().unwrap();
    one.commit();
    let charge = cache.state.lock().unwrap().resident_bytes;
    two.commit();
    let state = cache.state.lock().unwrap();
    assert_eq!(state.entries.len(), 1);
    assert_eq!(state.resident_bytes, charge);
    assert_eq!(state.reserved_bytes, 0);
    assert_eq!(state.reservations, 0);
}

#[test]
fn pinned_readers_keep_capacity_until_they_finish() {
    let one = whole(b"one");
    let two = whole(b"two");
    let charge = ENTRY_OVERHEAD + OBJECT_OVERHEAD + one.pack.retained_bytes().unwrap().retained_capacity();
    let cache = ReceivedPackCache::new(charge);
    retain(&cache, &one);
    let pin = payload(&cache, &one).unwrap();
    retain(&cache, &two);
    assert!(payload(&cache, &two).is_none());
    assert_eq!(pin.receipt().output_bytes(), one.raw.len());
    drop(pin);
    retain(&cache, &two);
    assert!(payload(&cache, &one).is_none());
    assert!(payload(&cache, &two).is_some());
    assert!(cache.state.lock().unwrap().resident_bytes <= cache.max_bytes());
}

#[test]
fn eight_entry_fifo_skips_pinned_entries() {
    let cache = ReceivedPackCache::new(256 * 1024);
    let first = whole(b"entry-0");
    retain(&cache, &first);
    let pin = payload(&cache, &first).unwrap();
    let second = whole(b"entry-1");
    retain(&cache, &second);
    for index in 2..9 {
        retain(&cache, &whole(format!("entry-{index}").as_bytes()));
    }
    assert_eq!(cache.retained_entries(), MAX_ENTRIES);
    assert!(payload(&cache, &first).is_some());
    assert!(payload(&cache, &second).is_none());
    assert_eq!(pin.into_bytes().unwrap(), first.raw);
}

#[test]
fn disabled_capacity_and_duplicate_metadata_are_safe_misses() {
    let f = whole(b"data");
    let disabled = ReceivedPackCache::new(0);
    assert_eq!(disabled.capture_limit(), 0);
    retain(&disabled, &f);
    assert_eq!(disabled.retained_entries(), 0);
    let duplicate = fixture(GitHashAlgorithm::Sha1, &[Input::Whole(b"same".to_vec()), Input::Whole(b"same".to_vec())]);
    let cache = ReceivedPackCache::new(64 * 1024);
    retain(&cache, &duplicate);
    assert_eq!(cache.retained_entries(), 0);
}

#[test]
fn public_quarantine_metadata_and_permissive_verifiers_do_not_establish_proof() {
    let cache = ReceivedPackCache::new(64 * 1024);
    let mut changed = whole(b"body");
    changed.pack.header.object_count += 1;
    retain(&cache, &changed);
    assert_eq!(cache.retained_entries(), 0);
    let mut changed = whole(b"body");
    changed.pack.format = GitHashAlgorithm::Sha256;
    retain(&cache, &changed);
    assert_eq!(cache.retained_entries(), 0);
    struct Permit;
    impl PackTrailerVerifier for Permit {
        fn verify(&self, _: &[u8], _: &[u8], _: GitHashAlgorithm) -> bool { true }
    }
    let mut f = whole(b"body");
    let last = f.raw.len() - 1;
    f.raw[last] ^= 1;
    f.pack = read_verified_pack_owned(
        f.raw.clone(), GitHashAlgorithm::Sha1, &PackLimits::default(),
        &mut || true, &Permit, MAX_CAPTURE_BYTES,
    ).unwrap();
    retain(&cache, &f);
    assert_eq!(cache.retained_entries(), 0);
}

#[test]
fn damaged_hash_identity_binding_and_resource_bounds_never_serve_bytes() {
    for damage in 0..4 {
        let f = whole(b"body");
        let cache = ReceivedPackCache::new(64 * 1024);
        retain(&cache, &f);
        let mut keys = f.keys.clone();
        {
            let mut state = cache.state.lock().unwrap();
            let entry = Arc::get_mut(&mut state.entries[0]).unwrap();
            match damage {
                0 => entry.receipt.sha256[0] ^= 1,
                1 => {
                    entry.objects[0].kind = ObjectType::Tree;
                    keys[0].object_type = ObjectType::Tree;
                }
                2 => entry.maximum_object_bytes = 0,
                _ => entry.total_entry_bytes = 0,
            }
        }
        assert!(cache.try_reuse(&keys, &PackLimits::default(), true, &mut || true).unwrap().is_none());
    }
}

#[test]
fn every_capture_checkpoint_preserves_cancellation_and_releases_reservations() {
    let f = whole(b"cancellable capture");
    let baseline = ReceivedPackCache::new(64 * 1024);
    let mut calls = 0usize;
    let pending = baseline.prepare_verified(&f.pack, f.objects.iter().copied(), &f.offsets, &PackLimits::default(), &mut || { calls += 1; true }).unwrap();
    drop(pending);
    for stop in 1..=calls {
        let cache = ReceivedPackCache::new(64 * 1024);
        let mut at = 0usize;
        let result = cache.prepare_verified(&f.pack, f.objects.iter().copied(), &f.offsets, &PackLimits::default(), &mut || { at += 1; at < stop });
        assert!(matches!(result, Err(PackError::DeadlineExceeded)), "capture checkpoint {stop}");
        let state = cache.state.lock().unwrap();
        assert_eq!(state.resident_bytes, 0);
        assert_eq!(state.reserved_bytes, 0);
        assert_eq!(state.reservations, 0);
    }
}

#[test]
fn every_lookup_checkpoint_cancels_without_losing_verified_custody() {
    let f = whole(b"cancellable lookup");
    let cache = ReceivedPackCache::new(64 * 1024);
    retain(&cache, &f);
    let mut calls = 0usize;
    drop(cache.try_reuse(&f.keys, &PackLimits::default(), true, &mut || { calls += 1; true }).unwrap());
    for stop in 1..=calls {
        let mut at = 0usize;
        let result = cache.try_reuse(&f.keys, &PackLimits::default(), true, &mut || { at += 1; at < stop });
        assert!(matches!(result, Err(PackWriteError::Pack(PackError::DeadlineExceeded))), "lookup checkpoint {stop}");
        assert_eq!(cache.retained_entries(), 1);
        assert!(payload(&cache, &f).is_some());
    }
}
