//! A complete cold-restoration owner uses recent results while preserving the
//! canonical body, current scope, native dependency and activation boundaries.

use super::*;
use fgit_pack::encode_entry_header;

fn varint(mut value: usize, output: &mut Vec<u8>) {
    loop {
        let mut byte = u8::try_from(value & 0x7f).unwrap();
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn append_delta(length: usize, byte: u8) -> Vec<u8> {
    let mut program = Vec::new();
    varint(length, &mut program);
    varint(length + 1, &mut program);
    program.extend([
        0xb0,
        u8::try_from(length & 0xff).unwrap(),
        u8::try_from(length >> 8).unwrap(),
        1,
        byte,
    ]);
    program
}

fn ofs_distance(mut distance: usize) -> Vec<u8> {
    let mut bytes = vec![u8::try_from(distance & 0x7f).unwrap()];
    while {
        distance >>= 7;
        distance != 0
    } {
        distance -= 1;
        bytes.push(0x80 | u8::try_from(distance & 0x7f).unwrap());
    }
    bytes.reverse();
    bytes
}

struct History {
    raw: Vec<u8>,
    pack: QuarantinedPack,
    hints: Vec<VerifiedReceivedObject>,
    authorized: BTreeSet<GitOid>,
    limits: PackLimits,
    depth: usize,
}

fn retained_history(node: &OneNode) -> History {
    let depth = 24;
    let mut raw = b"PACK".to_vec();
    raw.extend(2_u32.to_be_bytes());
    raw.extend(u32::try_from(depth + 1).unwrap().to_be_bytes());
    let mut body = vec![b'h'; 2048];
    let mut previous_offset = 0;
    let mut hints = Vec::new();
    for index in 0..=depth {
        let offset = raw.len();
        if index == 0 {
            raw.extend(encode_entry_header(3, body.len()).unwrap());
            raw.extend(zlib_stored(&body));
        } else {
            let next = u8::try_from(index).unwrap();
            let delta = append_delta(body.len(), next);
            raw.extend(encode_entry_header(6, delta.len()).unwrap());
            raw.extend(ofs_distance(offset - previous_offset));
            raw.extend(zlib_stored(&delta));
            body.push(next);
        }
        previous_offset = offset;
        let placed = node.put_git_object(ObjectType::Blob, body.clone()).unwrap();
        hints.push(VerifiedReceivedObject {
            id: placed.identity(),
            kind: ObjectType::Blob,
            bytes: body.len(),
        });
    }
    match node.object_format {
        GitHashAlgorithm::Sha1 => raw.extend(fgit_crypto::sha1_digest(&raw)),
        GitHashAlgorithm::Sha256 => raw.extend(fgit_crypto::sha256_digest(&raw)),
    }
    hints.sort_by_key(|hint| hint.id);
    let expanded: usize = hints.iter().map(|hint| hint.bytes).sum();
    let limits = PackLimits {
        max_entries: u32::try_from(hints.len()).unwrap(),
        max_object_bytes: body.len(),
        max_delta_depth: depth,
        max_cached_bytes: 2 * body.len(),
        max_total_expanded_bytes: expanded,
        max_delta_work: expanded * 4 + raw.len() * 2 + hints.len(),
        ..PackLimits::default()
    };
    let pack = read_verified_pack_owned(
        raw.clone(),
        node.object_format,
        &limits,
        &mut || true,
        &NativeChecksumVerifier,
        node.received_pack_cache().capture_limit(),
    )
    .unwrap();
    let authorized = hints.iter().map(|hint| hint.id).collect();
    History {
        raw,
        pack,
        hints,
        authorized,
        limits,
        depth,
    }
}

#[test]
fn cold_history_recovers_within_the_original_envelope_and_keeps_all_integrity_gates() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node) = node_for(format);
        let history = retained_history(&node);
        let validator = || {
            ProductionQuarantineValidator::new(
                &node,
                selected_closure(history.authorized.clone()),
                history.limits.clone(),
                ParseLimits {
                    max_object_bytes: history.limits.max_object_bytes,
                    tree_reference_bytes: format.digest_len(),
                    ..ParseLimits::default()
                },
            )
            .with_resident_budgets(0, history.limits.max_cached_bytes)
        };
        let restore = |validator: &ProductionQuarantineValidator<'_>,
                       authorized: &BTreeSet<GitOid>| {
            validator.restore_received_pack(
                &history.pack,
                &history.hints,
                authorized,
                &mut ResolutionBudget::new(),
                &mut || true,
            )
        };

        assert!(matches!(
            restore(&validator(), &history.authorized),
            Err(RefusalCode::ResourceBudgetExceeded)
        ));
        let recent = validator().for_received_pack_restoration();
        drop(restore(&recent, &history.authorized).unwrap().unwrap());
        assert_eq!(node.received_pack_cache().retained_entries(), 0);

        // Previously canonical metadata cannot widen the current upload.
        let mut restricted = history.authorized.clone();
        restricted.remove(&history.hints[0].id);
        assert!(restore(&recent, &restricted).unwrap().is_none());

        // Retention shortcuts must not hide the actual native chain depth.
        let mut shallower = validator().for_received_pack_restoration();
        shallower.pack_limits.max_delta_depth = history.depth - 1;
        assert!(restore(&shallower, &history.authorized).unwrap().is_none());

        // The expanded body is still reread and checked against its original
        // commitment even though the full history's compressed bytes survive.
        let path = stored_path(&node, history.hints[0].id);
        let original = fs::read(&path).unwrap();
        let mut corrupt = original.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        fs::write(&path, &corrupt).unwrap();
        assert!(restore(&recent, &history.authorized).unwrap().is_none());
        assert_eq!(fs::read(&path).unwrap(), corrupt);
        assert_eq!(node.received_pack_cache().retained_entries(), 0);
        fs::write(&path, original).unwrap();

        let pending = restore(&recent, &history.authorized).unwrap().unwrap();
        assert_eq!(node.received_pack_cache().retained_entries(), 0);
        pending.commit();
        let keys: Vec<_> = history.hints.iter().copied().map(key).collect();
        let reused = node
            .received_pack_cache()
            .try_reuse(&keys, &history.limits, true, &mut || true)
            .unwrap()
            .unwrap();
        assert_eq!(reused.receipt().maximum_delta_depth(), history.depth);
        assert_eq!(reused.into_bytes().unwrap(), history.raw);
        node.shutdown().unwrap();
    }
}
