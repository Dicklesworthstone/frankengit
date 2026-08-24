#![forbid(unsafe_code)]

mod fixtures;

use fgit_pack::{
    DeltaObject, ExternalBaseLookup, ObjectFormat, ObjectId, PackError, PackLimits, PackObject,
    ScalarResolver, apply_delta, parse_quarantined_pack,
};
use fgit_types::native::GitOidSha1;

fn oid(byte: u8) -> ObjectId {
    GitOidSha1::from_bytes([byte; 20]).into()
}

fn copy_one_delta() -> Vec<u8> {
    vec![1, 1, 0x90, 1]
}

fn delta_entry(kind: u8, base: &[u8], program: &[u8]) -> Vec<u8> {
    assert!(matches!(kind, 6 | 7), "delta pack entry kind");
    assert!(
        program.len() < 16,
        "small program uses one-byte pack header"
    );
    let mut entry = vec![kind << 4 | u8::try_from(program.len()).expect("small program")];
    entry.extend_from_slice(base);
    let length = u16::try_from(program.len()).expect("small stored program");
    entry.extend_from_slice(&[0x78, 0x01, 0x01]);
    entry.extend_from_slice(&length.to_le_bytes());
    entry.extend_from_slice(&(!length).to_le_bytes());
    entry.extend_from_slice(program);
    entry.extend_from_slice(&adler32(program).to_be_bytes());
    entry
}

fn adler32(bytes: &[u8]) -> u32 {
    let mut a = 1_u32;
    let mut b = 0_u32;
    for &byte in bytes {
        a = (a + u32::from(byte)) % 65_521;
        b = (b + a) % 65_521;
    }
    (b << 16) | a
}

fn parsed_objects(entries: &[Vec<u8>]) -> Vec<PackObject> {
    parse_quarantined_pack(
        &fixtures::pack_with_entries(entries),
        ObjectFormat::Sha1,
        &fixtures::limits(),
        &mut fixtures::always,
    )
    .expect("programmatically constructed bounded delta pack")
    .into_scalar_objects(|_| None)
    .expect("parsed quarantine entries convert to scalar inputs")
}

#[test]
fn deep_ofs_chain_hits_depth_accounting_before_resolver_stack_growth() {
    let base = fixtures::entry(3, b"x");
    let mut entries = vec![base];
    let mut previous_offset = 12_usize;
    let mut current_offset = previous_offset + entries[0].len();
    for _ in 0..3 {
        let distance = current_offset
            .checked_sub(previous_offset)
            .expect("programmatic entries stay forward ordered");
        let distance = u8::try_from(distance).expect("short fixture OFS distance");
        let entry = delta_entry(6, &[distance], &copy_one_delta());
        previous_offset = current_offset;
        current_offset = current_offset
            .checked_add(entry.len())
            .expect("short fixture offset");
        entries.push(entry);
    }
    let objects = parsed_objects(&entries);
    let target = u64::try_from(previous_offset).expect("fixture offset fits u64");

    let mut shallow = fixtures::limits();
    shallow.max_delta_depth = 2;
    let resolver =
        ScalarResolver::new(&objects, &(), &shallow, &mut fixtures::always).expect("shape");
    assert_eq!(
        resolver.resolve_offset(target, &mut fixtures::always),
        Err(PackError::DeltaDepthLimit { depth: 3, limit: 2 })
    );

    shallow.max_delta_depth = 3;
    let resolver =
        ScalarResolver::new(&objects, &(), &shallow, &mut fixtures::always).expect("shape");
    assert_eq!(
        resolver.resolve_offset(target, &mut fixtures::always),
        Ok(b"x".to_vec())
    );
}

#[test]
fn ofs_fanout_refusal_has_a_one_child_pack_near_neighbor() {
    let base = fixtures::entry(3, b"x");
    let base_offset = 12_usize;
    let first_offset = base_offset + base.len();
    let first_distance = u8::try_from(first_offset - base_offset).expect("short fixture distance");
    let first = delta_entry(6, &[first_distance], &copy_one_delta());
    let second_offset = first_offset + first.len();
    let second_distance =
        u8::try_from(second_offset - base_offset).expect("short fixture distance");
    let second = delta_entry(6, &[second_distance], &copy_one_delta());
    let objects = parsed_objects(&[base.clone(), first.clone(), second]);

    let mut narrow = fixtures::limits();
    narrow.max_delta_fanout = 1;
    let resolver =
        ScalarResolver::new(&objects, &(), &narrow, &mut fixtures::always).expect("shape");
    assert_eq!(
        resolver.resolve_offset(
            u64::try_from(first_offset).expect("fixture offset fits u64"),
            &mut fixtures::always,
        ),
        Err(PackError::DeltaFanoutLimit {
            fanout: 2,
            limit: 1,
        })
    );

    let one_child = parsed_objects(&[base, first]);
    let resolver =
        ScalarResolver::new(&one_child, &(), &narrow, &mut fixtures::always).expect("shape");
    assert_eq!(
        resolver.resolve_offset(
            u64::try_from(first_offset).expect("fixture offset fits u64"),
            &mut fixtures::always,
        ),
        Ok(b"x".to_vec())
    );
}

struct OneExternalBase {
    id: ObjectId,
    bytes: Vec<u8>,
}

impl ExternalBaseLookup for OneExternalBase {
    fn lookup(&self, id: &ObjectId) -> Option<&[u8]> {
        (id == &self.id).then_some(&self.bytes)
    }
}

#[test]
fn ref_cycle_and_thin_base_refusals_have_resolvable_near_neighbors() {
    let first_id = oid(1);
    let second_id = oid(2);
    let cyclic = parsed_objects(&[
        delta_entry(7, second_id.as_bytes(), &copy_one_delta()),
        delta_entry(7, first_id.as_bytes(), &copy_one_delta()),
    ]);
    let mut cyclic = cyclic;
    let first_ref_offset = match &cyclic[0] {
        PackObject::Base { offset, .. }
        | PackObject::TypedBase { offset, .. }
        | PackObject::Delta(DeltaObject { offset, .. }) => *offset,
    };
    if let PackObject::Delta(delta) = &mut cyclic[0] {
        delta.id = Some(first_id);
    }
    if let PackObject::Delta(delta) = &mut cyclic[1] {
        delta.id = Some(second_id);
    }
    {
        let limits = fixtures::limits();
        let resolver = ScalarResolver::new(&cyclic, &(), &limits, &mut fixtures::always)
            .expect("cycle is structurally bounded input");
        assert_eq!(
            resolver.resolve_offset(first_ref_offset, &mut fixtures::always),
            Err(PackError::DeltaCycle)
        );
    }

    let permitted_first_id = oid(1);
    let permitted_second_id = oid(2);
    let mut base_backed = parsed_objects(&[
        delta_entry(7, permitted_second_id.as_bytes(), &copy_one_delta()),
        fixtures::entry(3, b"x"),
    ]);
    if let PackObject::Delta(delta) = &mut base_backed[0] {
        delta.id = Some(permitted_first_id);
    }
    if let PackObject::Base { id, .. } | PackObject::TypedBase { id, .. } = &mut base_backed[1] {
        *id = Some(permitted_second_id);
    }
    let limits = fixtures::limits();
    let resolver = ScalarResolver::new(&base_backed, &(), &limits, &mut fixtures::always)
        .expect("base-backed REF near-neighbor is structurally bounded");
    assert_eq!(
        resolver.resolve_offset(12, &mut fixtures::always),
        Ok(b"x".to_vec())
    );

    let missing_id = oid(3);
    let thin = parsed_objects(&[delta_entry(7, missing_id.as_bytes(), &copy_one_delta())]);
    {
        let limits = fixtures::limits();
        let resolver = ScalarResolver::new(&thin, &(), &limits, &mut fixtures::always)
            .expect("thin pack stays parseable in quarantine");
        assert_eq!(
            resolver.resolve_offset(12, &mut fixtures::always),
            Err(PackError::MissingDeltaBase)
        );
    }

    let external = OneExternalBase {
        id: missing_id,
        bytes: b"x".to_vec(),
    };
    let limits = fixtures::limits();
    let resolver =
        ScalarResolver::new(&thin, &external, &limits, &mut fixtures::always).expect("thin shape");
    assert_eq!(
        resolver.resolve_offset(12, &mut fixtures::always),
        Ok(b"x".to_vec())
    );
}

#[test]
fn raw_delta_size_and_chain_work_bombs_refuse_before_result_allocation() {
    // A Git delta program is not compressed input: this nine-byte copy
    // instruction reconstructs 30,733 bytes, a shape produced by Git 2.54.0.
    let base = vec![0_u8; 30_733];
    let copy_all = vec![0x8d, 0xf0, 0x01, 0x8d, 0xf0, 0x01, 0xb0, 0x0d, 0x78];

    let accepted = apply_delta(
        &base,
        &copy_all,
        &PackLimits::default(),
        &mut fixtures::always,
    );
    assert_eq!(
        accepted,
        Ok(base.clone()),
        "ordinary high-copy delta remains admissible under the default resource policy"
    );

    let mut total_limited = fixtures::limits();
    total_limited.max_object_bytes = base.len();
    total_limited.max_total_expanded_bytes = base.len() * 2 - 1;
    assert_eq!(
        apply_delta(&base, &copy_all, &total_limited, &mut fixtures::always),
        Err(PackError::TotalExpandedLimit {
            actual: base.len() * 2,
            limit: base.len() * 2 - 1,
        })
    );

    let mut work_limited = fixtures::limits();
    work_limited.max_object_bytes = base.len();
    work_limited.max_total_expanded_bytes = base.len() * 2;
    work_limited.max_delta_work = base.len() - 1;
    assert_eq!(
        apply_delta(&base, &copy_all, &work_limited, &mut fixtures::always),
        Err(PackError::DeltaWorkLimit {
            attempted: base.len(),
            limit: base.len() - 1,
        })
    );
}
