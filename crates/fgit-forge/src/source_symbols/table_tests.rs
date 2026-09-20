use super::*;
fn build(bytes: &[u8]) -> Table { Table::build(bytes, &mut Budget::new(engine::MAX_WORK).unwrap(), &|| false).unwrap() }
fn find(table: &Table, name: &[u8], prefix: bool, kinds: &[Kind]) -> Vec<Vec<u8>> {
    table.lookup(name, prefix, kinds, &mut Work::new(engine::MAX_WORK).unwrap(), &|| false).unwrap()
        .into_iter().map(|i| table.rows()[i].name.clone()).collect()
}
#[test]
fn persisted_rows_keep_raw_identifiers_offsets_excerpts_and_exclusions() {
    let source = b"// fn fake() {}\r\n#[cfg(any())]\npub struct Thing;\nfn r#type() {}\nfn ThingMore() {}\nmacro_rules! m {() => { fn hidden() {} }}\n";
    let table = build(source); let raw = table.encode(&|| false).unwrap();
    let decoded = Table::decode(&raw, &|| false).unwrap(); assert_eq!(decoded, table);
    assert_eq!(table.rows().len(), 4); assert_eq!(table.macros, 1); assert_eq!(table.attributes, 1);
    assert_eq!(find(&decoded, b"Thing", true, &[]), vec![b"Thing".to_vec(), b"ThingMore".to_vec()]);
    assert!(find(&decoded, b"fake", false, &[]).is_empty());
    for row in decoded.rows() {
        assert_eq!(&source[row.offset..row.offset + row.name.len()], row.name);
        assert_eq!(&source[row.excerpt_offset..row.excerpt_offset + row.excerpt.len()], row.excerpt);
    }
    assert!(decoded.rows()[1].raw);
}
#[test]
fn prefix_dictionary_results_preserve_source_order_not_name_order() {
    let table = build(b"fn Zoo() {} struct Zed; fn Zoo() {} fn Alpha() {} fn _one() {}\n");
    assert_eq!(find(&table, b"Z", true, &[]), vec![b"Zoo".to_vec(), b"Zed".to_vec(), b"Zoo".to_vec()]);
    assert_eq!(find(&table, b"Zoo", false, &[Kind::Struct]), Vec::<Vec<u8>>::new());
    assert_eq!(find(&table, b"Z", true, &[Kind::Struct]), vec![b"Zed".to_vec()]);
    assert_eq!(find(&table, b"_", true, &[]), vec![b"_one".to_vec()]);
    assert!(find(&table, b"z", true, &[]).is_empty());
}
#[test]
fn all_prefixes_and_kind_filters_agree_with_scalar_entry_oracle() {
    let source: String = (0..200).map(|i| format!("{} Name{:03}{}\n", if i % 2 == 0 {"fn"} else {"struct"}, 199-i,
        if i % 2 == 0 {"() {}"} else {";"})).collect();
    let table = build(source.as_bytes());
    let table = Table::decode(&table.encode(&|| false).unwrap(), &|| false).unwrap();
    for name in [b"Name".as_slice(), b"Name0", b"Name001", b"Missing", b"Name199"] {
        for prefix in [false, true] { for kinds in [vec![], vec![Kind::Function], vec![Kind::Struct], vec![Kind::Macro]] {
            let expected: Vec<_> = table.rows().iter().filter(|r|
                (if prefix {r.name.starts_with(name)} else {r.name == name}) && (kinds.is_empty() || kinds.contains(&r.kind)))
                .map(|r| r.name.clone()).collect();
            assert_eq!(find(&table, name, prefix, &kinds), expected);
        }}
    }
}
#[test]
fn every_truncation_and_suffix_is_rejected_without_a_partial_table() {
    let raw = build(b"struct One; fn Two() {}\n").encode(&|| false).unwrap();
    for n in 0..raw.len() { assert!(Table::decode(&raw[..n], &|| false).is_err(), "cut {n}"); }
    for suffix in [b"\0".as_slice(), b"\n", b"next-table"] {
        assert!(Table::decode(&[raw.as_slice(), suffix].concat(), &|| false).is_err());
    }
}
#[test]
fn hostile_count_tag_span_and_name_substitutions_are_rejected() {
    let original = build(b"fn valid() {}\n").encode(&|| false).unwrap();
    let start = MAGIC.len() + 16;
    for (offset, value) in [(MAGIC.len()+12, 255), (start, 255), (start+1, 2),
        (start+2, 255), (start+4, 255), (start+8, 0), (start+12, 0), (start+20, 255), (start+22, b'!')]
    {
        let mut raw = original.clone(); raw[offset] = value;
        assert!(Table::decode(&raw, &|| false).is_err(), "field {offset}");
    }
}
#[test]
fn empty_tables_and_literal_only_sources_are_initialized_empty_values() {
    for source in [b"".as_slice(), b"// fn hidden() {}\n", b"const TEXT: &str = \"fn hidden() {}\";\n"] {
        let table = build(source); assert!(table.rows().is_empty());
        assert_eq!(Table::decode(&table.encode(&|| false).unwrap(), &|| false).unwrap(), table);
        assert!(find(&table, b"hidden", false, &[]).is_empty());
    }
}
#[test]
fn utf8_comments_and_crlf_do_not_change_native_byte_coordinates() {
    let source = "// 🦀\r\nfn Café() {}".as_bytes();
    assert!(matches!(Table::build(source, &mut Budget::new(engine::MAX_WORK).unwrap(), &|| false), Err(Error::Syntax(_))));
    let source = "// 🦀\r\nfn Good() {}\r\n".as_bytes();
    let table = build(source); let row = &table.rows()[0];
    assert_eq!(row.line, 2); assert_eq!(row.column, 4); assert_eq!(&source[row.offset..row.offset+4], b"Good");
    assert_eq!(Table::decode(&table.encode(&|| false).unwrap(), &|| false).unwrap(), table);
}
#[test]
fn cancellation_is_not_a_missing_table_or_successful_empty_lookup() {
    let table = build(b"fn Found() {}\n"); let raw = table.encode(&|| false).unwrap();
    assert!(matches!(Table::decode(&raw, &|| true), Err(Error::Cancelled)));
    assert!(matches!(table.encode(&|| true), Err(Error::Cancelled)));
    assert!(matches!(table.lookup(b"Found", false, &[], &mut Work::new(engine::MAX_WORK).unwrap(), &|| true), Err(Error::Cancelled)));
    assert!(Table::build(b"", &mut Budget::new(engine::MAX_WORK).unwrap(), &|| true).is_err());
}
#[test]
fn query_work_is_shared_and_has_an_exact_success_boundary() {
    let table = build(b"fn One() {} fn One() {} fn Other() {}\n");
    let mut measured = Work::new(engine::MAX_WORK).unwrap();
    table.lookup(b"O", true, &[], &mut measured, &|| false).unwrap();
    let exact = measured.used;
    assert!(table.lookup(b"O", true, &[], &mut Work::new(exact).unwrap(), &|| false).is_ok());
    assert!(table.lookup(b"O", true, &[], &mut Work::new(exact-1).unwrap(), &|| false).is_err());
    let mut shared = Work::new(exact).unwrap();
    table.lookup(b"O", true, &[], &mut shared, &|| false).unwrap();
    assert!(table.lookup(b"Absent", true, &[], &mut shared, &|| false).is_err());
    for limit in [0, engine::MAX_WORK+1] { assert!(Work::new(limit).is_err()); }
}
#[test]
fn table_byte_limits_and_invalid_source_never_silently_omit_declarations() {
    assert!(Table::decode(&vec![0; MAX_BYTES+1], &|| false).is_err());
    for source in [b"fn Good() {} /* open".as_slice(), b"fn Good() {} {", b"fn Good() {} \xff"] {
        assert!(Table::build(source, &mut Budget::new(engine::MAX_WORK).unwrap(), &|| false).is_err());
    }
    let source: String = (0..8000).map(|i| format!("fn Name{i:05}{}() {{}}\n", "x".repeat(100))).collect();
    assert!(matches!(Table::build(source.as_bytes(), &mut Budget::new(engine::MAX_WORK).unwrap(), &|| false), Err(Error::Limit("table bytes"))));
}
#[test]
fn repeated_builds_have_identical_canonical_bytes_and_search_work() {
    let source = b"fn Outer() { fn Inner() {} } struct Item;\n";
    let first = build(source); let second = build(source);
    assert_eq!(first.encode(&|| false).unwrap(), second.encode(&|| false).unwrap());
    let mut a = Work::new(engine::MAX_WORK).unwrap(); let mut b = Work::new(engine::MAX_WORK).unwrap();
    assert_eq!(first.lookup(b"I", true, &[], &mut a, &|| false).unwrap(), second.lookup(b"I", true, &[], &mut b, &|| false).unwrap());
    assert_eq!(a.used, b.used);
}
#[test]
fn raw_name_prefix_is_checked_and_query_underscore_is_admitted() {
    let mut table = build(b"fn r#type() {} fn _thing() {}\n");
    assert_eq!(find(&table, b"_", true, &[]), vec![b"_thing".to_vec()]);
    assert!(find(&table, b"_", false, &[]).is_empty());
    let at = table.rows[0].offset - table.rows[0].excerpt_offset - 1;
    table.rows[0].excerpt[at] = b'!';
    assert!(table.encode(&|| false).is_err());
}
