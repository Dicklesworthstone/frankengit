use super::*;
fn scan(text: &[u8]) -> Scan {
    extract(text, &mut Budget::new(MAX_WORK).unwrap(), &|| false).unwrap()
}
fn names(bytes: &[u8]) -> Vec<(Kind, Vec<u8>)> {
    scan(bytes)
        .declarations
        .iter()
        .map(|d| {
            (
                d.kind,
                bytes[d.byte_offset..d.byte_offset + d.byte_length].to_vec(),
            )
        })
        .collect()
}
#[test]
fn all_supported_heads_include_associated_and_nested_functions() {
    let raw = concat!(
        "pub async uns",
        "afe fn run<T>() { fn nested() {} } struct Unit; struct Pair(u8); enum E { A } trait T { type A; fn method(); } type Alias = u8; mod inner { union U { value: u8 } } mod external; macro_rules! make { () => { fn generated() {} } }"
    );
    let text = raw.as_bytes();
    assert_eq!(
        names(text),
        vec![
            (Kind::Function, b"run".to_vec()),
            (Kind::Function, b"nested".to_vec()),
            (Kind::Struct, b"Unit".to_vec()),
            (Kind::Struct, b"Pair".to_vec()),
            (Kind::Enum, b"E".to_vec()),
            (Kind::Trait, b"T".to_vec()),
            (Kind::Type, b"A".to_vec()),
            (Kind::Function, b"method".to_vec()),
            (Kind::Type, b"Alias".to_vec()),
            (Kind::Module, b"inner".to_vec()),
            (Kind::Union, b"U".to_vec()),
            (Kind::Module, b"external".to_vec()),
            (Kind::Macro, b"make".to_vec())
        ]
    );
}
#[test]
fn comment_string_attribute_and_macro_text_cannot_fabricate_declarations() {
    let text = br####"// fn hidden() {}
/* struct Fake; /* enum Nested {} */ fn nope() {} */
#[allow(any_tokens(fn fake(), struct Fake))]
fn real() {
 let _ = "fn fake() { \" struct Nope;";
 let _ = r###"fn raw() {} \"## struct Hidden;"###;
 let _ = br#"fn bytes(){}"#; let _ = cr"struct C;";
 crate::call! { fn macro_argument() {} }
}
"####;
    let result = scan(text);
    assert_eq!(names(text), vec![(Kind::Function, b"real".to_vec())]);
    assert_eq!(result.attributes_skipped, 1);
    assert_eq!(result.macro_bodies_skipped, 1);
}
#[test]
fn raw_names_keep_original_byte_span_but_never_act_as_keywords() {
    let text = b"fn r#type() {} struct r#async; fn r#fn() {} r#fn fake() {}";
    let result = scan(text);
    assert_eq!(result.declarations.len(), 3);
    for d in result.declarations {
        assert!(d.raw_identifier);
        assert_eq!(&text[d.byte_offset - 2..d.byte_offset], b"r#");
    }
    assert_eq!(
        names(text)
            .iter()
            .map(|(_, n)| n.as_slice())
            .collect::<Vec<_>>(),
        vec![b"type".as_slice(), b"async", b"fn"]
    );
}
#[test]
fn lifetimes_labels_chars_and_function_pointer_types_are_not_heads() {
    let text = br"fn f<'a>(x: &'a str, cb: fn(u8)) { 'outer: loop { let _ = '{'; let _ = '\''; let _ = b'}'; break 'outer; } } type Callback = for<'a> fn(&'a str);";
    assert_eq!(
        names(text),
        vec![
            (Kind::Function, b"f".to_vec()),
            (Kind::Type, b"Callback".to_vec())
        ]
    );
}
#[test]
fn unicode_literals_comments_and_crlf_preserve_original_byte_coordinates() {
    let text = "// 🦀\r\n  fn r#type() { let _ = 'é'; let _ = \"é\"; }\r\ntrait T {}".as_bytes();
    let result = scan(text);
    let first = result.declarations[0];
    assert_eq!(first.line, 2);
    assert_eq!(first.byte_column, 8);
    assert_eq!(
        &text[first.byte_offset..first.byte_offset + first.byte_length],
        b"type"
    );
    let second = result.declarations[1];
    assert_eq!(second.line, 3);
    assert_eq!(second.byte_column, 7);
}
#[test]
fn unsupported_code_identifiers_and_invalid_utf8_refuse_not_split_into_ascii_names() {
    for text in [
        "fn naïve() {}",
        "fn é() {}",
        "struct Thingé;",
        "fn f<'é>() {}",
    ] {
        assert_eq!(
            extract(
                text.as_bytes(),
                &mut Budget::new(MAX_WORK).unwrap(),
                &|| false
            )
            .unwrap_err()
            .kind,
            ErrorKind::UnsupportedIdentifier
        );
    }
    assert_eq!(
        extract(
            b"// \xff\nfn good(){}",
            &mut Budget::new(MAX_WORK).unwrap(),
            &|| false
        )
        .unwrap_err()
        .kind,
        ErrorKind::InvalidUtf8
    );
}
#[test]
fn unmatched_delimiters_literals_and_nested_comments_fail_the_whole_scan() {
    for text in [
        b"fn good(){} /*".as_slice(),
        b"fn good(){} \"open",
        b"fn good(){} r##\"open\"#",
        b"fn good(){} (]",
        b"fn good(){",
        b"fn good(){} m!{ fn x(){}",
    ] {
        assert!(
            extract(text, &mut Budget::new(MAX_WORK).unwrap(), &|| false).is_err(),
            "{}",
            String::from_utf8_lossy(text)
        );
    }
}
#[test]
fn input_and_aggregate_work_limits_have_exact_success_twins() {
    let text = b"fn f(){}";
    let mut budget = Budget::new(MAX_WORK).unwrap();
    extract(text, &mut budget, &|| false).unwrap();
    let work = budget.work;
    assert!(extract(text, &mut Budget::new(work).unwrap(), &|| false).is_ok());
    assert_eq!(
        extract(text, &mut Budget::new(work - 1).unwrap(), &|| false)
            .unwrap_err()
            .kind,
        ErrorKind::WorkLimit
    );
    let mut shared = Budget::new(work * 2 - 1).unwrap();
    extract(text, &mut shared, &|| false).unwrap();
    assert!(extract(text, &mut shared, &|| false).is_err());
    assert!(Budget::new(0).is_err());
    assert!(Budget::new(MAX_WORK + 1).is_err());
    assert!(
        extract(
            &vec![b' '; MAX_FILE_BYTES],
            &mut Budget::new(MAX_WORK).unwrap(),
            &|| false
        )
        .is_ok()
    );
    assert_eq!(
        extract(
            &vec![b' '; MAX_FILE_BYTES + 1],
            &mut Budget::new(MAX_WORK).unwrap(),
            &|| false
        )
        .unwrap_err()
        .kind,
        ErrorKind::FileLimit
    );
}
#[test]
fn nesting_is_bounded_in_code_comments_and_opaque_trees() {
    for (left, right) in [("(", ")"), ("/*", "*/"), ("m!{", "}")] {
        let text = format!("{}{}", left.repeat(129), right.repeat(129));
        assert_eq!(
            extract(
                text.as_bytes(),
                &mut Budget::new(MAX_WORK).unwrap(),
                &|| false
            )
            .unwrap_err()
            .kind,
            ErrorKind::DepthLimit
        );
    }
    let text = format!("{}{}", "(".repeat(128), ")".repeat(128));
    assert!(
        extract(
            text.as_bytes(),
            &mut Budget::new(MAX_WORK).unwrap(),
            &|| false
        )
        .is_ok()
    );
}
#[test]
fn declaration_and_name_limits_are_shared_and_do_not_silently_truncate() {
    let text = "fn f(){}".repeat(MAX_DECLARATIONS);
    let mut budget = Budget::new(MAX_WORK).unwrap();
    assert_eq!(
        extract(text.as_bytes(), &mut budget, &|| false)
            .unwrap()
            .declarations
            .len(),
        MAX_DECLARATIONS
    );
    assert_eq!(
        extract(b"fn extra(){}", &mut budget, &|| false)
            .unwrap_err()
            .kind,
        ErrorKind::DeclarationLimit
    );
    let yes = format!("fn {}(){{}}", "a".repeat(MAX_NAME_BYTES));
    assert_eq!(scan(yes.as_bytes()).declarations.len(), 1);
    let no = format!("fn {}(){{}}", "a".repeat(MAX_NAME_BYTES + 1));
    assert_eq!(
        extract(no.as_bytes(), &mut Budget::new(MAX_WORK).unwrap(), &|| {
            false
        })
        .unwrap_err()
        .kind,
        ErrorKind::NameLimit
    );
}
#[test]
fn cancellation_during_strings_comments_and_empty_input_is_not_empty_success() {
    for text in [
        b"".to_vec(),
        format!("/*{}*/ fn f(){{}}", "x".repeat(8192)).into_bytes(),
        format!("\"{}\"; fn f(){{}}", "x".repeat(8192)).into_bytes(),
    ] {
        assert_eq!(
            extract(&text, &mut Budget::new(MAX_WORK).unwrap(), &|| true)
                .unwrap_err()
                .kind,
            ErrorKind::Cancelled
        );
        let count = std::cell::Cell::new(0);
        let cancelled = || {
            count.set(count.get() + 1);
            count.get() > 4
        };
        if text.len() > 8192 {
            assert_eq!(
                extract(&text, &mut Budget::new(MAX_WORK).unwrap(), &cancelled)
                    .unwrap_err()
                    .kind,
                ErrorKind::Cancelled
            );
        }
        assert!(extract(&text, &mut Budget::new(MAX_WORK).unwrap(), &|| false).is_ok());
    }
}
#[test]
fn raw_string_hash_count_and_embedded_quotes_are_exact() {
    for hashes in [0, 1, 2, 16, 255] {
        let h = "#".repeat(hashes);
        let text = format!("fn real(){{let _=r{h}\"fn fake(){{}} \\\n\"{h};}}");
        assert_eq!(
            names(text.as_bytes()),
            vec![(Kind::Function, b"real".to_vec())]
        );
    }
    let text = format!("r{}\"x\"{}", "#".repeat(256), "#".repeat(256));
    assert!(
        extract(
            text.as_bytes(),
            &mut Budget::new(MAX_WORK).unwrap(),
            &|| false
        )
        .is_err()
    );
}
#[test]
fn bom_shebang_inner_attributes_and_cfg_disabled_heads_are_explicit() {
    let text=b"\xef\xbb\xbf#!/usr/bin/env rust-script\n#![allow(dead_code)]\n#[cfg(any())]\nfn disabled(){}\nfn enabled(){}";
    assert_eq!(
        names(text),
        vec![
            (Kind::Function, b"disabled".to_vec()),
            (Kind::Function, b"enabled".to_vec())
        ]
    );
    assert_eq!(scan(text).attributes_skipped, 2);
}
#[test]
fn constants_generics_fields_references_and_type_uses_are_not_supported_heads() {
    let text=b"const VALUE: u8=0; static STATIC:u8=0; fn f<const N:usize>() { let x=Thing {}; } struct Thing {field:u8} impl Thing { fn method(){} }";
    assert_eq!(
        names(text),
        vec![
            (Kind::Function, b"f".to_vec()),
            (Kind::Struct, b"Thing".to_vec()),
            (Kind::Function, b"method".to_vec())
        ]
    );
}
#[test]
fn string_suffixes_and_numbers_cannot_be_misread_as_declaration_keywords() {
    let text = b"\"text\"fn Fake(){} 42fn Fake(){} fn real(){}";
    assert_eq!(names(text), vec![(Kind::Function, b"real".to_vec())]);
}
#[test]
fn unary_not_blocks_are_not_treated_as_macros() {
    let text = b"fn f(){ if !{ fn inside(){} true } {} }";
    assert_eq!(
        names(text),
        vec![
            (Kind::Function, b"f".to_vec()),
            (Kind::Function, b"inside".to_vec())
        ]
    );
}
#[test]
fn declaration_headers_can_cross_comments_and_physical_lines() {
    let text=b"pub(in crate) async fn /* comment */\nthing\n<T>() {} struct\nS\nwhere T: Copy {} trait A: Send {} type T: Clone;";
    let all = scan(text);
    assert_eq!(all.declarations.len(), 4);
    assert_eq!(all.declarations[0].line, 2);
}
#[test]
fn identifier_shaped_macros_skip_all_three_group_forms_and_raw_names() {
    let text=b"m!(fn a(){});m![struct B;];path::r#fn!{trait C{}} macro_rules! maker ( () => { fn generated(){} } ); fn real(){}";
    assert_eq!(
        names(text),
        vec![
            (Kind::Macro, b"maker".to_vec()),
            (Kind::Function, b"real".to_vec())
        ]
    );
    assert_eq!(scan(text).macro_bodies_skipped, 4);
}
#[test]
fn repeated_scans_have_identical_order_offsets_and_work() {
    let text = b"mod z{fn a(){}} mod a{fn z(){}} fn r#async(){}";
    let mut a = Budget::new(MAX_WORK).unwrap();
    let first = extract(text, &mut a, &|| false).unwrap();
    let mut b = Budget::new(MAX_WORK).unwrap();
    assert_eq!(extract(text, &mut b, &|| false).unwrap(), first);
    assert_eq!(a.work, b.work);
    assert!(
        first
            .declarations
            .windows(2)
            .all(|d| d[0].byte_offset < d[1].byte_offset)
    );
}
#[test]
fn hostile_byte_corpus_never_panics_or_returns_out_of_bounds_spans() {
    let mut seed = 0x123456789abcdefu64;
    for length in 0..128 {
        for _ in 0..32 {
            let mut bytes = Vec::new();
            for _ in 0..length {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                bytes.push((seed >> 32) as u8);
            }
            if let Ok(out) = extract(&bytes, &mut Budget::new(MAX_WORK).unwrap(), &|| false) {
                for d in out.declarations {
                    assert!(d.byte_length > 0);
                    assert!(d.byte_offset + d.byte_length <= bytes.len());
                }
            }
        }
    }
}
#[test]
fn generated_supported_heads_match_an_independent_name_position_oracle() {
    for (word, tail, kind) in [
        ("fn", "() {}", Kind::Function),
        ("struct", ";", Kind::Struct),
        ("enum", "{ }", Kind::Enum),
        ("mod", ";", Kind::Module),
        ("trait", "{}", Kind::Trait),
        ("type", "=u8;", Kind::Type),
        ("union", "{x:u8}", Kind::Union),
    ] {
        for gap in [" ", "\n", "/* fake fn hidden(){} */"] {
            for raw in ["", "r#"] {
                let text = format!("// fn ignored(){{}}\n{word}{gap}{raw}Target{tail}");
                let found = scan(text.as_bytes());
                assert_eq!(found.declarations.len(), 1);
                let d = found.declarations[0];
                assert_eq!(d.kind, kind);
                assert_eq!(d.byte_offset, text.find("Target").unwrap());
                assert_eq!(d.byte_length, 6);
            }
        }
    }
}
