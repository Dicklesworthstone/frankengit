//! Structural fixtures are NOT valid compressed Git objects. Decoder doubles
//! below establish adapter contracts only; native composition tests decode Git.
use super::*;
use crate::patch::{PatchedFile, UnifiedPatch};
use std::cell::Cell;
const MEMBER: &str = "literal 3\nC00000\n\n";
fn patch(width: usize, mode: &str, old: char, new: char, payload: &str) -> String {
    format!("diff --git a/file b/file\n{mode}index {}..{}\nGIT binary patch\n{payload}",
        old.to_string().repeat(width), new.to_string().repeat(width))
}
fn parse(bytes: &[u8]) -> Result<UnifiedPatch<'_>, PatchError> {
    UnifiedPatch::parse_with_binary(bytes, PatchLimits::default(), &|| false)
}
#[test]
fn defaults_refuse_and_opt_in_retains_exact_borrowed_payload() {
    for width in [40, 64] {
        let input = patch(width, "", 'a', 'b', &(MEMBER.to_owned() + MEMBER));
        assert!(UnifiedPatch::parse(input.as_bytes(), PatchLimits::default(), &|| false).is_err());
        assert!(UnifiedPatch::parse_with_renames(input.as_bytes(), PatchLimits::default(), &|| false).is_err());
        let parsed = parse(input.as_bytes()).unwrap(); let file = &parsed.files()[0];
        let body = file.binary_hunks().unwrap();
        assert_eq!(body.bytes(), format!("GIT binary patch\n{MEMBER}{MEMBER}").as_bytes());
        assert_eq!(body.bytes().as_ptr(), input.as_bytes()[input.find("GIT binary patch").unwrap()..].as_ptr());
        assert_eq!(file.hunk_count(), 2);
        assert!(matches!(file.apply(Some((0o100644, b"old")), parsed.limits(), &|| false),
            Err(PatchError::Unsupported { .. })));
    }
}
#[test]
fn full_index_domains_and_presence_cannot_be_reinterpreted() {
    for (width, mode, old, new) in [(7,"",'a','b'),(63,"",'a','b'),(40,"",'0','b'),
        (40,"new file mode 100644\n",'a','b'),(40,"deleted file mode 100644\n",'a','b'),
        (40,"new file mode 100644\n",'0','0')] {
        assert!(parse(patch(width,mode,old,new,MEMBER).as_bytes()).is_err());
    }
    let good = patch(40,"",'a','b',MEMBER);
    assert!(parse(good.replace(&"b".repeat(40), &"b".repeat(64)).as_bytes()).is_err());
    assert!(parse(good.replace(&format!("index {}..{}\n", "a".repeat(40), "b".repeat(40)), "").as_bytes()).is_err());
}
#[test]
fn exact_create_modify_delete_and_empty_vs_absent() {
    for (mode, old, new, source, expected) in [
        ("new file mode 100755\n", '0','b',None,Some(PatchedFile { mode:0o100755,content:vec![] })),
        ("old mode 100644\nnew mode 100755\n",'a','b',Some((0o100644,b"old".as_slice())),Some(PatchedFile{mode:0o100755,content:vec![]})),
        ("deleted file mode 100644\n",'a','0',Some((0o100644,b"old".as_slice())),None),
    ] {
        let input=patch(40,mode,old,new,MEMBER);let parsed=parse(input.as_bytes()).unwrap();
        let mut called=false;
        let result=parsed.files()[0].apply_with_binary_decoder(source,parsed.limits(),&||false,|body,index,base| {
            called=true; assert!(body.starts_with(b"GIT binary patch\n"));assert_eq!(index.old.len(),40);
            assert_eq!(base,source.map_or(b"".as_slice(),|(_,bytes)|bytes)); Ok(vec![])
        }).unwrap();
        assert!(called);assert_eq!(result,expected);
    }
}
#[test]
fn decoder_failures_and_bad_results_never_become_unchanged_success() {
    let input=patch(40,"",'a','b',MEMBER);let parsed=parse(input.as_bytes()).unwrap();let file=&parsed.files()[0];
    assert_eq!(file.apply_with_binary_decoder(Some((0o100644,b"old")),parsed.limits(),&||false,
        |_,_,_| Err(PatchError::Cancelled)),Err(PatchError::Cancelled));
    assert!(file.apply_with_binary_decoder(Some((0o100644,b"old")),PatchLimits{max_output_bytes:3,..parsed.limits()},
        &||false,|_,_,_|Ok(vec![0;4])).is_err());
    let input=patch(40,"deleted file mode 100644\n",'a','0',MEMBER);let parsed=parse(input.as_bytes()).unwrap();
    assert_eq!(parsed.files()[0].apply_with_binary_decoder(Some((0o100644,b"old")),parsed.limits(),&||false,
        |_,_,_|Ok(vec![0])),Err(PatchError::NonemptyDeletion));
}
#[test]
fn source_modes_presence_and_narrowed_limits_precede_decoder() {
    let input=patch(40,"old mode 100644\nnew mode 100755\n",'a','b',MEMBER);let parsed=parse(input.as_bytes()).unwrap();
    for (source,limits) in [(None,parsed.limits()),(Some((0o100755,b"old".as_slice())),parsed.limits()),
        (Some((0o100644,b"old".as_slice())),PatchLimits{max_file_bytes:2,..parsed.limits()}),
        (Some((0o100644,b"old".as_slice())),PatchLimits{max_lines:3,..parsed.limits()}),
        (Some((0o100644,b"old".as_slice())),PatchLimits{max_patch_bytes:8,..parsed.limits()})] {
        assert!(parsed.files()[0].apply_with_binary_decoder(source,limits,&||false,|_,_,_|panic!("must not decode")).is_err());
    }
}
#[test]
fn cancellation_after_decoder_cannot_return_a_candidate() {
    let input=patch(40,"",'a','b',MEMBER);let parsed=parse(input.as_bytes()).unwrap();let cancelled=Cell::new(false);
    assert_eq!(parsed.files()[0].apply_with_binary_decoder(Some((0o100644,b"old")),parsed.limits(),&||cancelled.get(),
        |_,_,_|{cancelled.set(true);Ok(vec![0,255])}),Err(PatchError::Cancelled));
    assert_eq!(UnifiedPatch::parse_with_binary(input.as_bytes(),parsed.limits(),&||true),Err(PatchError::Cancelled));
}
#[test]
fn truncated_extra_or_mixed_records_refuse() {
    for payload in ["", "literal 3\n\n", "literal 03\nC00000\n\n", "delta -1\nC00000\n\n",
        "literal 3\nC00000\n", "literal 3\nC0000\n\n", "literal 3\nC0000/\n\n",
        "literal 3\n000000\n\n", "literal 3\nC00000\n\ntrailer\n", "literal 3\nC00000\n\n@@ -1 +1 @@\n"] {
        assert!(parse(patch(40,"",'a','b',payload).as_bytes()).is_err(),"{payload}");
    }
    assert!(parse(patch(40,"",'a','b',&MEMBER.repeat(3)).as_bytes()).is_err());
    let input=patch(40,"",'a','b',MEMBER).replace("GIT binary patch\n", "--- a/file\n+++ b/file\nGIT binary patch\n");
    assert!(parse(input.as_bytes()).is_err());
}
#[test]
fn binary_and_literal_files_share_global_paths_and_budgets() {
    let binary=patch(40,"",'a','b',MEMBER);
    let text="diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1 +1 @@\n-old\n+new\n";
    let input=binary.clone()+text;let parsed=parse(input.as_bytes()).unwrap();
    assert_eq!(parsed.files().len(),2);assert_eq!(parsed.files()[0].path(),b"a");
    assert_eq!(parsed.files()[0].apply_with_binary_decoder(Some((0o100644,b"old\n")),parsed.limits(),&||false,
        |_,_,_|panic!("literal file" )).unwrap().unwrap().content,b"new\n");
    assert_eq!(parse((binary.clone()+&binary).as_bytes()),Err(PatchError::DuplicatePath));
    assert_eq!(parse((binary+&text.replace("a/a b/a","a/file/child b/file/child").replace("--- a/a", "--- a/file/child").replace("+++ b/a","+++ b/file/child")).as_bytes()),Err(PatchError::OverlappingPaths));
    let input=patch(40,"",'a','b',&MEMBER.repeat(2));
    assert!(UnifiedPatch::parse_with_binary(input.as_bytes(),PatchLimits{max_hunks:1,..Default::default()},&||false).is_err());
    let input=patch(40,"",'a','b',MEMBER)+&patch(40,"",'a','b',MEMBER).replace("a/file b/file","a/other b/other");
    assert!(UnifiedPatch::parse_with_binary(input.as_bytes(),PatchLimits{max_output_bytes:5,..Default::default()},&||false).is_err());
}
#[test]
fn raw_paths_are_exact_and_rename_is_not_implicitly_enabled() {
    let input=patch(40,"",'a','b',MEMBER).replace("a/file b/file","\"a/dir/\\377\" \"b/dir/\\377\"");
    assert_eq!(parse(input.as_bytes()).unwrap().files()[0].path(),b"dir/\xff");
    let rename=patch(40,"rename from file\nrename to other\n",'a','b',MEMBER).replace("a/file b/file","a/file b/other");
    assert!(parse(rename.as_bytes()).is_err());
    for mode in ["new file mode 120000\n","new file mode 160000\n"] {
        assert!(parse(patch(40,mode,'0','b',MEMBER).as_bytes()).is_err());
    }
}
#[test]
fn delta_size_is_a_program_bound_and_binary_output_is_not_line_split() {
    let input=patch(64,"",'a','b',"delta 3\nC00000\n\n");let parsed=parse(input.as_bytes()).unwrap();
    let file=&parsed.files()[0];assert_eq!(file.binary_hunks().unwrap().declared_inflated_bytes(),3);
    assert_eq!(file.apply_with_binary_decoder(Some((0o100644,b"old")),parsed.limits(),&||false,
        |_,_,_|Ok(vec![0,255,10,0])).unwrap().unwrap().content,vec![0,255,10,0]);
}
