use super::*;

#[test]
fn quoted_octal_escapes_decode_every_byte_without_intermediate_overflow() {
    for byte in 0u8..=255 {
        let input=format!("\"\\{byte:03o}\"");
        let (decoded,consumed)=unquote(input.as_bytes(),0).unwrap();
        assert_eq!(decoded,[byte]);assert_eq!(consumed,input.len());
    }
    for bad in [b"\"\\400\"".as_slice(),b"\"\\999\"",b"\"\\38x\"",b"\"\\3",b"\"\\377"] {
        assert!(matches!(unquote(bad,0),Err(PatchError::Syntax{..})));
    }
}

#[test]
fn high_byte_filename_creation_parses_and_applies_exactly() {
    let input=b"diff --git \"a/\\377\" \"b/\\377\"\nnew file mode 100644\n--- /dev/null\n+++ \"b/\\377\"\n@@ -0,0 +1 @@\n+body\n";
    let limits=PatchLimits::default();let patch=UnifiedPatch::parse(input,limits,&||false).unwrap();
    assert_eq!(patch.files()[0].path(),[255]);
    assert_eq!(patch.files()[0].apply(None,limits,&||false).unwrap().unwrap().content,b"body\n");
}
