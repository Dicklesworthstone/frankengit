import pathlib,sys
root=pathlib.Path.cwd(); payload=pathlib.Path(sys.argv[1])
p=root/'crates/fgit-wire/src/lib.rs'; text=p.read_text()
start=text.index('pub fn parse_filter(\n'); end=text.index('fn validate_opaque_path(',start)
text=text[:start]+'''pub fn parse_filter(
    text: &[u8], object_format: GitObjectFormat, limits: &WireLimits,
) -> Result<ObjectFilter, WireError> {
    filter_syntax::parse(text, object_format, limits)
}

'''+text[end:]
old='''            .any(|reference| reference.oid == oid)
        {
            return Err(WireError::WantNotAdvertised { oid });
        }'''
new='''            .any(|reference| reference.oid == oid)
            && !(self.server_capabilities.contains(b"allow-reachable-sha1-in-want")
                && repository.contains_want(oid))
        {
            return Err(WireError::WantNotAdvertised { oid });
        }'''
assert text.count(old)==1
text=text.replace(old,new)
text=text.replace('pub mod closure;','pub mod closure;\nmod filter_syntax;',1)
p.write_text(text)
for source,dest in [('filter_syntax.rs','crates/fgit-wire/src/filter_syntax.rs'),('wire_tests.rs','crates/fgit-wire/tests/partial_clone_filter_syntax.rs')]:
    path=root/dest; assert not path.exists(); path.write_text((payload/source).read_text())
