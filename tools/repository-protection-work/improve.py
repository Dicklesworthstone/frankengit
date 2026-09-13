import pathlib,sys
root=pathlib.Path.cwd();payload=pathlib.Path(sys.argv[1]).resolve()
def replace(name,old,new):
 p=root/name;text=p.read_text();assert text.count(old)==1,(name,old[:80],text.count(old))
 p.write_text(text.replace(old,new))
replace('crates/fgit-forge/tests/atomic_merge.rs','for unknown in [0_u32, 9, 99, u32::from(u16::MAX)]','for unknown in [0_u32, 10, 99, u32::from(u16::MAX)]')
p='crates/fgit-forge/src/event/protection.rs'
replace(p,'        let mut count = 0;\n        let branches = input.read_sequence','        check_count(input, "protection.branches", MAX_PROTECTED_BRANCHES)?;\n        let mut count = 0;\n        let branches = input.read_sequence')
replace(p,'    let mut count = 0;\n    let values = input.read_sequence','    check_count(input, "protection.principals", limit)?;\n    let mut count = 0;\n    let values = input.read_sequence')
replace(p,'fn validate_principals(values:', '''fn check_count(input: &Decoder<'_>, field: &'static str, limit: usize) -> Result<(), CodecRefusal> {
    // Peek the framing count before the generic decoder can reserve its Vec.
    // The original decoder still owns depth, byte and truncation checks.
    let mut probe = input.clone();
    let observed = u64::from(probe.read_scalar::<u32>(field)?);
    if observed > limit as u64 {
        return Err(CodecRefusal::CountBoundExceeded { field, observed, limit: limit as u64 });
    }
    Ok(())
}
fn validate_principals(values:''')
p='crates/fgit-node/src/treefs_workspace/protection_tests.rs'
replace(p,'use super::*;','use super::*;\n#[path = "protection_race.rs"]\nmod race;')
(root/'crates/fgit-node/src/treefs_workspace/protection_race.rs').write_bytes((payload/'protection_race.rs').read_bytes())
