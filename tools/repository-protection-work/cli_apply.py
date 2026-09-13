import pathlib,sys
root=pathlib.Path.cwd();payload=pathlib.Path(sys.argv[1]).resolve()
for dest,source in [('crates/fgit-cli/src/protection.rs','protection_cli.rs'),('crates/fgit-cli/tests/native_protection_smoke.rs','native_protection_smoke.rs'),('scripts/e2e/protection_smoke.py','protection_smoke.py')]:
 p=root/dest;assert not p.exists(),dest;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((payload/source).read_bytes())
def replace(name,old,new):
 p=root/name;text=p.read_text();assert text.count(old)==1,(name,old[:100],text.count(old))
 p.write_text(text.replace(old,new))
p='crates/fgit-cli/src/main.rs'
replace(p,'mod issues;','mod issues;\nmod protection;')
replace(p,'    let review_mode = match','''    if arguments.first().is_some_and(|argument| argument == "protection") {
        return match protection::run(&arguments[1..]) {
            Ok(code) => ExitCode::from(code),
            Err(error) => { eprintln!("fg: {error}"); ExitCode::from(2) }
        };
    }
    let review_mode = match''')
p='crates/fgit-cli/src/protection.rs'
replace(p,'    let result=(|| {','    let result: Result<Completion,String>=(|| {')
replace(p,'quote(&String::from_utf8_lossy(rule.target.as_bytes())),principals(&rule.reviewers)',
 '''std::str::from_utf8(rule.target.as_bytes()).map(quote).unwrap_or_else(|_| "null".to_owned()),
        quote(&rule.target.as_bytes().iter().map(|byte| format!("{byte:02x}")).collect::<String>()),principals(&rule.reviewers)''')
replace(p,'{{\\"target\\":{},\\"reviewers\\":{}}}', '{{\\"target\\":{},\\"target_hex\\":{},\\"reviewers\\":{}}}')
p='scripts/e2e/protection_smoke.py'
replace(p,"'target':'refs/heads/main','reviewers'", "'target':'refs/heads/main','target_hex':b'refs/heads/main'.hex(),'reviewers'")
