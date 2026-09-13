import os,pathlib,subprocess,tempfile
ROOT=pathlib.Path.cwd();BASE='7ab59dc11d542e26f34dc861a84cbe184ab251dc'
def git(*args,cwd=ROOT):return subprocess.check_output(['git','-c','core.hooksPath=/dev/null',*args],cwd=cwd,text=True).strip()
with tempfile.TemporaryDirectory(prefix='fg-rebase-integration-') as td:
    work=pathlib.Path(td)/'source';git('worktree','add','--detach',str(work),BASE)
    guards={'crates/fgit-node/src/treefs_workspace/merge_prepare.rs':'92370010a32eb2c4ad86f5160661e28ba4d6b520',
      'crates/fgit-node/src/treefs_workspace/commit_replay/tests.rs':'887a02544cc44214b5ff03bd1426e64c822278be',
      'crates/fgit-cli/src/main.rs':'764e599276e12530efb6f8b381335a43b6d0187f',
      'crates/fgit-cli/src/commit_replay.rs':'185840aefde47ad7884cd8f03f3fb5b0dbeee146'}
    for path,sha in guards.items():assert git('rev-parse',f'{BASE}:{path}')==sha,(path,sha)
    def replace(path,old,new):
        p=work/path;t=p.read_text();assert t.count(old)==1,(path,old[:80],t.count(old));p.write_text(t.replace(old,new))
    def add(path,text):
        p=work/path;assert not p.exists();p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
    def commit(paths,message):
        changed=set(git('diff','--name-only',cwd=work).splitlines())|set(git('ls-files','--others','--exclude-standard',cwd=work).splitlines())
        assert changed==set(paths),(changed,paths)
        git('diff','--check',cwd=work);git('add','--',*paths,cwd=work);git('commit','-m',message,cwd=work)
        result=git('rev-parse','HEAD',cwd=work);print('PRODUCT_COMMIT',result,message,flush=True);return result
    git('config','user.name','Jeff Emanuel',cwd=work);git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    node_path='crates/fgit-node/src/treefs_workspace/rebase.rs';test_path='crates/fgit-node/src/treefs_workspace/rebase/tests.rs'
    node=(ROOT/'tools/rebase-session/node.rs').read_text()
    # Validate identity first, then parse explicitly: never depend on whether
    # the native verifier exposes an internal parsed-object return value.
    old='''        let parsed = verify_native_object(original.inner.object_format, object.kind, &object.body, &object.id,
            AcceptanceProfile::StrictCreate, &original.limits).map_err(|_| invalid())?;
        let ParsedObject::Commit(commit) = parsed else { return Err(invalid()); };'''
    new='''        verify_native_object(original.inner.object_format, object.kind, &object.body, &object.id,
            AcceptanceProfile::StrictCreate, &original.limits).map_err(|_| invalid())?;
        let ParsedObject::Commit(commit) = parse_object_body(object.kind, &object.body,
            AcceptanceProfile::StrictCreate, &original.limits).map_err(|_| invalid())? else { return Err(invalid()); };'''
    assert node.count(old)==1;node=node.replace(old,new)
    add(node_path,node)
    scaffold=(work/'crates/fgit-node/src/treefs_workspace/commit_replay/tests.rs').read_text().split('fn inputs(f: &Fixture)')[0]
    assert scaffold.count('use fgit_forge::preparation::replay::ReplayDirection;')==1
    scaffold=scaffold.replace('use fgit_forge::preparation::replay::ReplayDirection;','use fgit_forge::preparation::{MergeMetadata, rebase::EmptyCommitPolicy};')
    add(test_path,scaffold+(ROOT/'tools/rebase-session/node-tests.rs').read_text())
    for path in [node_path,test_path]:subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true',path],cwd=work,check=True,timeout=180)
    replace('crates/fgit-node/src/treefs_workspace/merge_prepare.rs','mod commit_replay;','mod commit_replay;\n#[path = "rebase.rs"]\nmod rebase;')
    commit([node_path,test_path,'crates/fgit-node/src/treefs_workspace/merge_prepare.rs'],'feat(rebase): bind series preparation to authenticated tips and complete native bundles')
    cli='crates/fgit-cli/src/rebase.rs';add(cli,(ROOT/'tools/rebase-session/cli.rs').read_text())
    subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true',cli],cwd=work,check=True,timeout=180)
    for function in ['decimal','unhex','hex','token','parse_head','write_receipt']:
        replace('crates/fgit-cli/src/commit_replay.rs','fn '+function+'(','pub(super) fn '+function+'(')
    replace('crates/fgit-cli/src/main.rs','mod commit_replay;','mod commit_replay;\nmod rebase;')
    replace('crates/fgit-cli/src/main.rs','    if arguments.first().is_some_and(|argument| argument == "issue") {','''    if arguments.first().is_some_and(|argument| argument == "rebase") {
        return match rebase::run(&arguments[1..]) {
            Ok(code) => ExitCode::from(code),
            Err(error) => { eprintln!("fg: {error}"); ExitCode::from(2) }
        };
    }
    if arguments.first().is_some_and(|argument| argument == "issue") {''')
    result=commit([cli,'crates/fgit-cli/src/main.rs','crates/fgit-cli/src/commit_replay.rs'],'feat(cli): expose exact-input multi-commit rebase preparation with checked receipts')
    branch='tooling/rebase-source-'+os.environ['GITHUB_SHA'][:12];git('push','origin',result+':refs/heads/'+branch,cwd=work)
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:out.write('source='+result+'\n')
    print('PRODUCT_SOURCE',result,branch,flush=True)
