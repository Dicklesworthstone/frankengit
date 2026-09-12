import os, pathlib, subprocess, tempfile
root=pathlib.Path.cwd()
base='b9f9c05cda1d6b693b9fb61b8abfd42fa0a9ae1f'
wire='crates/fgit-wire/src/lib.rs'
test='crates/fgit-wire/tests/v2_ref_prefixes.rs'
def git(*args,cwd=root):
    return subprocess.check_output(['git','-c','core.hooksPath=/dev/null',*args],cwd=cwd,text=True).strip()
with tempfile.TemporaryDirectory(prefix='fg-shallow-product-') as td:
    work=pathlib.Path(td)/'source'
    git('worktree','add','--detach',str(work),base)
    assert git('rev-parse',f'{base}:{wire}')=='dabc0e41eee95b20862a4b91a6ab8e6b52a6eac0'
    path=work/wire;text=path.read_text()
    old='''                if self.ref_prefixes.contains(&prefix) {
                    return Err(WireError::MalformedRequestLine {
                        line: line.to_vec(),
                    });
                }
'''
    new='''                // Prefixes are an OR-query, not conflicting declarations.
                // Git can repeat one while expanding fetch refspecs. Keep
                // every argument bounded by the existing request ceiling;
                // matching still visits each advertised ref exactly once.
'''
    assert text.count(old)==1
    path.write_text(text.replace(old,new))
    assert not (work/test).exists()
    (work/test).write_bytes((root/'tools/shallow-v2-ref-prefixes.rs').read_bytes())
    subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true',test],cwd=work,check=True,timeout=180)
    assert git('diff','--name-only',cwd=work)==wire
    assert git('ls-files','--others','--exclude-standard',cwd=work)==test
    git('diff','--check',cwd=work)
    git('config','user.name','Jeff Emanuel',cwd=work)
    git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    git('add','--',wire,test,cwd=work)
    git('commit','-m','fix(wire): accept bounded repeated ls-refs prefixes from real Git clients','-m','The pinned Git 2.54.0 multi-branch unshallow transcript repeats refs/heads/public during ls-refs; rejecting that valid OR-query reset the v2 connection before fetch. Preserve argument order and count every occurrence against the unchanged max_ref_prefixes bound. Add both-hash fragmented-input, inclusive duplicate/unique quota, per-command reset and framing/output-bound regressions. No authorization or shallow-graph rule changes.',cwd=work)
    source=git('rev-parse','HEAD',cwd=work)
    assert set(git('diff','--name-only',base,source,cwd=work).splitlines())=={wire,test}
    branch='tooling/shallow-complete-source-'+os.environ['GITHUB_SHA'][:12]
    git('push','origin',source+':refs/heads/'+branch,cwd=work)
    with open(os.environ['GITHUB_OUTPUT'],'a') as output: output.write('source='+source+'\n')
    print('PRODUCT_SOURCE',source,branch,flush=True)
