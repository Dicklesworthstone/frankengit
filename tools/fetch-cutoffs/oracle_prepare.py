import os,pathlib,subprocess,tempfile
root=pathlib.Path.cwd();base='4922c1ec5962a9aa283a09965365971649ca9dd9'
name='crates/fgit-node/src/upload_visibility/tests/shallow_oracle/cutoff_oracle.rs'
def git(*args,cwd=root):return subprocess.check_output(['git',*args],cwd=cwd,text=True).strip()
with tempfile.TemporaryDirectory(prefix='fg-cutoff-checkout-') as td:
    work=pathlib.Path(td)/'source';git('worktree','add','--detach',str(work),base)
    assert git('rev-parse',f'{base}:{name}')=='908834d4c86952dc3b0010160dc1eb5336d977e0'
    path=work/name;text=path.read_text()
    old='''                let (returned, _) = live_client(
                    node,
                    &listener,
                    command(
                        &run,
                        "checkout",
                        &client,
                        &[&endpoint, &repository, version, &tip],
                    ),
                );
                node = returned;'''
    new='''                let checkout = command(
                    &run,
                    "checkout",
                    &client,
                    &[&endpoint, &repository, version, &tip],
                );
                if profile == "full" {
                    // The exact initial inventory above already contains every
                    // checkout object. No daemon session should be necessary.
                    checked(checkout);
                } else {
                    let (returned, _) = live_client(node, &listener, checkout);
                    node = returned;
                }'''
    assert text.count(old)==1;text=text.replace(old,new);path.write_text(text)
    subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true',name],cwd=work,check=True,timeout=180)
    assert git('diff','--name-only',cwd=work)==name
    git('diff','--check',cwd=work);git('config','user.name','Jeff Emanuel',cwd=work);git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    git('add','--',name,cwd=work);git('commit','-m','test(fetch): require network hydration only for filtered cutoff checkouts','-m','The actual full-clone checkout already has its exact verified object inventory and emits no network request. Execute that pinned checkout directly; retain mandatory successful native pack sessions for blobless and treeless hydration, and preserve all byte, history, boundary, fsck and authority assertions. Production source is unchanged.',cwd=work)
    source=git('rev-parse','HEAD',cwd=work);branch='tooling/fetch-cutoffs-result-'+os.environ['GITHUB_SHA'][:12]
    git('push','origin',source+':refs/heads/'+branch,cwd=work)
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:out.write('source='+source+'\n')
    print('PRODUCT_SOURCE',source,branch,flush=True)
