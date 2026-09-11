import os,pathlib,re,subprocess,tempfile
ROOT=pathlib.Path.cwd(); BASE='5bfd8068be7a548e3fa46a099c873dfbf6d73f46'
def git(*args,cwd=ROOT): return subprocess.check_output(['git',*args],cwd=cwd,text=True).strip()
def verify(work,td,label,command,timeout=720):
    log=pathlib.Path(td)/(label+'.log')
    with log.open('w') as out:
        try: code=subprocess.run(command,cwd=work,stdout=out,stderr=subprocess.STDOUT,timeout=timeout).returncode
        except subprocess.TimeoutExpired: code=124
    lines=log.read_text().splitlines()
    print('VERIFICATION',label,'REVISION',git('rev-parse','HEAD',cwd=work),'EXIT',code,'COMMAND',' '.join(command),flush=True)
    print('\n'.join(lines[-240:] if code else [line for line in lines if line.startswith('test result:') or 'partial_clone' in line or 'Finished ' in line]),flush=True)
    return code
with tempfile.TemporaryDirectory(prefix='fg-partial-node-') as td:
    work=pathlib.Path(td)/'source'; payload=ROOT/'tools/partial-payload'
    subprocess.run(['git','worktree','add','--detach',str(work),BASE],check=True)
    git('config','user.name','Jeff Emanuel',cwd=work); git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    p=work/'crates/fgit-wire/tests/partial_clone_filter_syntax.rs'; text=p.read_text()
    start=text.index('                    let caps = Capabilities::parse_v1('); end=text.index('                    let mut machine',start)
    text=text[:start]+'''                    let caps = if allow {
                        Capabilities::parse_v1(b"allow-reachable-sha1-in-want", &WireLimits::default()).unwrap()
                    } else { Capabilities::default() };
'''+text[end:]; p.write_text(text)
    subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true',str(p)],cwd=work,check=True)
    git('add','--','crates/fgit-wire/tests/partial_clone_filter_syntax.rs',cwd=work)
    git('commit','-m','test(wire): construct the empty capability set through its typed API',cwd=work)
    result=git('rev-parse','HEAD',cwd=work); branch='tooling/partial-wire-'+os.environ['GITHUB_SHA'][:12]
    subprocess.run(['git','push','origin',f'{result}:refs/heads/{branch}'],cwd=work,check=True)
    print('WIRE_RESULT',result,branch,flush=True)
    if verify(work,td,'wire',['cargo','test','--locked','-p','fgit-wire','--all-targets']): raise SystemExit(1)
    subprocess.run(['python3',str(payload/'apply-node.py'),str(payload)],cwd=work,check=True)
    p=work/'crates/fgit-node/src/upload_visibility/tests/partial_clone.rs'; assert not p.exists(); p.parent.mkdir(parents=True,exist_ok=True); p.write_text((payload/'partial_tests.rs').read_text())
    parent=work/'crates/fgit-node/src/upload_visibility/tests.rs'; parent.write_text(parent.read_text()+'\nmod partial_clone;\n')
    paths=['crates/fgit-node/src/lib.rs','crates/fgit-node/src/upload_visibility.rs','crates/fgit-node/src/upload_visibility/partial_clone.rs','crates/fgit-node/src/upload_visibility/tests.rs','crates/fgit-node/src/upload_visibility/tests/partial_clone.rs']
    for path in [paths[2],paths[4]]: subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true',path],cwd=work,check=True)
    changed=set(git('diff','--name-only',cwd=work).splitlines())|set(git('ls-files','--others','--exclude-standard',cwd=work).splitlines()); assert changed==set(paths),changed
    subprocess.run(['git','diff','--check'],cwd=work,check=True)
    git('add','--',*paths,cwd=work)
    git('commit','-m','feat(fetch): serve filtered partial clones and authorized lazy object retrieval','-m','Carry bounded native metadata in the private exact-head disclosure proof. Apply blob-none/limit, minimum tree-depth, and compound filters to actual selected packs; preserve explicit requested object semantics and restore lazy blob/tree wants that commit haves cannot prove present. Keep current visibility authoritative on every follow-up, canonical retention unchanged, include-tag after filtering, and unsupported sparse/shallow controls typed. Add six native graph/resource/cancellation and real TCP protocol/hash integration tests.',cwd=work)
    result=git('rev-parse','HEAD',cwd=work); branch='tooling/partial-result-'+os.environ['GITHUB_SHA'][:12]
    subprocess.run(['git','push','origin',f'{result}:refs/heads/{branch}'],cwd=work,check=True)
    print('PRODUCT_RESULT',result,branch,flush=True)
    for label,command in [('node-check',['cargo','check','--locked','-p','fgit-node','--all-targets']),('node-visibility',['cargo','test','--locked','-p','fgit-node','--lib','upload_visibility','--','--nocapture']),('node-library',['cargo','test','--locked','-p','fgit-node','--lib'])]:
        if verify(work,td,label,command): raise SystemExit(1)
    assert not git('status','--porcelain',cwd=work)
