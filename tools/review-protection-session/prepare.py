import os, pathlib, subprocess, tempfile
ROOT=pathlib.Path.cwd()
BASE='686d81fe2e972b0c373b68488af5da989ddc4ec2'
PATH='crates/fgit-node/src/treefs_workspace/native_merge.rs'
def git(*args,cwd=ROOT):
    return subprocess.check_output(['git','-c','core.hooksPath=/dev/null',*args],cwd=cwd,text=True).strip()
with tempfile.TemporaryDirectory(prefix='fg-review-send-') as td:
    work=pathlib.Path(td)/'source'
    git('worktree','add','--detach',str(work),BASE)
    assert git('rev-parse',BASE+':'+PATH)=='aba29c343d3258106edae47c1d92fff49da8190f'
    path=work/PATH
    original=path.read_text()
    old='''            let exhaustion = Cell::new(None);
            let source = VerifiedFabricPackSource {'''
    new='''            // Finish all synchronous object reads before awaiting policy:
            // neither the reader nor its thread-local budget cell may cross
            // an asynchronous authority operation.
            let closure = {
            let exhaustion = Cell::new(None);
            let source = VerifiedFabricPackSource {'''
    assert original.count(old)==1
    text=original.replace(old,new)
    old='            fgit_admission::merge::native::protection::enforce_merge_at('
    assert text.count(old)==1
    text=text.replace(old,'            closure\n            };\n'+old)
    start=text.index('            let exhaustion = Cell::new(None);',text.index('            let closure = {'))
    end=text.index('            };\n            fgit_admission::merge::native::protection::enforce_merge_at(',start)
    text=text[:start]+''.join('    '+line if line.strip() else line for line in text[start:end].splitlines(keepends=True))+text[end:]
    path.write_text(text)
    assert git('hash-object',PATH,cwd=work)=='b976d9482be764d2df49abbe7c994a4980b722b5'
    assert git('diff','--name-only',cwd=work)==PATH
    git('diff','--check',cwd=work)
    git('config','user.name','Jeff Emanuel',cwd=work)
    git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    git('add','--',PATH,cwd=work)
    git('commit','-m','fix(node): finish native object reads before awaiting mandatory review policy','-m','The full native compiler at 686d81fe detected a non-Send verified object source retained across the new policy await. End its synchronous lexical scope and retain only the validated closure. Preserve the existing Cell accounting, all original native object and workspace checks, the Send future contract, and the asynchronous policy check. Do not substitute locks or unsafe implementations. Native tests run separately against this exact successor.',cwd=work)
    source=git('rev-parse','HEAD',cwd=work)
    branch='tooling/review-protection-fix-'+os.environ['GITHUB_SHA'][:12]
    git('push','origin',source+':refs/heads/'+branch,cwd=work)
    print('PRODUCT_COMMIT fix',source,branch,flush=True)
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:out.write('source='+source+'\n')
    assert not git('status','--porcelain',cwd=work)
