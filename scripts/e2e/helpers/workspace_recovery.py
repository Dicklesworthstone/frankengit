"""Native saved-candidate recovery, including a genuinely killed execution owner."""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from workspace_tool_smoke import AUTHOR,TENANT,REPOSITORY,PRINCIPAL,REF,write_object,tree,commit,identity,inspect_bundle

fg,root=sys.argv[1],Path(sys.argv[2]).resolve()
root.mkdir(parents=True,exist_ok=True)
sequence=0
results=[]
def invoke(label,args,success=True):
    global sequence
    sequence+=1
    out,err=(root/f'{sequence:03d}-{label}.{suffix}' for suffix in ('out','err'))
    with out.open('wb') as stdout,err.open('wb') as stderr:
        done=subprocess.run([fg,*map(str,args)],stdout=stdout,stderr=stderr,timeout=35)
    diagnostic=err.read_bytes()
    if diagnostic:
        sys.stderr.buffer.write(diagnostic);sys.stderr.buffer.flush()
    assert (done.returncode==0)==success,(label,done.returncode,diagnostic)
    return out.read_bytes(),diagnostic

def reservation(diagnostic):
    found=re.search(rb'workspace invocation reserved: ([^\n]+); request_sha256=([0-9a-f]{64})',diagnostic)
    assert found,'no retained original request identity'
    return Path(os.fsdecode(found[1])),found[2].decode()

def result(fmt,case,**values):
    row={'format':fmt,'case':case,**values};results.append(row);print(json.dumps(row),flush=True)

for fmt in ('sha1','sha256'):
    source,node,parent=(root/f'{fmt}-{name}' for name in ('source','node','private'))
    parent.mkdir(mode=0o700);(source/'refs/heads').mkdir(parents=True)
    (source/'HEAD').write_text(f'ref: {REF}\n')
    old=write_object(source,fmt,'blob',b'before\n')
    tree_id=write_object(source,fmt,'tree',tree([(b'100644',b'edit.txt',old)]))
    base=write_object(source,fmt,'commit',commit(tree_id,None,0,b'base\n'))
    (source/REF).write_text(base+'\n')
    scope=[node,TENANT,REPOSITORY]
    invoke('init',['init',*scope,fmt]);invoke('import',['import',*scope,PRINCIPAL,'recovery-source',source])
    listing=['at',*scope,'latest','refs'];before,_=invoke('refs-before',listing)
    counter=root/f'{fmt}-effects';destination=parent/'candidate.bundle'
    def command(slot,script,name='candidate.bundle'):
        return ['workspace','run',*scope,REF,parent,slot,name,'--trusted-local','--read','edit.txt','--write','edit.txt',
                '--author',AUTHOR,'--timestamp','1','--message','candidate\n','--',sys.executable,'-c',script]
    script=(f"from pathlib import Path; p=Path({str(counter)!r}); p.open('a').write('x'); "
            "Path('edit.txt').write_bytes(b'after\\n'); " + f"Path({str(destination)!r}).mkdir()")
    original=command('ab'*16,script)
    _,error=invoke('publication-failed',original,False)
    directory,request=reservation(error)
    assert counter.read_text()=='x' and destination.is_dir()
    assert not (parent/('workspace-'+'ab'*16)).exists()
    recover=['workspace','recover',directory,'--trusted-local','--request-id',request]
    text,_=invoke('inspect-saved',recover);saved=json.loads(text)
    receipt=json.loads(saved['receipt_json']);terminal=saved['terminal_sha256']
    blob=identity(fmt,'blob',b'after\n');candidate_tree=identity(fmt,'tree',tree([(b'100644',b'edit.txt',blob)]))
    candidate=identity(fmt,'commit',commit(candidate_tree,base,1,b'candidate\n'))
    assert saved['reexecuted'] is False and saved['published_to_repository'] is False
    assert receipt['candidate_commit']==candidate and receipt['source_commit']==base
    bundle=(directory/'candidate.bundle').read_bytes()
    assert len(inspect_bundle(bundle,fmt,base,candidate))==3
    snapshot={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.iterdir() if p.is_file()}
    repeated,_=invoke('inspect-repeat',recover)
    assert repeated==text and destination.is_dir() and counter.read_text()=='x'
    assert {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.iterdir() if p.is_file()}==snapshot
    result(fmt,'inspect-ready',counter='x',candidate=candidate)
    destination.rmdir()
    invoke('same-id-retry',original,False);assert counter.read_text()=='x'
    invoke('export-saved',recover+['--terminal-id',terminal,'--output',destination])
    assert destination.read_bytes()==bundle
    invoke('export-collision',recover+['--output',destination],False)
    assert destination.read_bytes()==bundle and counter.read_text()=='x'
    result(fmt,'export-and-replay-refusal',counter='x',exact_bytes=True)
    for name in ('request','terminal','candidate.bundle','receipt.json'):
        path=directory/name;good=path.read_bytes();bad=bytearray(good);bad[-1]^=1;path.write_bytes(bad)
        output=parent/('bad-'+name)
        invoke('corrupt-'+name,recover+['--output',output],False)
        assert not output.exists();path.write_bytes(good)
        invoke('restored-'+name,recover)
        result(fmt,'corruption-'+name,output_absent=True)
    for label,args in [('request',['workspace','recover',directory,'--trusted-local','--request-id','00'*32]),
                       ('terminal',recover+['--terminal-id','00'*32])]:
        output=parent/('wrong-'+label)
        invoke('wrong-'+label,args+['--output',output],False);assert not output.exists()
    result(fmt,'wrong-independent-pins',output_absent=True)
    after,_=invoke('refs-still-source',listing);assert after==before
    apply=['workspace','apply',*scope,REF,destination,'--trusted-local','--principal',PRINCIPAL,
           '--idempotency-key','recovered-workspace','--expected-base',base,'--expected-commit',candidate]
    invoke('apply-recovered',apply);invoke('apply-recovered-repeat',apply)
    published,_=invoke('refs-after-apply',listing);assert candidate.encode() in published
    result(fmt,'ordinary-admission',candidate=candidate)
    # Recovery does not need current source, repository authority or tool executable.
    moved=root/f'{fmt}-moved-node';node.rename(moved)
    invoke('offline-recovery',recover if not str(directory).startswith(str(node)) else
           ['workspace','recover',moved/directory.relative_to(node),'--trusted-local','--request-id',request,'--terminal-id',terminal,
            '--output',parent/'offline.bundle'])
    assert (parent/'offline.bundle').read_bytes()==bundle
    moved.rename(node)
    result(fmt,'offline-recovery',exact_bytes=True)
    failed_counter=root/f'{fmt}-failed-effects'
    failed=command('cd'*16,f"from pathlib import Path; Path({str(failed_counter)!r}).open('a').write('x'); raise SystemExit(7)",'failed.bundle')
    _,error=invoke('tool-failed',failed,False);failed_dir,failed_id=reservation(error)
    _,error=invoke('recover-failed',['workspace','recover',failed_dir,'--trusted-local','--request-id',failed_id],False)
    assert b'external effects may have occurred' in error
    invoke('failed-retry',failed,False);assert failed_counter.read_text()=='x'
    result(fmt,'failed-terminal',counter='x')
    # SIGKILL cannot cooperate. The test owns cleanup of its planted sleeping tool;
    # this is evidence of replay refusal, not a claim that fg survived SIGKILL to drain.
    pidfile=root/f'{fmt}-killed-pid';killed_counter=root/f'{fmt}-killed-effects'
    sleeping=command('ef'*16,f"from pathlib import Path; import os,time; Path({str(killed_counter)!r}).open('a').write('x'); Path({str(pidfile)!r}).write_text(str(os.getpid())); time.sleep(30)",'killed.bundle')
    out,err=root/f'{fmt}-killed.out',root/f'{fmt}-killed.err'
    tool_pid=None
    with out.open('wb') as stdout,err.open('wb') as stderr:
        owner=subprocess.Popen([fg,*map(str,sleeping)],stdout=stdout,stderr=stderr)
        try:
            end=time.monotonic()+8
            while time.monotonic()<end:
                if pidfile.exists() and pidfile.read_text().strip():tool_pid=int(pidfile.read_text());break
                assert owner.poll() is None;time.sleep(.01)
            assert tool_pid is not None
            owner.kill();owner.wait(timeout=5)
            assert owner.returncode==-signal.SIGKILL
        finally:
            if owner.poll() is None:owner.kill();owner.wait(timeout=5)
            if tool_pid is not None:
                try:os.killpg(tool_pid,signal.SIGKILL)
                except ProcessLookupError:pass
    diagnostic=err.read_bytes();sys.stderr.buffer.write(diagnostic)
    killed_dir,killed_id=reservation(diagnostic)
    _,error=invoke('recover-killed',['workspace','recover',killed_dir,'--trusted-local','--request-id',killed_id],False)
    assert b'unresolved' in error
    invoke('killed-retry',sleeping,False);assert killed_counter.read_text()=='x'
    assert not (killed_dir/'terminal').exists() and not (parent/'killed.bundle').exists()
    result(fmt,'killed-owner-unresolved',counter='x',fixture_owned_child_cleanup=True)
(root/'results.json').write_text(json.dumps({'cases':results,'commands':sequence},indent=2)+'\n')
