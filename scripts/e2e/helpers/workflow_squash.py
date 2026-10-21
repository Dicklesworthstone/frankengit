"""Actual native squash preparation, CI execution, retained artifacts and signal drain."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import time
import zlib
FG,ROOT=sys.argv[1],Path(sys.argv[2]).resolve()
ROOT.mkdir(parents=True,exist_ok=True)
TENANT,REPO,OWNER='71'*16,'72'*16,'73'*16
TARGET,SOURCE='refs/heads/main','refs/heads/topic'
COUNT,RESULTS=0,[]
def invoke(label,args,code=0):
    global COUNT
    COUNT+=1
    out,err=(ROOT/f'{COUNT:03d}-{label}.{s}' for s in ('out','err'))
    with out.open('wb') as stdout,err.open('wb') as stderr:
        result=subprocess.run([FG,'--timeout-secs','120',*map(str,args)],stdout=stdout,stderr=stderr,timeout=150)
    if err.stat().st_size:sys.stderr.buffer.write(err.read_bytes());sys.stderr.buffer.flush()
    assert result.returncode==code,(label,result.returncode,err.read_bytes()[-3000:],out.read_bytes()[-3000:])
    return out.read_bytes()
def record(fmt,case,**data):
    row=dict(format=fmt,case=case,**data);RESULTS.append(row);print(json.dumps(row),flush=True)
def replace(args,flag,value):
    a=list(args);a[a.index(flag)+1]=str(value);return a
def live(pid):
    try:return Path(f'/proc/{pid}/stat').read_text().rsplit(') ',1)[1][0] not in 'ZX'
    except FileNotFoundError:return False
class Fixture:
    def __init__(self,fmt,label,mode='normal'):
        self.fmt,self.root=fmt,ROOT/(fmt+'-'+label);self.root.mkdir()
        self.source,self.node,self.runs,self.artifacts,self.effects,self.pidfile,self.late=(self.root/n for n in ['source','node','runs','artifacts','effects','pid','late'])
        self.runs.mkdir(mode=0o700);self.artifacts.mkdir(mode=0o700)
        (self.source/'refs/heads').mkdir(parents=True)
        (self.source/'HEAD').write_text(f'ref: {TARGET}\n')
        (self.source/'config').write_text('[core]\nbare=true\nrepositoryformatversion='+('1\n[extensions]\nobjectformat=sha256\n' if fmt=='sha256' else '0\n'))
        def put(kind,body):
            raw=kind.encode()+b' '+str(len(body)).encode()+b'\0'+body
            oid=hashlib.new(fmt,raw).hexdigest();path=self.source/'objects'/oid[:2]/oid[2:]
            path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(zlib.compress(raw));return oid
        effect=f'printf x >> {shlex.quote(str(self.effects))}; '
        action=effect+'test "$(cat left)" = target && test "$(cat right)" = source || exit 7; cat left right > result.bin; chmod +x result.bin'
        needs='    needs: a\n';consumer='test ! -e result.bin; test -x .fgit-artifacts/input; cat left right > expected; cmp expected .fgit-artifacts/input; printf delivered'
        if mode=='fail':action=effect+'exit 11';consumer='exit 99'
        if mode=='slow':action=effect+f'echo $$ > {shlex.quote(str(self.pidfile))}; exec sleep 30';needs='    if: always()\n';consumer=f'printf later > {shlex.quote(str(self.late))}'
        workflow=f'name: actual-squash\non: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: set -e; {action}\n  b:\n    runs-on: fgit-trusted-local\n{needs}    steps:\n      - run: set -e; {consumer}\n'.encode()
        blob=put('blob',workflow)
        def tree(left,right):
            return put('tree',b'100644 left\0'+bytes.fromhex(put('blob',left))+b'100644 right\0'+bytes.fromhex(put('blob',right))+b'100644 workflow.yml\0'+bytes.fromhex(blob))
        def commit(tree,parents,message):return put('commit',(f'tree {tree}\n'+''.join(f'parent {p}\n' for p in parents)+'author Test <x@example.invalid> 1 +0000\ncommitter Test <x@example.invalid> 1 +0000\n\n'+message+'\n').encode())
        self.base=commit(tree(b'base\n',b'base\n'),[],'base')
        self.target=commit(tree(b'target\n',b'base\n'),[self.base],'target')
        self.incoming=commit(tree(b'base\n',b'source\n'),[self.base],'source')
        for name,oid in [(TARGET,self.target),(SOURCE,self.incoming)]: (self.source/name).write_text(oid+'\n')
        self.scope=[self.node,TENANT,REPO];invoke('init',['init',*self.scope,fmt]);invoke('import',['import',*self.scope,OWNER,'squash-fixture',self.source])
        self.refs=['refs',*self.scope,'--trusted-local','--object-format',fmt]
        self.before=invoke('before',self.refs)
        self.bundle=self.runs/'squash.bundle'
        prep=json.loads(invoke('prepare',['merge','prepare',*self.scope,TARGET,self.bundle,'--trusted-local','--profile','path-v1','--source-ref',SOURCE,'--author','Test <x@example.invalid>','--timestamp','9','--message','actual squash CI','--method','squash','--object-format',fmt]))
        assert prep['outcome']=='prepared' and prep['expected_target']==self.target and prep['expected_source']==self.incoming and prep['merge_base']==self.base
        self.candidate=prep['candidate_commit'];self.tree=prep['root_tree']
        self.args=['workflow','run-merge-candidate',*self.scope,TARGET,'--trusted-local','--bundle',self.bundle,'--candidate-commit',self.candidate,'--expected-commit',self.target,'--source-ref',SOURCE,'--expected-source',self.incoming,'--merge-base',self.base,'--workflow','workflow.yml','--input','workflow.yml','--input','left','--input','right','--run-id','41'*16,'--run-parent',self.runs,'--object-format',fmt,'--method','squash']
        if mode=='normal':self.args+=['--artifact-root',self.artifacts,'--artifact','workflow.yml:a:result.bin','--artifact-input','workflow.yml:b:a:result.bin:input']
    def count(self):return len(self.effects.read_bytes()) if self.effects.exists() else 0
    def unchanged(self):assert invoke('unchanged',self.refs)==self.before
    def recover(self,run):
        directory=Path(os.fsdecode(bytes.fromhex(run['run_directory_hex'])))
        marker=directory/'attempt.json';jid=hashlib.sha256(marker.read_bytes()).hexdigest()
        args=['workflow','recover',directory,TENANT,REPO,'--journal-id',jid]
        first=invoke('recover',args);assert first==invoke('recover-repeat',args)
        assert self.count()==1
        return directory,args
for fmt in ['sha1','sha256']:
    f=Fixture(fmt,'complete');f.unchanged();record(fmt,'native-preparation-leaves-authority-unchanged')
    for flag,value in [('--method','merge-commit'),('--method','auto'),('--expected-source',f.base),('--merge-base',f.incoming)]:
        invoke('preflight-negative',replace(f.args,flag,value),2);assert f.count()==0
        assert not any(f.runs.glob('workflow-*'))
    record(fmt,'wrong-method-source-and-base-refuse-before-execution')
    original=f.bundle.read_bytes();f.bundle.write_bytes(original[:-1]+bytes([original[-1]^1]));invoke('bad-pack',f.args,2);assert f.count()==0;f.bundle.write_bytes(original)
    record(fmt,'corrupt-bundle-does-not-consume-the-attempt')
    result=json.loads(invoke('execute',f.args));run=result['run'];assert result['node_closed'] and run['succeeded'] and run['workspaces_closed']
    assert run['executed_commit']==f.candidate and run['executed_tree']==f.tree and run['source_commit']==f.target
    assert run['merge']['method']=='squash' and run['merge']['parents']==[f.target]
    assert run['merge']['source_tip']==f.incoming and run['merge']['merge_base']==f.base
    assert f.count()==1 and run['execution']['jobs'][1]['steps'][0]['stdout_hex']=='delivered'.encode().hex()
    assert len(run['artifacts'])==1 and len(run['artifact_inputs'])==1
    f.unchanged();record(fmt,'real-squash-tree-execution-with-same-run-artifacts')
    artifact=run['artifacts'][0]
    for key,name in [('manifest_id_sha256','manifest'),(None,'payload')]:
        oid=artifact[key] if key else artifact['outputs'][0]['artifact_id_sha256'];out=f.runs/name
        invoke('export',['artifact','export',f.artifacts,TENANT,REPO,run['repository_incarnation'],'--trusted-local','--trust-domain','trusted-workflow-local-owner','--id',oid,'--output',out])
    assert (f.runs/'payload').read_bytes()==b'target\nsource\n'
    producer=json.loads((f.runs/'manifest').read_bytes())['producer'];assert producer['merge']['method']=='squash' and producer['merge']['parents']==[f.target] and producer['executed_commit']==f.candidate
    record(fmt,'source-independent-artifact-export-preserves-squash-provenance')
    directory,recovery=f.recover(run);saved=(directory/'report.json').read_bytes();(directory/'report.json').rename(directory/'saved-report')
    invoke('offline-without-report',recovery);(directory/'saved-report').rename(directory/'report.json')
    assert f.count()==1;record(fmt,'journal-reopens-without-reexecuting-or-reading-final-report')
    invoke('no-replay',f.args,2);assert f.count()==1 and (directory/'report.json').read_bytes()==saved;f.unchanged();record(fmt,'occupied-squash-attempt-refuses-reexecution')
    bad=Fixture(fmt,'failed','fail');result=json.loads(invoke('failed-execution',bad.args,1));failed=result['run']
    assert not failed['succeeded'] and failed['execution']['jobs'][0]['outcome']=='failed' and failed['execution']['jobs'][1]['outcome']=='skipped'
    bad.recover(failed);bad.unchanged();record(fmt,'failed-and-skipped-jobs-stay-nonpassing')
    for sig in [signal.SIGTERM,signal.SIGINT]:
        slow=Fixture(fmt,str(sig),'slow');out,err=slow.runs/'stdout',slow.runs/'stderr';pid=None
        with out.open('wb') as stdout,err.open('wb') as stderr:
            child=subprocess.Popen([FG,*map(str,slow.args)],stdout=stdout,stderr=stderr)
            try:
                end=time.monotonic()+20
                while time.monotonic()<end and not (slow.pidfile.exists() and slow.pidfile.read_text().strip()):
                    assert child.poll() is None;time.sleep(.02)
                pid=int(slow.pidfile.read_text());assert live(pid)
                child.send_signal(sig);time.sleep(.02)
                if child.poll() is None:child.send_signal(sig)
                code=child.wait(timeout=15);alive=live(pid)
                assert code==1 and not alive,(code,err.read_bytes(),out.read_bytes(),alive)
            finally:
                if child.poll() is None:child.kill();child.wait(timeout=5)
                if pid and live(pid):os.kill(pid,signal.SIGKILL)
        stopped=json.loads(out.read_bytes());assert stopped['node_closed'] and not stopped['run']['succeeded'] and stopped['run']['request_interrupted']
        assert not slow.late.exists() and slow.count()==1
        slow.recover(stopped['run']);invoke('signal-replay',slow.args,2);slow.unchanged()
        record(fmt,'real-signal-drain-and-restart-refusal',signal=sig.name,live_child_before=True,live_child_after=False)
(ROOT/'results.json').write_text(json.dumps(RESULTS,indent=2)+'\n')
