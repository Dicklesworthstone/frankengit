"""Real fg merge/squash -> batch execution -> artifact and journal recovery.
Python encodes fixture objects; no Git executable or substitute service is used.
"""
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
FG, ROOT = str(Path(sys.argv[1]).resolve()), Path(sys.argv[2]).resolve()
ROOT.mkdir(parents=True, exist_ok=True)
TENANT, REPO, OWNER = '71'*16, '72'*16, '73'*16
TARGET, SOURCE = 'refs/heads/main', 'refs/heads/topic'
COUNT, RESULTS = 0, []
def invoke(label, args, code=0):
    global COUNT
    COUNT += 1
    out, err = (ROOT/f'{COUNT:03d}-{label}.{suffix}' for suffix in ['out','err'])
    with out.open('wb') as stdout, err.open('wb') as stderr:
        result = subprocess.run([FG,'--timeout-secs','120',*map(str,args)], stdout=stdout, stderr=stderr, timeout=150)
    if err.stat().st_size: sys.stderr.buffer.write(err.read_bytes());sys.stderr.buffer.flush()
    assert result.returncode == code, (label,result.returncode,err.read_bytes()[-3500:],out.read_bytes()[-3500:])
    return out.read_bytes()
def record(f, name, **fields):
    row=dict(format=f.fmt,method=f.method,case=name,**fields);RESULTS.append(row);print(json.dumps(row),flush=True)
def replace(args,flag,value):
    result=list(args);result[result.index(flag)+1]=str(value);return result
def live(pid):
    try:return Path(f'/proc/{pid}/stat').read_text().rsplit(') ',1)[1][0] not in 'ZX'
    except FileNotFoundError:return False
def identity(fmt,kind,body):return hashlib.new(fmt,kind.encode()+b' '+str(len(body)).encode()+b'\0'+body).hexdigest()
def tree(entries):
    return b''.join(mode+b' '+name+b'\0'+bytes.fromhex(oid) for name,mode,oid in sorted(entries,key=lambda e:e[0]+(b'/' if e[1]==b'40000' else b'')))
class Fixture:
    def __init__(self,fmt,method,label,mode='normal'):
        self.fmt,self.method=fmt,method;self.root=ROOT/(fmt+'-'+method+'-'+label);self.root.mkdir()
        self.source,self.node,self.runs,self.artifacts,self.effects,self.pidfile,self.late=(self.root/name for name in ['source','node','runs','artifacts','effects','pid','late'])
        self.runs.mkdir(mode=0o700);self.artifacts.mkdir(mode=0o700)
        (self.source/'refs/heads').mkdir(parents=True);(self.source/'HEAD').write_text(f'ref: {TARGET}\n')
        (self.source/'config').write_text('[core]\nbare=true\nrepositoryformatversion='+('0\n' if fmt=='sha1' else '1\n[extensions]\nobjectformat=sha256\n'))
        def put(kind,body):
            name=identity(fmt,kind,body);p=self.source/'objects'/name[:2]/name[2:];p.parent.mkdir(parents=True,exist_ok=True)
            p.write_bytes(zlib.compress(kind.encode()+b' '+str(len(body)).encode()+b'\0'+body));return name
        parents_check='test "$(cat left)" = target && test "$(cat right)" = source || exit 7; '
        effect=lambda value:f'printf {value} >> {shlex.quote(str(self.effects))}; '
        action=parents_check+effect('a')+'cat left right > result.bin; chmod +x result.bin'
        consumer='test ! -e result.bin; test -x .fgit-artifacts/input; cat left right > expected; cmp expected .fgit-artifacts/input; printf delivered'
        independent=parents_check+effect('b')+'test ! -e result.bin; printf independent'
        if mode=='fail':action=effect('a')+'exit 11';consumer='exit 99'
        if mode=='slow':
            action=effect('a')+f'echo $$ > {shlex.quote(str(self.pidfile))}; exec sleep 30'
            consumer=independent=f'printf late > {shlex.quote(str(self.late))}'
        first=f'name: batch-a\non:\n  pull_request:\n    branches:\n      - main\n    paths:\n      - right\n  workflow_dispatch: \'\'\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: set -e; {action}\n  consume:\n    runs-on: fgit-trusted-local\n    needs: build\n    steps:\n      - run: set -e; {consumer}\n'.encode()
        second=f'name: batch-b\non:\n  pull_request:\n    paths-ignore:\n      - left\n  workflow_dispatch: \'\'\njobs:\n  independent:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: set -e; {independent}\n'.encode()
        wrong=f'name: excluded\non:\n  pull_request:\n    branches:\n      - topic\njobs:\n  wrong:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: {effect("x")}exit 99\n'.encode()
        target_only=wrong.replace(b'branches:\n      - topic',b'paths:\n      - left')
        defs=[(b'a.yml',first),(b'b.yml',second),(b'excluded.yml',wrong),(b'target-only.yml',target_only)]
        ci=put('tree',tree([(name,b'100644',put('blob',body))for name,body in defs]))
        self.blobs={name:identity(fmt,'blob',body)for name,body in defs}
        def source_tree(left,right):return put('tree',tree([(b'ci',b'40000',ci),(b'left',b'100644',put('blob',left)),(b'right',b'100644',put('blob',right))]))
        author='Batch <batch@example.invalid>'
        def commit(root,parents,msg):return put('commit',(f'tree {root}\n'+''.join(f'parent {p}\n'for p in parents)+f'author {author} 1 +0000\ncommitter {author} 1 +0000\n\n{msg}\n').encode())
        self.base=commit(source_tree(b'base\n',b'base\n'),[],'base');self.target=commit(source_tree(b'target\n',b'base\n'),[self.base],'target');self.incoming=commit(source_tree(b'base\n',b'source\n'),[self.base],'source')
        for ref,tip in [(TARGET,self.target),(SOURCE,self.incoming)]:(self.source/ref).write_text(tip+'\n')
        self.scope=[self.node,TENANT,REPO];invoke('init',['init',*self.scope,fmt]);invoke('import',['import',*self.scope,OWNER,'batch-fixture',self.source])
        self.refs=['refs',*self.scope,'--trusted-local','--object-format',fmt];self.before=invoke('basis',self.refs)
        self.bundle=self.runs/'candidate.bundle'
        self.tree=identity(fmt,'tree',tree([(b'ci',b'40000',ci),(b'left',b'100644',identity(fmt,'blob',b'target\n')),(b'right',b'100644',identity(fmt,'blob',b'source\n'))]))
        self.parents=[self.target] if method=='squash' else [self.target,self.incoming]
        self.candidate=identity(fmt,'commit',(f'tree {self.tree}\n'+''.join(f'parent {p}\n'for p in self.parents)+f'author {author} 9 +0000\ncommitter {author} 9 +0000\n\nbatch\n').encode())
        prepared=json.loads(invoke('prepare',['merge','prepare',*self.scope,TARGET,self.bundle,'--trusted-local','--profile','path-v1','--source-ref',SOURCE,'--author',author,'--timestamp','9','--message','batch\n','--method',method,'--object-format',fmt]))
        assert prepared['outcome']=='prepared' and prepared['candidate_commit']==self.candidate and prepared['root_tree']==self.tree
        self.args=['workflow','dispatch-merge-candidate',*self.scope,TARGET,'--trusted-local','--event','pull_request','--bundle',self.bundle,'--candidate-commit',self.candidate,'--expected-commit',self.target,'--source-ref',SOURCE,'--expected-source',self.incoming,'--merge-base',self.base,'--workflow','ci','--input','ci','--input','left','--input','right','--run-id','41'*16,'--run-parent',self.runs,'--object-format',fmt,'--method',method]
        if mode=='normal':self.args+=['--artifact-root',self.artifacts,'--artifact','ci/a.yml:build:result.bin','--artifact-input','ci/a.yml:consume:build:result.bin:input']
    def count(self):return self.effects.read_bytes() if self.effects.exists() else b''
    def unchanged(self):assert invoke('unchanged',self.refs)==self.before
    def recover(self,run):
        directory=Path(os.fsdecode(bytes.fromhex(run['run_directory_hex'])));jid=hashlib.sha256((directory/'attempt.json').read_bytes()).hexdigest()
        args=['workflow','recover',directory,TENANT,REPO,'--journal-id',jid]
        a=invoke('recover',args);assert a==invoke('recover-again',args)
        return directory,args
for fmt in ['sha1','sha256']:
    for method in ['merge-commit','squash']:
        f=Fixture(fmt,method,'normal');f.unchanged();record(f,'prepared-candidate-has-independently-calculated-tree-and-parents')
        for ref,tip in [(TARGET,f.target),(SOURCE,f.incoming)]:
            args=['workflow','run',*f.scope,ref,'--trusted-local','--expected-commit',tip,'--workflow','ci/a.yml','--input','ci','--input','left','--input','right','--run-id',('11' if ref==TARGET else '12')*16,'--run-parent',f.runs,'--object-format',fmt]
            result=json.loads(invoke('parent-twin',args,1));assert not result['run']['succeeded'] and not f.count()
        record(f,'each-parent-fails-the-same-check-which-requires-the-merged-tree')
        for flag,value in [('--method','squash' if method=='merge-commit' else 'merge-commit'),('--expected-source',f.base),('--merge-base',f.incoming),('--event','push')]:
            invoke('negative-before-run',replace(f.args,flag,value),2);assert not f.count() and not any(f.runs.glob('dispatch-*'))
        record(f,'wrong-style-source-base-and-event-refuse-before-batch-reservation')
        raw=f.bundle.read_bytes();f.bundle.write_bytes(raw[:-1]+bytes([raw[-1]^1]));invoke('corrupt-bundle',f.args,2);f.bundle.write_bytes(raw)
        assert not f.count() and not any(f.runs.glob('dispatch-*'));record(f,'corrupt-bundle-refuses-before-execution')
        extra=list(f.args)+['--artifact','ci/excluded.yml:wrong:output'];invoke('excluded-artifact',extra,2)
        assert not f.count() and not any(f.runs.glob('dispatch-*'));record(f,'excluded-artifact-contract-refuses-before-execution')
        result=json.loads(invoke('batch',f.args));d=result['dispatch'];assert result['node_closed'] and d['succeeded']
        assert d['matched_count']==d['executed_count']==2 and f.count()==b'ab'
        assert d['plan']['executed_commit']==f.candidate and d['plan']['source_commit']==f.target
        assert d['plan']['changed_paths']['after']==f.incoming and d['plan']['changed_paths']['count']==1
        for r in d['runs']:
            assert r['executed_commit']==f.candidate and r['executed_tree']==f.tree and r['source_commit']==f.target
            assert r['merge']['parents']==f.parents and r['candidate']['bundle_sha256']==hashlib.sha256(raw).hexdigest()
            assert r['workflow_blob']==f.blobs[Path(os.fsdecode(bytes.fromhex(r['workflow_path_hex']))).name.encode()]
        assert d['runs'][0]['execution']['jobs'][1]['steps'][0]['stdout_hex']==b'delivered'.hex()
        assert d['runs'][1]['execution']['jobs'][0]['steps'][0]['stdout_hex']==b'independent'.hex()
        f.unchanged();record(f,'all-selected-workflows-execute-the-exact-candidate-with-fresh-job-copies')
        for definition in d['plan']['workflows']:
            path=bytes.fromhex(definition['path_hex']);event=b'pull_request'
            expected=hashlib.sha256(b'frankengit/workflow-dispatch-child/v1\0'+bytes.fromhex('41'*16)+len(event).to_bytes(8,'big')+event+len(path).to_bytes(8,'big')+path).hexdigest()[:32]
            assert definition['run_id']==expected
        assert len({r['run_id']for r in d['runs']})==2;record(f,'child-identities-bind-original-batch-event-and-byte-exact-path')
        artifact=d['runs'][0]['artifacts'][0]
        for oid,name in [(artifact['manifest_id_sha256'],'manifest'),(artifact['outputs'][0]['artifact_id_sha256'],'payload')]:
            invoke('artifact-export',['artifact','export',f.artifacts,TENANT,REPO,d['runs'][0]['repository_incarnation'],'--trusted-local','--trust-domain','trusted-workflow-local-owner','--id',oid,'--output',f.runs/name])
        assert (f.runs/'payload').read_bytes()==b'target\nsource\n'
        producer=json.loads((f.runs/'manifest').read_bytes())['producer'];assert producer['executed_commit']==f.candidate and producer['merge']['parents']==f.parents
        record(f,'verified-artifact-delivery-and-source-independent-export-retain-candidate-provenance')
        for r in d['runs']:
            directory,recovery=f.recover(r);saved=(directory/'report.json').read_bytes();(directory/'report.json').rename(directory/'saved-report')
            invoke('recover-without-report',recovery);(directory/'saved-report').rename(directory/'report.json');assert f.count()==b'ab'
        record(f,'each-original-child-journal-recovers-without-report-or-script-replay')
        batch=f.runs/('dispatch-'+'41'*16);saved=(batch/'report.json').read_bytes();invoke('occupied-batch',f.args,2)
        (batch/'report.json').rename(batch/'saved-report');invoke('occupied-missing-report',f.args,2);(batch/'saved-report').rename(batch/'report.json')
        assert f.count()==b'ab' and (batch/'report.json').read_bytes()==saved;record(f,'occupied-batch-refuses-replay-even-after-report-loss')
        manual=replace(replace(f.args,'--event','workflow_dispatch'),'--run-id','42'*16)
        m=json.loads(invoke('manual',manual))['dispatch'];assert m['succeeded'] and m['executed_count']==2 and f.count()==b'abab'
        assert 'changed_paths' not in m['plan'];record(f,'manual-event-does-not-borrow-pr-branch-or-path-filters')
        lost=replace(f.args,'--run-id','43'*16);err=f.runs/'lost.stderr'
        with err.open('wb') as stderr:
            p=subprocess.Popen([FG,*map(str,lost)],stdout=subprocess.PIPE,stderr=stderr);p.stdout.close();assert p.wait(timeout=90)==2
        retained=f.runs/('dispatch-'+'43'*16)/'report.json';assert json.loads(retained.read_bytes())['succeeded'] and f.count()==b'ababab'
        invoke('lost-output-no-replay',lost,2);assert f.count()==b'ababab';f.unchanged();record(f,'lost-stdout-retains-whole-batch-and-does-not-authorize-replay')
        failed=Fixture(fmt,method,'failed','fail');bad=json.loads(invoke('failed',failed.args,1))['dispatch']
        assert not bad['succeeded'] and bad['executed_count']==2 and bad['runs'][1]['succeeded']
        assert bad['runs'][0]['execution']['jobs'][0]['outcome']=='failed' and bad['runs'][0]['execution']['jobs'][1]['outcome']=='skipped'
        failed.unchanged();record(failed,'failed-check-retains-independent-workflow-result-and-skipped-dependency')
        for sig in [signal.SIGTERM,signal.SIGINT]:
            slow=Fixture(fmt,method,'signal-'+sig.name,'slow');out,err=slow.runs/'stdout',slow.runs/'stderr';pid=None
            with out.open('wb') as stdout,err.open('wb') as stderr:
                process=subprocess.Popen([FG,*map(str,slow.args)],stdout=stdout,stderr=stderr)
                try:
                    deadline=time.monotonic()+20
                    while time.monotonic()<deadline and not(slow.pidfile.exists() and slow.pidfile.read_text().strip()):
                        assert process.poll() is None;time.sleep(.02)
                    pid=int(slow.pidfile.read_text());assert live(pid);process.send_signal(sig);time.sleep(.02)
                    if process.poll() is None:process.send_signal(sig)
                    code=process.wait(timeout=15);alive=live(pid);assert code==1 and not alive,(code,err.read_bytes(),out.read_bytes(),alive)
                finally:
                    if process.poll() is None:process.kill();process.wait(timeout=5)
                    if pid and live(pid):os.kill(pid,signal.SIGKILL)
            stopped=json.loads(out.read_bytes());assert stopped['node_closed'] and not stopped['dispatch']['succeeded'] and stopped['dispatch']['executed_count']==1
            assert not slow.late.exists() and slow.count()==b'a';invoke('signal-no-replay',slow.args,2);slow.unchanged()
            record(slow,'signal-drain-stops-later-workflows-and-restart-replay',signal=sig.name,live_child_before=True,live_child_after=False)
(ROOT/'results.json').write_text(json.dumps(RESULTS,indent=2)+'\n')
