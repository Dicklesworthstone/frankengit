"""Native PR lifecycle -> real jobs/artifacts -> canonical checks and crash recovery."""
import json
import os
from pathlib import Path
import selectors
import shlex
import signal
import subprocess
import sys
import time
import zlib
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from pull_request_smoke import TENANT,REPOSITORY,PRINCIPAL,TARGET,SOURCE,commit,identity
FG,ROOT=sys.argv[1],Path(sys.argv[2]).resolve()
ROOT.mkdir(parents=True,exist_ok=True)
SEQUENCE,RESULTS=0,[]
def invoke(label,args,code=0):
    global SEQUENCE
    SEQUENCE+=1
    out,err=(ROOT/f'{SEQUENCE:03d}-{label}.{suffix}' for suffix in ('out','err'))
    with out.open('wb') as stdout,err.open('wb') as stderr:
        done=subprocess.run([FG,*map(str,args)],stdout=stdout,stderr=stderr,timeout=150)
    diagnostic=err.read_bytes()
    if diagnostic:sys.stderr.buffer.write(diagnostic);sys.stderr.buffer.flush()
    assert done.returncode==code,(label,done.returncode,diagnostic[-2500:],out.read_bytes()[-5000:])
    return out.read_bytes()
def rows(data):return [json.loads(line) for line in data.splitlines() if line]
def record(fmt,case,**values):
    row=dict(format=fmt,case=case,**values);RESULTS.append(row);print(json.dumps(row),flush=True)
def polled(data):return [r['poll'] for r in rows(data) if r['type']=='workflow_watch_poll']
def changed(args,flag,value):
    out=list(args);out[out.index(flag)+1]=str(value);return out
def alive(pid):
    try:return Path(f'/proc/{pid}/stat').read_text().rsplit(') ',1)[1][0] not in 'ZX'
    except FileNotFoundError:return False
class Fixture:
    def __init__(self,fmt,label,mode='normal'):
        self.fmt,self.root=fmt,ROOT/(fmt+'-'+label)
        self.root.mkdir()
        self.source,self.node,self.runs,self.artifact_root,self.effects,self.push_effects,self.pidfile=(self.root/p for p in ('source','node','runs','artifacts','effects','push-effects','child-pid'))
        self.runs.mkdir(mode=0o700);self.artifact_root.mkdir(mode=0o700)
        (self.source/'refs/heads').mkdir(parents=True)
        (self.source/'HEAD').write_text(f'ref: {TARGET}\n')
        (self.source/'config').write_text('[core]\nbare=true\nrepositoryformatversion='+('1\n[extensions]\nobjectformat=sha256\n' if fmt=='sha256' else '0\n'))
        def store(kind,body):
            oid=identity(fmt,kind,body);path=self.source/'objects'/oid[:2]/oid[2:];path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(zlib.compress(kind.encode()+b' '+str(len(body)).encode()+b'\0'+body));return oid
        trigger='workflow_dispatch' if mode=='unmatched' else 'pull_request'
        workflow=f'name: native-pr-head\non: {trigger}\njobs:\n'
        self.outcomes={}
        for job in (['slow'] if mode=='active' else ['produce','consume','fail','skip','ok0','ok1','ok2','ok3']):
            needs='    needs: '+('produce' if job=='consume' else 'fail')+'\n' if job in ('consume','skip') else ''
            action=f"printf '{job}\\n' >> {shlex.quote(str(self.effects))}; "
            if job=='produce':action+='cat input.txt > built.bin'
            elif job=='consume':action+='cmp .fgit-artifacts/copied.bin input.txt'
            elif job=='fail':action+='exit 7'
            elif job=='slow':action+=f'echo $$ > {shlex.quote(str(self.pidfile))}; exec sleep 30'
            else:action+='true'
            workflow+=f'  {job}:\n{needs}    runs-on: fgit-trusted-local\n    steps:\n      - run: {action}\n'
            self.outcomes[job]='failure' if job=='fail' else 'action_required' if job=='skip' else 'success'
        pr=store('blob',workflow.encode())
        push=store('blob',f"name: push-only\non: push\njobs:\n  push:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf push >> {shlex.quote(str(self.push_effects))}\n".encode())
        ci=store('tree',b'100644 pr.yml\0'+bytes.fromhex(pr)+b'100644 push.yml\0'+bytes.fromhex(push))
        def tree(payload):
            blob=store('blob',payload)
            return store('tree',b'40000 ci\0'+bytes.fromhex(ci)+b'100644 input.txt\0'+bytes.fromhex(blob))
        first,second=tree(b'original input\n'),tree(b'changed source input\n')
        self.target=store('commit',commit(first,[],'base'));self.tip=store('commit',commit(first,[self.target],'topic'))
        self.future=store('commit',commit(second,[self.tip],'next source'));self.future2=store('commit',commit(second,[self.future],'last source'))
        for name,oid in [(TARGET,self.target),(SOURCE,self.tip),('refs/heads/future',self.future),('refs/heads/future2',self.future2)]: (self.source/name).write_text(oid+'\n')
        self.scope=[self.node,TENANT,REPOSITORY]
        invoke('init',['init',*self.scope,fmt]);invoke('import',['import',*self.scope,PRINCIPAL,'pr-watch-source',self.source])
        self.base=['workflow','watch',*self.scope,SOURCE,'--trusted-local','--workflow','ci','--input','ci','--input','input.txt','--run-parent',self.runs,'--object-format',fmt]
        self.watch=self.base+['--pull-request','7']
        if mode=='normal':self.watch+=['--artifact-root',self.artifact_root,'--artifact','ci/pr.yml:produce:built.bin','--artifact-input','ci/pr.yml:consume:produce:built.bin:copied.bin']
        self.checks=['pr','checks',*self.scope,'7','--trusted-local','--object-format',fmt,'--limit','100']
        self.listing=['pr','list',*self.scope,'--trusted-local','--object-format',fmt]
    def count(self):return len(self.effects.read_bytes().splitlines()) if self.effects.exists() else 0
    def transition(self,action,previous,number=7):
        return invoke(action,['pr',action,*self.scope,str(number),'--trusted-local','--principal',PRINCIPAL,
            '--idempotency-key',f'pr-{number}-{previous}-{action}','--expected-version',str(previous),
            '--source-ref',SOURCE,'--target-ref',TARGET,'--expected-source',self.tip,'--expected-target',self.target,
            '--title','Native PR watch','--body','Source-head evidence, not synthetic merge','--object-format',self.fmt])
    def move(self,reference,old,new,key):
        invoke('move',['branch','update',*self.scope,'--trusted-local','--principal',PRINCIPAL,'--idempotency-key',key,
            '--ref',reference,'--expected-tip',old,'--target',new,'--object-format',self.fmt])

for fmt in ('sha1','sha256'):
    f=Fixture(fmt,'normal');before=invoke('head-before',f.listing)
    absent=polled(invoke('absent',f.watch))[0];assert absent['state']=='pull_request_unavailable' and f.count()==0
    assert invoke('absent-no-authority',f.listing)==before;record(fmt,'absent-pr-no-execution')
    invoke('zero-number',changed(f.watch,'--pull-request','0'),2);assert f.count()==0;record(fmt,'invalid-number-before-execution')
    f.transition('open',0)
    raw=invoke('opened-pr',f.watch+['--polls','2','--interval-ms','10'],1);observed=polled(raw);first=observed[0]
    assert [p['state'] for p in observed]==['dispatched','previously_settled'] and f.count()==7 and not f.push_effects.exists()
    event=first['event'];assert event['commit']==f.tip and event['pull_request']['number']=='7' and event['pull_request']['version']=='1'
    assert event['pull_request']['synthetic_merge'] is False and event['pull_request']['observed_target_commit']==f.target
    assert first['dispatch']['matched_count']==1 and first['dispatch']['plan']['event']=='pull_request'
    run=first['dispatch']['runs'][0];assert run['executed_commit']==f.tip and run['artifacts'] and run['artifact_inputs']
    assert json.loads(invoke('no-implicit-checks',f.checks))['checks']==[]
    record(fmt,'opened-pr-selects-only-pr-jobs-and-hands-off-artifacts',effects=f.count(),source=f.tip)
    invoke('separate-push',f.base);assert f.push_effects.read_bytes()==b'push' and f.count()==7
    assert polled(invoke('pr-after-push',f.watch))[0]['state']=='previously_settled';record(fmt,'push-and-pr-scopes-are-independent')
    wrong=list(f.watch);wrong[5]=TARGET
    assert polled(invoke('mismatched-source',wrong))[0]['state']=='pull_request_unavailable' and f.count()==7;record(fmt,'mismatched-pr-source-no-execution')
    auto=f.watch+['--publish-checks','--principal-id',PRINCIPAL,'--expected-incarnation',event['repository_incarnation']]
    directory=Path(os.fsdecode(bytes.fromhex(run['run_directory_hex'])))
    journal=directory/'check-proposals.journal';good=journal.read_bytes();before=invoke('before-corruption',f.listing)
    journal.write_bytes(good[:-1]);refused=rows(invoke('corrupt-original-journal',auto,2))
    assert not any(r['type']=='workflow_check_set_decision' for r in refused) and invoke('corrupt-no-authority',f.listing)==before and f.count()==7
    journal.write_bytes(good);record(fmt,'corrupt-pr-custody-never-publishes')
    first_decision=None;pending=bytearray()
    with (f.root/'killed-reporting.err').open('wb') as stderr:
        child=subprocess.Popen([FG,*map(str,auto)],stdout=subprocess.PIPE,stderr=stderr)
        try:
            os.set_blocking(child.stdout.fileno(),False)
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout,selectors.EVENT_READ);deadline=time.monotonic()+60
                while first_decision is None and time.monotonic()<deadline:
                    for key,_ in selector.select(.05):
                        chunk=os.read(key.fileobj.fileno(),65536)
                        if not chunk:continue
                        pending.extend(chunk)
                        while b'\n' in pending:
                            line,_,pending=pending.partition(b'\n');row=json.loads(line)
                            if row['type']=='workflow_check_set_decision':first_decision=row;child.kill();break
                    if child.poll() is not None and first_decision is None:break
            assert first_decision is not None;child.wait(timeout=10)
        finally:
            if child.poll() is None:child.kill();child.wait()
            child.stdout.close()
    partial=json.loads(invoke('partial-pr-checks',f.checks))['checks'];assert 1<=len(partial)<8 and f.count()==7
    record(fmt,'killed-real-pr-reporter-after-admission',checks=len(partial))
    resumed=rows(invoke('resume-original-pr-report',auto));assert first_decision in resumed and f.count()==7
    checks=json.loads(invoke('completed-pr-checks',f.checks))['checks'];assert len(checks)==8
    assert {c['job']:c['conclusion'] for c in checks}==f.outcomes
    record(fmt,'resume-original-check-decisions-without-reexecution',checks=len(checks))
    before=invoke('before-repeat',f.listing);invoke('repeat-report',auto)
    assert invoke('after-repeat',f.listing)==before and f.count()==7;record(fmt,'fresh-process-deduplication')
    invoke('unrelated',['branch','create',*f.scope,'--trusted-local','--principal',PRINCIPAL,'--idempotency-key','unrelated',
        '--ref','refs/heads/unrelated','--target',f.tip,'--object-format',fmt]);invoke('after-unrelated',auto)
    assert f.count()==7;record(fmt,'unrelated-authority-change-does-not-trigger-pr')
    invoke('append-real-pr-comment',['pr','comment',*f.scope,'7','--trusted-local','--principal',PRINCIPAL,
        '--idempotency-key','unrelated-discussion','--expected-version','0','--body','A comment cannot schedule scripts','--object-format',fmt])
    assert polled(invoke('comment-does-not-reexecute',auto))[0]['state']=='previously_settled' and f.count()==7
    record(fmt,'canonical-pr-comment-does-not-trigger-execution')
    f.transition('close',1);assert polled(invoke('closed',auto))[0]['state']=='pull_request_unavailable' and f.count()==7
    record(fmt,'closed-pr-suppresses-execution')
    f.transition('reopen',2);reopened=polled(invoke('reopened',auto,1))[0]
    assert reopened['event']['event_id']!=event['event_id'] and reopened['event']['pull_request']['version']=='3' and f.count()==14
    record(fmt,'reopened-same-commit-is-a-new-versioned-event')
    f.transition('update',3);updated=polled(invoke('metadata-version',auto,1))[0]
    assert updated['event']['pull_request']['version']=='4' and f.count()==21;record(fmt,'metadata-version-is-explicit-trigger')
    original=f.tip;f.move(SOURCE,f.tip,f.future,'advance-source');f.tip=f.future
    advanced_rows=rows(invoke('current-source-with-stale-recorded-tip',auto,1))
    advanced=next(r['poll'] for r in advanced_rows if r['type']=='workflow_watch_poll')
    assert advanced['event']['commit']==f.tip and advanced['event']['pull_request']['recorded_source_commit']==original
    assert advanced['dispatch']['runs'][0]['executed_commit']==f.tip and f.count()==28
    selected=[c for r in advanced_rows if r['type']=='workflow_check_set' for c in r['checks']]
    assert {c['job']:c['conclusion'] for c in selected}==f.outcomes and all(c['source_commit']==f.tip for c in selected)
    assert advanced_rows[-1]['committed_check_decisions']==8 and advanced_rows[-1]['refused_check_decisions']==0
    stale=json.loads(invoke('stale-pr-coordinates-never-show-current-checks',f.checks))
    assert stale['source_current'] is False and stale['checks']==[] and stale['source_tip']==original
    f.transition('update',4)
    current=json.loads(invoke('explicitly-refreshed-pr-checks',f.checks));assert current['source_current'] is True
    assert {c['job']:c['conclusion'] for c in current['checks']}==f.outcomes
    assert f.count()==28
    record(fmt,'source-update-runs-actual-current-bytes-with-artifacts',source=f.tip)
    f.move(TARGET,f.target,f.tip,'advance-target');f.target=f.tip
    target_changed=polled(invoke('current-target-change',auto,1))[0]
    assert target_changed['event']['pull_request']['observed_target_commit']==f.target and f.count()==35
    record(fmt,'observed-target-change-retriggers-source-head-profile')
    f.move(SOURCE,f.tip,f.future2,'source-before-merge');f.tip=f.future2;f.transition('update',5)
    invoke('canonical-fast-forward',['pr','fast-forward',*f.scope,'7','--trusted-local','--principal',PRINCIPAL,
        '--idempotency-key','merge-pr-seven','--expected-version','6','--source-ref',SOURCE,'--expected-source',f.tip,
        '--target-ref',TARGET,'--expected-target',f.target,'--object-format',fmt]);f.target=f.tip
    assert polled(invoke('merged',auto))[0]['state']=='pull_request_unavailable' and f.count()==35;record(fmt,'merged-pr-never-starts-new-jobs')
    f.transition('open',0,8);other=changed(auto,'--pull-request','8');other_poll=polled(invoke('another-pr',other,1))[0]
    assert other_poll['event']['pull_request']['number']=='8' and f.count()==42
    record(fmt,'different-pr-number-has-independent-custody')
    empty=Fixture(fmt,'unmatched','unmatched');empty.transition('open',0)
    no_match=polled(invoke('no-pr-definitions',empty.watch))[0]
    assert no_match['dispatch']['matched_count']==0 and empty.count()==0 and not empty.push_effects.exists()
    assert json.loads(invoke('no-empty-green-check',empty.checks))['checks']==[];record(fmt,'no-matching-pr-workflows-is-not-a-check')
    slow=Fixture(fmt,'active','active');slow.transition('open',0)
    out,err=slow.root/'signal.out',slow.root/'signal.err';pid=None
    with out.open('wb') as stdout,err.open('wb') as stderr:
        child=subprocess.Popen([FG,*map(str,slow.watch)],stdout=stdout,stderr=stderr)
        try:
            deadline=time.monotonic()+15
            while time.monotonic()<deadline and not (slow.pidfile.exists() and slow.pidfile.read_text().strip()):
                assert child.poll() is None;time.sleep(.02)
            pid=int(slow.pidfile.read_text());assert alive(pid)
            child.send_signal(signal.SIGTERM);time.sleep(.02)
            if child.poll() is None:child.send_signal(signal.SIGTERM)
            assert child.wait(timeout=15)==1
            assert not alive(pid),'product must stop the observed live child before fixture cleanup'
        finally:
            if child.poll() is None:child.kill();child.wait()
            if pid and alive(pid):os.kill(pid,signal.SIGKILL)
    summary=rows(out.read_bytes())[-1];assert summary['requires_reconciliation'] and summary['node_closed'] and slow.count()==1
    slow.transition('close',1);slow.transition('reopen',2)
    blocked=polled(invoke('reopened-unresolved',slow.watch,1))[0]
    assert blocked['state']=='blocked_unresolved' and slow.count()==1;record(fmt,'signal-drain-preserves-pr-replay-fence')
(ROOT/'results.json').write_text(json.dumps(RESULTS,indent=2)+'\n')
