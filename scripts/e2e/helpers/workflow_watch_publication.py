"""Actual native ref execution, durable automatic checks and interrupted reporting."""
import base64
import hashlib
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
from pull_request_smoke import TENANT, REPOSITORY, PRINCIPAL, TARGET, SOURCE, commit, identity
FG, ROOT=sys.argv[1],Path(sys.argv[2]).resolve()
ROOT.mkdir(parents=True,exist_ok=True)
COUNT, SEQUENCE, RESULTS=24,0,[]
def invoke(label,args,code=0):
    global SEQUENCE
    SEQUENCE+=1
    out,err=(ROOT/f'{SEQUENCE:03d}-{label}.{suffix}' for suffix in ('out','err'))
    with out.open('wb') as stdout,err.open('wb') as stderr:
        done=subprocess.run([FG,*map(str,args)],stdout=stdout,stderr=stderr,timeout=180)
    diagnostic=err.read_bytes()
    if diagnostic:sys.stderr.buffer.write(diagnostic);sys.stderr.buffer.flush()
    assert done.returncode==code,(label,done.returncode,diagnostic[-4000:],out.read_bytes()[-4000:])
    return out.read_bytes()
def rows(data):return [json.loads(line) for line in data.splitlines() if line]
def record(fmt,case,**data):
    row=dict(format=fmt,case=case,**data);RESULTS.append(row);print(json.dumps(row),flush=True)
def fixture(root,fmt,event='push'):
    source,node,runs,effects=(root/p for p in ('source','node','runs','effects'))
    runs.mkdir(parents=True,mode=0o700)
    (source/'refs/heads').mkdir(parents=True)
    (source/'HEAD').write_text(f'ref: {TARGET}\n')
    (source/'config').write_text('[core]\nbare=true\nrepositoryformatversion='+('1\n[extensions]\nobjectformat=sha256\n' if fmt=='sha256' else '0\n'))
    def store(kind,body):
        oid=identity(fmt,kind,body);path=source/'objects'/oid[:2]/oid[2:];path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(zlib.compress(kind.encode()+b' '+str(len(body)).encode()+b'\0'+body));return oid
    entries=[];outcomes={}
    for group in range(2):
        workflow=f'name: watch-report-{group}\non: {event}\njobs:\n'
        for i in range(12):
            job=f'job_{group}_{i:02d}';failure=i==1 and group==0;skipped=i==2 and group==0
            needs='    needs: job_0_01\n' if skipped else ''
            action=f"printf '{job}\\n' >> {shlex.quote(str(effects))}; "+('exit 7' if failure else 'printf evidence')
            workflow+=f'  {job}:\n{needs}    runs-on: fgit-trusted-local\n    steps:\n      - run: {action}\n'
            outcomes[job]='failure' if failure else 'action_required' if skipped else 'success'
        oid=store('blob',workflow.encode());entries.append(f'100644 {group}.yml'.encode()+b'\0'+bytes.fromhex(oid))
    ci=store('tree',b''.join(entries));tree=store('tree',b'40000 ci\0'+bytes.fromhex(ci))
    target=store('commit',commit(tree,[],'target'));tip=store('commit',commit(tree,[target],'tip'));future=store('commit',commit(tree,[tip],'next'))
    for ref,value in [(TARGET,target),(SOURCE,tip),('refs/heads/future',future)]: (source/ref).write_text(value+'\n')
    scope=[node,TENANT,REPOSITORY];invoke('init',['init',*scope,fmt]);invoke('import',['import',*scope,PRINCIPAL,'watch-report-source',source])
    watch=['workflow','watch',*scope,SOURCE,'--trusted-local','--workflow','ci','--input','ci','--run-parent',runs,'--object-format',fmt]
    observed=rows(invoke('execute-without-reporting',watch,1 if event=='push' else 0))
    poll=next(r['poll'] for r in observed if r['type']=='workflow_watch_poll')
    incarnation=poll['event']['repository_incarnation'];eventdir=Path(os.fsdecode(bytes.fromhex(poll['event']['custody_directory_hex'])))
    auto=watch+['--publish-checks','--principal-id',PRINCIPAL,'--expected-incarnation',incarnation]
    return dict(source=source,node=node,runs=runs,effects=effects,scope=scope,tip=tip,future=future,target=target,watch=watch,auto=auto,poll=poll,event=eventdir,incarnation=incarnation,outcomes=outcomes)

for fmt in ('sha1','sha256'):
    f=fixture(ROOT/fmt,fmt);scope=f['scope'];effects=f['effects'].read_bytes();assert len(effects.splitlines())==COUNT-1
    invoke('open-review',['pr','open',*scope,'7','--trusted-local','--principal',PRINCIPAL,'--idempotency-key','watch-report-pr','--expected-version','0','--source-ref',SOURCE,'--target-ref',TARGET,'--expected-source',f['tip'],'--expected-target',f['target'],'--title','Automatic native CI','--body','Native check evidence only','--object-format',fmt])
    listing=['pr','list',*scope,'--trusted-local','--object-format',fmt]
    checks=['pr','checks',*scope,'7','--trusted-local','--object-format',fmt,'--limit','100']
    before=invoke('head-before',listing);refs=['at',*scope,'latest','refs'];before_refs=invoke('refs-before',refs)
    assert json.loads(invoke('no-default-checks',checks))['checks']==[]
    record(fmt,'default-is-execution-only',effects=COUNT-1)
    auto=f['auto']
    missing=list(auto);i=missing.index('--expected-incarnation');del missing[i:i+2]
    invoke('require-incarnation',missing,2);assert invoke('unchanged-invalid-flags',listing)==before
    children=f['poll']['dispatch']['runs'];assert len(children)==2
    second=Path(os.fsdecode(bytes.fromhex(children[1]['run_directory_hex'])))
    journal=second/'check-proposals.journal';original=journal.read_bytes();journal.write_bytes(original[:-1])
    out=rows(invoke('corrupt-second-child',auto,2));assert not any(r['type']=='workflow_check_set_decision' for r in out)
    assert invoke('no-partial-preflight',listing)==before and f['effects'].read_bytes()==effects
    journal.write_bytes(original);record(fmt,'all-child-preflight-before-first-admission',effects_unchanged=True)
    handoff=f['event']/'check-sources';good=handoff.read_bytes();handoff.unlink()
    invoke('legacy-handoff-refused',auto,2);assert invoke('legacy-no-admission',listing)==before
    handoff.write_bytes(good);handoff.chmod(0o600);record(fmt,'legacy-state-not-reconstructed')
    with open('/dev/full','wb') as output:
        rejected=subprocess.run([FG,*map(str,auto)],stdout=output,stderr=subprocess.PIPE,timeout=180)
    sys.stderr.buffer.write(rejected.stderr);assert rejected.returncode==2 and invoke('output-failure-no-admission',listing)==before
    record(fmt,'broken-output-prevents-admission')
    first=None;captured=bytearray();err=ROOT/f'{fmt}-killed.err'
    with err.open('wb') as stderr:
        child=subprocess.Popen([FG,*map(str,auto)],stdout=subprocess.PIPE,stderr=stderr)
        try:
            os.set_blocking(child.stdout.fileno(),False)
            selector=selectors.DefaultSelector();selector.register(child.stdout,selectors.EVENT_READ)
            deadline=time.monotonic()+90;pending=bytearray()
            while first is None and time.monotonic()<deadline:
                for _,_ in selector.select(.1):
                    data=os.read(child.stdout.fileno(),65536);captured.extend(data);pending.extend(data)
                    while b'\n' in pending:
                        line,_,rest=pending.partition(b'\n');pending=bytearray(rest)
                        row=json.loads(line)
                        if row.get('type')=='workflow_check_set_decision':first=row;break
                if child.poll() is not None:break
            assert first and first['command_committed']
            child.kill();child.wait(timeout=10)
            selector.close()
        finally:
            if child.poll() is None:child.kill();child.wait()
            child.stdout.close()
    (ROOT/f'{fmt}-killed.out').write_bytes(captured);sys.stderr.buffer.write(err.read_bytes())
    partial=json.loads(invoke('partial-canonical-checks',checks))['checks'];assert 1<=len(partial)<COUNT
    assert not (f['event']/'reported').exists() and f['effects'].read_bytes()==effects
    record(fmt,'real-process-interruption',canonical_checks=len(partial),effects_unchanged=True)
    resumed=rows(invoke('resume-automatic-reporting',auto));decisions=[r for r in resumed if r['type']=='workflow_check_set_decision']
    assert len(decisions)==COUNT and first in decisions and all(r['command_committed'] for r in decisions)
    assert resumed[-1]['dispatched']==0 and resumed[-1]['committed_check_decisions']==COUNT
    assert f['effects'].read_bytes()==effects and invoke('refs-unmodified-by-checks',refs)==before_refs
    visible=json.loads(invoke('all-canonical-checks',checks))['checks'];assert len(visible)==COUNT
    for row in decisions:assert row['conclusion']==f['outcomes'][row['job']]
    record(fmt,'resume-publishes-original-outcomes',checks=COUNT,original_decision_preserved=True)
    after=invoke('head-after-reporting',listing);again=rows(invoke('repeat-completed-reporting',auto));assert again[-1]['committed_check_decisions']==0
    assert invoke('head-unchanged-on-repeat',listing)==after and f['effects'].read_bytes()==effects
    record(fmt,'restart-suppresses-duplicate-checks-and-scripts')
    switched=list(auto);switched[switched.index('--principal-id')+1]='ff'*16
    refused=rows(invoke('publisher-change',switched,2));assert refused[-1]['polls']==0 and invoke('publisher-unchanged',listing)==after
    record(fmt,'publisher-substitution-refused-before-poll')
    invoke('advance-ref',['branch','update',*scope,'--trusted-local','--principal',PRINCIPAL,'--idempotency-key','advance-for-auto','--ref',SOURCE,'--expected-tip',f['tip'],'--target',f['future'],'--object-format',fmt])
    new=rows(invoke('execute-and-report-next-event',auto,1));new_decisions=[r for r in new if r['type']=='workflow_check_set_decision']
    assert len(new_decisions)==COUNT and new[-1]['dispatched']==1 and new[-1]['non_green']
    assert len(f['effects'].read_bytes().splitlines())==2*(COUNT-1)
    plans=[r for r in new if r['type']=='workflow_check_set'];assert all(c['source_commit']==f['future'] for p in plans for c in p['checks'])
    assert all(r['command_committed'] for r in new_decisions);record(fmt,'new-event-executes-and-reports',checks=COUNT,ordinary_failure_not_green=True)
    final=invoke('new-head',listing);invoke('new-event-repeat',auto);assert invoke('new-head-stable',listing)==final
    empty=fixture(ROOT/f'{fmt}-empty',fmt,'workflow_dispatch');emptylisting=['pr','list',*empty['scope'],'--trusted-local','--object-format',fmt]
    head=invoke('empty-before',emptylisting);no=rows(invoke('empty-auto',empty['auto']));assert no[-1]['committed_check_decisions']==0
    assert invoke('empty-after',emptylisting)==head and not empty['effects'].exists();record(fmt,'zero-matches-create-no-checks')
(ROOT/'results.json').write_text(json.dumps(RESULTS,indent=2))
