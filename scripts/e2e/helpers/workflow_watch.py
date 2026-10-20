"""Real native latest-ref workflow polling and cancellation, no execution stand-in."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from workspace_tool_smoke import TENANT,REPOSITORY,PRINCIPAL,REF,write_object,tree,commit
fg,root=sys.argv[1],Path(sys.argv[2]).resolve()
root.mkdir(parents=True,exist_ok=True)
results=[]
sequence=0

def invoke(label,args,code=0):
    global sequence
    sequence+=1
    out,err=(root/f'{sequence:03d}-{label}.{s}' for s in ('out','err'))
    with out.open('wb') as stdout,err.open('wb') as stderr:
        done=subprocess.run([fg,*map(str,args)],stdout=stdout,stderr=stderr,timeout=40)
    text=err.read_bytes()
    if text:sys.stderr.buffer.write(text);sys.stderr.buffer.flush()
    assert done.returncode==code,(label,done.returncode,out.read_bytes(),text)
    return out.read_bytes()

def rows(path):
    return [json.loads(line)for line in Path(path).read_text().splitlines() if line.startswith('{')]

def wait_for(test,seconds=8):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        if test():return
        time.sleep(.01)
    raise AssertionError('bounded wait expired')

def case(fmt,name,**extra):
    row={'format':fmt,'case':name,**extra};results.append(row);print(json.dumps(row),flush=True)

class Fixture:
    def __init__(self,fmt,label,tail='true',event='push'):
        self.fmt=fmt;self.home=root/f'{fmt}-{label}';self.home.mkdir()
        self.source=self.home/'source';self.node=self.home/'node';self.parent=self.home/'runs';self.parent.mkdir(mode=0o700)
        (self.source/'refs/heads').mkdir(parents=True);(self.source/'HEAD').write_text(f'ref: {REF}\n')
        (self.source/'config').write_text('[core]\nrepositoryformatversion=0\nbare=true\n' if fmt=='sha1' else '[core]\nrepositoryformatversion=1\nbare=true\n[extensions]\nobjectformat=sha256\n')
        self.effects=self.home/'effects';self.pids=self.home/'pids'
        workflow=f"name: native-watch\non: {event}\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf x >> '{self.effects}'; {tail.format(pids=self.pids)}\n"
        blob=write_object(self.source,fmt,'blob',workflow.encode())
        ci=write_object(self.source,fmt,'tree',tree([(b'100644',b'build.yml',blob)]))
        self.tree=write_object(self.source,fmt,'tree',tree([(b'40000',b'ci',ci)]))
        self.tip=None;self.revision=0;self.advance_files()
        self.scope=[self.node,TENANT,REPOSITORY]
        invoke('init',['init',*self.scope,fmt]);self.import_source()
    def advance_files(self):
        self.revision+=1;self.tip=write_object(self.source,self.fmt,'commit',commit(self.tree,self.tip,self.revision,b'next\n'))
        (self.source/REF).write_text(self.tip+'\n')
    def import_source(self):invoke('import',['import',*self.scope,PRINCIPAL,f'watch-import-{self.revision}-{len(list((self.source/"refs/heads").iterdir()))}',self.source])
    def advance(self):
        old=self.tip;self.advance_files()
        for path in (self.source/'refs/heads').iterdir():path.unlink()
        branch=f'future-{self.revision}'
        (self.source/'refs/heads'/branch).write_text(self.tip+'\n')
        (self.source/'HEAD').write_text(f'ref: refs/heads/{branch}\n')
        self.import_source()
        invoke('advance',['branch','update',*self.scope,'--trusted-local','--principal',PRINCIPAL,'--idempotency-key',f'advance-{self.revision}','--ref',REF,'--expected-tip',old,'--target',self.tip,'--object-format',self.fmt])
    def count(self):return self.effects.read_text()if self.effects.exists()else''
    def args(self,polls=1,interval=10):return ['workflow','watch',*self.scope,REF,'--trusted-local','--workflow','ci','--input','ci','--run-parent',self.parent,'--object-format',self.fmt,'--polls',polls,'--interval-ms',interval]
    def poll(self,code=0,polls=1):return [json.loads(l)for l in invoke('watch',self.args(polls),code).splitlines()]
    def started(self,mode,polls=1000,interval=30):
        out,err=self.home/f'{mode}.out',self.home/f'{mode}.err'
        a,b=out.open('wb'),err.open('wb');child=subprocess.Popen([fg,*map(str,self.args(polls,interval))],stdout=a,stderr=b);a.close();b.close()
        return child,out,err

def complete(child,out,err,expected):
    try:status=child.wait(timeout=8)
    finally:
        if child.poll()is None:child.kill();child.wait()
    diagnostic=err.read_bytes()
    if diagnostic:sys.stderr.buffer.write(diagnostic);sys.stderr.buffer.flush()
    assert status==expected,(status,out.read_bytes(),diagnostic)
    observed=rows(out);assert observed[-1]['type']=='workflow_watch_result' and observed[-1]['node_closed']
    return observed

def alive(pid):
    try:return Path(f'/proc/{pid}/stat').read_text().rsplit(') ',1)[1][0]not in 'ZX'
    except FileNotFoundError:return False

for fmt in ('sha1','sha256'):
    f=Fixture(fmt,'ordinary')
    first=f.poll(polls=2);assert [x['poll']['state']for x in first[:-1]]==['dispatched','previously_settled'] and f.count()=='x'
    assert first[-1]['polls']==2 and first[-1]['dispatched']==1
    f.poll();assert f.count()=='x';case(fmt,'restart-deduplication',effects=1)
    invoke('unrelated',['branch','create',*f.scope,'--trusted-local','--principal',PRINCIPAL,'--idempotency-key','unrelated','--ref','refs/heads/other','--target',f.tip,'--object-format',fmt])
    assert f.poll()[0]['poll']['state']=='previously_settled'and f.count()=='x';case(fmt,'unrelated-update-not-reexecuted')
    f.advance();again=f.poll(polls=2);assert again[0]['poll']['state']=='dispatched'and f.count()=='xx'
    assert again[0]['poll']['event']['event_id']!=first[0]['poll']['event']['event_id'];case(fmt,'new-ref-change',effects=2)
    child,out,err=f.started('observes-live-update')
    try:
        wait_for(lambda:bool(rows(out)))
        f.advance();wait_for(lambda:f.count()=='xxx')
        wait_for(lambda:any(x.get('poll',{}).get('state')=='dispatched'for x in rows(out)))
        child.send_signal(signal.SIGTERM)
        observed=complete(child,out,err,1);assert observed[-1]['request_stopped']
    finally:
        if child.poll()is None:child.kill();child.wait()
    assert f.count()=='xxx';case(fmt,'running-watch-observes-next-change',effects=3)
    child,out,err=f.started('idle-int',interval=60000)
    try:
        wait_for(lambda:bool(rows(out)));child.send_signal(signal.SIGINT)
        observed=complete(child,out,err,1);assert observed[-1]['request_stopped']and observed[-1]['dispatched']==0
    finally:
        if child.poll()is None:child.kill();child.wait()
    case(fmt,'idle-signal-drain')
    started=time.monotonic();bounded=[json.loads(l)for l in invoke('global-timeout',['--timeout-secs','2',*f.args(10,60000)],1).splitlines()]
    assert bounded[-1]['request_stopped']and bounded[-1]['polls']==1 and time.monotonic()-started<5;case(fmt,'whole-command-idle-budget')
    bad=Fixture(fmt,'failure',tail='exit 7');failed=bad.poll(code=1);assert failed[-1]['non_green']and not failed[-1]['requires_reconciliation']
    assert bad.poll()[0]['poll']['state']=='previously_settled'and bad.count()=='x';case(fmt,'ordinary-failure-settles-without-retry')
    skipped=Fixture(fmt,'unmatched',event='workflow_dispatch');no=skipped.poll();assert no[0]['poll']['dispatch']['matched_count']==0 and skipped.count()=='';case(fmt,'zero-matching-definitions-not-a-check')
    interrupted=Fixture(fmt,'active',tail="sleep 30 & echo $! > '{pids}'; wait")
    child,out,err=interrupted.started('active-term');pid=None
    try:
        wait_for(lambda:interrupted.pids.exists()and bool(interrupted.pids.read_text().strip()))
        pid=int(interrupted.pids.read_text());assert alive(pid)
        child.send_signal(signal.SIGTERM);time.sleep(.02)
        if child.poll()is None:child.send_signal(signal.SIGTERM)
        observed=complete(child,out,err,1);wait_for(lambda:not alive(pid),seconds=1)
        assert observed[-1]['requires_reconciliation']and interrupted.count()=='x'
    finally:
        if child.poll()is None:child.kill();child.wait()
        if pid and alive(pid):os.kill(pid,signal.SIGKILL)
    interrupted.advance();blocked=interrupted.poll(code=1);assert blocked[0]['poll']['state']=='blocked_unresolved' and interrupted.count()=='x';case(fmt,'active-drain-blocks-later-events')
    old=f.count();invalid=f.args();invalid.extend(['--event','push']);invoke('reject-caller-event',invalid,2);assert f.count()==old;case(fmt,'caller-event-refused')
(root/'results.json').write_text(json.dumps(results,indent=2))
