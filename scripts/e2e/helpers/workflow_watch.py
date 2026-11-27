"""Real native latest-ref workflow polling and cancellation, no execution stand-in."""
from array import array
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import termios
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
        self.workflow_blob=write_object(self.source,fmt,'blob',workflow.encode())
        ci=write_object(self.source,fmt,'tree',tree([(b'100644',b'build.yml',self.workflow_blob)]))
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

def stop_during_settled_output(fmt):
    # Keep the foreground CLI blocked while delivering the settled poll. The
    # workflow itself has already closed before the signal reaches the watch.
    f = Fixture(fmt, 'settled-output-stop', tail="printf '%08000d' 0")
    base_ref = 'refs/heads/base'
    base_tree = write_object(f.source, fmt, 'tree', b'')
    base = write_object(f.source, fmt, 'commit', commit(base_tree, None, 2, b'base\n'))
    (f.source / REF).unlink()
    (f.source / base_ref).write_text(base + '\n')
    (f.source / 'HEAD').write_text(f'ref: {base_ref}\n')
    invoke('import-base', ['import', *f.scope, PRINCIPAL, 'settled-output-base', f.source])
    credentials = invoke('read-incarnation', ['serve-http', *f.scope, '127.0.0.1:0', '--trusted-local',
                                               '--print-credentials-header']).decode().split()
    assert credentials[:3] == ['frankengit-http-credentials-v1', TENANT, REPOSITORY] and len(credentials) == 4
    invoke('open-pr', ['pr', 'open', *f.scope, '7', '--trusted-local', '--principal', PRINCIPAL,
                       '--idempotency-key', 'settled-output-pr', '--expected-version', '0', '--source-ref', REF,
                       '--target-ref', base_ref, '--expected-source', f.tip, '--expected-target', base,
                       '--title', 'Settled output stop', '--body', 'Check publication restart', '--object-format', fmt])

    def checks(label):
        result = invoke(label, ['pr', 'checks', *f.scope, '7', '--trusted-local', '--object-format', fmt])
        return json.loads(result)['checks']

    assert checks('before-settled-stop') == []
    watch = [*f.args(), '--publish-checks', '--principal-id', PRINCIPAL, '--expected-incarnation', credentials[-1]]
    out, err = f.home / 'settled-stop.out', f.home / 'settled-stop.err'
    with err.open('wb') as stderr:
        child = subprocess.Popen([fg, *map(str, watch)], stdout=subprocess.PIPE, stderr=stderr, pipesize=4096)
    try:
        def delivering_poll():
            available = array('i', [0])
            fcntl.ioctl(child.stdout.fileno(), termios.FIONREAD, available, True)
            assert child.poll() is None, err.read_bytes()
            return available[0] > 0 and any(f.parent.glob('watch-*/event-*/settled'))

        wait_for(delivering_poll, seconds=15)
        child.send_signal(signal.SIGTERM)
        time.sleep(.2)  # Keep stdout full while the owned signal observer runs.
        assert child.poll() is None
        output, _ = child.communicate(timeout=15)
        out.write_bytes(output)
        assert child.returncode == 1, (child.returncode, err.read_bytes())
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        child.stdout.close()
    if diagnostic := err.read_bytes():
        sys.stderr.buffer.write(diagnostic)
        sys.stderr.buffer.flush()
    observations = rows(out)
    poll = next(row['poll'] for row in observations if row['type'] == 'workflow_watch_poll')
    terminal = observations[-1]
    assert poll['execution_settled'] and poll['dispatch']['succeeded'] and f.count() == 'x'
    assert terminal['node_closed'] and terminal['request_stopped'] and not terminal['non_green']
    assert not terminal['requires_reconciliation'], terminal
    assert terminal['committed_check_decisions'] == 0 and checks('before-settled-restart') == []

    restarted = [json.loads(line) for line in invoke('restart-settled-stop', watch).splitlines()]
    assert restarted[-1]['dispatched'] == 0 and restarted[-1]['committed_check_decisions'] == 1
    retained = checks('after-settled-restart')
    assert len(retained) == 1 and retained[0]['conclusion'] == 'success' and f.count() == 'x'
    repeated = json.loads(invoke('repeat-settled-stop', watch).splitlines()[-1])
    assert repeated['dispatched'] == repeated['committed_check_decisions'] == 0
    assert checks('after-settled-repeat') == retained and f.count() == 'x'
    f.advance()
    successor = [json.loads(line) for line in invoke('successor-after-settled-stop', watch).splitlines()]
    assert successor[-1]['dispatched'] == successor[-1]['committed_check_decisions'] == 1
    selected = next(row['poll'] for row in successor if row['type'] == 'workflow_watch_poll')
    assert selected['dispatch']['runs'][0]['source_commit'] == f.tip and f.count() == 'xx'
    case(fmt, 'settled-output-stop-recovers-one-check-and-resumes', event=poll['event']['event_id'],
         check=retained[0]['id'], successor=f.tip)

def definition_refusal(fmt, ordered):
    profile = 'ordered' if ordered else 'latest'
    f = Fixture(fmt, f'{profile}-definition-refusal')
    watch = f.args()
    if ordered:
        watch.append('--ordered-branch-updates')

    def poll(label, code=0):
        return [json.loads(line) for line in invoke(label, watch, code).splitlines()]

    def poll_observation(rows):
        return next(row['poll'] for row in rows if row['type'] == 'workflow_watch_poll')

    first = poll_observation(poll('valid-anchor'))
    watch.extend(['--publish-checks', '--principal-id', PRINCIPAL,
                  '--expected-incarnation', first['event']['repository_incarnation']])
    assert poll('publish-anchor')[-1]['committed_check_decisions'] == 1
    assert f.count() == 'x'
    good_tree = f.tree
    source = f.source
    bad_path = b'ci/z-invalid.yml'
    bad_yaml = b'name: invalid\non: push\njobs:\n  check:\n    runs-on: fgit-trusted-local\n    steps:\n      - uses: external/action@v1\n'
    bad_blob = write_object(source, fmt, 'blob', bad_yaml)
    bad_entries = tree([(b'100644', b'build.yml', f.workflow_blob),
                        (b'100644', b'z-invalid.yml', bad_blob)])
    bad_ci = write_object(source, fmt, 'tree', bad_entries)
    f.tree = write_object(source, fmt, 'tree', tree([(b'40000', b'ci', bad_ci)]))
    f.advance()
    rejected = f.tip
    if ordered:
        f.tree = good_tree
        f.advance()

    listing = ['pr', 'list', *f.scope, '--trusted-local', '--object-format', fmt]
    authority = invoke('authority-before-refusal', listing)
    observations = poll('reject-invalid-definition', 1)
    rejected_poll = poll_observation(observations)
    summary = observations[-1]
    dispatch = rejected_poll['dispatch']
    assert rejected_poll['event']['commit'] == rejected
    assert rejected_poll['execution_settled']
    assert dispatch['stop_reason'] == 'definition_refused'
    assert dispatch['executed_count'] == 0 and not dispatch['succeeded']
    assert dispatch['plan']['workflows'] == []
    refusal = dispatch['plan']['definition_refusal']
    assert bytes.fromhex(refusal['path_hex']) == bad_path and refusal['blob'] == bad_blob
    assert bytes.fromhex(refusal['diagnostic_hex'])
    assert not summary['requires_reconciliation'] and summary['non_green']
    assert summary['committed_check_decisions'] == 0
    assert invoke('authority-after-refusal', listing) == authority and f.count() == 'x'
    case(fmt, f'{profile}-definition-refuses-before-any-job', rejected=rejected)

    event_dir = Path(os.fsdecode(bytes.fromhex(rejected_poll['event']['custody_directory_hex'])))
    dispatch_dir = Path(os.fsdecode(bytes.fromhex(dispatch['plan']['run_directory_hex'])))
    marker = event_dir / 'settled'
    plan = dispatch_dir / 'dispatch.json'
    original = plan.read_bytes()
    marker.unlink()
    plan.write_bytes(original + b' ')
    poll('reject-changed-refusal-plan', 2)
    assert not marker.exists() and f.count() == 'x'
    assert invoke('changed-plan-authority', listing) == authority
    plan.write_bytes(original)
    if not ordered:
        again = poll('recover-refusal-acknowledgement')
        assert poll_observation(again)['state'] == 'previously_settled' and marker.exists()
        assert again[-1]['committed_check_decisions'] == 0 and f.count() == 'x'
        f.tree = good_tree
        f.advance()
    repaired = poll('run-repaired-successor')
    assert poll_observation(repaired)['event']['commit'] == f.tip and marker.exists()
    assert repaired[-1]['committed_check_decisions'] == 1 and f.count() == 'xx'
    assert poll('suppress-repaired-repeat')[-1]['committed_check_decisions'] == 0
    assert f.count() == 'xx'
    case(fmt, f'{profile}-refusal-ack-recovery-and-successor', repaired=f.tip)

def failed_report(fmt, level):
    # Block a real job until the fixture occupies one report's name.
    # The execution journal and handoff remain writable.
    f = Fixture(fmt, f'{level}-report-failure',
                tail="printf ready > '{pids}'; while [ ! -f '{pids}.release' ]; do sleep .02; done")
    release = f.pids.with_suffix('.release')
    watcher, out, err = f.started('report-collision', polls=1)
    occupied = b'occupied batch report fixture\n'
    try:
        wait_for(lambda: f.pids.exists() and f.pids.read_bytes() == b'ready')
        assert watcher.poll() is None and f.count() == 'x'
        event, = f.parent.glob('watch-*/event-*')
        batch, = event.glob('dispatch-*')
        child, = batch.glob('workflow-*')
        assert (batch / 'dispatch.json').exists()
        blocked_report = (child if level == 'child' else batch) / 'report.json'
        with blocked_report.open('xb') as output:
            output.write(occupied)
        release.touch()
        failure = complete(watcher, out, err, 2)[-1]
    finally:
        release.touch()
        if watcher.poll() is None:
            watcher.terminate()
            watcher.wait(timeout=12)
    assert 'report durability failed' in failure['operation_error']
    assert blocked_report.read_bytes() == occupied
    handoff = event / 'check-sources'
    settled = event / 'settled'
    assert handoff.is_file() and settled.is_file(), 'closed run lost its original handoff'
    if level == 'child':
        execution, = json.loads((batch / 'report.json').read_bytes())['runs']
    else:
        execution = json.loads((child / 'report.json').read_bytes())
    assert execution['workspaces_closed'] and execution['executed_commit'] == f.tip
    case(fmt, f'late-{level}-report-failure-preserves-closed-execution', commit=f.tip)

    metadata = json.loads((event / 'event.json').read_bytes())
    original = f.tip
    auto = f.args() + ['--publish-checks', '--principal-id', PRINCIPAL,
                       '--expected-incarnation', metadata['repository_incarnation']]
    settled.unlink()
    captured = [json.loads(line) for line in invoke('recover-with-occupied-report', auto).splitlines()]
    decisions = [row for row in captured if row['type'] == 'workflow_check_set_decision']
    checks = [check for row in captured if row['type'] == 'workflow_check_set' for check in row['checks']]
    assert len(decisions) == len(checks) == 1
    assert decisions[0]['command_committed'] and checks[0]['source_commit'] == original
    assert checks[0]['conclusion'] == 'success' and settled.is_file()
    assert f.count() == 'x' and blocked_report.read_bytes() == occupied
    repeated = [json.loads(line) for line in invoke('repeat-after-report-failure', auto).splitlines()]
    assert repeated[-1]['committed_check_decisions'] == 0 and f.count() == 'x'
    case(fmt, 'recover-original-check-without-replaying-jobs-or-writing-report',
         blocked_report=level, commit=original)

    f.advance()
    successor = [json.loads(line) for line in invoke('run-after-report-failure', auto).splitlines()]
    poll = next(row['poll'] for row in successor if row['type'] == 'workflow_watch_poll')
    assert poll['event']['commit'] == f.tip and poll['execution_settled']
    assert successor[-1]['committed_check_decisions'] == 1 and f.count() == 'xx'
    directory = Path(os.fsdecode(bytes.fromhex(poll['dispatch']['plan']['run_directory_hex'])))
    assert json.loads((directory / 'report.json').read_bytes()) == poll['dispatch']
    case(fmt, 'report-failure-does-not-block-next-commit', blocked_report=level, commit=f.tip)

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
    definition_refusal(fmt, ordered=False)
    definition_refusal(fmt, ordered=True)
    failed_report(fmt, 'batch')
    failed_report(fmt, 'child')
    stop_during_settled_output(fmt)
(root/'results.json').write_text(json.dumps(results,indent=2))
