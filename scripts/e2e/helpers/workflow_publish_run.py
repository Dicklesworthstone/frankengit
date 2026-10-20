"""Real multi-job check publication, canonical PR reads, SIGKILL and exact restart."""
import base64
import hashlib
import json
import os
from pathlib import Path
import selectors
import shlex
import shutil
import signal
import subprocess
import sys
import time
import zlib
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pull_request_smoke import TENANT, REPOSITORY, PRINCIPAL, TARGET, SOURCE, commit, identity

FG, ROOT = sys.argv[1], Path(sys.argv[2]).resolve()
ROOT.mkdir(parents=True, exist_ok=True)
COUNT, SEQUENCE, RESULTS = 24, 0, []

def invoke(label, arguments, code=0):
    global SEQUENCE
    SEQUENCE += 1
    out, err = (ROOT / f'{SEQUENCE:03d}-{label}.{suffix}' for suffix in ('out', 'err'))
    with out.open('wb') as stdout, err.open('wb') as stderr:
        done = subprocess.run([FG, *map(str, arguments)], stdout=stdout, stderr=stderr, timeout=180)
    error = err.read_bytes()
    if error:
        sys.stderr.buffer.write(error)
        sys.stderr.buffer.flush()
    assert done.returncode == code, (label, done.returncode, error[-8000:])
    return out.read_bytes()

def rows(data):
    return [json.loads(line) for line in data.splitlines() if line]

def changed(args, flag, value):
    copy = list(args)
    copy[copy.index(flag) + 1] = str(value)
    return copy

def record(fmt, case, **values):
    entry = dict(format=fmt, case=case, **values)
    RESULTS.append(entry)
    print(json.dumps(entry), flush=True)

def fixture(source, fmt, log):
    (source / 'refs/heads').mkdir(parents=True)
    (source / 'HEAD').write_text(f'ref: {TARGET}\n')
    (source / 'config').write_text('[core]\nbare=true\nrepositoryformatversion=' +
        ('1\n[extensions]\nobjectformat=sha256\n' if fmt == 'sha256' else '0\n'))
    def store(kind, body):
        oid = identity(fmt, kind, body)
        path = source / 'objects' / oid[:2] / oid[2:]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(zlib.compress(f'{kind} {len(body)}\0'.encode() + body))
        return oid
    workflow = 'name: whole-run\non: push\njobs:\n'
    outcomes = {}
    for i in range(COUNT):
        job = f'job_{i:02d}'
        dependency = '    needs: job_01\n' if i == 2 else ''
        action = f"printf '{job}\\n' >> {shlex.quote(str(log))}; " + ('exit 7' if i == 1 else 'printf evidence')
        workflow += f'  {job}:\n{dependency}    runs-on: fgit-trusted-local\n    steps:\n      - run: {action}\n'
        outcomes[job] = 'failure' if i == 1 else 'action_required' if i == 2 else 'success'
    blob = store('blob', workflow.encode())
    tree = store('tree', b'100644 workflow.yml\0' + bytes.fromhex(blob))
    target = store('commit', commit(tree, [], 'target'))
    tip = store('commit', commit(tree, [target], 'run input'))
    future = store('commit', commit(tree, [tip], 'future input'))
    for name, oid in [(TARGET, target), (SOURCE, tip), ('refs/heads/future', future)]:
        (source / name).write_text(oid + '\n')
    return target, tip, future, outcomes

def check_plan(plan, facts, scope, snapshot, incarnation, fmt, outcomes):
    assert plan['type'] == 'workflow_check_set' and plan['selected_checks'] == COUNT
    assert plan['snapshot'] == snapshot and plan['journal_id'] == scope
    assert plan['execution_complete'] is None and len(plan['checks']) == COUNT
    assert plan['repository_incarnation'] == incarnation and plan['principal_id'] == PRINCIPAL
    assert plan['tenant_id'] == TENANT and plan['repository_id'] == REPOSITORY
    def part(value):
        return len(value).to_bytes(8, 'big') + value
    manifest = b''.join(part(value) for value in [b'frankengit/workflow-check-set/v1', bytes.fromhex(TENANT),
        bytes.fromhex(REPOSITORY), bytes.fromhex(incarnation), bytes.fromhex(PRINCIPAL), scope.encode(), snapshot.encode(), SOURCE.encode()])
    manifest += COUNT.to_bytes(8, 'big')
    for index, check in enumerate(plan['checks']):
        entry, fact_index, fact = facts[check['job']]
        digest = hashlib.sha256(b'frankengit/trusted-workflow-check/v1\0' + bytes.fromhex(PRINCIPAL)
            + bytes.fromhex(entry['run_sha256']) + bytes.fromhex(entry['attempt_sha256'])
            + hashlib.sha256(fact['job'].encode()).digest()).digest()
        expected_id = 'check/' + base64.b32hexencode(digest).decode().lower().rstrip('=')
        key = hashlib.sha256(b''.join(part(value) for value in [b'frankengit/workflow-check-set-child/v1',
            bytes.fromhex(TENANT), bytes.fromhex(REPOSITORY), bytes.fromhex(incarnation), digest, SOURCE.encode()])).hexdigest()
        assert check['index'] == index and check['check_id'] == expected_id
        assert check['batch_sha256'] == entry['batch_sha256'] and check['fact_index'] == fact_index
        assert check['evidence_sha256'] == fact['evidence_sha256'] and check['idempotency_key_hex'] == key
        assert check['conclusion'] == outcomes[check['job']] and check['source_commit'] == entry['source_commit']
        assert check['source_ref_hex'] == SOURCE.encode().hex()
        assert len(check['source_commit']) == (40 if fmt == 'sha1' else 64)
        manifest += b''.join(part(value) for value in [check['batch_sha256'].encode(), fact_index.to_bytes(8,'big'),
            bytes.fromhex(key), bytes.fromhex(check['evidence_sha256'])])
    assert hashlib.sha256(manifest).hexdigest() == plan['set_sha256']

for fmt in ('sha1', 'sha256'):
    root = ROOT / fmt
    root.mkdir()
    source, node, runs, log = (root / name for name in ('source', 'node', 'runs', 'effects'))
    runs.mkdir(mode=0o700)
    target, tip, future, outcomes = fixture(source, fmt, log)
    scope = [node, TENANT, REPOSITORY]
    invoke('init', ['init', *scope, fmt])
    invoke('import', ['import', *scope, PRINCIPAL, 'publish-run-source', source])
    run_id = '71' * 16
    invoke('run', ['workflow', 'run', *scope, SOURCE, '--trusted-local', '--workflow', 'workflow.yml',
        '--input', 'workflow.yml', '--run-parent', runs, '--run-id', run_id,
        '--expected-commit', tip, '--object-format', fmt], 1)
    directory = runs / ('workflow-' + run_id)
    report = json.loads((directory / 'report.json').read_text())
    incarnation = report['repository_incarnation']
    marker = hashlib.sha256((directory / 'attempt.json').read_bytes()).hexdigest()
    original = {name: (directory / name).read_bytes() for name in ('attempt.json', 'execution.owner', 'check-proposals.journal')}
    effects = log.read_bytes()
    assert len(effects.splitlines()) == COUNT - 1 and b'job_02\n' not in effects
    history_args = ['workflow', 'recover', directory, TENANT, REPOSITORY, '--journal-id', marker, '--limit', '128']
    history = json.loads(invoke('recover', history_args))
    assert history['next_after'] is None
    facts = {}
    for entry in history['entries']:
        for index, fact in enumerate(entry['facts']):
            if fact['status'] == 'completed':
                assert fact['job'] not in facts
                facts[fact['job']] = (entry, index, fact)
    assert len(facts) == COUNT
    invoke('open-native-review', ['pr', 'open', *scope, '7', '--trusted-local', '--principal', PRINCIPAL,
        '--idempotency-key', 'check-set-pr', '--expected-version', '0', '--source-ref', SOURCE, '--target-ref', TARGET,
        '--expected-source', tip, '--expected-target', target, '--title', 'Saved native checks', '--body', 'No automatic merge authority', '--object-format', fmt])
    listing = ['pr', 'list', *scope, '--trusted-local', '--object-format', fmt]
    checks = ['pr', 'checks', *scope, '7', '--trusted-local', '--object-format', fmt, '--limit', '100']
    refs = ['at', *scope, 'latest', 'refs']
    before = invoke('authority-before', listing)
    original_refs = invoke('refs-before', refs)
    assert json.loads(invoke('empty-checks', checks))['checks'] == []
    arguments = ['workflow', 'publish-run', *scope, SOURCE, '--trusted-local', '--run-directory', directory,
        '--journal-id', marker, '--at-pin', history['snapshot'], '--principal-id', PRINCIPAL,
        '--expected-incarnation', incarnation, '--object-format', fmt]
    plan_rows = rows(invoke('plan-only', arguments + ['--plan-only']))
    plan = plan_rows[0]
    check_plan(plan, facts, marker, history['snapshot'], incarnation, fmt, outcomes)
    assert plan_rows[-1]['plan_only'] and plan_rows[-1]['node_closed'] and plan_rows[-1]['publication'] is None
    assert invoke('authority-after-plan', listing) == before
    record(fmt, 'verified-plan', selected=COUNT, retained_batches=history['retained_batches'], independently_encoded_ids=True)
    tested = arguments + ['--expected-set', plan['set_sha256']]
    for name, invalid in [('journal', changed(tested, '--journal-id', 'ff'*32)),
        ('snapshot', changed(tested, '--at-pin', history['snapshot'].split(':')[0] + ':' + 'ff'*32)),
        ('incarnation', changed(tested, '--expected-incarnation', 'ff'*16)),
        ('set', changed(tested, '--expected-set', 'ff'*32)),
        ('limit', tested + ['--max-checks', str(COUNT-1)])]:
        output = rows(invoke('refuse-'+name, invalid, 2))
        assert not any(row.get('type') == 'workflow_check_set_decision' for row in output)
        assert invoke('unchanged-'+name, listing) == before
        record(fmt, 'preflight-'+name, no_check_admitted=True)
    assert Path('/dev/full').exists()
    with open('/dev/full', 'wb') as full:
        failed = subprocess.run([FG, *map(str, tested)], stdout=full, stderr=subprocess.PIPE, timeout=180)
    sys.stderr.buffer.write(failed.stderr)
    assert failed.returncode == 2 and invoke('full-output-no-admission', listing) == before
    record(fmt, 'output-failure-before-admission', no_check_admitted=True)
    (directory / 'report.json').unlink()
    shutil.rmtree(source)
    first_decision = None
    captured = bytearray()
    diagnostic = root / 'killed-publisher.err'
    with diagnostic.open('wb') as stderr:
        child = subprocess.Popen([FG, *map(str, tested)], stdout=subprocess.PIPE, stderr=stderr)
        assert child.stdout is not None
        selector = selectors.DefaultSelector()
        selector.register(child.stdout, selectors.EVENT_READ)
        pending = bytearray()
        try:
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline and first_decision is None:
                ready = selector.select(.25)
                if not ready:
                    assert child.poll() is None, 'publisher exited before a real decision'
                    continue
                chunk = os.read(child.stdout.fileno(), 8192)
                assert chunk, 'publisher stream ended before a decision'
                captured.extend(chunk)
                pending.extend(chunk)
                assert len(captured) <= 512*1024, 'bounded receipt capture exceeded'
                while b'\n' in pending:
                    line, _, rest = pending.partition(b'\n')
                    pending = bytearray(rest)
                    row = json.loads(line)
                    if row.get('type') == 'workflow_check_set_decision':
                        first_decision = row
                        os.kill(child.pid, signal.SIGSTOP)
                        os.kill(child.pid, signal.SIGKILL)
                        break
            assert first_decision is not None, 'no actual committed decision before deadline'
            assert child.wait(timeout=10) == -signal.SIGKILL
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)
            child.stdout.close()
            selector.close()
    (root / 'killed-publisher.out').write_bytes(captured)
    sys.stderr.buffer.write(diagnostic.read_bytes())
    assert first_decision['command_committed'] is True
    partial = json.loads(invoke('partial-canonical-checks', checks))
    assert 1 <= len(partial['checks']) < COUNT, len(partial['checks'])
    record(fmt, 'sigkill-after-commit', canonical_checks_before_restart=len(partial['checks']), receipt_tx=first_decision['tx_id'])
    resumed = rows(invoke('restart-whole-set', tested))
    decisions = [r for r in resumed if r.get('type') == 'workflow_check_set_decision']
    assert len(decisions) == COUNT and decisions[0] == first_decision
    assert resumed[0] == plan and resumed[-1]['node_closed'] is True
    assert resumed[-1]['publication']['all_committed'] is True
    page = json.loads(invoke('all-canonical-checks', checks))
    assert page['complete'] is True and len(page['checks']) == COUNT
    assert {check['job']: check['conclusion'] for check in page['checks']} == outcomes
    assert {check['id'] for check in page['checks']} == {check['check_id'] for check in plan['checks']}
    assert page['merge_permission'] is None and page['source_current'] is True
    assert invoke('unchanged-refs', refs) == original_refs
    record(fmt, 'complete-canonical-pr-read', selected=COUNT, exact_conclusions=True, first_decision_preserved=True)
    head = invoke('published-authority', listing)
    assert rows(invoke('repeat-whole-set', tested)) == resumed
    assert invoke('idempotent-authority', listing) == head
    record(fmt, 'repeat-no-new-authority', decisions=COUNT)
    invoke('advance-source', ['branch', 'update', *scope, '--trusted-local', '--principal', PRINCIPAL,
        '--idempotency-key', 'advance-check-source', '--ref', SOURCE, '--expected-tip', tip, '--target', future, '--object-format', fmt])
    moved = invoke('moved-authority', listing)
    assert rows(invoke('historical-replay', tested)) == resumed
    assert invoke('historical-no-new-authority', listing) == moved
    assert json.loads(invoke('stale-pr-source', checks))['source_current'] is False
    record(fmt, 'historical-replay-after-movement', original_decisions=True)
    other = changed(arguments, '--principal-id', 'e3'*16)
    refused = rows(invoke('fresh-publisher-stale-source', other, 3))
    stale = [r for r in refused if r.get('type') == 'workflow_check_set_decision']
    assert len(stale) == COUNT and all(r['refusal_code'] == 'TargetRefMoved' and not r['command_committed'] for r in stale)
    refusal_head = invoke('refused-authority', listing)
    assert rows(invoke('stable-canonical-refusals', other, 3)) == refused
    assert invoke('refusal-replay-no-new-authority', listing) == refusal_head
    record(fmt, 'fresh-stale-refusals', stable_refusals=COUNT)
    damaged = bytearray(original['check-proposals.journal'])
    damaged[-1] ^= 1
    path = directory / 'check-proposals.journal'
    path.write_bytes(damaged)
    output = rows(invoke('corrupt-journal', tested, 2))
    assert not any(r.get('type') == 'workflow_check_set_decision' for r in output)
    assert invoke('corruption-no-authority', listing) == refusal_head
    path.write_bytes(original['check-proposals.journal'])
    assert all((directory/name).read_bytes() == value for name,value in original.items())
    assert log.read_bytes() == effects
    assert not (directory/'report.json').exists() and not source.exists()
    record(fmt, 'corruption-and-execution-custody', scripts_reexecuted=False, journal_unchanged=True)
(ROOT / 'results.json').write_text(json.dumps(RESULTS, indent=2) + '\n')
