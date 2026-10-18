import hashlib, json, os, pathlib, shutil, signal, subprocess, sys, time, zlib

fg, root = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
repo_root = pathlib.Path(__file__).resolve().parents[3]
supervisor = repo_root / 'scripts/fg_workflow_supervisor.mjs'
tenant, repository, principal = '1' * 32, '2' * 32, '3' * 32
commands, native_commands, operator_commands = 0, 0, 0
cases = []

def call(label, args, expected=0, native=False):
    global commands, native_commands, operator_commands
    commands += 1
    native_commands += int(native)
    operator_commands += int(not native)
    result = subprocess.run(list(map(str, args)), capture_output=True, timeout=180)
    (root / f'{commands:03d}-{label}.out').write_bytes(result.stdout)
    (root / f'{commands:03d}-{label}.err').write_bytes(result.stderr)
    if result.stderr:
        sys.stderr.buffer.write(result.stderr)
        sys.stderr.buffer.flush()
    assert result.returncode == expected, (label, result.returncode, expected, result.stdout.decode(errors='replace'), result.stderr.decode(errors='replace'))
    return result.stdout

def object_file(source, fmt, kind, body):
    raw = kind.encode() + b' ' + str(len(body)).encode() + b'\0' + body
    oid = hashlib.new(fmt, raw).hexdigest()
    path = source / 'objects' / oid[:2] / oid[2:]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(zlib.compress(raw))
    return oid

def source_tree(source, fmt, files):
    entries = {}
    for name, value in files.items():
        first, separator, rest = name.partition('/')
        if separator:
            entries.setdefault(first, {})[rest] = value
        else:
            entries[first] = value
    body = b''
    for name, value in sorted(entries.items(), key=lambda item: item[0] + ('/' if isinstance(item[1], dict) else '')):
        directory = isinstance(value, dict)
        oid = source_tree(source, fmt, value) if directory else object_file(source, fmt, 'blob', value)
        body += (b'40000' if directory else b'100644') + b' ' + name.encode() + b'\0' + bytes.fromhex(oid)
    return object_file(source, fmt, 'tree', body)

def private_json(path, value):
    path.write_text(json.dumps(value) + '\n')
    path.chmod(0o600)

def snapshot(directory):
    return {str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in directory.rglob('*') if p.is_file()}

def wait_for(predicate, seconds=20):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        result = predicate()
        if result:
            return result
        time.sleep(0.01)
    raise AssertionError('bounded native process condition did not arrive')

def process_identity(pid):
    try:
        raw = pathlib.Path(f'/proc/{pid}/stat').read_bytes()
        fields = raw[raw.rfind(b')') + 2:].split()
        return fields[0], fields[19]
    except FileNotFoundError:
        return None

def active_dispatch(binary, store):
    for entry in pathlib.Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            args = (entry / 'cmdline').read_bytes().split(b'\0')
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        if args[:4] == [os.fsencode(binary), b'workflow', b'dispatch', os.fsencode(store)]:
            identity = process_identity(int(entry.name))
            if identity and identity[0] not in (b'Z', b'X'):
                return int(entry.name), identity[1]
    return None

GOOD = '''name: real supervisor loop
on: push
jobs:
  build:
    runs-on: fgit-trusted-local
    strategy:
      fail-fast: false
      matrix:
        mode:
          - debug
          - release
    steps:
      - run: printf '%s' "$MODE"; test "$MODE" != never-fails
        env:
          MODE: '${{ matrix.mode }}'
  diagnostic:
    runs-on: fgit-trusted-local
    needs: build
    if: failure()
    steps:
      - run: printf DIAGNOSTIC
  package:
    runs-on: fgit-trusted-local
    needs: build
    steps:
      - run: printf PACKAGE
'''

for fmt in ('sha1', 'sha256'):
    base = root / fmt
    base.mkdir(mode=0o700)
    binary = base / 'fg'
    shutil.copyfile(fg, binary)
    binary.chmod(0o700)
    source, store = base / 'source', base / 'node'
    for name in ['watch', 'publication', 'runs', 'supervisor']:
        (base / name).mkdir(mode=0o700)
    tip = None
    def import_revision(text, revision):
        global tip
        tree = source_tree(source, fmt, {'.github/workflows/ci.yml': text.encode(), 'src/input.txt': f'revision {revision}\n'.encode()})
        old_tip = tip
        parent = '' if old_tip is None else f'parent {old_tip}\n'
        body = f'tree {tree}\n{parent}author Fixture <fixture@example.invalid> {revision} +0000\ncommitter Fixture <fixture@example.invalid> {revision} +0000\n\nrevision {revision}\n'.encode()
        tip = object_file(source, fmt, 'commit', body)
        (source / 'refs/heads').mkdir(parents=True, exist_ok=True)
        # Import admits absent refs; updates use the native expected-tip API.
        # Only mutable fixture refs are replaced, never destination authority.
        for path in (source / 'refs/heads').iterdir():
            path.unlink()
        branch = 'main' if old_tip is None else f'revision-{revision}'
        (source / 'refs/heads' / branch).write_text(tip + '\n')
        (source / 'HEAD').write_text(f'ref: refs/heads/{branch}\n')
        outcome = json.loads(call(fmt + '-import-' + str(revision), [binary, 'import', store, tenant, repository, principal, f'{fmt}-import-{revision}', source, '--json'], native=True))
        assert outcome['state'] == 'committed'
        if old_tip is not None:
            call(fmt + '-advance-' + str(revision), [binary, 'branch', 'update', store, tenant, repository,
                '--trusted-local', '--principal', principal, '--idempotency-key', f'{fmt}-advance-{revision}',
                '--ref', 'refs/heads/main', '--expected-tip', old_tip, '--target', tip, '--object-format', fmt], native=True)
        return outcome['repository_incarnation_id']
    call(fmt + '-init', [binary, 'init', store, tenant, repository, fmt], native=True)
    incarnation = import_revision(GOOD, 1)
    watch = {'schema': 'frankengit-workflow-watch-v1', 'fg': str(binary), 'storage_root': str(store),
             'tenant_id': tenant, 'repository_id': repository, 'repository_incarnation': incarnation, 'object_format': fmt,
             'ref_hex': b'refs/heads/main'.hex(), 'workflow_directory_hex': b'.github/workflows'.hex(),
             'input_prefixes_hex': [b'.github'.hex(), b'src'.hex()], 'event': 'push', 'state_directory': str(base / 'watch'),
             'run_parent': str(base / 'runs'), 'max_runs': 16, 'trust': 'selected-branch-host-execution'}
    publisher = {'schema': 'frankengit-workflow-check-publisher-v1', 'watch': watch,
                 'state_directory': str(base / 'publication'), 'principal_id': principal}
    config = {'schema': 'frankengit-workflow-supervisor-v1', 'state_directory': str(base / 'supervisor'),
              'lanes': [{'name': 'main', 'publisher': publisher}]}
    config_path = base / 'config.json'
    private_json(config_path, config)
    def operator(action='once', expected=0, extra=()):
        return json.loads(call(fmt + '-' + action, ['node', supervisor, action, '--config', config_path, '--trusted-local', *extra], expected))
    first = operator()
    assert first['lanes'][0]['execution']['outcome'] == 'observed_succeeded'
    assert first['lanes'][0]['after']['committed'] == 4 and not first['pending']
    previous = (snapshot(base / 'watch'), snapshot(base / 'runs'), snapshot(base / 'publication'))
    idle = operator()
    assert idle['lanes'][0]['execution']['reason'] == 'commit_already_observed'
    assert previous == (snapshot(base / 'watch'), snapshot(base / 'runs'), snapshot(base / 'publication'))
    import_revision(GOOD.replace('!= never-fails', '!= release'), 2)
    failed = operator(expected=1)
    assert failed['failed'] and not failed['pending']
    assert failed['lanes'][0]['execution']['outcome'] == 'observed_failed'
    assert failed['lanes'][0]['after']['committed'] == 8
    import_revision(GOOD, 3)
    limited = operator(expected=2, extra=['--max-publications', '1'])
    assert limited['lanes'][0]['after']['pending'] == 3
    executed = snapshot(base / 'runs')
    for remaining in [2, 1, 0]:
        progress = operator(expected=2 if remaining else 0, extra=['--max-publications', '1'])
        assert progress['lanes'][0]['before']['pending'] == remaining
        if remaining:
            assert 'execution' not in progress['lanes'][0]
        else:
            assert progress['lanes'][0]['execution']['reason'] == 'commit_already_observed'
        assert snapshot(base / 'runs') == executed
    assert operator()['lanes'][0]['execution']['reason'] == 'commit_already_observed'
    plans = sorted((base / 'publication').glob('plan-*.json'))
    assert len(plans) == 3
    checks = set()
    for path in plans:
        plan = json.loads(path.read_text())
        assert len(plan['jobs']) == 4
        dispatch = json.loads((base / 'runs' / ('dispatch-' + plan['watch_id'][:32]) / 'report.json').read_text())
        run = dispatch['runs'][0]
        jobs = {job['id']: job for job in run['execution']['jobs']}
        for index, job in enumerate(plan['jobs']):
            assert job['graph_root'] == run['execution']['workflow_graph'].split(':')[-1]
            assert job['source_commit'] == run['source_commit']
            terminal = json.loads((base / 'publication' / f'terminal-{plan["watch_id"]}-{index:03d}.json').read_text())
            assert terminal['outcome'] == 'committed'
            checks.add(terminal['check_id'])
            repeat = ['workflow', 'publish', store, tenant, repository, watch['ref_hex'], '--ref-hex', '--trusted-local',
                      '--run-directory', job['directory'], '--journal-id', job['journal_id'], '--minimum-pin', job['minimum_pin'],
                      '--batch', job['batch_sha256'], '--fact-index', job['fact_index'], '--principal-id', principal,
                      '--idempotency-key', job['key'], '--expected-incarnation', incarnation, '--object-format', fmt]
            receipt = json.loads(call(fmt + '-exact-publication-recovery', [binary, *repeat], native=True))
            for field in ['check_id', 'tx_id', 'decision_sequence', 'repository_commit_id']:
                assert receipt[field] == terminal[field]
            expected = {'succeeded': 'success', 'skipped': 'action_required', 'failed': 'failure'}[jobs[job['job']]['outcome']]
            assert receipt['conclusion'] == job['conclusion'] == expected
            assert receipt['evidence_sha256'] == job['evidence_sha256']
            assert not receipt['refs_changed'] and not receipt['execution_retried'] and not receipt['authoritative_check']
    assert len(checks) == 12
    # Kill only the supervisor we own after Rust has durably recorded a workflow
    # start. Its already admitted finite native workflow completes independently.
    import_revision(GOOD.replace("printf '%s'", "sleep 1; printf '%s'"), 4)
    commands += 1
    operator_commands += 1
    process = subprocess.Popen(['node', str(supervisor), 'once', '--config', str(config_path), '--trusted-local'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        pid, started = wait_for(lambda: active_dispatch(binary, store))
        def underway():
            for directory in (base / 'runs').glob('dispatch-*'):
                if (directory / 'report.json').exists():
                    continue
                if list(directory.glob('workflow-*/attempt.json')):
                    return directory
            return None
        directory = wait_for(underway)
        process.kill()
        output, errors = process.communicate(timeout=10)
        assert process.returncode == -signal.SIGKILL
        (base / 'killed-supervisor.out').write_bytes(output)
        (base / 'killed-supervisor.err').write_bytes(errors)
        wait_for(lambda: (directory / 'report.json').exists())
        def settled():
            identity = process_identity(pid)
            return identity is None or identity[1] != started or identity[0] in (b'Z', b'X')
        wait_for(settled)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=10)
    unknown = operator('status', expected=2)
    assert unknown['owner_present'] and unknown['lanes'][0]['watcher']['execution_unknown'] == 1
    lock = base / 'supervisor/owner.lock'
    original_lock = lock.stat().st_ino
    retained = snapshot(base / 'runs')
    publication_before = snapshot(base / 'publication')
    source.rename(base / 'source-offline')
    binary.rename(base / 'fg-offline')
    store.rename(base / 'node-offline')
    recovered = operator('reconcile', expected=2)
    assert not recovered['failed'] and recovered['pending'] and recovered['owner_present']
    assert recovered['lanes'][0]['watcher']['execution_unknown'] == 0
    assert recovered['lanes'][0]['watcher']['observed_succeeded'] == 3
    assert not recovered['publication_submitted'] and not recovered['execution_retried'] and not recovered['locks_removed']
    assert lock.stat().st_ino == original_lock
    assert snapshot(base / 'runs') == retained and snapshot(base / 'publication') == publication_before
    watcher_after = snapshot(base / 'watch')
    assert operator('reconcile', expected=2) == recovered
    assert snapshot(base / 'watch') == watcher_after
    cases.append({'format': fmt, 'automatic_runs': 3, 'distinct_checks': len(checks), 'failed_matrix_published': True,
                  'publication_backpressure': True, 'supervisor_sigkill_reconciled': True, 'source_and_binary_free': True,
                  'retained_owner_preserved': True, 'no_reexecution_or_republication_during_reconciliation': True})
(root / 'results.json').write_text(json.dumps({'top_level_commands': commands, 'direct_native_commands': native_commands,
    'operator_commands': operator_commands, 'cases': cases, 'native_peers_are_fixtures': False}, indent=2) + '\n')
