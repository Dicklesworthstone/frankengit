import hashlib, json, os, pathlib, shutil, signal, subprocess, sys, time, zlib

fg, root = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
repo_root = pathlib.Path(__file__).resolve().parents[3]
supervisor = repo_root / 'scripts/fg_workflow_supervisor.mjs'
publisher_cli = repo_root / 'scripts/fg_workflow_checks.mjs'
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

def first_cycle(path):
    line, separator, _ = path.read_bytes().partition(b'\n')
    return json.loads(line) if separator else None

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

binary = root / 'fg'
shutil.copyfile(fg, binary)
binary.chmod(0o700)
for fmt in ('sha1', 'sha256'):
    base = root / fmt
    base.mkdir(mode=0o700)
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
    # Withhold only the fixture's native state. The configured storage directory
    # still passes preflight, so the real fg refs read fails before any intent.
    withheld = base / 'node-withheld'
    store.rename(withheld)
    store.mkdir(mode=0o700)
    retry_stdout, retry_stderr = base / 'observation-retry.out', base / 'observation-retry.err'
    commands += 1
    operator_commands += 1
    process = None
    try:
        try:
            with retry_stdout.open('wb') as output, retry_stderr.open('wb') as errors:
                process = subprocess.Popen(['node', str(supervisor), 'serve', '--config', str(config_path),
                    '--trusted-local', '--interval-ms', '1000', '--max-cycles', '2'], stdout=output, stderr=errors)
            unavailable = wait_for(lambda: first_cycle(retry_stdout))
            assert unavailable['type'] == 'workflow_supervisor_cycle' and unavailable['cycle'] == 1
            lane = unavailable['lanes'][0]
            assert lane['blocked'] and 'execution' not in lane and 'after' not in lane
            assert lane['error']['stage'] == 'execution' and lane['error']['phase'] == 'observation'
            assert not lane['error']['containment_unknown']
            assert previous == (snapshot(base / 'watch'), snapshot(base / 'runs'), snapshot(base / 'publication'))
        finally:
            store.rename(base / 'node-observation-unavailable')
            withheld.rename(store)
        assert process.wait(timeout=90) == 1, (fmt, retry_stdout.read_text(), retry_stderr.read_text())
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
    observed = [json.loads(line) for line in retry_stdout.read_bytes().splitlines()]
    assert [row['type'] for row in observed] == [
        'workflow_supervisor_cycle', 'workflow_supervisor_cycle', 'workflow_supervisor_service'
    ], (fmt, observed)
    failed, service = observed[1:]
    assert service['cycles'] == 2 and service['quarantined'] == [] and not service['pending']
    assert service['failed'] and not service['execution_retried']
    assert failed['failed'] and not failed['pending']
    assert failed['lanes'][0]['execution']['outcome'] == 'observed_failed'
    assert failed['lanes'][0]['execution']['commit'] == tip
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
    prior_tip = tip
    import_revision(GOOD.replace("printf '%s'", "sleep 1; printf '%s'"), 4)
    opened = json.loads(call(fmt + '-open-recovered-run-pr', [
        binary, 'pr', 'open', store, tenant, repository, '7', '--trusted-local', '--principal', principal,
        '--idempotency-key', f'{fmt}-post-crash-pr', '--expected-version', '0', '--source-ref', 'refs/heads/main',
        '--target-ref', 'refs/heads/revision-3', '--expected-source', tip, '--expected-target', prior_tip,
        '--title', 'Recovered workflow run', '--body', 'Post-crash canonical check fixture', '--object-format', fmt
    ], native=True))
    assert opened['command_committed'] and opened['node_closed']
    def canonical_checks(label):
        page = json.loads(call(fmt + '-' + label, [
            binary, 'pr', 'checks', store, tenant, repository, '7', '--trusted-local', '--object-format', fmt
        ], native=True))
        assert page['found'] and page['complete'] and page['source_current'] and page['source_tip'] == tip
        assert page['repository_incarnation'] == incarnation
        return page
    def publish_recovered(label):
        return [json.loads(line) for line in call(fmt + '-' + label, [
            'node', publisher_cli, 'once', '--supervisor-config', config_path, '--lane', 'main', '--trusted-local'
        ]).splitlines()]
    before_crash = canonical_checks('before-supervisor-crash')
    assert before_crash['checks'] == []
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
    supervisor_lock, watcher_lock = base / 'supervisor/owner.lock', base / 'watch/owner.lock'
    original_locks = (supervisor_lock.stat().st_ino, watcher_lock.stat().st_ino)
    retained = snapshot(base / 'runs')
    publication_before = snapshot(base / 'publication')
    pending_publication, = publish_recovered('publication-before-reconciliation')
    assert pending_publication['publications'] == 0 and snapshot(base / 'publication') == publication_before
    assert canonical_checks('unreconciled-run-has-no-checks') == before_crash
    offline = [(source, base / 'source-offline'), (binary, base / 'fg-offline'), (store, base / 'node-offline')]
    for path, hidden in offline:
        path.rename(hidden)
    finalization = directory / 'finalization.json'
    try:
        finalization.rename(base / 'retained-finalization.json')
        try:
            still_pending = operator('reconcile', expected=2)
            assert still_pending['lanes'][0]['watcher']['execution_unknown'] == 1
            assert still_pending['lanes'][0]['watcher']['owner_present']
        finally:
            (base / 'retained-finalization.json').rename(finalization)
        recovered = operator('reconcile', expected=2)
        assert not recovered['failed'] and recovered['pending'] and recovered['owner_present']
        assert recovered['lanes'][0]['watcher']['execution_unknown'] == 0
        assert recovered['lanes'][0]['watcher']['observed_succeeded'] == 3
        assert not recovered['publication_submitted'] and not recovered['execution_retried'] and not recovered['locks_removed']
        assert recovered['lanes'][0]['watcher']['owner_present']
        assert snapshot(base / 'runs') == retained and snapshot(base / 'publication') == publication_before
        watcher_after = snapshot(base / 'watch')
        assert operator('reconcile', expected=2) == recovered
        assert snapshot(base / 'watch') == watcher_after
    finally:
        for path, hidden in reversed(offline):
            hidden.rename(path)
    assert canonical_checks('reconciled-run-still-has-no-checks') == before_crash

    *observations, published = publish_recovered('publish-reconciled-run')
    assert published['publications'] == len(observations) == 4
    assert sum(run['committed'] for run in published['runs']) == 16
    assert not published['execution_retried'] and all(row['outcome'] == 'committed' for row in observations)
    original_plan, = [path for path in (base / 'publication').glob('plan-*.json') if path.name not in publication_before]
    plan = json.loads(original_plan.read_bytes())
    assert directory.name == 'dispatch-' + plan['watch_id'][:32]
    original_report = json.loads((directory / 'report.json').read_bytes())
    original_run, = original_report['runs']
    job_outcomes = {job['id']: job['outcome'] for job in original_run['execution']['jobs']}
    run_directory = pathlib.Path(os.fsdecode(bytes.fromhex(original_run['run_directory_hex'])))
    assert run_directory == directory / ('workflow-' + original_run['run_id'])
    journal_id = hashlib.sha256((run_directory / 'attempt.json').read_bytes()).hexdigest()
    history = json.loads(call(fmt + '-recovered-native-journal', [
        binary, 'workflow', 'recover', run_directory, tenant, repository, '--journal-id', journal_id,
        '--limit', '128', '--page-bytes', '1048576', '--timeout-ms', '30000'
    ], native=True))
    assert history['next_after'] is None
    original_facts = {fact['job']: (batch, index, fact)
                      for batch in history['entries'] for index, fact in enumerate(batch['facts'])
                      if fact['status'] == 'completed'}
    page = canonical_checks('canonical-recovered-checks')
    by_job = {row['job']: row for row in page['checks']}
    assert len(page['checks']) == len(by_job) == len(job_outcomes) == 4
    assert set(by_job) == set(job_outcomes) == set(original_facts)
    original_check_ids = set()
    for index, job in enumerate(plan['jobs']):
        saved_terminal = json.loads((base / 'publication' / f'terminal-{plan["watch_id"]}-{index:03d}.json').read_bytes())
        row = by_job[job['job']]
        batch, fact_index, fact = original_facts[job['job']]
        assert job['directory'] == str(run_directory) and job['journal_id'] == journal_id and job['source_commit'] == tip
        assert job['batch_sha256'] == batch['batch_sha256'] and job['fact_index'] == fact_index
        assert job['run_id'] == batch['run_sha256'] and job['attempt_id'] == batch['attempt_sha256']
        assert job['evidence_sha256'] == fact['evidence_sha256'] and job['graph_root'] == batch['workflow_graph_sha256']
        assert row['id'] == saved_terminal['check_id'] and row['publisher'] == principal
        assert all(row[field] == job[field] for field in ['run_id', 'attempt_id', 'graph_root', 'evidence_sha256'])
        assert row['conclusion'] == {'succeeded': 'success', 'skipped': 'action_required', 'failed': 'failure'}[job_outcomes[row['job']]]
        original_check_ids.add(row['id'])
    assert len(original_check_ids) == 4 and original_check_ids.isdisjoint(checks)
    authority = call(fmt + '-post-crash-authority', [binary, 'at', store, tenant, repository, 'latest'], native=True)
    after_publication = snapshot(base / 'publication')
    repeated, = publish_recovered('repeat-recovered-publication')
    assert repeated['publications'] == 0
    assert sorted(repeated['runs'], key=lambda run: run['id']) == sorted(published['runs'], key=lambda run: run['id'])
    assert canonical_checks('repeat-preserves-canonical-checks') == page
    assert call(fmt + '-repeat-authority', [binary, 'at', store, tenant, repository, 'latest'], native=True) == authority
    assert snapshot(base / 'watch') == watcher_after and snapshot(base / 'runs') == retained
    assert snapshot(base / 'publication') == after_publication
    assert (supervisor_lock.stat().st_ino, watcher_lock.stat().st_ino) == original_locks
    assert not (base / 'publication/owner.lock').exists()
    blocked = call(fmt + '-retained-supervisor-fence', [
        'node', supervisor, 'once', '--config', config_path, '--trusted-local'
    ], expected=1)
    assert not blocked and snapshot(base / 'runs') == retained
    cases.append({'format': fmt, 'automatic_runs': 3, 'distinct_checks': len(checks), 'failed_matrix_published': True,
                  'read_only_observation_recovered': True,
                  'required_native_finalization_under_retained_owner': True,
                  'publication_backpressure': True, 'supervisor_sigkill_reconciled': True, 'source_and_binary_free': True,
                  'retained_owner_preserved': True, 'no_reexecution_or_republication_during_reconciliation': True,
                  'reconciled_checks_published_once': len(original_check_ids), 'repeat_publications': repeated['publications']})
(root / 'results.json').write_text(json.dumps({'top_level_commands': commands, 'direct_native_commands': native_commands,
    'operator_commands': operator_commands, 'cases': cases, 'native_peers_are_fixtures': False}, indent=2) + '\n')
