import hashlib, json, pathlib, subprocess, sys, zlib

fg, root = sys.argv[1], pathlib.Path(sys.argv[2])
tenant, repository, principal = '1' * 32, '2' * 32, '3' * 32
commands = 0
cases = []

def run(label, args, expected=0):
    global commands
    commands += 1
    result = subprocess.run([fg, '--timeout-secs', '120', *map(str, args)], capture_output=True, timeout=180)
    (root / f'{commands:03d}-{label}.out').write_bytes(result.stdout)
    (root / f'{commands:03d}-{label}.err').write_bytes(result.stderr)
    if result.stderr:
        sys.stderr.buffer.write(result.stderr)
        sys.stderr.buffer.flush()
    assert result.returncode == expected, (label, result.returncode, expected, result.stdout.decode(errors='replace'), result.stderr.decode(errors='replace'))
    return result.stdout

def native_object(source, fmt, kind, body):
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
        oid = source_tree(source, fmt, value) if directory else native_object(source, fmt, 'blob', value)
        body += (b'40000' if directory else b'100644') + b' ' + name.encode() + b'\0' + bytes.fromhex(oid)
    return native_object(source, fmt, 'tree', body)

good = '''name: persisted matrix
on: workflow_dispatch
jobs:
  build:
    runs-on: fgit-trusted-local
    strategy:
      fail-fast: false
      matrix:
        mode:
          - debug
          - release
        target:
          - linux
          - portable
        exclude:
          - mode: debug
            target: portable
        include:
          - payload: '$(touch injected); literal $HOME'
          - mode: release
            target: custom
            payload: '$(touch injected); literal $HOME'
    steps:
      - run: mkdir -p linux portable custom
      - env:
          MODE: '${{ matrix.mode }}'
          TARGET: '${{ matrix.target }}'
          PAYLOAD: '${{ matrix.payload }}'
        working-directory: '${{ matrix.target }}'
        run: |
          test -f ../src/input.txt
          test ! -e state
          printf '%s' "$MODE:$TARGET" > state
          printf '%s|%s' "$MODE:$TARGET" "$PAYLOAD"
          test "$MODE:$TARGET" != never:fail
      - run: test -z "${MODE+x}"; test ! -e linux/injected; test ! -e portable/injected; test ! -e custom/injected
  diagnostics:
    runs-on: fgit-trusted-local
    needs: build
    if: failure()
    steps:
      - run: printf DIAGNOSTICS
  package:
    runs-on: fgit-trusted-local
    needs: build
    steps:
      - run: test ! -e linux; printf PACKAGE
  unrelated:
    runs-on: fgit-trusted-local
    steps:
      - run: test ! -e linux; test -z "${MODE+x}"; printf INDEPENDENT
'''
bad = good.replace('!= never:fail', '!= release:linux')
invalid = good.replace('fail-fast: false', 'fail-fast: true')
missing = good.replace("          - mode: release\n            target: custom\n            payload: '$(touch injected); literal $HOME'", '          - mode: release\n            target: custom')
variants = [f'build__matrix_{i:03d}' for i in range(4)]

for fmt in ('sha1', 'sha256'):
    source = root / (fmt + '-source')
    files = {f'.github/workflows/{name}.yml': text.encode() for name, text in [('good', good), ('bad', bad), ('invalid', invalid), ('missing', missing)]}
    files['src/input.txt'] = b'persisted native input\n'
    tree = source_tree(source, fmt, files)
    tip = native_object(source, fmt, 'commit', f'tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nmatrix\n'.encode())
    (source / 'refs/heads').mkdir(parents=True)
    (source / 'refs/heads/main').write_text(tip + '\n')
    (source / 'HEAD').write_text('ref: refs/heads/main\n')
    store, parent = root / (fmt + '-node'), root / (fmt + '-runs')
    parent.mkdir(mode=0o700)
    scope = [store, tenant, repository]
    run(fmt + '-init', ['init', *scope, fmt])
    assert json.loads(run(fmt + '-import', ['import', *scope, principal, fmt + '-import', source, '--json']))['state'] == 'committed'

    def workflow(name, number, expected=0):
        nonce = f'{number:032x}'
        args = ['workflow', 'run', *scope, 'refs/heads/main', '--trusted-local', '--workflow', f'.github/workflows/{name}.yml', '--run-parent', parent, '--run-id', nonce, '--input', '.github', '--input', 'src', '--object-format', fmt]
        raw = run(fmt + '-' + name, args, expected)
        directory = parent / ('workflow-' + nonce)
        if expected == 2:
            assert not directory.exists()
            return None
        envelope = json.loads(raw)
        assert envelope['node_closed'] and envelope['node_cleanup_error'] is None
        report = envelope['run']
        assert report['workspaces_closed'] and not report['request_interrupted']
        assert report['source_commit'] == tip
        assert [job['id'] for job in report['execution']['jobs']] == variants + ['diagnostics', 'package', 'unrelated']
        saved = (directory / 'report.json').read_bytes()
        journal = hashlib.sha256((directory / 'attempt.json').read_bytes()).hexdigest()
        recovery_args = ['workflow', 'recover', directory, tenant, repository, '--journal-id', journal]
        history_raw = run(fmt + '-' + name + '-recover', recovery_args)
        history = json.loads(history_raw)
        assert history['execution_retried'] is False
        facts = {fact['job']: (entry, index, fact) for entry in history['entries'] for index, fact in enumerate(entry['facts']) if fact['status'] == 'completed'}
        assert set(facts) == set(variants + ['diagnostics', 'package', 'unrelated'])
        for entry, index, fact in facts.values():
            assert entry['workflow_graph_sha256'] == report['execution']['workflow_graph'].split(':')[-1]
            assert entry['source_commit'] == tip and fact['evidence_sha256']
        return report, directory, args, saved, journal, recovery_args, history_raw, facts

    completed = workflow('good', 1)
    report, directory, args, saved, journal, recovery_args, history_raw, facts = completed
    jobs = report['execution']['jobs']
    assert report['succeeded']
    assert jobs[4]['outcome'] == 'skipped' and not jobs[4]['steps']
    assert all(job['outcome'] == 'succeeded' for job in jobs[:4] + jobs[5:])
    assert report['execution']['succeeded'] is False
    observed = [bytes.fromhex(job['steps'][1]['stdout_hex']).decode() for job in jobs[:4]]
    expected = [f'{mode}:{target}|$(touch injected); literal $HOME' for mode, target in [('debug', 'linux'), ('release', 'linux'), ('release', 'portable'), ('release', 'custom')]]
    assert observed == expected
    checks = set()
    for job in jobs:
        entry, index, fact = facts[job['id']]
        publish = ['workflow', 'publish', *scope, 'refs/heads/main', '--trusted-local', '--run-directory', directory, '--journal-id', journal, '--batch', entry['batch_sha256'], '--fact-index', index, '--principal-id', principal, '--idempotency-key', fmt + '-good-' + job['id'], '--object-format', fmt]
        raw = run(fmt + '-publish-' + job['id'], publish)
        record = json.loads(raw)
        assert record['command_committed'] and record['node_closed'] and record['cleanup_error'] is None
        assert record['job'] == job['id'] and record['graph_root'] == entry['workflow_graph_sha256']
        assert record['evidence_sha256'] == fact['evidence_sha256'] and record['source_commit'] == tip
        assert record['conclusion'] == ('action_required' if job['outcome'] == 'skipped' else 'success')
        assert record['authoritative_check'] is False and record['refs_changed'] is False and record['execution_retried'] is False
        assert record['check_id'] not in checks
        checks.add(record['check_id'])
        assert run(fmt + '-retry-' + job['id'], publish) == raw
    run(fmt + '-occupied', args, 2)
    assert (directory / 'report.json').read_bytes() == saved
    failed = workflow('bad', 2, 1)
    failure_report, failure_dir, _, _, failure_journal, _, _, failure_facts = failed
    states = {job['id']: job['outcome'] for job in failure_report['execution']['jobs']}
    assert not failure_report['succeeded']
    assert states[variants[1]] == 'failed'
    assert states[variants[2]] == states[variants[3]] == states['diagnostics'] == states['unrelated'] == 'succeeded'
    assert states['package'] == 'skipped'
    for job, conclusion in [(variants[1], 'failure'), ('package', 'action_required'), ('diagnostics', 'success')]:
        entry, index, fact = failure_facts[job]
        publish = ['workflow', 'publish', *scope, 'refs/heads/main', '--trusted-local', '--run-directory', failure_dir, '--journal-id', failure_journal, '--batch', entry['batch_sha256'], '--fact-index', index, '--principal-id', principal, '--idempotency-key', fmt + '-bad-' + job, '--object-format', fmt]
        record = json.loads(run(fmt + '-publish-failure-' + job, publish))
        assert record['command_committed'] and record['conclusion'] == conclusion and record['job'] == job
        assert record['evidence_sha256'] == fact['evidence_sha256'] and record['execution_retried'] is False
    workflow('invalid', 3, 2)
    workflow('missing', 4, 2)
    source.rename(root / (fmt + '-source-offline'))
    assert run(fmt + '-source-free-recover', recovery_args) == history_raw
    rerun = workflow('good', 5)
    assert rerun[0]['succeeded'] and rerun[0]['execution']['workflow_graph'] == report['execution']['workflow_graph']
    cases.append({'format': fmt, 'matrix_variants': len(variants), 'distinct_published_checks': len(checks), 'failed_variant_blocks_package': True, 'skipped_diagnostics_not_failed_run': True, 'source_free_recovery': True})
    print(json.dumps(cases[-1]), flush=True)
(root / 'results.json').write_text(json.dumps({'commands': commands, 'cases': cases}, indent=2) + '\n')
