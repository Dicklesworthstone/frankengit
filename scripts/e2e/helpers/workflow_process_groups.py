import hashlib, json, pathlib, re, subprocess, sys, time, zlib

fg, root = sys.argv[1], pathlib.Path(sys.argv[2])
tenant, repository, principal = '1' * 32, '2' * 32, '3' * 32
commands, cases = 0, []

def invoke(label, args, expected=0, seconds=120):
    global commands
    commands += 1
    start = time.monotonic()
    result = subprocess.run([fg, '--timeout-secs', str(seconds), *map(str, args)], capture_output=True, timeout=180)
    elapsed = time.monotonic() - start
    (root / f'{commands:03d}-{label}.out').write_bytes(result.stdout)
    (root / f'{commands:03d}-{label}.err').write_bytes(result.stderr)
    if result.stderr:
        sys.stderr.buffer.write(result.stderr)
        sys.stderr.buffer.flush()
    assert result.returncode == expected, (label, result.returncode, expected, result.stdout.decode(errors='replace'), result.stderr.decode(errors='replace'))
    return result.stdout, elapsed

def object_file(source, fmt, kind, body):
    raw = kind.encode() + b' ' + str(len(body)).encode() + b'\0' + body
    oid = hashlib.new(fmt, raw).hexdigest()
    path = source / 'objects' / oid[:2] / oid[2:]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(zlib.compress(raw))
    return oid

def tree(source, fmt, files):
    nested = {}
    for path, data in files.items():
        name, separator, remainder = path.partition('/')
        if separator:
            nested.setdefault(name, {})[remainder] = data
        else:
            nested[name] = data
    body = bytearray()
    for name, data in sorted(nested.items(), key=lambda item: item[0] + ('/' if isinstance(item[1], dict) else '')):
        directory = isinstance(data, dict)
        oid = tree(source, fmt, data) if directory else object_file(source, fmt, 'blob', data)
        body.extend((b'40000' if directory else b'100644') + b' ' + name.encode() + b'\0' + bytes.fromhex(oid))
    return object_file(source, fmt, 'tree', bytes(body))

def workflow(script):
    return ('name: process ownership\non: workflow_dispatch\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: |\n' + ''.join('          ' + line + '\n' for line in script.splitlines()) + '''  b:
    runs-on: fgit-trusted-local
    needs: a
    if: always()
    steps:
      - run: printf 'dependent-ran'
  z:
    runs-on: fgit-trusted-local
    steps:
      - run: printf 'independent-ran'
''').encode()

scripts = {
    'joined': "sleep 0.02 & wait; printf 'joined-result'",
    'orphan': "sleep 10 & printf 'worker=%s\\n' \"$!\"; exit 0",
    'signal': "sleep 10 & printf 'worker=%s\\n' \"$!\"; kill -TERM $$",
    'deadline': "sh -c 'sleep 10 & printf \"grandchild=%s\\n\" \"$!\"; wait' & printf 'worker=%s\\n' \"$!\"; wait",
}

def alive(pid):
    try:
        data = pathlib.Path(f'/proc/{pid}/stat').read_bytes()
    except FileNotFoundError:
        return False
    return data[data.rindex(b')') + 1:].split()[0] not in (b'Z', b'X')

def stopped(pids):
    end = time.monotonic() + 0.5
    while any(alive(pid) for pid in pids) and time.monotonic() < end:
        time.sleep(0.01)
    assert not any(alive(pid) for pid in pids), pids

for fmt in ('sha1', 'sha256'):
    source = root / (fmt + '-source')
    files = {f'.github/workflows/{name}.yml': workflow(script) for name, script in scripts.items()}
    files['src/readme'] = b'input for native process ownership\n'
    tree_id = tree(source, fmt, files)
    tip = object_file(source, fmt, 'commit', f'tree {tree_id}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nprocess ownership\n'.encode())
    (source / 'refs/heads').mkdir(parents=True)
    (source / 'refs/heads/main').write_text(tip + '\n')
    (source / 'HEAD').write_text('ref: refs/heads/main\n')
    parent = root / (fmt + '-runs')
    parent.mkdir(mode=0o700)
    store = root / (fmt + '-node')
    scope = [store, tenant, repository]
    invoke(fmt + '-init', ['init', *scope, fmt])
    invoke(fmt + '-import', ['import', *scope, principal, fmt + '-import', source, '--json'])
    recoveries = []
    published_ids = set()
    for number, name in enumerate(scripts, 1):
        nonce = f'{number:032x}'
        args = ['workflow', 'run', *scope, 'refs/heads/main', '--trusted-local', '--workflow', f'.github/workflows/{name}.yml', '--run-parent', parent, '--run-id', nonce, '--input', '.github', '--input', 'src', '--object-format', fmt]
        raw, elapsed = invoke(fmt + '-' + name, args, 0 if name == 'joined' else 1, 3 if name == 'deadline' else 120)
        envelope = json.loads(raw)
        assert envelope['node_closed'] and envelope['node_cleanup_error'] is None
        report = envelope['run']
        assert report['source_commit'] == tip
        jobs = report['execution']['jobs']
        assert [job['id'] for job in jobs] == ['a', 'b', 'z']
        if name == 'joined':
            assert report['succeeded'] and report['workspaces_closed']
            assert all(job['outcome'] == 'succeeded' for job in jobs)
        else:
            assert not report['succeeded'] and not report['workspaces_closed']
            assert jobs[0]['outcome'] == 'refused'
            assert all(job['outcome'] == 'cancelled' and not job['steps'] for job in jobs[1:])
            observation = jobs[0]['steps'][0]
            assert observation['workspace_retained']
            assert observation['outcome'] in ('containment_failure', 'cancelled', 'timed_out')
            if name == 'orphan':
                assert observation['exit_code'] == 0 and observation['outcome'] == 'containment_failure'
            output = bytes.fromhex(observation['stdout_hex'])
            pids = [int(pid) for pid in re.findall(rb'(?:worker|grandchild)=(\d+)', output)]
            assert len(pids) == (2 if name == 'deadline' else 1), (name, output)
            stopped(pids)
            assert elapsed < (8 if name == 'deadline' else 5), (name, elapsed)
        directory = parent / ('workflow-' + nonce)
        saved = (directory / 'report.json').read_bytes()
        marker = (directory / 'attempt.json').read_bytes()
        journal = hashlib.sha256(marker).hexdigest()
        recovery_args = ['workflow', 'recover', directory, tenant, repository, '--journal-id', journal]
        recovered, _ = invoke(fmt + '-' + name + '-recover', recovery_args)
        history = json.loads(recovered)
        assert not history['execution_retried']
        facts = [(entry, index, fact) for entry in history['entries'] for index, fact in enumerate(entry['facts']) if fact['status'] == 'completed']
        assert len(facts) == 3
        if name != 'joined':
            assert all(fact['conclusion'] != 'success' for _, _, fact in facts)
        invoke(fmt + '-' + name + '-occupied', args, 2)
        assert (directory / 'report.json').read_bytes() == saved
        for entry, index, fact in facts:
            publish = ['workflow', 'publish', *scope, 'refs/heads/main', '--trusted-local', '--run-directory', directory, '--journal-id', journal, '--batch', entry['batch_sha256'], '--fact-index', index, '--principal-id', principal, '--idempotency-key', f'{fmt}-{name}-{fact["job"]}-observation', '--object-format', fmt]
            published, _ = invoke(fmt + '-' + name + '-' + fact['job'] + '-publish', publish)
            record = json.loads(published)
            conclusion = 'success' if name == 'joined' else ('failure' if fact['job'] == 'a' else 'cancelled')
            assert record['command_committed'] and record['node_closed'] and record['cleanup_error'] is None
            assert record['conclusion'] == conclusion
            assert record['source_commit'] == tip and record['evidence_sha256'] == fact['evidence_sha256']
            assert record['graph_root'] == entry['workflow_graph_sha256']
            assert not record['refs_changed'] and not record['execution_retried']
            assert not record['journal_acknowledged'] and not record['authoritative_check']
            assert record['check_id'] not in published_ids
            published_ids.add(record['check_id'])
            assert invoke(fmt + '-' + name + '-' + fact['job'] + '-publish-retry', publish)[0] == published
        assert (directory / 'report.json').read_bytes() == saved
        recoveries.append((recovery_args, recovered))
        cases.append({'format': fmt, 'case': name, 'elapsed_seconds': round(elapsed, 3), 'run_succeeded': report['succeeded'], 'retained': not report['workspaces_closed'], 'terminal_facts': len(facts), 'published_distinct_checks': len(facts)})
        print(json.dumps(cases[-1]), flush=True)
    source.rename(root / (fmt + '-source-offline'))
    for number, (args, original) in enumerate(recoveries):
        assert invoke(fmt + f'-source-free-{number}', args)[0] == original
(root / 'results.json').write_text(json.dumps({'commands': commands, 'cases': cases}, indent=2) + '\n')
