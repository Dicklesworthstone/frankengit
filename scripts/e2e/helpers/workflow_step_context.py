import hashlib, json, os, pathlib, subprocess, sys, zlib

fg, root = sys.argv[1], pathlib.Path(sys.argv[2])
tenant, repository, principal = '1' * 32, '2' * 32, '3' * 32
counter = 0
results = []

def run(label, args, expected=0):
    global counter
    counter += 1
    result = subprocess.run([fg, '--timeout-secs', '120', *map(str, args)], capture_output=True, timeout=180)
    (root / f'{counter:03d}-{label}.out').write_bytes(result.stdout)
    (root / f'{counter:03d}-{label}.err').write_bytes(result.stderr)
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

literal = '$(touch injected) ; literal $HOME'
good = '''name: context
on: workflow_dispatch
jobs:
  build:
    runs-on: fgit-trusted-local
    steps:
      - run: mkdir -p build/nested
      - name: explicit inputs
        env:
          BUILD_MODE: release
          EMPTY: ''
          LITERAL: '$(touch injected) ; literal $HOME'
        working-directory: ./build/nested
        run: |
          test "$BUILD_MODE" = release
          test "${EMPTY+x}" = x
          test -f ../../src/input.txt
          printf '%s' "$LITERAL"
          printf '%s' "$BUILD_MODE" > result
      - name: restored defaults
        run: |
          test -z "${BUILD_MODE+x}"
          test -z "${EMPTY+x}"
          test -f build/nested/result
          test ! -e build/nested/injected
          test "$PATH" = /usr/bin:/bin
          test "$LANG" = C
          printf 'root restored'
  independent:
    runs-on: fgit-trusted-local
    steps:
      - run: test -z "${BUILD_MODE+x}"; test ! -e build; printf 'fresh job'
'''
invalid = '''name: invalid
on: workflow_dispatch
jobs:
  build:
    runs-on: fgit-trusted-local
    steps:
      - run: printf SHOULD_NOT_RUN
      - run: printf SHOULD_NOT_RUN
        env:
          BASH_ENV: rejected
'''
symlinked = '''name: symlinked
on: workflow_dispatch
jobs:
  build:
    runs-on: fgit-trusted-local
    steps:
      - run: ln -s src alias
      - run: printf SHOULD_NOT_RUN
        working-directory: alias
'''
missing = symlinked.replace('ln -s src alias', 'printf prepared').replace('working-directory: alias', 'working-directory: missing')

for fmt in ('sha1', 'sha256'):
    source = root / (fmt + '-source')
    files = {
        '.github/workflows/good.yml': good.encode(),
        '.github/workflows/invalid.yml': invalid.encode(),
        '.github/workflows/symlinked.yml': symlinked.encode(),
        '.github/workflows/missing.yml': missing.encode(),
        'src/input.txt': b'exact source input\n',
    }
    tree = source_tree(source, fmt, files)
    tip = native_object(source, fmt, 'commit', f'tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nstep context\n'.encode())
    (source / 'refs/heads').mkdir(parents=True)
    (source / 'refs/heads/main').write_text(tip + '\n')
    (source / 'HEAD').write_text('ref: refs/heads/main\n')
    store = root / (fmt + '-node')
    parent = root / (fmt + '-runs')
    parent.mkdir(mode=0o700)
    scope = [store, tenant, repository]
    run(fmt + '-init', ['init', *scope, fmt])
    imported = json.loads(run(fmt + '-import', ['import', *scope, principal, fmt + '-import', source, '--json']))
    assert imported['state'] == 'committed'
    def workflow(name, number, expected=0):
        nonce = f'{number:032x}'
        args = ['workflow', 'run', *scope, 'refs/heads/main', '--trusted-local', '--workflow', '.github/workflows/' + name + '.yml', '--run-parent', parent, '--run-id', nonce, '--input', '.github', '--input', 'src', '--object-format', fmt]
        raw = run(fmt + '-' + name, args, expected)
        return raw, parent / ('workflow-' + nonce), args
    raw, directory, args = workflow('good', 1)
    envelope = json.loads(raw)
    assert envelope["node_closed"] and envelope["node_cleanup_error"] is None
    report = envelope["run"]
    assert report['succeeded'] and report['workspaces_closed'] and not report['request_interrupted']
    jobs = report['execution']['jobs']
    assert [job['id'] for job in jobs] == ['build', 'independent']
    assert all(job['outcome'] == 'succeeded' for job in jobs)
    output = b''.join(bytes.fromhex(step['stdout_hex']) for job in jobs for step in job['steps'])
    assert literal.encode() in output and b'root restored' in output and b'fresh job' in output
    assert (directory / 'report.json').exists() and (directory / 'check-proposals.journal').exists()
    before = (directory / 'report.json').read_bytes()
    run(fmt + '-occupied-attempt', args, 2)
    assert (directory / 'report.json').read_bytes() == before
    marker = (directory / 'attempt.json').read_bytes().rstrip(b'\n')
    journal = hashlib.sha256(marker).hexdigest()
    recovery = run(fmt + '-recover', ['workflow', 'recover', directory, tenant, repository, '--journal-id', journal])
    assert json.loads(recovery)
    invalid_raw, invalid_directory, _ = workflow('invalid', 2, 2)
    assert not invalid_directory.exists()
    for number, name in [(3, 'symlinked'), (4, 'missing')]:
        raw, failed_directory, _ = workflow(name, number, 1)
        envelope = json.loads(raw)
        assert envelope["node_closed"] and envelope["node_cleanup_error"] is None
        failed = envelope["run"]
        assert not failed['succeeded'] and failed['workspaces_closed']
        assert failed['execution']['jobs'][0]['outcome'] == 'refused'
        assert len(failed['execution']['jobs'][0]['steps']) == 1
        assert b'SHOULD_NOT_RUN'.hex() not in raw.decode()
        assert (failed_directory / 'report.json').exists()
    history = json.loads(recovery)
    selected = next((entry, index, fact) for entry in history["entries"] for index, fact in enumerate(entry["facts"]) if fact["status"] == "completed" and fact["job"] == "build")
    entry, index, fact = selected
    publish = ["workflow", "publish", *scope, "refs/heads/main", "--trusted-local", "--run-directory", directory, "--journal-id", journal, "--batch", entry["batch_sha256"], "--fact-index", index, "--principal-id", principal, "--idempotency-key", fmt + "-context-publish", "--object-format", fmt]
    published_raw = run(fmt + "-publish", publish)
    published = json.loads(published_raw)
    assert published["command_committed"] and published["node_closed"]
    assert published["graph_root"] == entry["workflow_graph_sha256"]
    assert published["evidence_sha256"] == fact["evidence_sha256"]
    assert not published["refs_changed"] and not published["execution_retried"]
    assert not published["authoritative_check"]
    assert run(fmt + "-publish-retry", publish) == published_raw
    source.rename(root / (fmt + "-source-offline"))
    assert run(fmt + '-source-free-recovery', ['workflow', 'recover', directory, tenant, repository, '--journal-id', journal]) == recovery
    results.append({'format': fmt, 'graph': report["execution"]["workflow_graph"], 'literal_inputs': True, 'separate_steps_and_jobs': True, 'refusal_twins': True, 'source_free_recovery': True})
    print(json.dumps(results[-1]), flush=True)
(root / 'results.json').write_text(json.dumps({'commands': counter, 'cases': results}, indent=2) + '\n')
