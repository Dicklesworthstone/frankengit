"""Real fg signal -> request cancellation -> journal/owner settlement campaign."""
import hashlib
import json
import os
import pathlib
import shlex
import signal
import subprocess
import sys
import time
import zlib

fg, root = sys.argv[1], pathlib.Path(sys.argv[2]).resolve()
root.mkdir(parents=True, exist_ok=True)
tenant, repository, principal = '1' * 32, '2' * 32, '3' * 32
commands, cases = 0, []


def invoke(label, args, expected=0):
    global commands
    commands += 1
    result = subprocess.run([fg, '--timeout-secs', '120', *map(str, args)], capture_output=True, timeout=150)
    (root / f'{commands:03d}-{label}.out').write_bytes(result.stdout)
    (root / f'{commands:03d}-{label}.err').write_bytes(result.stderr)
    if result.stderr:
        sys.stderr.buffer.write(result.stderr)
        sys.stderr.buffer.flush()
    assert result.returncode == expected, (label, result.returncode, result.stdout, result.stderr)
    return result.stdout


def obj(source, fmt, kind, body):
    raw = kind.encode() + b' ' + str(len(body)).encode() + b'\0' + body
    oid = hashlib.new(fmt, raw).hexdigest()
    path = source / 'objects' / oid[:2] / oid[2:]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(zlib.compress(raw))
    return oid


def tree(source, fmt, files):
    nested = {}
    for path, body in files.items():
        name, sep, tail = path.partition('/')
        if sep:
            nested.setdefault(name, {})[tail] = body
        else:
            nested[name] = body
    result = bytearray()
    for name, body in sorted(nested.items(), key=lambda pair: pair[0] + ('/' if isinstance(pair[1], dict) else '')):
        directory = isinstance(body, dict)
        oid = tree(source, fmt, body) if directory else obj(source, fmt, 'blob', body)
        result.extend((b'40000' if directory else b'100644') + b' ' + name.encode() + b'\0' + bytes.fromhex(oid))
    return obj(source, fmt, 'tree', result)


def live(pid):
    try:
        stat = pathlib.Path(f'/proc/{pid}/stat').read_bytes()
    except FileNotFoundError:
        return False
    return stat[stat.rindex(b')') + 1:].split()[0] not in (b'Z', b'X')


def wait_until(predicate, child, seconds=30):
    end = time.monotonic() + seconds
    while not predicate():
        assert child.poll() is None, 'fg ended before readiness; inspect retained process logs'
        assert time.monotonic() < end, 'workflow readiness deadline exceeded'
        time.sleep(.01)


for fmt in ('sha1', 'sha256'):
    base = root / fmt
    base.mkdir(mode=0o700)
    source, node, runs = base / 'source', base / 'node', base / 'runs'
    runs.mkdir(mode=0o700)
    ready, release, late = base / 'ready', base / 'release', base / 'late'
    worker, grandchild = base / 'worker', base / 'grandchild'
    nested = f"while test ! -f {shlex.quote(str(release))}; do sleep 0.05; done"
    script = '\n'.join([
        f"sh -c {shlex.quote(nested)} &",
        f"printf '%s\\n' \"$!\" > {shlex.quote(str(grandchild))}",
        f"printf '%s\\n' \"$$\" > {shlex.quote(str(worker))}",
        f"printf ready > {shlex.quote(str(ready))}",
        'wait',
    ])
    primary = ('name: signal drain\non: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: |\n'
               + ''.join('          ' + line + '\n' for line in (f'sh -c {shlex.quote(script)} &\nwait').splitlines())
               + f'''  b:
    runs-on: fgit-trusted-local
    needs: a
    if: always()
    steps:
      - run: printf dependent >> {shlex.quote(str(late))}
  z:
    runs-on: fgit-trusted-local
    steps:
      - run: printf independent >> {shlex.quote(str(late))}
''').encode()
    secondary = f'''name: later workflow
on: push
jobs:
  last:
    runs-on: fgit-trusted-local
    steps:
      - run: printf later-workflow >> {shlex.quote(str(late))}
'''.encode()
    tid = tree(source, fmt, {'.github/workflows/a.yml': primary, '.github/workflows/z.yml': secondary})
    tip = obj(source, fmt, 'commit', f'tree {tid}\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\nsignal fixture\n'.encode())
    (source / 'refs/heads').mkdir(parents=True)
    (source / 'refs/heads/main').write_text(tip + '\n')
    (source / 'HEAD').write_text('ref: refs/heads/main\n')
    scope = [node, tenant, repository]
    invoke(fmt + '-init', ['init', *scope, fmt])
    invoke(fmt + '-import', ['import', *scope, principal, fmt + '-signal-fixture', source, '--json'])
    refs = ['refs', *scope, '--trusted-local', '--object-format', fmt]
    before = invoke(fmt + '-before', refs)
    pin = json.loads(before)['snapshot_token']
    for mode in ('run', 'dispatch'):
        for signum in (None, signal.SIGTERM, signal.SIGINT):
            for path in (ready, release, late, worker, grandchild):
                path.unlink(missing_ok=True)
            run_id = f'{len(cases) + 1:032x}'
            label = f'{fmt}-{mode}-{signum or "complete"}'
            args = ['workflow', mode, *scope, 'refs/heads/main', '--trusted-local', '--workflow',
                    '.github/workflows' if mode == 'dispatch' else '.github/workflows/a.yml',
                    '--input', '.github', '--run-parent', runs, '--run-id', run_id,
                    '--expected-head', pin, '--expected-commit', tip, '--object-format', fmt]
            if mode == 'dispatch':
                args.extend(['--event', 'push'])
            out, err = root / f'{label}.out', root / f'{label}.err'
            with out.open('wb') as stdout, err.open('wb') as stderr:
                child = subprocess.Popen([fg, '--timeout-secs', '120', *map(str, args)], stdout=stdout, stderr=stderr)
                pids = []
                try:
                    wait_until(ready.exists, child)
                    pids = [int(path.read_text()) for path in (worker, grandchild)]
                    assert all(live(pid) for pid in pids), 'cancellation must interrupt genuinely live descendants'
                    started = time.monotonic()
                    if signum:
                        child.send_signal(signum)
                        time.sleep(.02)
                        if child.poll() is None:
                            child.send_signal(signum)
                    else:
                        release.write_text('complete')
                    code = child.wait(timeout=12)
                    elapsed = time.monotonic() - started
                    until = time.monotonic() + .5
                    while any(live(pid) for pid in pids) and time.monotonic() < until:
                        time.sleep(.01)
                    remaining_live = [pid for pid in pids if live(pid)]
                finally:
                    release.write_text('fixture cleanup')
                    if child.poll() is None:
                        child.kill()
                        child.wait(timeout=5)
                    for pid in pids:
                        if live(pid):
                            os.kill(pid, signal.SIGKILL)
            if err.read_bytes():
                sys.stderr.buffer.write(err.read_bytes())
                sys.stderr.buffer.flush()
            assert code == (1 if signum else 0), (label, code, out.read_bytes(), err.read_bytes())
            value = json.loads(out.read_bytes())
            assert value['node_closed'] and value['node_cleanup_error'] is None, value
            report = value['dispatch'] if mode == 'dispatch' else value['run']
            run = report['runs'][0] if mode == 'dispatch' else report
            jobs = run['execution']['jobs']
            assert run['source_commit'] == tip and [job['id'] for job in jobs] == ['a', 'b', 'z']
            assert not remaining_live, ('native drain left live descendants before fixture cleanup', remaining_live)
            if signum:
                assert not run['succeeded'] and run['request_interrupted']
                assert jobs[0]['outcome'] in ('cancelled', 'refused')
                assert jobs[0]['steps'][0]['outcome'] in ('cancelled', 'containment_failure')
                assert all(job['outcome'] == 'cancelled' and job['steps'] == [] for job in jobs[1:])
                assert not late.exists(), 'always() and independent jobs must not start after a stop request'
                if mode == 'dispatch':
                    assert report['executed_count'] == 1 and report['matched_count'] == 2
                    assert report['stop_reason'] in ('request_stopped', 'containment_unproved')
            else:
                assert run['succeeded'] and run['workspaces_closed']
                assert all(job['outcome'] == 'succeeded' for job in jobs)
                assert late.read_text() == 'dependentindependent' + ('later-workflow' if mode == 'dispatch' else '')
            directory = pathlib.Path(bytes.fromhex(run['run_directory_hex']).decode())
            marker = (directory / 'attempt.json').read_bytes()
            saved = (directory / 'report.json').read_bytes()
            assert json.loads(saved) == run
            recovery_args = ['workflow', 'recover', directory, tenant, repository, '--journal-id', hashlib.sha256(marker).hexdigest()]
            first = invoke(label + '-recover', recovery_args)
            assert invoke(label + '-recover-again', recovery_args) == first
            history = json.loads(first)
            facts = [fact for entry in history['entries'] for fact in entry['facts'] if fact['status'] == 'completed']
            assert len(facts) == 3 and len({fact['job'] for fact in facts}) == 3
            assert not history['execution_retried']
            if signum:
                assert all(fact['conclusion'] not in ('success', 'neutral') for fact in facts)
            invoke(label + '-occupied', args, 2)
            assert (directory / 'report.json').read_bytes() == saved and (directory / 'attempt.json').read_bytes() == marker
            assert invoke(label + '-unchanged', refs) == before
            case = {'format': fmt, 'mode': mode, 'signal': int(signum) if signum else None,
                    'elapsed_seconds': round(elapsed, 3), 'exit': code, 'terminal_facts': len(facts),
                    'workspaces_closed': run['workspaces_closed'], 'descendants_alive': False}
            cases.append(case)
            print(json.dumps(case), flush=True)
(root / 'results.json').write_text(json.dumps({'commands': commands, 'cases': cases}, indent=2) + '\n')
assert len(cases) == 12
