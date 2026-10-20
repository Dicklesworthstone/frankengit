"""Real fg workspace process custody, exact source pins and candidate publication."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from workspace_tool_smoke import AUTHOR, TENANT, REPOSITORY, PRINCIPAL, REF, write_object, tree, commit, identity, inspect_bundle

fg, root = sys.argv[1], Path(sys.argv[2]).resolve()
root.mkdir(parents=True, exist_ok=True)
results, sequence = [], 0

def invoke(label, arguments, success=True):
    global sequence
    sequence += 1
    out, err = root / f'{sequence:03d}-{label}.out', root / f'{sequence:03d}-{label}.err'
    with out.open('wb') as stdout, err.open('wb') as stderr:
        done = subprocess.run([fg, *map(str, arguments)], stdout=stdout, stderr=stderr, timeout=30)
    diagnostic = err.read_bytes()
    if diagnostic:
        sys.stderr.buffer.write(diagnostic)
        sys.stderr.buffer.flush()
    assert (done.returncode == 0) == success, (label, done.returncode, out.read_bytes(), diagnostic)
    return out.read_bytes(), diagnostic

def alive(pid):
    try:
        return Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1][0] not in 'ZX'
    except FileNotFoundError:
        return False

def stopped(pids):
    end = time.monotonic() + .5
    while any(alive(pid) for pid in pids) and time.monotonic() < end:
        time.sleep(.005)
    return not any(alive(pid) for pid in pids)

for fmt in ('sha1', 'sha256'):
    source, node, parent = (root / f'{fmt}-{name}' for name in ('source', 'node', 'private'))
    parent.mkdir(mode=0o700)
    (source / 'refs/heads').mkdir(parents=True)
    (source / 'HEAD').write_text(f'ref: {REF}\n')
    initial = write_object(source, fmt, 'blob', b'before\n')
    keep = write_object(source, fmt, 'blob', b'preserved\n')
    source_tree = write_object(source, fmt, 'tree', tree([(b'100644', b'edit.txt', initial), (b'100644', b'keep.txt', keep)]))
    base = write_object(source, fmt, 'commit', commit(source_tree, None, 0, b'base\n'))
    (source / REF).write_text(base + '\n')
    scope = [node, TENANT, REPOSITORY]
    invoke('init', ['init', *scope, fmt])
    invoke('import', ['import', *scope, PRINCIPAL, 'workspace-lifecycle', source])
    listing = ['at', *scope, 'latest', 'refs']
    before, _ = invoke('refs-before', listing)
    pin, _ = invoke('pin', ['pr', 'list', *scope, '--trusted-local', '--object-format', fmt])
    head = json.loads(pin)['snapshot_token']

    def args(slot, script, seconds='10', expected_head=head, expected_commit=base):
        return ['workspace', 'run', *scope, REF, parent, slot, slot + '.bundle', '--trusted-local',
                '--read', 'edit.txt', '--write', 'edit.txt', '--author', AUTHOR, '--timestamp', '1',
                '--message', 'candidate\n', '--timeout-secs', seconds, '--expected-head', expected_head,
                '--expected-commit', expected_commit, '--', sys.executable, '-c', script]

    marker = root / f'{fmt}-not-started'
    script = f"from pathlib import Path; Path({str(marker)!r}).write_text('bad'); Path('edit.txt').write_bytes(b'after\\n')"
    wrong_head = head[:-1] + ('0' if head[-1] != '0' else '1')
    for label, expected, reason in [('head', (wrong_head, base), b'SnapshotMoved'), ('commit', (head, initial), b'CommitMoved')]:
        _, error = invoke('stale-' + label, args('11' * 16, script, expected_head=expected[0], expected_commit=expected[1]), False)
        assert reason in error and not marker.exists() and not list(parent.iterdir())
        results.append({'format': fmt, 'case': 'stale-' + label, 'no_host_effect': True})

    joined_script = "from pathlib import Path; import subprocess; Path('edit.txt').write_bytes(b'after\\n'); subprocess.run(['/bin/sleep', '.02'], check=True); print('joined diagnostic')"
    receipt, error = invoke('joined', args('22' * 16, joined_script))
    receipt = json.loads(receipt)
    edited = identity(fmt, 'blob', b'after\n')
    candidate_tree = identity(fmt, 'tree', tree([(b'100644', b'edit.txt', edited), (b'100644', b'keep.txt', keep)]))
    candidate = identity(fmt, 'commit', commit(candidate_tree, base, 1, b'candidate\n'))
    assert receipt['candidate_commit'] == candidate and receipt['source_commit'] == base
    inspect_bundle((parent / ('22' * 16 + '.bundle')).read_bytes(), fmt, base, candidate)
    assert b'joined diagnostic' in error and not (parent / ('workspace-' + '22' * 16)).exists()
    invoke('published-destination-refuses-replay', args('22' * 16, joined_script), False)
    results.append({'format': fmt, 'case': 'joined', 'exact_candidate': candidate})

    for index, mode in enumerate(('orphan', 'sigterm', 'sigint', 'timeout'), 3):
        slot = f'{index:032x}'
        pidfile, grandfile, counter = (root / f'{fmt}-{mode}-{suffix}' for suffix in ('pids', 'grand', 'count'))
        orphan = mode == 'orphan'
        script = ("from pathlib import Path; import os,subprocess,time,json; "
                  f"counter=Path({str(counter)!r}); counter.write_text(counter.read_text()+'x' if counter.exists() else 'x'); "
                  "Path('edit.txt').write_bytes(b'after\\n'); "
                  f"child=subprocess.Popen(['/bin/sh','-c', 'sleep 30 & echo $! > {str(grandfile)}; wait']); "
                  f"Path({str(pidfile)!r}).write_text(json.dumps([os.getpid(),child.pid])); "
                  + ("" if orphan else "time.sleep(30)"))
        command = args(slot, script, '1' if mode == 'timeout' else '10')
        out, err = root / f'{fmt}-{mode}.out', root / f'{fmt}-{mode}.err'
        pids, all_stopped = [], False
        started = time.monotonic()
        with out.open('wb') as stdout, err.open('wb') as stderr:
            child = subprocess.Popen([fg, *map(str, command)], stdout=stdout, stderr=stderr)
            try:
                end = time.monotonic() + 5
                while time.monotonic() < end:
                    if pidfile.exists():
                        try:
                            pids = json.loads(pidfile.read_text())
                            if grandfile.exists() and grandfile.read_text().strip():
                                pids.append(int(grandfile.read_text()))
                                break
                            if orphan and child.poll() is not None:
                                break
                        except (ValueError, json.JSONDecodeError):
                            pass
                    time.sleep(.002)
                assert pids, (mode, 'tool never started', err.read_bytes())
                if mode in ('sigterm', 'sigint'):
                    assert len(pids) == 3 and all(alive(pid) for pid in pids), 'signal must interrupt genuinely live descendants'
                    signum = signal.SIGTERM if mode == 'sigterm' else signal.SIGINT
                    child.send_signal(signum)
                    time.sleep(.005)
                    if child.poll() is None:
                        child.send_signal(signum)
                child.wait(timeout=8)
                assert child.returncode != 0, (mode, out.read_bytes())
                all_stopped = stopped(pids)
                assert all_stopped, ('survivors before fixture cleanup', pids)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)
                for pid in pids:
                    if alive(pid):
                        os.kill(pid, signal.SIGKILL)
        diagnostic = err.read_bytes()
        if diagnostic:
            sys.stderr.buffer.write(diagnostic)
            sys.stderr.buffer.flush()
        assert b'Containment' in diagnostic and not (parent / (slot + '.bundle')).exists()
        assert (parent / ('workspace-' + slot)).is_dir()
        _, _ = invoke('retained-slot-refuses-replay', command, False)
        assert counter.read_text() == 'x', 'recovery refusal must not execute the tool again'
        results.append({'format': fmt, 'case': mode, 'observed_processes': len(pids),
                        'descendants_stopped': all_stopped, 'workspace_retained': True,
                        'seconds': round(time.monotonic() - started, 3)})
    after, _ = invoke('refs-after', listing)
    assert after == before, 'workspace execution must not publish canonical repository changes'
(root / 'results.json').write_text(json.dumps({'cases': results, 'command_invocations': sequence}, indent=2) + '\n')
for result in results:
    print(json.dumps(result), flush=True)
