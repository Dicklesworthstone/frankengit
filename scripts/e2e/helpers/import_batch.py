"""Native import batch boundaries, exact payloads, cold reopen and process death."""
import hashlib
import json
import pathlib
import signal
import subprocess
import sys
import time
import zlib

fg, root = sys.argv[1], pathlib.Path(sys.argv[2]).resolve()
root.mkdir(parents=True, exist_ok=True)
tenant, repository, principal = '11' * 16, '22' * 16, '33' * 16
sequence, cases = 0, []

def invoke(label, args, expected=0):
    global sequence
    sequence += 1
    result = subprocess.run([fg, '--timeout-secs', '300', *map(str, args)], capture_output=True, timeout=330)
    (root / f'{sequence:03d}-{label}.out').write_bytes(result.stdout)
    (root / f'{sequence:03d}-{label}.err').write_bytes(result.stderr)
    if result.stderr:
        sys.stderr.buffer.write(result.stderr)
        sys.stderr.buffer.flush()
    assert result.returncode == expected, (label, result.returncode, result.stdout, result.stderr)
    return result.stdout

def fixture(source, fmt, count=400):
    bodies = {}
    def obj(kind, body):
        raw = kind.encode() + b' ' + str(len(body)).encode() + b'\0' + body
        oid = hashlib.new(fmt, raw).hexdigest()
        path = source / 'objects' / oid[:2] / oid[2:]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(zlib.compress(raw))
        bodies[oid] = body
        return oid
    parent = None
    for index in range(count):
        blob = obj('blob', b'' if index == 0 else f'line {index}\n'.encode())
        tree = obj('tree', b'100644 file\0' + bytes.fromhex(blob))
        body = f'tree {tree}\n' + (f'parent {parent}\n' if parent else '')
        body += f'author Fixture <fixture@example.invalid> {index + 1} +0000\ncommitter Fixture <fixture@example.invalid> {index + 1} +0000\n\ncommit {index}\n'
        parent = obj('commit', body.encode())
    (source / 'refs/heads').mkdir(parents=True)
    (source / 'refs/heads/main').write_text(parent + '\n')
    (source / 'HEAD').write_text('ref: refs/heads/main\n')
    return parent, bodies

def payloads(node, expected):
    files = [p for p in (node / 'objects').rglob('*') if p.is_file()]
    assert len(files) == len(expected), (len(files), len(expected))
    for path in files:
        raw = path.read_bytes()
        assert raw[:4] == b'FGOB'
        offset = 8 + int.from_bytes(raw[4:8], 'big')
        assert path.name in expected and raw[offset:] == expected[path.name]
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in files}

for fmt in ('sha1', 'sha256'):
    source, node = root / (fmt + '-source'), root / (fmt + '-node')
    tip, bodies = fixture(source, fmt)
    scope = [node, tenant, repository]
    invoke(fmt + '-init', ['init', *scope, fmt])
    args = ['import', *scope, principal, fmt + '-batch', source, '--json']
    listing = ['at', *scope, 'latest', 'refs']
    before = invoke(fmt + '-genesis', listing)
    out = root / (fmt + '-crash.out')
    err = root / (fmt + '-crash.err')
    with out.open('wb') as stdout, err.open('wb') as stderr:
        child = subprocess.Popen([fg, '--timeout-secs', '300', *map(str, args)], stdout=stdout, stderr=stderr)
        deadline = time.monotonic() + 30
        try:
            while time.monotonic() < deadline:
                linked = sum(p.is_file() for p in (node / 'objects').rglob('*'))
                if 0 < linked < len(bodies):
                    child.send_signal(signal.SIGKILL)
                    break
                assert child.poll() is None, 'import finished before the planted process-death boundary'
                time.sleep(.002)
            else:
                raise AssertionError('no partial immutable placement observed')
            child.wait(timeout=10)
            assert child.returncode == -signal.SIGKILL
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)
    if err.read_bytes():
        sys.stderr.buffer.write(err.read_bytes())
    assert invoke(fmt + '-after-crash', listing) == before, 'partial placements must not publish refs'
    invoke(fmt + '-resume-exact-import', args)
    retained = payloads(node, bodies)
    published = invoke(fmt + '-cold-refs', listing)
    assert tip.encode() in published
    invoke(fmt + '-repeat-exact-import', args)
    assert payloads(node, bodies) == retained
    assert invoke(fmt + '-repeat-refs', listing) == published
    cases.append({'format': fmt, 'objects': len(bodies), 'observed_partial_files': linked,
                  'crash_left_refs_unchanged': True, 'exact_payloads': True, 'retry_did_not_replace_objects': True})
    print(json.dumps(cases[-1]), flush=True)
(root / 'results.json').write_text(json.dumps({'cases': cases, 'commands': sequence}, indent=2) + '\n')
