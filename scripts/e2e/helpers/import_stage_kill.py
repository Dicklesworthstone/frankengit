"""Real Linux syscall-boundary SIGKILLs; no production markers or fault flags."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
import zlib

STAGES = [('body-write', 'write'), ('body-sync', 'fsync'), ('immutable-link', 'linkat'),
          ('directory-sync', 'fsync'), ('stage-cleanup', 'unlink'), ('lost-response', 'write')]
TENANT, REPOSITORY, PRINCIPAL = '11' * 16, '22' * 16, '33' * 16


def require(test, message):
    if not test:
        raise AssertionError(message)


def cold_refs(raw):
    lines = raw.decode('utf-8', errors='strict').splitlines()
    require(bool(lines), 'cold ref output absent')
    header = re.fullmatch(r'references at latest \((\d+) total\):', lines[0])
    require(header is not None, 'unexpected cold ref output header')
    refs = {}
    for line in lines[1:]:
        match = re.fullmatch(r'  (refs/\S+) -> ([0-9a-f]{40}|[0-9a-f]{64})', line)
        require(match is not None, 'unexpected cold ref row')
        name, oid = match.groups()
        require(name not in refs, 'duplicate cold ref row')
        refs[name] = oid
    require(len(refs) == int(header[1]), 'cold ref count mismatch')
    return refs


def exact_target(line, path):
    return ('<' + str(path) + '>') in line or ('"' + str(path) + '"') in line


def cold_head(raw):
    text = raw.decode('utf-8', errors='strict')
    summaries = list(re.finditer(r'^snapshot at latest \(head (alg:[0-9]+:[0-9a-f]{64}), decision Some\(([0-9]+)\)\):', text, re.M))
    details = list(re.finditer(r'^  Head: frankengit/authority-head/v1/v1\.0/alg:([0-9]+)/([0-9a-f]{64}) \(gen ([1-9][0-9]*)\)$', text, re.M))
    sequences = list(re.finditer(r'^  Decision Sequence: ([0-9]+)$', text, re.M))
    require(len(summaries) == len(details) == len(sequences) == 1,
            'cold authority witness absent, malformed or duplicated')
    summary, detail, sequence = summaries[0], details[0], sequences[0]
    require(summary[1] == 'alg:' + detail[1] + ':' + detail[2] and summary[2] == sequence[1],
            'cold authority witness disagrees')
    return {'head_id': summary[1], 'decision_sequence': int(summary[2]), 'generation': int(detail[3])}


def syscall_lines(trace):
    """Pair strace's interleaved lines by exact tracee PID and syscall.

    Missing, duplicate or wrong-PID/syscall resumes invalidate the trace.
    """
    pending, complete = {}, []
    for line in trace.splitlines():
        entry = re.match(r'^(\d+)\s+(write|fsync|linkat|unlink)\(', line)
        resumed = re.match(r'^(\d+)\s+<\.\.\. (write|fsync|linkat|unlink) resumed>(.*)$', line)
        if entry:
            key = entry.groups()
            require(not any(prior[0] == key[0] for prior in pending),
                    'second tracked syscall entry for a TID before matching resume')
            if line.endswith(' <unfinished ...>'):
                pending[key] = line[:-len(' <unfinished ...>')]
            else:
                complete.append(line)
        elif resumed:
            pid, syscall, tail = resumed.groups()
            key = (pid, syscall)
            require(key in pending, 'syscall resume has no exact PID/syscall entry')
            complete.append(pending.pop(key) + tail)
    require(not pending, 'unfinished syscall has no exact matching resume')
    return complete


def fixture(root, fmt, count, branch='main'):
    bodies = {}
    def store(kind, body):
        raw = f'{kind} {len(body)}\0'.encode() + body
        oid = hashlib.new(fmt, raw).hexdigest()
        path = root / 'objects' / oid[:2] / oid[2:]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(zlib.compress(raw))
        bodies[oid] = (kind, body)
        return oid
    parent = None
    for n in range(count):
        blob = store('blob', f'entry {n}\n'.encode())
        tree = store('tree', b'100644 file\0' + bytes.fromhex(blob))
        text = f'tree {tree}\n' + (f'parent {parent}\n' if parent else '')
        text += f'author Fixture <fixture@example.invalid> {n + 1} +0000\ncommitter Fixture <fixture@example.invalid> {n + 1} +0000\n\ncommit {n}\n'
        parent = store('commit', text.encode())
    (root / 'refs/heads').mkdir(parents=True)
    (root / ('refs/heads/' + branch)).write_text(parent + '\n')
    (root / 'HEAD').write_text('ref: refs/heads/' + branch + '\n')
    (root / 'config').write_text('[core]\nbare=true\nrepositoryformatversion=' +
                               ('0\n' if fmt == 'sha1' else '1\n[extensions]\nobjectformat=sha256\n'))
    return parent, bodies


def immutable_files(node, expected, fmt):
    found = {}
    for path in (node / 'objects').rglob('*'):
        if not path.is_file():
            continue
        oid = path.name
        require(oid in expected and oid not in found, 'unexpected/duplicate immutable object name')
        raw = path.read_bytes()
        require(len(raw) >= 8 and raw[:4] == b'FGOB', 'actual immutable target must be complete FGOB')
        start = 8 + int.from_bytes(raw[4:8], 'big')
        require(start <= len(raw), 'partial immutable envelope')
        kind, body = expected[oid]
        require(raw[start:] == body, 'immutable payload differs from independent fixture')
        require(hashlib.new(fmt, f'{kind} {len(body)}\0'.encode() + raw[start:]).hexdigest() == oid,
                'immutable native identity differs')
        found[oid] = {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()}
    return found


class Campaign:
    def __init__(self, fg, root, source_cut, expected_hash, twins_only=False, workload_seconds=840):
        self.fg, self.root, self.sequence = str(fg), root, 0
        require(0 < workload_seconds <= 840, 'workload budget exceeds cleanup reserve')
        self.workload_deadline = time.monotonic() + workload_seconds
        self.twins_only = twins_only
        require(hashlib.sha256(fg.read_bytes()).hexdigest() == expected_hash, 'fg hash changed')
        self.strace = shutil.which('strace')
        require(sys.platform == 'linux' and self.strace is not None, 'Linux with strace required')
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.results, self.calls = [], []
        self.plan = {'source_cut': source_cut, 'fg_sha256': expected_hash,
                     'strace_version': subprocess.check_output([self.strace, '--version'], text=True).splitlines()[0],
                     'strace_path': self.strace,
                     'strace_sha256': hashlib.sha256(Path(self.strace).read_bytes()).hexdigest(),
                     'python_path': sys.executable, 'python_version': sys.version,
                     'kernel': list(os.uname()), 'load_at_start': list(os.getloadavg()),
                     'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                     'formats': ['sha1', 'sha256'], 'stages': [x[0] for x in STAGES],
                     'fixture': '91 linear commits/273 objects on new main; existing seed ref at1 commit/3 objects; import adds90 commits/270 objects and preserves seed',
                     'cells_per_format': {'unfiltered_calibration': 1, 'no_kill': 6,
                                          'sigkill': 0 if twins_only else 6},
                     'per_command_timeout_seconds': 180,
                     'overall_workload_budget_seconds': workload_seconds,
                     'outer_guard_seconds': 900, 'cleanup_reserve_seconds': 60,
                     'permission_probe': 'real traced Python writes and native import; no ptrace fallback',
                     'nonclaims': ['no power loss', 'no complete CAS/SQLite instruction-boundary matrix',
                                   'no throughput or pinned-Git differential claim',
                                   'Python verifies physical framing/payload/native identity, not full envelope commitments; native import retry revalidates existing objects'],
                     'partial_staging_allowed': True, 'immutable_partial_bodies_forbidden': True}
        (root / 'plan.json').write_text(json.dumps(self.plan, indent=2) + '\n')

    def invoke(self, label, args, expected=0, traced=None, selected=None, injection=None,
               executable=None, timeout_seconds=180):
        self.sequence += 1
        base = self.root / f'{self.sequence:03d}-{label}'
        out, err, trace = base.with_suffix('.out'), base.with_suffix('.err'), base.with_suffix('.strace')
        command = [executable or self.fg, *map(str, args)]
        if traced:
            prefix = [self.strace, '-f', '-yy', '--always-show-pid', '--kill-on-exit', '-s', '160',
                      '-e', 'trace=write,fsync,linkat,unlink', '-o', str(trace)]
            if selected:
                prefix += ['-P', str(out if selected == 'stdout' else selected)]
            if injection:
                prefix += ['--inject=' + injection]
            command = prefix + command
        started = time.monotonic()
        row = {'label': label, 'command': command, 'exit': None, 'expected': expected,
               'started_unix_ns': time.time_ns(), 'pid': None,
               'owned_process_group_quiescent': False, 'owned_process_group_reaped': False,
               'containment': 'not_started',
               'stdout': str(out), 'stderr': str(err), 'trace': str(trace) if traced else None}
        self.calls.append(row)
        def checkpoint():
            base.with_suffix('.command.json').write_text(json.dumps(row, indent=2) + '\n')
            (self.root / 'commands.json').write_text(json.dumps(self.calls, indent=2) + '\n')
        process = None
        try:
            with out.open('wb') as stdout, err.open('wb') as stderr:
                remaining = self.workload_deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, 0, stderr='overall workload deadline exhausted')
                process = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
                row['pid'] = process.pid
                row['spawned_unix_ns'] = time.time_ns()
                row['containment'] = 'pending'
                checkpoint()
                row['exit'] = process.wait(timeout=min(timeout_seconds, remaining))
        except BaseException as error:
            row['error'] = type(error).__name__ + ': ' + str(error)
            raise
        finally:
            try:
                if process is not None:
                    try:
                        os.killpg(process.pid, 0)
                    except ProcessLookupError:
                        row['owned_process_group_quiescent'] = True
                    else:
                        row['owned_process_group_quiescent'] = False
                        row['cleanup_sent_sigkill'] = True
                        row['containment'] = 'cleanup_pending'
                        checkpoint()
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        row['cleanup_signal_sent_unix_ns'] = time.time_ns()
                        checkpoint()
                        process.wait(timeout=10)
                    row['exit'] = process.returncode
                    deadline = time.monotonic() + 5
                    while True:
                        try:
                            os.killpg(process.pid, 0)
                        except ProcessLookupError:
                            row['owned_process_group_reaped'] = True
                            row['containment'] = 'reaped'
                            break
                        if time.monotonic() >= deadline:
                            row['owned_process_group_reaped'] = False
                            row['containment'] = 'unresolved'
                            break
                        time.sleep(0.01)
            except BaseException as error:
                row['cleanup_error'] = type(error).__name__ + ': ' + str(error)
                raise
            finally:
                row['elapsed'] = time.monotonic() - started
                for name, path in [('stdout', out), ('stderr', err), ('trace', trace)]:
                    if path.exists():
                        row[name + '_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
                checkpoint()
                if err.exists() and err.stat().st_size:
                    sys.stderr.buffer.write(err.read_bytes())
                    sys.stderr.buffer.flush()
        require(row['owned_process_group_quiescent'], 'owned process group not quiescent')
        require(row['owned_process_group_reaped'], 'owned process group not reaped')
        require(row['exit'] == expected, f'{label}: exit {row["exit"]}, expected {expected}')
        return row, out.read_bytes(), trace.read_text() if traced else ''

    def calibrate_strace_ordinals(self):
        # Two unselected writes precede two selected writes. when=1 must kill
        # the first selected call; when=3 must not fire. Reject other semantics.
        toy = ('import os,sys; '
               'a=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT,0o600);'
               'os.write(a,b"A");os.write(a,b"A");'
               'b=os.open(sys.argv[2],os.O_WRONLY|os.O_CREAT,0o600);'
               'os.write(b,b"B");os.write(b,b"B")')
        observed = []
        for ordinal in [0, 1, 3]:
            a, b = self.root / f'ordinal-a-{ordinal}', self.root / f'ordinal-b-{ordinal}'
            row, _, trace = self.invoke(f'ordinal-{ordinal}', ['-c', toy, a, b],
                executable=sys.executable, traced=True, selected=b,
                injection=f'write:signal=SIGKILL:when={ordinal}' if ordinal else None,
                expected=-signal.SIGKILL if ordinal == 1 else 0)
            require(a.read_bytes() == b'AA', 'unselected writes changed by filtered ordinal injection')
            require(b.read_bytes() == (b'' if ordinal == 1 else b'BB'), 'unsupported strace -P ordinal semantics')
            entries = [line for line in trace.splitlines() if
                       re.match(r'^\d+\s+write\(', line) and exact_target(line, b)]
            require(len(entries) == (1 if ordinal == 1 else 2), 'ordinal calibration trace count mismatch')
            if ordinal == 1:
                require(entries[-1].endswith('= ?') and 'killed by SIGKILL' in trace,
                        'ordinal calibration did not kill exact selected entry')
            observed.append({'ordinal': ordinal, 'command_label': row['label'],
                             'selected_bytes': b.read_bytes().hex(), 'entries': entries})
        (self.root / 'ordinal-calibration.json').write_text(json.dumps(observed, indent=2) + '\n')

    def node(self, fmt, name, baseline, baseline_objects):
        node = self.root / name
        scope = [node, TENANT, REPOSITORY]
        self.invoke(name + '-init', ['init', *scope, fmt])
        self.invoke(name + '-seed', ['import', *scope, PRINCIPAL, 'baseline', baseline, '--json'])
        _, before, _ = self.invoke(name + '-before', ['at', *scope, 'latest', 'refs'])
        _, before_head, _ = self.invoke(name + '-before-head', ['at', *scope, 'latest'])
        require(cold_refs(before) == {'refs/heads/seed': next(oid for oid, (kind, _) in
                baseline_objects.items() if kind == 'commit')}, 'baseline must select exactly seed')
        existing = immutable_files(node, baseline_objects, fmt)
        directories = {Path(x['path']).parent for x in existing.values()}
        require(len(directories) == 1, 'fixture must have one actual physical namespace/hash directory')
        return node, scope, before, cold_head(before_head), directories.pop()

    def run_format(self, fmt):
        baseline, source = self.root / (fmt + '-baseline'), self.root / (fmt + '-source')
        base_tip, baseline_objects = fixture(baseline, fmt, 1, branch='seed')
        tip, objects = fixture(source, fmt, 91)
        (self.root / (fmt + '-inputs.json')).write_text(json.dumps({oid:
            {'kind': kind, 'bytes': len(body), 'payload_sha256': hashlib.sha256(body).hexdigest()}
            for oid, (kind, body) in sorted(objects.items())}, indent=2) + '\n')
        require(len(objects) == 273 and len(baseline_objects) == 3, 'fixture denominator changed')
        require(set(baseline_objects) <= set(objects), 'source must extend baseline')
        first_new = min(set(objects) - set(baseline_objects))
        first_batch = set(sorted(objects)[:256])
        first_batch_total = len(first_batch | set(baseline_objects))
        node, scope, before, before_head, directory = self.node(fmt, fmt + '-calibration', baseline, baseline_objects)
        stage = node / 'staging' / '0000000000000001.stage'
        args = ['import', *scope, PRINCIPAL, 'target', source, '--json']
        row, result, trace = self.invoke(fmt + '-calibration-import', args, traced=True)
        receipt = json.loads(result)
        require(receipt['state'] == 'committed' and receipt['node_closed'], 'calibration must really commit')
        require(len(immutable_files(node, objects, fmt)) == 273, 'calibration closure incomplete')
        counts, candidates = {}, {name: [] for name, _ in STAGES}
        for line in syscall_lines(trace):
            match = re.match(r'^(\d+)\s+(write|fsync|linkat|unlink)\(', line)
            if not match:
                continue
            pid, syscall = match.groups()
            slot = (pid, syscall)
            counts[slot] = counts.get(slot, 0) + 1
            for name, expected_call in STAGES:
                path = str(stage if name in ['body-write', 'body-sync', 'stage-cleanup'] else
                           directory / first_new if name == 'immutable-link' else
                           directory if name == 'directory-sync' else row['stdout'])
                # fd paths and quoted pathname arguments include a closing delimiter.
                exact = exact_target(line, path)
                if syscall == expected_call and exact:
                    filtered_ordinal = 1 + sum(x['pid'] == pid for x in candidates[name])
                    candidates[name].append({'ordinal': filtered_ordinal,
                                             'unfiltered_ordinal': counts[slot], 'pid': pid, 'line': line})
        calibrated = {}
        for name, syscall in STAGES:
            index = 1 if name == 'directory-sync' else 0
            require(len(candidates[name]) > index, f'missing exact calibration stage {name}')
            calibrated[name] = candidates[name][index]
            calibrated[name]['syscall'] = syscall
        (self.root / (fmt + '-calibration.json')).write_text(json.dumps(calibrated, indent=2) + '\n')
        for killed in ([False] if self.twins_only else [False, True]):
            for name, syscall in STAGES:
                label = f'{fmt}-{name}-' + ('kill' if killed else 'twin')
                node, scope, before, before_head, directory = self.node(fmt, label, baseline, baseline_objects)
                selected = (node / 'staging' / '0000000000000001.stage' if name in
                            ['body-write', 'body-sync', 'stage-cleanup'] else directory / first_new if name ==
                            'immutable-link' else directory if name == 'directory-sync' else 'stdout')
                injection = f'{syscall}:signal=SIGKILL:when={calibrated[name]["ordinal"]}' if killed else None
                args = ['import', *scope, PRINCIPAL, 'target', source, '--json']
                row, output, trace = self.invoke(label + '-import', args,
                    expected=-signal.SIGKILL if killed else 0, traced=True, selected=selected, injection=injection)
                require(syscall + '(' in trace and 'killed by SIGKILL' in trace if killed else True,
                        'required targeted syscall/SIGKILL absent')
                actual_path = row['stdout'] if selected == 'stdout' else str(selected)
                require(actual_path in trace, 'trace did not observe exact intended physical target')
                if killed:
                    entries = [line for line in syscall_lines(trace) if
                               re.match(r'^\d+\s+' + syscall + r'\(', line) and exact_target(line, actual_path)]
                    require(len(entries) == calibrated[name]['ordinal'], 'wrong filtered injection ordinal')
                    require(entries[-1].endswith('= ?'), 'target syscall did not stop on entry')
                present = immutable_files(node, objects, fmt)
                _, cold, _ = self.invoke(label + '-cold', ['at', *scope, 'latest', 'refs'])
                _, cold_summary, _ = self.invoke(label + '-cold-head', ['at', *scope, 'latest'])
                observed_head = cold_head(cold_summary)
                complete = not killed or name == 'lost-response'
                if complete:
                    require(cold_refs(cold) == {'refs/heads/main': tip, 'refs/heads/seed': base_tip},
                            'committed main must select complete tip and preserve baseline seed')
                    require(len(present) == 273, 'committed closure incomplete')
                    require(observed_head['decision_sequence'] == before_head['decision_sequence'] + 1 and
                            observed_head['generation'] == before_head['generation'] + 1,
                            'completed import must publish exactly one authority transition')
                else:
                    require(cold == before, 'placement-stage SIGKILL changed canonical refs')
                    require(observed_head == before_head, 'placement-stage SIGKILL changed authenticated authority')
                    expected_count = first_batch_total if name in ['directory-sync', 'stage-cleanup'] else 3
                    require(len(present) == expected_count, 'wrong placement stage or partial target publication')
                staging = sorted(p.name for p in (node / 'staging').iterdir())
                staging_details = {name: {'bytes': (node / 'staging' / name).stat().st_size,
                    'sha256': hashlib.sha256((node / 'staging' / name).read_bytes()).hexdigest()}
                    for name in staging}
                _, retried, _ = self.invoke(label + '-retry', args)
                first = json.loads(retried)
                require(first['state'] == 'committed' and first['node_closed'], 'retry did not commit/close')
                retained = immutable_files(node, objects, fmt)
                require(len(retained) == 273, 'retry closure incomplete')
                _, after, _ = self.invoke(label + '-after', ['at', *scope, 'latest', 'refs'])
                require(cold_refs(after) == {'refs/heads/main': tip, 'refs/heads/seed': base_tip},
                        'retry must select exactly main and seed')
                _, after_summary, _ = self.invoke(label + '-after-head', ['at', *scope, 'latest'])
                after_head = cold_head(after_summary)
                require(after_head['decision_sequence'] == first['decision_sequence'],
                        'recovered terminal result must select actual latest decision')
                require(after_head['decision_sequence'] == before_head['decision_sequence'] + 1 and
                        after_head['generation'] == before_head['generation'] + 1,
                        'retry must settle exactly one import transition')
                if complete:
                    require(after_head == observed_head, 'completed import retry changed original authority transition')
                _, repeated, _ = self.invoke(label + '-repeat', args)
                require(json.loads(repeated) == first, 'same-key repeat changed original terminal result')
                require(immutable_files(node, objects, fmt) == retained, 'same-key repeat replaced immutable bytes')
                _, unchanged, _ = self.invoke(label + '-unchanged', ['at', *scope, 'latest', 'refs'])
                require(unchanged == after, 'same-key repeat republished canonical state')
                _, repeated_summary, _ = self.invoke(label + '-unchanged-head', ['at', *scope, 'latest'])
                require(cold_head(repeated_summary) == after_head, 'same-key repeat advanced authenticated authority')
                if not killed:
                    require(json.loads(output) == first, 'no-kill twin retry changed terminal result')
                self.results.append({'format': fmt, 'stage': name, 'killed': killed, 'objects': 273,
                    'immutable_objects_at_kill': len(present), 'staging_residue_retained': staging,
                    'staging_residue_before_retry': staging_details,
                    'first_batch_total': first_batch_total, 'calibrated_syscall_ordinal': calibrated[name]['ordinal'],
                    'cold_ref_complete': complete, 'all_closure_payloads_exact_after_retry': True,
                    'same_key_repeat_same_original_outcome': True, 'same_key_repeat_no_publication': True})
                self.results[-1]['authority_before'] = before_head
                self.results[-1]['authority_at_kill'] = observed_head
                self.results[-1]['authority_after_retry_and_repeat'] = after_head
                (self.root / 'results.json').write_text(json.dumps(self.results, indent=2) + '\n')
                print(json.dumps({'format': fmt, 'stage': name, 'killed': killed,
                    'immutable_objects': len(present), 'retained_staging_files': len(staging),
                    'exact_refs_and_payloads_after_retry': True,
                    'same_key_repeat_original_result_and_no_publication': True}), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('fg', type=Path)
    parser.add_argument('root', type=Path)
    parser.add_argument('--source-cut', required=True)
    parser.add_argument('--fg-sha256', required=True)
    parser.add_argument('--twins-only', action='store_true')
    args = parser.parse_args()
    require(re.fullmatch('[0-9a-f]{40}', args.source_cut) is not None, 'exact source commit required')
    require(re.fullmatch('[0-9a-f]{64}', args.fg_sha256) is not None, 'exact executable SHA256 required')
    def interrupted(signum, _frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    campaign = Campaign(args.fg.resolve(), args.root.resolve(), args.source_cut, args.fg_sha256, args.twins_only)
    campaign.calibrate_strace_ordinals()
    for fmt in ['sha1', 'sha256']:
        campaign.run_format(fmt)
    require(len(campaign.results) == (12 if args.twins_only else 24), 'requested stage/twin matrix incomplete')
    require(hashlib.sha256(args.fg.read_bytes()).hexdigest() == args.fg_sha256, 'fg hash changed during campaign')


if __name__ == '__main__':
    main()
