"""Actual native ref changes and path-filtered CI; no mock service or Git executable."""
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from workspace_tool_smoke import TENANT, REPOSITORY, PRINCIPAL, write_object, tree, commit
FG, ROOT = str(Path(sys.argv[1]).resolve()), Path(sys.argv[2]).resolve()
ROOT.mkdir(parents=True, exist_ok=True)
SEQUENCE, RESULTS = 0, []
def invoke(label, args, code=0):
    global SEQUENCE
    SEQUENCE += 1
    out, err = (ROOT / f'{SEQUENCE:03d}-{label}.{s}' for s in ('out', 'err'))
    with out.open('wb') as stdout, err.open('wb') as stderr:
        result = subprocess.run([FG, *map(str, args)], stdout=stdout, stderr=stderr, timeout=90)
    diagnostic = err.read_bytes()
    if diagnostic: sys.stderr.buffer.write(diagnostic); sys.stderr.buffer.flush()
    assert result.returncode == code, (label, result.returncode, out.read_bytes()[-3000:], diagnostic[-3000:])
    return out.read_bytes()
def record(fmt, name, **values):
    row = dict(format=fmt, case=name, **values); RESULTS.append(row); print(json.dumps(row), flush=True)
def path_digest(paths):
    body = b'frankengit/workflow-changed-paths/v1\0'
    for path in sorted(paths): body += len(path).to_bytes(8, 'big') + path
    return hashlib.sha256(body).hexdigest()
def changed(before, after):
    return sorted(p for p in set(before) | set(after) if before.get(p) != after.get(p))
class Fixture:
    def __init__(self, fmt):
        self.fmt = fmt; self.home = ROOT / fmt; self.home.mkdir()
        self.source, self.node, self.runs, self.effects = (self.home / n for n in ('source', 'node', 'runs', 'effects'))
        self.runs.mkdir(mode=0o700); (self.source / 'refs/heads').mkdir(parents=True)
        (self.source / 'HEAD').write_text('ref: refs/heads/main\n')
        (self.source / 'config').write_text('[core]\nbare=true\nrepositoryformatversion=' + ('0\n' if fmt == 'sha1' else '1\n[extensions]\nobjectformat=sha256\n'))
        filters = {
            'any': "    paths:\n      - '**'",
            'code': "    branches:\n      - work\n    paths:\n      - 'src/**'\n      - '!src/private/**'\n      - 'src/private/public.rs'",
            'docs': "    paths:\n      - 'docs/**'",
            'non_docs': "    paths-ignore:\n      - 'docs/**'",
            'raw': "    paths:\n      - 'raw/**'",
            'wrong_branch': "    branches:\n      - never\n    paths:\n      - '**'",
        }
        self.files = {b'src/unit.rs': (b'100644', b'original\n'), b'docs/manual.md': (b'100644', b'old docs\n'), b'asset.bin': (b'100644', b'\0' + b'x' * (2 * 1024 * 1024))}
        for name, filtering in filters.items():
            workflow = f"name: {name}\non:\n  push:\n{filtering}\njobs:\n  {name}:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf '{name}\\n' >> {shlex.quote(str(self.effects))}\n"
            self.files[f'ci/{name}.yml'.encode()] = (b'100644', workflow.encode())
        self.serial = 0; self.base = self.build(self.files, None, 'base'); self.tip = self.base
        self.original = dict(self.files); self.ref = 'refs/heads/work'
        (self.source / 'refs/heads/main').write_text(self.base + '\n')
        self.scope = [self.node, TENANT, REPOSITORY]
        invoke('init', ['init', *self.scope, fmt]); invoke('import', ['import', *self.scope, PRINCIPAL, 'initial', self.source])
        self.branch('create', 'create-work', target=self.base)
        self.listing = ['pr', 'list', *self.scope, '--trusted-local', '--object-format', fmt]
        self.events = set(); self.number = 0; self.pending_jobs = 0
    def build(self, files, parent, label):
        self.serial += 1
        def directory(prefix):
            names = {p[len(prefix):].split(b'/', 1)[0] for p in files if p.startswith(prefix)}; entries = []
            for name in names:
                full = prefix + name
                if full in files:
                    mode, body = files[full]; identity = write_object(self.source, self.fmt, 'blob', body)
                else: mode = b'40000'; identity = directory(full + b'/')
                entries.append((mode, name, identity))
            entries.sort(key=lambda e: e[1] + (b'/' if e[0] == b'40000' else b'\0'))
            return write_object(self.source, self.fmt, 'tree', tree(entries))
        return write_object(self.source, self.fmt, 'commit', commit(directory(b''), parent, self.serial, (label + '\n').encode()))
    def branch(self, operation, key, old=None, target=None, reference=None):
        args = ['branch', operation, *self.scope, '--trusted-local', '--principal', PRINCIPAL, '--idempotency-key', key, '--ref', reference or self.ref, '--object-format', self.fmt]
        if old: args += ['--expected-tip', old]
        if target: args += ['--target', target]
        return invoke(operation, args)
    def stage(self, tip):
        for p in (self.source / 'refs/heads').iterdir(): p.unlink()
        name = f'staged-{self.serial}'
        (self.source / 'HEAD').write_text(f'ref: refs/heads/{name}\n')
        (self.source / 'refs/heads' / name).write_text(tip + '\n')
        invoke('stage', ['import', *self.scope, PRINCIPAL, name, self.source])
    def advance(self, files, label):
        old = self.tip; tip = self.build(files, old, label); self.stage(tip)
        self.branch('update', f'advance-{self.serial}', old, tip); self.tip = tip; self.files = dict(files)
        return old
    def count(self): return self.effects.read_text().splitlines() if self.effects.exists() else []
    def watch(self, incarnation=None, code=0, reference=None, parent=None):
        args = ['workflow', 'watch', *self.scope, reference or self.ref, '--trusted-local', '--workflow', 'ci', '--input', 'ci', '--run-parent', parent or self.runs, '--object-format', self.fmt]
        if incarnation: args += ['--publish-checks', '--principal-id', PRINCIPAL, '--expected-incarnation', incarnation]
        output = [json.loads(l) for l in invoke('watch', args, code).splitlines() if l]
        if code == 2: return output
        assert output[-1]['node_closed']
        return next(r['poll'] for r in output if r['type'] == 'workflow_watch_poll'), output
    def check(self, label, before, paths, wanted, publish=False):
        start = self.count(); authority = invoke('basis', self.listing)
        poll, _ = self.watch(); d = poll['dispatch']; proof = d['plan']['changed_paths']
        assert poll['state'] == 'dispatched' and poll['event']['previous_commit'] == before
        assert poll['event']['event_id'] not in self.events; self.events.add(poll['event']['event_id'])
        assert [r['workflow_path_hex'] for r in d['runs']] == [f'ci/{name}.yml'.encode().hex() for name in wanted]
        assert d['matched_count'] == d['executed_count'] == len(wanted) and self.count() == start + wanted
        assert proof['profile'] == 'canonical-ref-difference-v1' and proof['requested_before'] == proof['compared_before'] == before and proof['after'] == self.tip
        assert (proof['before_tree'] is None) == (before is None)
        assert proof['count'] == len(paths) and proof['sha256'] == path_digest(paths) and proof['complete']
        assert invoke('basis', self.listing) == authority
        record(self.fmt, label + '-exact-canonical-change', selected=wanted, paths=len(paths))
        again, _ = self.watch(); assert again['state'] == 'previously_settled' and self.count() == start + wanted
        record(self.fmt, label + '-fresh-process-no-reexecution')
        stale_jobs = self.pending_jobs
        self.pending_jobs += len(wanted)
        if publish:
            self.number += 1; number = self.number
            invoke('open-pr', ['pr', 'open', *self.scope, str(number), '--trusted-local', '--principal', PRINCIPAL, '--idempotency-key', f'open-{number}', '--expected-version', '0', '--source-ref', self.ref, '--target-ref', 'refs/heads/main', '--expected-source', self.tip, '--expected-target', self.base, '--title', 'Push path checks', '--body', 'Original native observations', '--object-format', self.fmt])
            again, output = self.watch(poll['event']['repository_incarnation'], code=1 if stale_jobs else 0)
            decisions = [r for r in output if r['type'] == 'workflow_check_set_decision']
            refused = [r for r in decisions if not r['command_committed']]
            assert len(refused) == stale_jobs and all(r['refusal_code'] == 'TargetRefMoved' for r in refused)
            assert sum(r['command_committed'] for r in decisions) == len(wanted)
            self.pending_jobs = 0
            assert again['state'] == 'previously_settled' and self.count() == start + wanted
            checks = json.loads(invoke('checks', ['pr', 'checks', *self.scope, str(number), '--trusted-local', '--object-format', self.fmt]))['checks']
            assert sorted(c['job'] for c in checks) == sorted(wanted) and all(c['conclusion'] == 'success' for c in checks)
            if not wanted: assert not any(r['command_committed'] for r in decisions)
            record(self.fmt, label + '-only-selected-original-checks', stale_results_refused=stale_jobs)
for fmt in ('sha1', 'sha256'):
    f = Fixture(fmt)
    f.check('branch-creation', None, sorted(f.files), ['any', 'code', 'docs', 'non_docs'], publish=True)
    start = f.count(); f.branch('create', 'unrelated', target=f.tip, reference='refs/heads/unrelated')
    assert f.watch()[0]['state'] == 'previously_settled' and f.count() == start
    record(fmt, 'unrelated-canonical-ref-does-not-retrigger')
    cases = [
        ('source', b'src/unit.rs', (b'100644', b'changed\n'), ['any', 'code', 'non_docs']),
        ('docs', b'docs/manual.md', (b'100644', b'new docs\n'), ['any', 'docs']),
        ('mode-only', b'src/unit.rs', (b'100755', b'changed\n'), ['any', 'code', 'non_docs']),
        ('private', b'src/private/a.rs', (b'100644', b'private\n'), ['any', 'non_docs']),
        ('reincluded', b'src/private/public.rs', (b'100644', b'public\n'), ['any', 'code', 'non_docs']),
        ('raw-bytes', b'raw/\xff.bin', (b'100644', b'\0raw\xff'), ['any', 'non_docs', 'raw']),
        ('binary-payload-not-hydrated', b'asset.bin', (b'100644', b'\0' + b'y' * (2 * 1024 * 1024)), ['any', 'non_docs']),
        ('deletion', b'src/unit.rs', None, ['any', 'code', 'non_docs']),
    ]
    for label, path, value, wanted in cases:
        new = dict(f.files)
        if value is None: del new[path]
        else: new[path] = value
        old = f.advance(new, label); f.check(label, old, [path], wanted, publish=label == 'docs')
    old = f.advance(f.files, 'same-tree'); f.check('empty-difference', old, [], [], publish=True)
    before = dict(f.files); old = f.tip
    middle = dict(before); middle[b'src/middle.rs'] = (b'100644', b'intermediate\n')
    mid = f.build(middle, old, 'unpublished-intermediate')
    final = dict(middle); final[b'docs/new.md'] = (b'100644', b'final\n')
    tip = f.build(final, mid, 'two-commits-one-ref-update'); f.stage(tip)
    assert f.watch()[0]['state'] == 'previously_settled'
    f.branch('update', 'two-commits', old, tip); f.tip = tip; f.files = final
    f.check('multi-commit-push-not-first-parent', old, changed(before, final), ['any', 'code', 'docs', 'non_docs'])
    intermediate = dict(f.files); intermediate[b'src/missed.rs'] = (b'100644', b'missed event\n')
    f.advance(intermediate, 'coalesced-first')
    after = dict(f.files); after[b'docs/coalesced.md'] = (b'100644', b'last event\n')
    old = f.advance(after, 'coalesced-second')
    f.check('coalesced-events-use-latest-predecessor', old, [b'docs/coalesced.md'], ['any', 'docs'], publish=True)
    before = dict(f.files); after = dict(before); after[b'src/moved.bin'] = after.pop(b'raw/\xff.bin')
    old = f.advance(after, 'rename'); f.check('both-rename-endpoints', old, changed(before, after), ['any', 'code', 'non_docs', 'raw'])
    before = dict(f.files); after = dict(before); del after[b'src/moved.bin']; after[b'src/moved.bin/child'] = (b'100644', b'nested\n')
    old = f.advance(after, 'file-to-directory'); f.check('file-directory-transition', old, changed(before, after), ['any', 'code', 'non_docs'])
    f.branch('delete', 'delete-work', old=f.tip); start = f.count(); poll, _ = f.watch()
    assert poll['state'] == 'ref_unavailable' and f.count() == start; record(fmt, 'deleted-ref-starts-no-work')
    f.branch('create', 'recreate-work', target=f.base); f.tip = f.base; f.files = dict(f.original)
    f.check('recreation-does-not-skip-deletion', None, sorted(f.files), ['any', 'code', 'docs', 'non_docs'])
    many = dict(f.files)
    for i in range(520): many[f'many/{i:04}.txt'.encode()] = (b'100644', b'x')
    oversized = f.build(many, f.tip, 'oversized-comparison'); f.stage(oversized)
    f.branch('create', 'oversized-branch', target=oversized, reference='refs/heads/oversized')
    before = f.count(); authority = invoke('basis', f.listing)
    f.watch(code=2, reference='refs/heads/oversized')
    assert f.count() == before and invoke('basis', f.listing) == authority
    poll, _ = f.watch(code=1, reference='refs/heads/oversized')
    assert poll['state'] == 'blocked_unresolved' and f.count() == before
    record(fmt, 'incomplete-comparison-refuses-and-retains-unresolved-custody')
(ROOT / 'results.json').write_text(json.dumps(RESULTS, indent=2) + '\n')
