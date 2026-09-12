#!/usr/bin/env python3
"""Fresh-process native issue lifecycle; no upstream Git or mock authority."""
import argparse
import json
import pathlib
import subprocess
import tempfile


def run_case(fg, root, fmt):
    tenant, repository, principal = '11' * 16, '22' * 16, '33' * 16
    calls = 0
    def invoke(args, expected=0, decode=True):
        nonlocal calls
        calls += 1
        result = subprocess.run([str(fg), *map(str, args)], capture_output=True, timeout=90)
        if result.returncode != expected:
            raise AssertionError(f'command {args[:2]} exit {result.returncode}, expected {expected}\n{result.stdout.decode(errors="replace")}\n{result.stderr.decode(errors="replace")}')
        if not decode:
            return result
        value = json.loads(result.stdout)
        assert value['node_closed'] is True
        return value
    def mutation(verb, number, version, key, fields=(), expected=0):
        args = ['issue', verb, root, tenant, repository, str(number), '--trusted-local',
                '--object-format', fmt, '--principal', principal, '--idempotency-key', key,
                '--expected-version', str(version), *fields]
        receipt = invoke(args, expected)
        assert receipt['type'] == 'issue_publication'
        assert receipt['action']['name'] == verb and receipt['number'] == number
        assert receipt['expected_version'] == version and receipt['object_format'] == fmt
        assert receipt['refs_changed'] is False and receipt['delivery_acknowledged'] is None
        assert receipt['command_committed'] == (expected == 0)
        assert receipt['outcome'] == ('committed' if expected == 0 else 'refused')
        assert key not in json.dumps(receipt), 'private retry key must not be emitted'
        return receipt
    def read(verb='show', number=7, fields=(), expected=0):
        args = ['issue', verb, root, tenant, repository]
        if verb == 'show': args.append(str(number))
        return invoke([*args, '--trusted-local', '--object-format', fmt, *fields], expected)
    def same_decision(left, right):
        for field in ['tx_id', 'decision_sequence', 'repository_commit_id', 'refusal_record_id', 'refusal_code', 'outcome']:
            assert left[field] == right[field], field
    invoke(['init', root, tenant, repository, fmt], decode=False)
    empty = read('list'); assert empty['issues'] == []
    body = root.parent / f'body-{fmt}.txt'
    original = 'A precise report\r\n<script>data only</script>\né 🦀\n'
    body.write_bytes(original.encode())
    fields = ['--title', 'Opening title', '--body-file', str(body), '--label', 'zeta', '--label', 'alpha']
    opened = mutation('open', 7, 0, 'open-stable-private-key', fields)
    same_decision(opened, mutation('open', 7, 0, 'open-stable-private-key', fields))
    first = read(); assert first['issue']['version'] == 1 and first['issue']['body'] == original
    assert first['issue']['labels'] == ['alpha', 'zeta'] and len(first['events']) == 1
    assert first['snapshot_token'] == read()['snapshot_token'], 'reads must not advance authority'
    comment_text = 'Exact comment\r\n\u001b\u202e é 🦀'
    comment = mutation('comment', 7, 1, 'comment-stable-private-key', ['--body', comment_text])
    current = read(); assert current['issue']['comments'] == 1
    assert current['events'][1]['action'] == {'name': 'comment', 'body': comment_text}
    assert current['issue']['body'] == original
    mutation('edit', 7, 2, 'edit-title-private-key', ['--title', 'Revised title'])
    revised = read(); assert revised['issue']['body'] == original and revised['issue']['labels'] == ['alpha', 'zeta']
    assert revised['events'][2]['action'] == {'name': 'edit', 'title': 'Revised title'}
    mutation('close', 7, 3, 'close-private-key')
    assert read()['issue']['state'] == 'closed'
    mutation('reopen', 7, 4, 'reopen-private-key')
    mutation('edit', 7, 5, 'clear-private-key', ['--body', '', '--clear-labels'])
    final = read(); assert final['issue']['version'] == 6 and final['issue']['state'] == 'open'
    assert final['issue']['body'] == '' and final['issue']['labels'] == [] and final['issue']['title'] == 'Revised title'
    assert [e['action']['name'] for e in final['events']] == ['open', 'comment', 'edit', 'close', 'reopen', 'edit']
    assert [e['version'] for e in final['events']] == list(range(1, 7))
    same_decision(comment, mutation('comment', 7, 1, 'comment-stable-private-key', ['--body', comment_text]))
    same_decision(opened, mutation('open', 7, 0, 'open-stable-private-key', fields))
    assert read()['snapshot_token'] == final['snapshot_token'], 'historical retries cannot create more events'
    stale = mutation('close', 7, 1, 'stale-private-key', expected=3)
    rejected_head = read()['snapshot_token']
    same_decision(stale, mutation('close', 7, 1, 'stale-private-key', expected=3))
    assert read()['snapshot_token'] == rejected_head, 'terminal refusal is idempotent'
    assert read()['issue']['version'] == 6
    changed = ['issue', 'comment', root, tenant, repository, '7', '--trusted-local', '--object-format', fmt,
               '--principal', principal, '--idempotency-key', 'comment-stable-private-key', '--expected-version', '1', '--body', 'changed bytes']
    assert invoke(changed, 2, False).stdout == b''
    assert read()['snapshot_token'] == rejected_head, 'key reuse must not mutate canonical history'
    mutation('open', 9, 0, 'open-second-private-key', ['--title', 'Second issue', '--body', ''])
    page = read('list', fields=['--limit', '1']); assert [i['number'] for i in page['issues']] == [7]
    assert page['next_after'] == 7 and page['has_more']
    tail = read('list', fields=['--limit', '1', '--after', '7', '--expected-head', page['snapshot_token']])
    assert [i['number'] for i in tail['issues']] == [9] and tail['next_after'] is None
    events = []
    after = 0
    token = None
    while True:
        flags = ['--limit', '2']
        if after: flags += ['--after-version', str(after), '--expected-head', token]
        history = read(fields=flags)
        token = history['snapshot_token'] if token is None else token
        assert history['snapshot_token'] == token
        events.extend(history['events'])
        after = history['next_after_version']
        if after is None: break
    assert events == final['events'], 'paging must not skip, repeat, or rewrite actions'
    missing = read(number=8, expected=4); assert not missing['found'] and missing['issue'] is None and missing['events'] == []
    mutation('comment', 9, 1, 'second-comment-private-key', ['--body', 'advance snapshot'])
    stale_read = ['issue', 'list', root, tenant, repository, '--trusted-local', '--object-format', fmt,
                  '--after', '7', '--expected-head', page['snapshot_token']]
    assert invoke(stale_read, 2, False).stdout == b''
    before_invalid = read('list')['snapshot_token']
    invalid = ['issue', 'comment', root, tenant, repository, '7', '--trusted-local', '--object-format', fmt,
               '--principal', principal, '--idempotency-key', 'invalid-file-private-key', '--expected-version', '6', '--body-file', str(body)]
    body.write_bytes(b'\xff')
    assert invoke(invalid, 2, False).stdout == b''
    body.write_bytes(b'x' * 65537)
    assert invoke(invalid, 2, False).stdout == b''
    assert read('list')['snapshot_token'] == before_invalid, 'bad body files must fail before publication'
    # Once input files disappear, recovery remains possible using only the
    # original authenticated principal and scoped key through the existing CLI.
    body.unlink()
    recovered = invoke(['outcome', root, tenant, repository, '--trusted-local', '--principal', principal,
                        '--object-format', fmt, '--idempotency-key', 'open-stable-private-key'], decode=False)
    value = json.loads(recovered.stdout)
    assert value['transaction']['tx_id'] == opened['tx_id']
    assert read('list')['snapshot_token'] == before_invalid
    print(f'ISSUE_LIFECYCLE format={fmt} passed commands={calls}', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fg', required=True, type=pathlib.Path)
    args = parser.parse_args()
    fg = args.fg.resolve(strict=True)
    if not fg.is_file(): parser.error('--fg must name the built native binary')
    with tempfile.TemporaryDirectory(prefix='fg-issue-cli-') as tmp:
        base = pathlib.Path(tmp)
        for fmt in ['sha1', 'sha256']:
            run_case(fg, base / fmt, fmt)

if __name__ == '__main__':
    main()
