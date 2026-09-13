#!/usr/bin/env python3
"""Fresh-process review-protection lifecycle over a native file-backed node."""
import argparse
import json
import pathlib
import subprocess
import tempfile
from pull_request_smoke import fixture as make_fixture


def run_case(fg, root, fmt):
    source = root / 'source'
    fixture = make_fixture(source, fmt)
    storage = root / 'node'
    tenant, repository = '11' * 16, '22' * 16
    admin, successor, stranger, reviewer = ['%02x' % n * 16 for n in (1, 2, 9, 3)]
    common = [storage, tenant, repository]
    calls = 0

    def invoke(args, expected=0, decode=True):
        nonlocal calls
        calls += 1
        result = subprocess.run([str(fg), *map(str, args)], capture_output=True, timeout=90)
        if result.returncode != expected:
            raise AssertionError(f'{args[:2]}: exit={result.returncode}, expected={expected}\n{result.stdout.decode(errors="replace")}\n{result.stderr.decode(errors="replace")}')
        if not decode:
            return result
        value = json.loads(result.stdout)
        assert value['node_closed'] is True
        return value

    def show():
        return invoke(['protection', 'show', *common, '--trusted-local', '--object-format', fmt])

    def configure(who, version, epoch, key, administrators, protect=True, expected=0):
        flags = ['--trusted-local', '--object-format', fmt, '--principal', who,
                 '--expected-version', str(version), '--expected-epoch', str(epoch), '--idempotency-key', key]
        for administrator in administrators:
            flags += ['--admin', administrator]
        if protect:
            for branch in ['refs/heads/main', 'refs/heads/protected']:
                flags += ['--require-reviewer', f'{branch}:{reviewer}']
        else:
            flags += ['--clear']
        value = invoke(['protection', 'set', *common, *flags], expected)
        assert value['type'] == 'review_protection_publication'
        assert value['committed'] == (expected == 0)
        assert value['refs_changed'] is False and value['delivery_acknowledged'] is None
        assert value['expected_version'] == version and value['expected_epoch'] == epoch
        assert value['committed_policy_epoch'] == (epoch + 1 if expected == 0 else None)
        assert key not in json.dumps(value)
        return value

    def branch(verb, name, key, fields, expected=0):
        return invoke(['branch', verb, *common, '--ref', name, '--trusted-local', '--object-format', fmt,
            '--principal', admin, '--idempotency-key', key, *fields], expected)

    def same_decision(left, right):
        for field in ['tx_id', 'decision_sequence', 'repository_commit_id', 'refusal_record_id', 'refusal_code', 'outcome']:
            assert left[field] == right[field], field

    invoke(['init', *common, fmt], decode=False)
    invoke(['import', *common, admin, 'initial-import', source], decode=False)
    absent = show()
    assert absent['version'] == 0 and absent['policy_epoch'] == 1 and absent['policy'] is None
    installed = configure(admin, 0, 1, 'first-policy-key', [admin])
    state = show()
    assert state['installed'] and state['version'] == 1 and state['policy_epoch'] == 2
    assert state['policy']['administrators'] == [admin]
    for item in state['policy']['branches']:
        assert bytes.fromhex(item['ref_hex']).decode() == item['ref']
        assert item['required_reviewers'] == [reviewer]
    same_decision(installed, configure(admin, 0, 1, 'first-policy-key', [admin]))
    assert show()['source_head'] == state['source_head']
    branch('create', 'refs/heads/protected', 'blocked-creation', ['--target', fixture['source']], 3)
    branch('update', 'refs/heads/main', 'blocked-update', ['--expected-tip', fixture['target'], '--target', fixture['source']], 3)
    branch('create', 'refs/heads/unprotected', 'permitted-create', ['--target', fixture['source']])
    rejected = configure(stranger, 1, 2, 'takeover-key', [stranger], expected=3)
    assert rejected['refusal_code'] == 'ProtectedRefTransitionDenied'
    configure(admin, 1, 2, 'disable-rotate-key', [successor], protect=False)
    disabled = show()
    assert disabled['version'] == 2 and disabled['policy_epoch'] == 3
    assert disabled['policy']['branches'] == [] and disabled['policy']['administrators'] == [successor]
    same_decision(rejected, configure(stranger, 1, 2, 'takeover-key', [stranger], expected=3))
    same_decision(installed, configure(admin, 0, 1, 'first-policy-key', [admin]))
    assert show()['source_head'] == disabled['source_head']
    configure(admin, 2, 3, 'removed-admin-key', [admin], expected=3)
    branch('create', 'refs/heads/protected', 'permitted-disabled', ['--target', fixture['source']])
    configure(successor, 2, 3, 'reenable-key', [successor])
    branch('delete', 'refs/heads/protected', 'blocked-delete', ['--expected-tip', fixture['source']], 3)
    latest = show()
    assert latest['version'] == 3 and latest['policy_epoch'] == 4
    invalid = ['protection', 'set', *common, '--trusted-local', '--object-format', fmt,
        '--principal', successor, '--idempotency-key', 'bad-epoch-key', '--expected-version', '3',
        '--expected-epoch', '0', '--admin', successor, '--clear']
    assert invoke(invalid, 2, False).stdout == b''
    assert show()['source_head'] == latest['source_head']
    print(f'PROTECTION_CLI format={fmt} passed commands={calls}', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fg', required=True, type=pathlib.Path)
    args = parser.parse_args()
    binary = args.fg.resolve(strict=True)
    if not binary.is_file():
        parser.error('--fg must name a built native binary')
    with tempfile.TemporaryDirectory(prefix='fg-protection-cli-') as temporary:
        for fmt in ['sha1', 'sha256']:
            root = pathlib.Path(temporary) / fmt
            root.mkdir()
            run_case(binary, root, fmt)


if __name__ == '__main__':
    main()
