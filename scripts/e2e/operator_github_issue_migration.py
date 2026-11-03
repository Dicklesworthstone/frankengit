#!/usr/bin/env python3
"""Synthetic GitHub inputs -> shipped migration CLIs -> real Rust authority.

No GitHub service, schema peer or foreign Git is used as native authority.
Reuse the existing bounded command owners and require every native service drain.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import signal
from typing import Any
from urllib.parse import urlsplit

from operator_issue_smoke import OperatorCampaign, ROOT, TOKEN, issue_server
from scoped_events_smoke import HttpServer, TENANT, REPOSITORY, PRINCIPAL, file_sha256, require


def requests(root: Path) -> dict[str, str]:
    result = {str(path.relative_to(root)): file_sha256(path) for path in root.rglob('*.request.json')}
    require(bool(result), 'prepared request population is empty')
    return result


@contextmanager
def without_issue_service(campaign: OperatorCampaign, root: Path, credentials: Path, fmt: str):
    # Same existing native owner, with only the issue service ceiling disabled.
    # Retain the normal Fetch-compatible port selection and drain every discard.
    for attempt in range(16):
        server = HttpServer(campaign, root, credentials, f'github-no-route-{fmt}-{attempt}')
        server.command.remove('--allow-issues')
        server.command.append('--allow-outcomes')
        with server:
            if urlsplit(server.url).port <= 10080:
                continue
            yield server
            return
    raise AssertionError('native Fetch-compatible listener selection exhausted')


def run_case(campaign: OperatorCampaign, fmt: str) -> None:
    directory = campaign.work / fmt
    directory.mkdir(mode=0o700)
    root = directory / 'repository'
    campaign.run('init', root, TENANT, REPOSITORY, fmt)
    credentials, _ = campaign.credentials(root, directory)
    header = credentials.read_text(encoding='utf-8').splitlines()[0]
    token = directory / 'token'
    token.write_text(TOKEN, encoding='ascii')

    def grants(scopes: str) -> None:
        pending = directory / 'credentials.next'
        with pending.open('x', encoding='utf-8') as out:
            out.write(f'{header}\n{hashlib.sha256(TOKEN.encode()).hexdigest()} {PRINCIPAL} {scopes}\n')
        pending.replace(credentials)

    grants('issues-read,issues-write,outcomes-read')
    source = directory / 'source'
    source.mkdir(mode=0o700)
    selected = campaign.node_command(ROOT / 'scripts/e2e/helpers/github_issue_migration_source.mjs', [str(source)])
    importer = ROOT / 'scripts/import_github_issues.mjs'
    migration = ROOT / 'scripts/migrate_github_issues.mjs'

    def canonical(number: int | None = None, selected_root: Path = root) -> dict[str, Any]:
        args: list[Any] = ['issue', 'list' if number is None else 'show', selected_root, TENANT, REPOSITORY]
        if number is not None:
            args.append(number)
        page = json.loads(campaign.run(*args, '--trusted-local', '--object-format', fmt, '--limit', 100))
        require(page['node_closed'] is True, 'independent Rust read did not close')
        return page

    def connection(url: str, workdir: Path, whole: bool) -> list[str]:
        return ['--url', url + '/ui/issues/', '--tenant' if whole else '--tenant-id', TENANT,
                '--repository' if whole else '--repository-id', REPOSITORY,
                '--token-file', str(token), '--workdir', str(workdir)]

    def readback(offset: int, selected_root: Path = root) -> None:
        for issue in selected['issues']:
            page = canonical(offset + issue['number'], selected_root)
            require(page['found'] is True and page['has_more'] is False, 'native history is incomplete')
            actual, events = page['issue'], page['events']
            require(actual['title'] == issue['title'] and actual['state'] == issue['state']
                    and actual['body'].endswith(issue['body']) and actual['labels'] == ['bug']
                    and actual['comments'] == len(issue['comments']) and actual['assignees'] == []
                    and actual['opened_by'] == PRINCIPAL and actual['last_actor'] == PRINCIPAL,
                    'native snapshot lost source text/lifecycle or imported source authority')
            comments = [event['action']['body'] for event in events if event['action']['name'] == 'comment']
            require(len(comments) == len(issue['comments'])
                    and all(body.endswith(original) for body, original in zip(comments, issue['comments']))
                    and all(event['actor'] == PRINCIPAL for event in events),
                    'literal comments or authenticated native authorship differ')
            require('https://github.com/owner/project/issues/' in actual['body']
                    and 'original-source-author' in actual['body'], 'source attribution is missing')

    with issue_server(campaign, root, credentials, 'github-' + fmt) as server:
        whole_dir, single_dir = directory / 'whole', directory / 'single'
        whole = connection(server.url, whole_dir, True)
        single = connection(server.url, single_dir, False)
        before = canonical()
        inspected = campaign.node_command(importer, ['inspect', '--capture', selected['combined'], '--offset', '2000'])
        require(inspected['mutation_submitted'] is False, 'source inspection claimed a mutation')
        plan = campaign.node_command(migration, ['prepare', *whole, '--sources', selected['sources'],
                                                '--sources-sha256', selected['sources_sha256']])
        batch = campaign.node_command(importer, ['prepare', *single, '--capture', selected['combined'], '--offset', '2000'])
        require(plan['steps'] == batch['steps'] == 7 and canonical() == before, 'offline preparation changed native state')
        whole += ['--confirm', plan['plan_sha256']]
        single += ['--confirm', batch['plan_sha256']]
        whole_requests, single_requests = requests(whole_dir), requests(single_dir)
        campaign.node_command(migration, ['inspect', *whole])
        campaign.facts[f'{fmt}_offline_preparation'] = True

        # Run/status must use owned captures after every external source path disappears.
        source.rename(directory / 'retained-source')
        partial = campaign.node_command(migration, ['run', *whole, '--max-mutations', '1'], 3)
        first = canonical()
        require(partial['mutation_calls'] == partial['committed_observed'] == 1 and not partial['complete']
                and [issue['number'] for issue in first['issues']] == [1003]
                and first['issues'][0]['state'] == 'open' and first['issues'][0]['comments'] == 0,
                'global mutation budget did not bound the native prefix')
        observed = campaign.node_command(migration, ['status', *whole], 3)
        require(observed['mutation_calls'] == 0 and not observed['complete'] and canonical() == first,
                'partial status submitted or lost the native prefix')
        campaign.facts[f'{fmt}_global_budget_and_status'] = True
        complete = campaign.node_command(migration, ['run', *whole])
        require(complete['complete'] and complete['committed_observed'] == 7
                and requests(whole_dir) == whole_requests, 'whole migration lost original custody')
        readback(1000)
        campaign.facts[f'{fmt}_owned_sources_and_resume'] = True

        # A denied HTTP write is still uncertain to the client. Keep its original
        # started marker/request; restoring grants must not silently auto-resend.
        grants('issues-read,outcomes-read')
        before = canonical()
        denied = campaign.node_command(importer, ['run', *single], 2, error_reply=True)
        require(denied['http_status'] == 403 and denied['import_progress']['mutation_calls'] == 1
                and denied['import_progress']['committed_observed'] == 0 and canonical() == before,
                'denied import claimed commitment or changed native issue state')
        grants('issues-read,issues-write,outcomes-read')
        uncertain = campaign.node_command(importer, ['run', *single], 1)
        require(uncertain['stop_reason'] == 'unresolved_original_request' and uncertain['mutation_calls'] == 0
                and canonical() == before, 'restored grant silently retried an uncertain request')
        permitted = campaign.node_command(importer, ['run', *single, '--retry-unresolved'])
        require(permitted['complete'] and permitted['committed_observed'] == 7
                and requests(single_dir) == single_requests, 'permitted retry replaced an original request')
        readback(2000)
        campaign.facts[f'{fmt}_denied_write_and_exact_retry'] = True
        campaign.facts[f'{fmt}_canonical_text_lifecycle_and_actor'] = True
        before = canonical()
        for script, args in [(migration, whole), (importer, single)]:
            for name in ['status', 'run']:
                recovered = campaign.node_command(script, [name, *args])
                require(recovered['complete'] and recovered['mutation_calls'] == 0 and canonical() == before,
                        'completed recovery resubmitted or changed canonical state')
        campaign.facts[f'{fmt}_completed_recovery'] = True

        # Existing destinations refuse canonically; no version refresh or new
        # recovery key may overwrite the imported issue or start later steps.
        retained_capture = directory / 'retained-source/combined.json'
        conflict_dir = directory / 'conflict'
        conflict = connection(server.url, conflict_dir, False)
        prepared = campaign.node_command(importer, ['prepare', *conflict, '--capture', str(retained_capture), '--offset', '1000'])
        conflict += ['--confirm', prepared['plan_sha256']]
        original = requests(conflict_dir)
        refused = campaign.node_command(importer, ['run', *conflict], 3)
        require(refused['stop_reason'] == 'terminal_refusal' and refused['committed_observed'] == 0
                and refused['refusal']['outcome'] == 'refused', 'occupied target did not refuse canonically')
        for name in ['status', 'run']:
            recovered = campaign.node_command(importer, [name, *conflict], 3)
            require(recovered['refusal'] == refused['refusal'] and recovered['mutation_calls'] == 0,
                    'conflict recovery lost the immutable refusal')
        require(requests(conflict_dir) == original and canonical()['issues'] == before['issues'],
                'occupied target or original requests changed')
        campaign.facts[f'{fmt}_occupied_target_refusal'] = True

        # Complete-plan preflight must inspect even an untouched later batch.
        selection = json.loads((directory / 'retained-source/sources.json').read_text())
        for descriptor in [selection['inventory'], *selection['captures']]:
            descriptor['path'] = str(directory / 'retained-source' / Path(descriptor['path']).name)
        selection['offset'] = 3000
        selection_file = directory / 'tamper-sources.json'
        selection_file.write_text(json.dumps(selection, separators=(',', ':')) + '\n')
        tamper_dir = directory / 'tamper'
        tamper = connection(server.url, tamper_dir, True)
        prepared = campaign.node_command(migration, ['prepare', *tamper, '--sources', str(selection_file),
            '--sources-sha256', file_sha256(selection_file)])
        last = sorted((tamper_dir / 'batch-000002').glob('*.request.json'))[-1]
        last.write_bytes(last.read_bytes() + b' ')
        before_tamper = canonical()
        rejected = campaign.node_command(migration, ['run', *tamper, '--confirm', prepared['plan_sha256']], 2, error_reply=True)
        require(rejected['migration_progress']['mutation_calls'] == 0
                and rejected['migration_progress']['committed_observed'] == 0 and canonical() == before_tamper,
                'changed later request allowed a native publication prefix')
        campaign.facts[f'{fmt}_later_request_tamper'] = True

    # Same original destination and request after an actual issue-service-disabled node.
    route_dir = directory / 'route-auth'
    route_dir.mkdir(mode=0o700)
    route_root = directory / 'route-repository'
    campaign.run('init', route_root, TENANT, REPOSITORY, fmt)
    route_credentials, _ = campaign.credentials(route_root, route_dir)
    route_header = route_credentials.read_text().splitlines()[0]
    route_credentials.write_text(f'{route_header}\n{hashlib.sha256(TOKEN.encode()).hexdigest()} {PRINCIPAL} issues-read,issues-write,outcomes-read\n')
    with without_issue_service(campaign, route_root, route_credentials, fmt) as disabled:
        route_url = disabled.url
        route_work = directory / 'route-import'
        route = connection(route_url, route_work, False)
        prepared = campaign.node_command(importer, ['prepare', *route, '--capture', str(retained_capture), '--offset', '4000'])
        route += ['--confirm', prepared['plan_sha256']]
        original = requests(route_work)
        before_route = canonical(selected_root=route_root)
        missing = campaign.node_command(importer, ['run', *route], 2, error_reply=True)
        require(missing['http_status'] == 403 and missing['import_progress']['committed_observed'] == 0
                and canonical(selected_root=route_root) == before_route, 'disabled issue service did not refuse without native issue changes')
    restored = HttpServer(campaign, route_root, route_credentials, 'github-route-restored-' + fmt)
    restored.command[5] = urlsplit(route_url).netloc
    restored.command.append('--allow-outcomes')
    with restored:
        require(restored.url == route_url, 'route restoration changed the sealed destination')
        pending = campaign.node_command(importer, ['run', *route], 1)
        require(pending['mutation_calls'] == 0 and pending['stop_reason'] == 'unresolved_original_request',
                'route restoration automatically resent an uncertain original')
        complete = campaign.node_command(importer, ['run', *route, '--retry-unresolved'])
        require(complete['complete'] and requests(route_work) == original, 'restored route changed original custody')
        readback(4000, route_root)
    campaign.facts[f'{fmt}_disabled_service_and_exact_retry'] = True
    campaign.facts[f'{fmt}_owned_services_drained'] = True
    print(f'GITHUB_ISSUE_MIGRATION {fmt}: actual CLIs, original custody, native publication/refusals/readback and drain', flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('fg', 'node', 'work', 'summary'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    fg, node = args.fg.resolve(strict=True), args.node.resolve(strict=True)
    require(all(path.is_file() and os.access(path, os.X_OK) for path in (fg, node)), 'prebuilt executables required')
    os.umask(0o077)
    args.work.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not any(args.work.iterdir()) and args.work.stat().st_mode & 0o077 == 0,
            '--work must be an empty private directory')
    campaign = OperatorCampaign(fg, node, args.work.resolve())
    summary: dict[str, Any] = {'complete': False, 'facts': campaign.facts,
        'binary_sha256': file_sha256(fg), 'node_sha256': file_sha256(node),
        'native_source_cut': os.environ.get('FG_SIGNED_BUNDLE_SOURCE_CUT'),
        'non_claim': 'Synthetic GitHub inputs, actual native destination; no live GitHub, TLS, power-loss, full entrypoint matrix, independent batch or same-source native build proof.'}
    interrupted = False

    def stop(_signal: int, _frame: Any) -> None:
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            raise InterruptedError('migration campaign interrupted; draining owned services')

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        runtime = campaign.node_command(ROOT / 'scripts/verify_js.mjs', ['runtime'])
        require(runtime.get('type') == 'js_runtime_identity' and runtime.get('corpus_started') is False,
                'pinned runtime identity unavailable')
        summary['node_version'] = runtime['node']
        for fmt in ('sha1', 'sha256'):
            run_case(campaign, fmt)
        summary['complete'] = True
    except BaseException as error:
        summary['failure'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
