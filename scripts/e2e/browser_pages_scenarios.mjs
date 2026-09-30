// Per-page scenarios for browser_pages_probe.mjs (frankengit-root-doctrine-x2mv.4.46).
//
// Each scenario names a served page and ordered steps. A step receives
// { open, step, upload, tokens, seed, files } and returns plain observations.
// `step(body, token)` runs `body` as an async function in the page, with `fg`
// (the UI helpers), `seed` and `token` in scope. Steps act only through the
// page's own controls and assert nothing: the smoke and the suite judge the
// observations and read every write back through the API.
//
// A writing page runs `forbidden` before `write`, and both attempt the same
// change: the read-only token first, then the full token. So the permitted
// write succeeds only if the refused one left nothing behind.
//
// Scenario order matters. Pulls opens against the seeded main tip, so it runs
// before replay and the source editor move main.

const js = JSON.stringify;
const IDENTITY = 'Pages UI <ui@example.invalid>';
const TIMESTAMP = '1700000100';
// How each page words a terminal outcome or a refusal after Send.
const SENT = /Canonical (committed|refused)|Committed|Refused|Native tag decision|Outcome unknown|scope is missing|rejected|revoked/;

// Shared tail: stage, confirm, send, wait for the outcome.
const sendTail = ({ stage, staged, confirm, send = 'send', status = 'status' }) => `
  ${stage ? `fg.click(${js(stage)}); await fg.until(() => ${staged}.test(fg.text(${js(status)})), 'a staged publication');` : ''}
  fg.check(${js(confirm)});
  await fg.until(() => fg.enabled(${js(send)}), 'the send control');
  fg.click(${js(send)});
  await fg.until(() => ${SENT}.test(fg.text(${js(status)})), 'the send outcome');
  return { status: fg.text(${js(status)}).slice(0, 400) };
`;
// Runs one page action and waits for its own outcome. A failure is a changed
// status in the page's error vocabulary; the status from before the action
// never counts, so an earlier "Choose ..." prompt cannot end the wait early.
// Returns from the step with the page's own words when the action failed.
const act = (action, pattern, status = 'status') => `
  { const before = fg.text(${js(status)}), now = () => fg.text(${js(status)});
    ${action};
    await fg.until(() => ${pattern}.test(now()) || (now() !== before && /scope is missing|rejected|revoked|refused|unknown|unavailable|exceed|limit|Choose|Confirm|must|invalid|not /i.test(now())), ${js(String(pattern))});
    if (!${pattern}.test(now())) return { status: now().slice(0, 400), stopped: true }; }
`;

const sourceBrowse = `
  fg.set('token', token);
  fg.set('reference', 'refs/heads/main');
  fg.set('format', 'sha1');
  fg.submit('connection');
  await fg.until(() => /Read complete|lacks read scope|rejected/i.test(fg.text('status')), 'the source listing or a refusal');
  return { status: fg.text('status').slice(0, 300), listing: fg.text('content').slice(0, 600) };
`;

const historyRead = `
  fg.set('history-token', token);
  fg.set('history-ref', 'refs/heads/main');
  fg.set('history-format', 'sha1');
  fg.submit('history-connect');
  await fg.until(() => /History page checked|permission is missing|rejected/i.test(document.body.innerText), 'the history open or a refusal');
  if (!/History page checked/.test(document.body.innerText)) return { status: fg.text('history-status').slice(0, 400) };
  fg.set('history-path', 'README');
  fg.submit('history-query');
  await fg.until(() => /Exact path history/.test(fg.text('history-content')), 'the README path history');
  return { status: fg.text('history-status').slice(0, 300), content: fg.text('history-content').slice(0, 800) };
`;

const searchRead = `
  fg.set('token', token);
  fg.set('reference', 'refs/heads/main');
  fg.set('format', 'sha1');
  fg.submit('connection');
  await fg.until(() => /Read token ready/.test(fg.text('status')), 'the search connection');
  fg.set('mode', 'literal');
  fg.set('query', 'gazpacho');
  fg.submit('search-form');
  await fg.until(() => !/^(Searching|Read token ready|Query changed)/.test(fg.text('status')) && fg.text('status') !== '', 'the search outcome');
  return { status: fg.text('status').slice(0, 300), results: fg.text('results').slice(0, 800) };
`;

const exportVerify = `
  fg.set('export-format', 'sha1');
  fg.set('export-token', token);
  fg.click('export-connect');
  await fg.until(() => /Connected|rejected/.test(fg.text('export-status')), 'the export connection');
  fg.click('export-build');
  await fg.until(() => !/^(Connected|Reading the complete)/.test(fg.text('export-status')), 'the export outcome');
  return { status: fg.text('export-status').slice(0, 400), report: fg.text('export-report').slice(0, 1600) };
`;

const transfersSelect = `
  fg.set('transfer-token', token);
  fg.click('transfer-connect');
  await fg.until(() => /Connected|rejected/.test(fg.text('transfer-status')), 'the transfer connection');
  fg.set('transfer-format', 'sha1');
  ${act("fg.click('select-target')", '/Target identity and authority snapshot selected/', 'transfer-status')}
  return { status: fg.text('transfer-status').slice(0, 300) };
`;
const transfersExport = `
  ${act("fg.click('export-bundle')", '/Complete snapshot-pinned export/', 'transfer-status')}
  return { status: fg.text('transfer-status').slice(0, 300), export: fg.text('export-info').slice(0, 800) };
`;
const transfersLoad = `
  ${act("fg.click('load-bundle')", '/Complete bundle verified locally/', 'transfer-status')}
  return { status: fg.text('transfer-status').slice(0, 300), refs: fg.text('bundle-refs').slice(0, 400) };
`;
const transfersFetch = destination => `
  const map = [...document.querySelectorAll('#bundle-refs button')].find(button => button.textContent === 'Map this reference');
  if (!map) return { status: 'no mappable reference', stopped: true };
  map.click();
  const [target, old] = document.querySelectorAll('#mapping-rows fieldset input');
  for (const [input, value] of [[target, ${js(destination)}], [old, 'absent']]) {
    input.value = value;
    input.dispatchEvent(new Event('input', { bubbles: true }));
  }
  ${act("fg.click('stage-fetch')", '/Exact atomic request prepared locally/', 'transfer-status')}
  ${sendTail({ confirm: 'confirm-transfer', send: 'send-transfer', status: 'transfer-status' })}
`;

const issuesConnect = `
  fg.set('issue-token', token);
  fg.submit('issue-connection');
  await fg.until(() => /Read complete|scope is missing|rejected/i.test(fg.text('issue-status')), 'the issue listing or a refusal');
  return { status: fg.text('issue-status').slice(0, 300), listing: fg.text('issue-content').slice(0, 600) };
`;
const issuesOpen = (number, title) => `
  fg.set('change-number', ${js(String(number))});
  fg.set('change-version', '0');
  fg.set('change-action', 'open');
  fg.set('change-title', ${js(title)});
  fg.set('change-body', 'Opened from the served issues page.');
  ${act("fg.submit('issue-change')", '/Prepared locally/', 'issue-status')}
  fg.click('send-change');
  await fg.until(() => ${SENT}.test(fg.text('issue-status')), 'the issue send outcome');
  return { status: fg.text('issue-status').slice(0, 400) };
`;

const pullsConnect = `
  fg.set('token', token);
  fg.submit('connection');
  await fg.until(() => /^Snapshot: /.test(fg.text('pr-list')) || /not available|rejected/i.test(fg.text('status')), 'the PR listing or a refusal');
  return { status: fg.text('status').slice(0, 300), listing: fg.text('pr-list').slice(0, 600) };
`;
const pullsOpen = (number, title) => `
  fg.click('new-pr');
  fg.set('pr-number', ${js(String(number))});
  fg.set('metadata-action', 'open');
  fg.set('expected-version', '0');
  fg.set('object-format', 'sha1');
  fg.set('source-ref', 'refs/heads/feature');
  fg.set('target-ref', 'refs/heads/main');
  fg.set('source-tip', seed.feature);
  fg.set('target-tip', seed.main);
  fg.set('title', ${js(title)});
  fg.set('body', 'Opened from the served pulls page.');
  ${act("fg.submit('metadata')", '/Metadata request prepared locally/')}
  ${sendTail({ confirm: 'confirm' })}
`;

const branchesLoad = `
  fg.set('token', token);
  fg.click('connect');
  await fg.until(() => /Connected|rejected/.test(fg.text('status')), 'the branch connection');
  fg.click('load');
  await fg.until(() => /Loaded a pinned reference page|scope is missing|rejected/i.test(fg.text('status')), 'the branch listing or a refusal');
  return { status: fg.text('status').slice(0, 300), listing: fg.text('refs').slice(0, 600) };
`;
const branchesCreate = destination => `
  fg.set('operation', 'create');
  fg.set('selected', 'refs/heads/main');
  fg.set('destination', ${js(destination)});
  await fg.until(() => fg.enabled('prepare'), 'the branch prepare control');
  ${act("fg.click('prepare')", '/Exact request prepared locally/')}
  ${sendTail({ confirm: 'confirm-send' })}
`;

const tagsLoad = `
  fg.set('token', token);
  fg.submit('connection');
  await fg.until(() => /Connected|rejected/.test(fg.text('status')), 'the tags connection');
  fg.set('format', 'sha1');
  fg.click('load');
  await fg.until(() => /Reference snapshot loaded|scope is missing|rejected/i.test(fg.text('status')), 'the tag listing or a refusal');
  const tags = [...document.getElementById('tag').options].map(option => option.textContent).join(' | ');
  return { status: fg.text('status').slice(0, 300), tags: tags.slice(0, 600) };
`;
// 726566732f68656164732f6d61696e is refs/heads/main as ref-name hex.
const tagsCreate = destination => `
  fg.set('operation', 'lightweight');
  fg.set('source', '726566732f68656164732f6d61696e');
  fg.set('destination', ${js(destination)});
  fg.set('name-encoding', 'text');
  await fg.until(() => fg.enabled('prepare'), 'the tag prepare control');
  ${act("fg.click('prepare')", '/Prepared locally/')}
  ${sendTail({ confirm: 'confirm' })}
`;

const initialPrepare = branch => `
  fg.set('token', token);
  fg.click('connect');
  await fg.until(() => /Connected|rejected/.test(fg.text('status')), 'the initial-commit connection');
  fg.set('branch', ${js(branch)});
  fg.set('format', 'sha1');
  fg.check('expected-absent');
  fg.set('path', 'hello.txt');
  fg.set('file-text', 'Hello from the served initial-commit page.\\n');
  ${act("fg.click('queue')", '/initial file\\(s\\) queued locally/')}
  fg.set('author', ${js(IDENTITY)});
  fg.set('committer', ${js(IDENTITY)});
  fg.set('timestamp', ${js(TIMESTAMP)});
  fg.set('message', 'Initial commit from the served page\\n');
  await fg.until(() => fg.enabled('prepare'), 'the initial prepare control');
  ${act("fg.click('prepare')", '/matched native preparation/')}
`;
const initialRead = branch => `${initialPrepare(branch)}
  return { status: fg.text('status').slice(0, 300), candidate: fg.text('candidate').slice(0, 600) };
`;
const initialCreate = branch => `${initialPrepare(branch)}
  ${sendTail({ stage: 'stage', staged: '/Creation-only request frozen locally/', confirm: 'confirm-send' })}
`;

const editorBase = `
  fg.set('token', token);
  fg.click('connect');
  await fg.until(() => /Connected|rejected/.test(fg.text('status')), 'the editor connection');
  fg.set('branch', 'refs/heads/main');
  fg.set('format', 'sha1');
  ${act("fg.click('select-base')", '/Immutable base selected/')}
`;
const editorRead = `${editorBase}
  return { status: fg.text('status').slice(0, 300), base: fg.text('base').slice(0, 600) };
`;
const editorCreate = path => `${editorBase}
  fg.set('path', ${js(path)});
  fg.set('change-kind', 'create');
  fg.set('file-text', 'Notes written from the served source editor.\\n');
  ${act("fg.click('queue-file')", '/exact file effect\\(s\\) queued/')}
  fg.set('author', ${js(IDENTITY)});
  fg.set('committer', ${js(IDENTITY)});
  fg.set('timestamp', ${js(TIMESTAMP)});
  fg.set('message', 'Add notes from the served source editor\\n');
  ${act("fg.click('prepare-edits')", '/Native preparation and inspection completed/')}
  ${sendTail({ stage: 'stage', staged: '/Publication prepared locally/', confirm: 'confirm-send' })}
`;

const replaySelect = `
  fg.set('token', token);
  fg.click('connect');
  await fg.until(() => /Connected|rejected/.test(fg.text('status')), 'the replay connection');
  fg.set('target', 'refs/heads/main');
  fg.set('source', 'refs/heads/topic');
  fg.set('format', 'sha1');
  ${act("fg.click('select')", '/Both branch tips are pinned/')}
`;
const replayRead = `${replaySelect}
  return { status: fg.text('status').slice(0, 300), selection: fg.text('selection').slice(0, 600) };
`;
const replayPick = `${replaySelect}
  fg.set('direction', 'cherry-pick');
  fg.set('commit', seed.topic);
  fg.set('author', ${js(IDENTITY)});
  fg.set('committer', ${js(IDENTITY)});
  fg.set('timestamp', ${js(TIMESTAMP)});
  fg.set('message', 'Replay the topic commit from the served page\\n');
  ${act("fg.click('prepare')", '/Candidate prepared and inspected/')}
  ${sendTail({ stage: 'stage', staged: '/Publication prepared locally/', confirm: 'confirm' })}
`;

const rebaseSelect = `
  fg.set('token', token);
  fg.click('connect');
  await fg.until(() => /Connected|rejected/.test(fg.text('status')), 'the rebase connection');
  fg.set('source', 'refs/heads/feature');
  fg.set('onto', 'refs/heads/main');
  fg.set('format', 'sha1');
  ${act("fg.click('select')", '/Both branches selected at one snapshot/')}
`;
const rebaseRead = `${rebaseSelect}
  return { status: fg.text('status').slice(0, 300), selection: fg.text('selection').slice(0, 600) };
`;
const rebaseRun = `${rebaseSelect}
  fg.set('upstream', seed.second);
  fg.set('empty', 'stop');
  fg.set('committer', ${js(IDENTITY)});
  fg.set('timestamp', ${js(TIMESTAMP)});
  fg.set('max-commits', '32');
  ${act("fg.click('prepare')", '/Native complete-series inspection finished/')}
  ${sendTail({ stage: 'stage', staged: '/Exact history rewrite prepared locally/', confirm: 'confirm-send' })}
`;

// A read-only page: the permitted read, then the same read without read scope.
const readPage = (name, path, body) => ({
  name, path,
  steps: {
    read: ({ step, tokens }) => step(body, tokens.full),
    forbidden: async ({ open, step, tokens }) => { await open(path); return step(body, tokens.other); },
  },
});
// A writing page: read, then the same write with the read-only token and then
// with the full token, each on a freshly loaded page.
const writePage = (name, path, read, write, prelude = null) => ({
  name, path,
  steps: {
    read: ({ step, tokens }) => step(read, tokens.full),
    forbidden: async ({ open, step, tokens }) => {
      await open(path);
      if (prelude) await step(prelude, tokens.read);
      return step(write, tokens.read);
    },
    write: async ({ open, step, tokens }) => {
      await open(path);
      if (prelude) await step(prelude, tokens.full);
      return step(write, tokens.full);
    },
  },
});
// The transfers page writes through a mapped fetch of an uploaded bundle.
const transfersWrite = token => async ({ open, step, upload, tokens, files }) => {
  await open('ui/transfers/');
  const selected = await step(transfersSelect, tokens[token]);
  if (selected.stopped) return selected;
  await upload('bundle-file', files.bundle);
  const loaded = await step(transfersLoad);
  return loaded.stopped ? loaded : step(transfersFetch('refs/heads/imported'));
};

export const SCENARIOS = [
  readPage('source', 'ui/', sourceBrowse),
  readPage('history', 'ui/history/', historyRead),
  readPage('search', 'ui/search/', searchRead),
  readPage('export-verify', 'ui/transfers/verify/', exportVerify),
  {
    name: 'transfers',
    path: 'ui/transfers/',
    steps: {
      read: async ({ step, tokens }) => {
        const selected = await step(transfersSelect, tokens.full);
        return selected.stopped ? selected : step(transfersExport);
      },
      forbidden: transfersWrite('read'),
      write: transfersWrite('full'),
    },
  },
  writePage('issues', 'ui/issues/', issuesConnect, issuesOpen(2, 'Opened in Chrome'), issuesConnect),
  writePage('pulls', 'ui/pulls/', pullsConnect, pullsOpen(2, 'Opened in Chrome'), pullsConnect),
  writePage('branches', 'ui/branches/', branchesLoad, branchesCreate('refs/heads/created-in-ui'), branchesLoad),
  writePage('tags', 'ui/tags/', tagsLoad, tagsCreate('refs/tags/ui-light'), tagsLoad),
  writePage('initial', 'ui/initial/', initialRead('refs/heads/fresh'), initialCreate('refs/heads/fresh')),
  writePage('rebase', 'ui/rebase/', rebaseRead, rebaseRun),
  writePage('replay', 'ui/replay/', replayRead, replayPick),
  writePage('source-edit', 'ui/source/', editorRead, editorCreate('notes.txt')),
];
