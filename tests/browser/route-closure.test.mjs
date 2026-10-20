// Static-source check over the Rust route tables, not live browser evidence.
//
// A page loads its modules from its own directory, so every relative import of
// every served module must itself be routed beside it. 3447fb9a added one import
// to the shared pulls-actions.mjs and routed it only at /ui/: nine pages then
// 405ed at boot, and only the real-browser suite noticed. This walks every page
// table at once, so the next shared import cannot miss a page.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';

const base = new URL('../../crates/fgit-node/src/smart_http/server/browser/', import.meta.url);

/** Route -> served file, for every `b"/ui/..." => ... include_str!("file")` arm. */
function routeTable(rust) {
  const routes = new Map();
  const arms = [...rust.matchAll(/b"(\/ui\/[^"]*)"\s*=>/g)];
  arms.forEach((arm, index) => {
    const end = index + 1 < arms.length ? arms[index + 1].index : rust.length;
    const file = rust.slice(arm.index, end).match(/include_str!\("([^"]+)"\)/);
    if (file) routes.set(arm[1], file[1]);
  });
  return routes;
}

/** Every `./x` a module imports, statically or dynamically. */
function relativeImports(source) {
  return [...source.matchAll(/(?:from|import)\s*\(?\s*['"]\.\/([^'"]+)['"]/g)].map(m => m[1]);
}

/** Routes a served module needs that its own table does not serve. */
function unroutedImports(routes, read) {
  const missing = [];
  for (const [route, file] of routes) {
    if (!file.endsWith('.mjs')) continue;
    const directory = route.slice(0, route.lastIndexOf('/') + 1);
    for (const name of relativeImports(read(file))) {
      const needed = directory + name;
      if (routes.get(needed) !== name) missing.push(`${route} imports ${needed}`);
    }
  }
  return missing;
}

const tables = readdirSync(base)
  .filter(name => name.endsWith('.rs'))
  .map(name => [name, routeTable(readFileSync(new URL(name, base), 'utf8'))])
  .filter(([, routes]) => routes.size > 0);
const read = file => readFileSync(new URL(file, base), 'utf8');

test('every relative import of every served browser module is routed beside it', () => {
  // Thirteen page tables today; a parse that silently found none would pass.
  assert(tables.length >= 13, `parsed ${tables.length} route tables`);
  for (const [name, routes] of tables) {
    assert.deepEqual(unroutedImports(routes, read), [], name);
  }
});

test('a page table missing one shared module is reported (planted negative)', () => {
  const [name, routes] = tables.find(([file]) => file === 'tags.rs');
  assert.equal(routes.get('/ui/tags/pulls-comments.mjs'), 'pulls-comments.mjs', name);
  const planted = new Map(routes);
  planted.delete('/ui/tags/pulls-comments.mjs');
  assert.deepEqual(unroutedImports(planted, read), [
    '/ui/tags/pulls-actions.mjs imports /ui/tags/pulls-comments.mjs',
  ]);
});
