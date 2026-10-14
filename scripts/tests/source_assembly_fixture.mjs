// Independent native framing in changeFixture; no assembly implementation here.
import { selectSource } from './source_replay_fixture.mjs';
import { buildSourceChanges, canonical, sha256 } from '../operator/source_changes.mjs';
export async function contribution(fixture, id, paths, changes) {
  const f = selectSource(fixture, paths);
  const draft = await buildSourceChanges(f.bytes, f.expected, changes);
  return { id, packageBytes: f.bytes, expected: f.expected, changes,
    confirmDraftSha256: sha256(canonical(draft.manifest)) };
}
