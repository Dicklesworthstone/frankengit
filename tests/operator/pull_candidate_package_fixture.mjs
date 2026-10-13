// Retained native-schema observations backed by the existing Git bundle oracle.
import { gitFixture, reports, SCOPE, META, HEAD, SOURCE_HEAD } from './pull_candidate_fixture.mjs';

export async function localCapture(algorithm = 'sha1', method = 'merge-commit', state = 'clean') {
  const f = await gitFixture(algorithm, method), r = reports(f, state);
  return { capture: { schema: 'frankengit-pull-candidate-capture-v1',
    request: { endpoint: 'https://forge.invalid/repo.git', scope: { ...SCOPE, object_format: algorithm }, number: '7', metadata: { ...META }, method, expected_head: null },
    pull: r.pull, review_pages: [{ type: 'review_page', schema_version: 1, ...SCOPE, object_format: algorithm,
      source_head: SOURCE_HEAD, snapshot_token: HEAD, number: 7, found: true, pull_request_version: 9, policy_epoch: 3,
      after: null, limit: 50, next_after: null, merge_authorized: false, reviews: r.reviews }],
    preparation_status: state === 'conflicted' ? 409 : 200, preparation: r.preparation, inspection: state === 'clean' ? r.inspection : null },
    bundle: state === 'clean' ? f.bundle : null };
}
