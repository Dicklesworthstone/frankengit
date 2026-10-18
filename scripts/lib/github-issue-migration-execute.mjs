// Compatibility entrypoints: preserve GitHub's original profiles and custody.
import { createIssueMigrationExecutor } from './issue-migration-execute.mjs';
export function createGithubIssueMigrationExecutor(backend) {
  return createIssueMigrationExecutor(backend, 'github');
}

export async function runGithubIssueMigration(raw) {
  const [migration, importer, operator] = await Promise.all([
    import('./github-issue-migration.mjs'), import('./github-issue-import.mjs'), import('./forge-issue-operator.mjs')]);
  return createGithubIssueMigrationExecutor({ connectionOptions: operator.issueConnectionOptions,
    inspect: migration.inspectGithubIssueMigration, runBatch: importer.runGithubIssueImport })(raw);
}
