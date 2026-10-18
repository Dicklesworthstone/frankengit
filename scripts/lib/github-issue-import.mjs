// FG-049's original capture and custody formats, over the shared native sender.
import { createIssueImportEngine } from './issue-import-engine.mjs';
import { parseCapture, issueImportSteps, CAPTURE_LIMIT } from './github-issue-source.mjs';

const engine = createIssueImportEngine({ kind: 'github', parseCapture, issueImportSteps, CAPTURE_LIMIT });
export const prepareGithubIssueImport = engine.prepare;
export const inspectPreparedGithubIssueImport = engine.inspect;
export const runGithubIssueImport = engine.run;
