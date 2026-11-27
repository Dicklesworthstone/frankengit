// Standalone discussions share the shipped native client's durable request
// custody. Their routes, grant, retry schema and key domain remain independent.
import { createMetadataOperator } from './forge-issue-operator.mjs';

const discussion = createMetadataOperator('discussion');
export const discussionOperatorOptions = discussion.options;
export const runDiscussionOperation = discussion.run;
