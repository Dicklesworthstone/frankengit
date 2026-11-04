// Closed native bearer spellings, not authentication or a scope grant.
// Keep SHA-256 digest validators separate: a token is not a digest.
export const MAX_CREDENTIAL_TOKEN_BYTES = 72;
export const isAgentCredentialToken = value => typeof value === 'string' && /^fgagent_[0-9a-f]{64}$/.test(value);
export const isCredentialToken = value => typeof value === 'string'
  && (/^[0-9a-f]{64}$/.test(value) || isAgentCredentialToken(value));
