// Compatibility entry point for the offline verifier. The implementation is
// shared with the already-served transfer protocol; neither entry performs I/O.
export { BUNDLE_VERIFY_LIMITS, BundleVerificationError, verifyGitBundleObjects, verifyGitBundle, normalizeBundleExpectation, verifyGitBundleAgainst } from './transfers-protocol.mjs';
