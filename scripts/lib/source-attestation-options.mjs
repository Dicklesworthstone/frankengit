// One opt-in CLI group shared by offline verification and recovery. A partial
// group is an error, never a request to silently downgrade to unsigned mode.
import { attestationPolicy, SourceAttestationError } from './source-attestation.mjs';
const FLAGS = ['--attestation', '--trust-key', '--repository', '--minimum-sequence'];
export const ATTESTATION_HELP = `  --attestation PATH        Require the detached source-backup DSSE approval
  --trust-key PATH          Separately trusted Ed25519 public-key PEM
  --repository OWNER/REPO   Expected signed repository identity
  --minimum-sequence N     External positive u64 backup-sequence floor
`;
const fail = code => { throw new SourceAttestationError(code); };
export class SourceAttestationOptions {
  #values = new Map();
  // Called only where the owning parser expects an option, not at another
  // option's value or after --. Return the consumed value's index if handled.
  take(args, index) {
    const flag = args[index];
    if (!FLAGS.includes(flag)) return index;
    if (this.#values.has(flag)) fail('duplicate_attestation_option');
    const value = args[index + 1];
    if (typeof value !== 'string' || !value || value.length > 4096 || value.startsWith('--') ||
        value.includes('\0') || /[\uD800-\uDFFF]/u.test(value)) fail('invalid_attestation_option_value');
    this.#values.set(flag, value); return index + 1;
  }
  finish() {
    if (!this.#values.size) return null;
    if (this.#values.size !== FLAGS.length) fail('complete_attestation_options_required');
    return Object.freeze({ envelope: this.#values.get('--attestation'), key: this.#values.get('--trust-key'),
      policy: Object.freeze(attestationPolicy({ repository: this.#values.get('--repository'), minimum_sequence: this.#values.get('--minimum-sequence') })) });
  }
}
