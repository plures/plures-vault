import {
  defineConstraint,
  defineContract,
  defineModule,
  defineRule,
  fact,
  RuleResult,
} from '@plures/praxis';

// ─── Context ──────────────────────────────────────────────────────────────────

export interface SyncAuthorizationContext {
  /** Public key fingerprint of the remote peer */
  peerFingerprint: string;
  /** Whether the peer's fingerprint is in the local trust list */
  isTrustedPeer: boolean;
  /** Whether the sync payload is encrypted end-to-end */
  isEncrypted: boolean;
  /** Whether the sync payload has a valid HMAC signature */
  hasValidSignature: boolean;
  /** Detected schema version mismatch between local and remote vault */
  hasConflict: boolean;
  /** Strategy chosen to resolve the conflict */
  conflictResolution?: 'local-wins' | 'remote-wins' | 'manual';
}

// ─── Contracts ────────────────────────────────────────────────────────────────

export const peerTrustGateContract = defineContract({
  ruleId: 'sync-authorization.peer-trust-gate',
  behavior: 'Reject sync from peers whose fingerprint is not in the local trust list',
  examples: [
    { given: 'isTrustedPeer is false', when: 'peerTrustGateRule evaluates', then: 'sync.peer-untrusted fact is emitted with the peer fingerprint' },
    { given: 'isTrustedPeer is true', when: 'peerTrustGateRule evaluates', then: 'noop is returned' },
  ],
  invariants: ['A trusted peer never produces a peer-untrusted fact'],
});

export const encryptionRequirementContract = defineContract({
  ruleId: 'sync-authorization.encryption-requirement',
  behavior: 'Reject sync payloads that are not end-to-end encrypted',
  examples: [
    { given: 'isEncrypted is false', when: 'encryptionRequirementRule evaluates', then: 'sync.unencrypted-payload fact is emitted' },
    { given: 'isEncrypted is true', when: 'encryptionRequirementRule evaluates', then: 'noop is returned' },
  ],
  invariants: ['An encrypted payload never produces an unencrypted-payload fact'],
});

export const signatureVerificationContract = defineContract({
  ruleId: 'sync-authorization.signature-verification',
  behavior: 'Reject sync payloads with invalid or missing HMAC signatures',
  examples: [
    { given: 'hasValidSignature is false', when: 'signatureVerificationRule evaluates', then: 'sync.invalid-signature fact is emitted' },
    { given: 'hasValidSignature is true', when: 'signatureVerificationRule evaluates', then: 'noop is returned' },
  ],
  invariants: ['A valid signature never produces an invalid-signature fact'],
});

export const conflictResolutionContract = defineContract({
  ruleId: 'sync-authorization.conflict-resolution',
  behavior: 'Block sync completion when a conflict exists without a chosen resolution strategy',
  examples: [
    { given: 'hasConflict is true and conflictResolution is undefined', when: 'conflictResolutionRule evaluates', then: 'sync.unresolved-conflict fact is emitted' },
    { given: 'hasConflict is true and conflictResolution is "local-wins"', when: 'conflictResolutionRule evaluates', then: 'noop is returned' },
    { given: 'hasConflict is false', when: 'conflictResolutionRule evaluates', then: 'noop is returned' },
  ],
  invariants: ['A resolved or absent conflict never produces an unresolved-conflict fact'],
});

export const encryptionAndSignatureContract = defineContract({
  ruleId: 'sync-authorization.encryption-and-signature-together',
  behavior: 'Require a valid signature whenever a sync payload is encrypted',
  examples: [
    { given: 'isEncrypted is true but hasValidSignature is false', when: 'constraint is checked', then: 'An error string is returned' },
    { given: 'isEncrypted is true and hasValidSignature is true', when: 'constraint is checked', then: 'true is returned' },
    { given: 'isEncrypted is false', when: 'constraint is checked', then: 'true is returned' },
  ],
  invariants: ['An encrypted payload without a valid signature never passes'],
});

export const trustedPeerEncryptionContract = defineContract({
  ruleId: 'sync-authorization.trusted-peer-must-use-encryption',
  behavior: 'Require encryption even for trusted peers',
  examples: [
    { given: 'isTrustedPeer is true and isEncrypted is false', when: 'constraint is checked', then: 'An error string is returned' },
    { given: 'isTrustedPeer is true and isEncrypted is true', when: 'constraint is checked', then: 'true is returned' },
  ],
  invariants: ['A trusted peer with encryption always passes'],
});

// ─── Rules ────────────────────────────────────────────────────────────────────

export const peerTrustGateRule = defineRule<SyncAuthorizationContext>({
  id: 'sync-authorization.peer-trust-gate',
  description: 'Sync is only allowed with trusted peers',
  contract: peerTrustGateContract,
  impl: ({ context }) => {
    if (!context.isTrustedPeer) {
      return RuleResult.emit([
        fact('sync.peer-untrusted', { fingerprint: context.peerFingerprint }),
      ]);
    }
    return RuleResult.noop('Peer is trusted');
  },
});

export const encryptionRequirementRule = defineRule<SyncAuthorizationContext>({
  id: 'sync-authorization.encryption-requirement',
  description: 'All sync payloads must be end-to-end encrypted',
  contract: encryptionRequirementContract,
  impl: ({ context }) => {
    if (!context.isEncrypted) {
      return RuleResult.emit([
        fact('sync.unencrypted-payload', { fingerprint: context.peerFingerprint }),
      ]);
    }
    return RuleResult.noop('Payload is encrypted');
  },
});

export const signatureVerificationRule = defineRule<SyncAuthorizationContext>({
  id: 'sync-authorization.signature-verification',
  description: 'Sync payloads must carry a valid HMAC signature',
  contract: signatureVerificationContract,
  impl: ({ context }) => {
    if (!context.hasValidSignature) {
      return RuleResult.emit([
        fact('sync.invalid-signature', { fingerprint: context.peerFingerprint }),
      ]);
    }
    return RuleResult.noop('Signature is valid');
  },
});

export const conflictResolutionRule = defineRule<SyncAuthorizationContext>({
  id: 'sync-authorization.conflict-resolution',
  description: 'Conflicts must be explicitly resolved before sync completes',
  contract: conflictResolutionContract,
  impl: ({ context }) => {
    if (context.hasConflict && !context.conflictResolution) {
      return RuleResult.emit([
        fact('sync.unresolved-conflict', { fingerprint: context.peerFingerprint }),
      ]);
    }
    return RuleResult.noop('No unresolved conflicts');
  },
});

// ─── Constraints ──────────────────────────────────────────────────────────────

export const encryptionAndSignatureConstraint = defineConstraint<SyncAuthorizationContext>({
  id: 'sync-authorization.encryption-and-signature-together',
  description: 'Encryption and a valid signature must both be present to allow sync',
  contract: encryptionAndSignatureContract,
  impl: ({ context }) => {
    if (context.isEncrypted && !context.hasValidSignature) {
      return 'Payload is encrypted but signature is missing or invalid';
    }
    return true;
  },
});

export const trustedPeerEncryptionConstraint = defineConstraint<SyncAuthorizationContext>({
  id: 'sync-authorization.trusted-peer-must-use-encryption',
  description: 'Even trusted peers must encrypt their sync payloads',
  contract: trustedPeerEncryptionContract,
  impl: ({ context }) => {
    if (context.isTrustedPeer && !context.isEncrypted) {
      return 'Trusted peer attempted to sync without encryption';
    }
    return true;
  },
});

// ─── Module ───────────────────────────────────────────────────────────────────

export const syncAuthorizationModule = defineModule<SyncAuthorizationContext>({
  rules: [
    peerTrustGateRule,
    encryptionRequirementRule,
    signatureVerificationRule,
    conflictResolutionRule,
  ],
  constraints: [encryptionAndSignatureConstraint, trustedPeerEncryptionConstraint],
  meta: { version: '1.0.0', domain: 'sync-authorization' },
});
