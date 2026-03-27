import {
  defineConstraint,
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

// ─── Rules ────────────────────────────────────────────────────────────────────

export const peerTrustGateRule = defineRule<SyncAuthorizationContext>({
  id: 'sync-authorization.peer-trust-gate',
  description: 'Sync is only allowed with trusted peers',
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
