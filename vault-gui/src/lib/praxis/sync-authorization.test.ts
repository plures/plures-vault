import { describe, it, expect } from 'vitest';
import { PraxisRegistry, validateContracts } from '@plures/praxis';
import {
  syncAuthorizationModule,
  peerTrustGateRule,
  encryptionRequirementRule,
  signatureVerificationRule,
  conflictResolutionRule,
  encryptionAndSignatureConstraint,
  trustedPeerEncryptionConstraint,
  peerTrustGateContract,
  encryptionRequirementContract,
  signatureVerificationContract,
  conflictResolutionContract,
  encryptionAndSignatureContract,
  trustedPeerEncryptionContract,
  type SyncAuthorizationContext,
} from './sync-authorization.js';

type SyncAuthorizationState = {
  context: SyncAuthorizationContext;
  facts: unknown[];
  meta: Record<string, unknown>;
};

function makeContext(overrides: Partial<SyncAuthorizationContext> = {}): SyncAuthorizationContext {
  return {
    peerFingerprint: 'abc123',
    isTrustedPeer: true,
    isEncrypted: true,
    hasValidSignature: true,
    hasConflict: false,
    conflictResolution: undefined,
    ...overrides,
  };
}

function makeState(ctx: SyncAuthorizationContext): SyncAuthorizationState {
  return { context: ctx, facts: [], meta: {} };
}

describe('sync-authorization module', () => {
  it('registers all rules and constraints', () => {
    const registry = new PraxisRegistry<SyncAuthorizationContext>();
    registry.registerModule(syncAuthorizationModule);
    expect(registry.getRuleIds()).toContain(peerTrustGateRule.id);
    expect(registry.getRuleIds()).toContain(encryptionRequirementRule.id);
    expect(registry.getRuleIds()).toContain(signatureVerificationRule.id);
    expect(registry.getRuleIds()).toContain(conflictResolutionRule.id);
    expect(registry.getConstraintIds()).toContain(encryptionAndSignatureConstraint.id);
    expect(registry.getConstraintIds()).toContain(trustedPeerEncryptionConstraint.id);
  });
});

describe('peerTrustGateRule', () => {
  it('emits sync.peer-untrusted for untrusted peers', () => {
    const ctx = makeContext({ isTrustedPeer: false });
    const result = peerTrustGateRule.impl(makeState(ctx), []);
    expect(result.kind).toBe('emit');
    expect(result.facts[0].tag).toBe('sync.peer-untrusted');
    expect((result.facts[0].payload as { fingerprint: string }).fingerprint).toBe('abc123');
  });

  it('returns noop for trusted peers', () => {
    const ctx = makeContext({ isTrustedPeer: true });
    const result = peerTrustGateRule.impl(makeState(ctx), []);
    expect(result.kind).toBe('noop');
  });
});

describe('encryptionRequirementRule', () => {
  it('emits sync.unencrypted-payload when not encrypted', () => {
    const ctx = makeContext({ isEncrypted: false });
    const result = encryptionRequirementRule.impl(makeState(ctx), []);
    expect(result.kind).toBe('emit');
    expect(result.facts[0].tag).toBe('sync.unencrypted-payload');
  });

  it('returns noop when encrypted', () => {
    const ctx = makeContext({ isEncrypted: true });
    const result = encryptionRequirementRule.impl(makeState(ctx), []);
    expect(result.kind).toBe('noop');
  });
});

describe('signatureVerificationRule', () => {
  it('emits sync.invalid-signature when signature is invalid', () => {
    const ctx = makeContext({ hasValidSignature: false });
    const result = signatureVerificationRule.impl(makeState(ctx), []);
    expect(result.kind).toBe('emit');
    expect(result.facts[0].tag).toBe('sync.invalid-signature');
  });

  it('returns noop when signature is valid', () => {
    const ctx = makeContext({ hasValidSignature: true });
    const result = signatureVerificationRule.impl(makeState(ctx), []);
    expect(result.kind).toBe('noop');
  });
});

describe('conflictResolutionRule', () => {
  it('emits sync.unresolved-conflict when conflict has no resolution', () => {
    const ctx = makeContext({ hasConflict: true, conflictResolution: undefined });
    const result = conflictResolutionRule.impl(makeState(ctx), []);
    expect(result.kind).toBe('emit');
    expect(result.facts[0].tag).toBe('sync.unresolved-conflict');
  });

  it('returns noop when conflict is resolved', () => {
    const ctx = makeContext({ hasConflict: true, conflictResolution: 'local-wins' });
    const result = conflictResolutionRule.impl(makeState(ctx), []);
    expect(result.kind).toBe('noop');
  });

  it('returns noop when there is no conflict', () => {
    const ctx = makeContext({ hasConflict: false });
    const result = conflictResolutionRule.impl(makeState(ctx), []);
    expect(result.kind).toBe('noop');
  });
});

describe('encryptionAndSignatureConstraint', () => {
  it('rejects encrypted payload with missing signature', () => {
    const ctx = makeContext({ isEncrypted: true, hasValidSignature: false });
    const result = encryptionAndSignatureConstraint.impl(makeState(ctx));
    expect(typeof result).toBe('string');
  });

  it('allows encrypted payload with valid signature', () => {
    const ctx = makeContext({ isEncrypted: true, hasValidSignature: true });
    const result = encryptionAndSignatureConstraint.impl(makeState(ctx));
    expect(result).toBe(true);
  });
});

describe('trustedPeerEncryptionConstraint', () => {
  it('rejects trusted peer without encryption', () => {
    const ctx = makeContext({ isTrustedPeer: true, isEncrypted: false });
    const result = trustedPeerEncryptionConstraint.impl(makeState(ctx));
    expect(typeof result).toBe('string');
  });

  it('allows trusted peer with encryption', () => {
    const ctx = makeContext({ isTrustedPeer: true, isEncrypted: true });
    const result = trustedPeerEncryptionConstraint.impl(makeState(ctx));
    expect(result).toBe(true);
  });
});

describe('sync-authorization contracts', () => {
  it('all rules and constraints have contracts with no gaps', () => {
    const registry = new PraxisRegistry<SyncAuthorizationContext>();
    registry.registerModule(syncAuthorizationModule);
    const report = validateContracts(registry);
    expect(report.missing).toHaveLength(0);
    expect(report.incomplete).toHaveLength(0);
    expect(report.complete.length).toBe(6);
  });

  it('contracts have matching ruleIds', () => {
    expect(peerTrustGateContract.ruleId).toBe(peerTrustGateRule.id);
    expect(encryptionRequirementContract.ruleId).toBe(encryptionRequirementRule.id);
    expect(signatureVerificationContract.ruleId).toBe(signatureVerificationRule.id);
    expect(conflictResolutionContract.ruleId).toBe(conflictResolutionRule.id);
    expect(encryptionAndSignatureContract.ruleId).toBe(encryptionAndSignatureConstraint.id);
    expect(trustedPeerEncryptionContract.ruleId).toBe(trustedPeerEncryptionConstraint.id);
  });
});
