import { describe, it, expect } from 'vitest';
import { PraxisRegistry } from '@plures/praxis';
import {
  accessControlModule,
  vaultInitializationGateRule,
  sessionTimeoutRule,
  biometricFallbackRule,
  bruteForceProtectionRule,
  vaultMustBeInitializedConstraint,
  sessionActiveConstraint,
  type AccessControlContext,
} from './access-control.js';

const SESSION_15_MIN = 15 * 60 * 1000;

type AccessControlPraxisState = Parameters<typeof vaultInitializationGateRule.impl>[0];
type AccessControlConstraintState = Parameters<typeof vaultMustBeInitializedConstraint.impl>[0];

function makeContext(overrides: Partial<AccessControlContext> = {}): AccessControlContext {
  return {
    isInitialized: true,
    isUnlocked: true,
    lastUnlockTime: Date.now(),
    sessionTimeoutMs: SESSION_15_MIN,
    biometricAvailable: false,
    biometricFailed: false,
    failedAttempts: 0,
    ...overrides,
  };
}

function makeState(ctx: AccessControlContext): AccessControlPraxisState {
  return { context: ctx, facts: [], meta: {} };
}

function makeConstraintState(ctx: AccessControlContext): AccessControlConstraintState {
  return { context: ctx, facts: [], meta: {} };
}

describe('access-control module', () => {
  it('registers all rules and constraints', () => {
    const registry = new PraxisRegistry<AccessControlContext>();
    registry.registerModule(accessControlModule);
    expect(registry.getRuleIds()).toContain(vaultInitializationGateRule.id);
    expect(registry.getRuleIds()).toContain(sessionTimeoutRule.id);
    expect(registry.getRuleIds()).toContain(biometricFallbackRule.id);
    expect(registry.getRuleIds()).toContain(bruteForceProtectionRule.id);
    expect(registry.getConstraintIds()).toContain(vaultMustBeInitializedConstraint.id);
    expect(registry.getConstraintIds()).toContain(sessionActiveConstraint.id);
  });
});

describe('vaultInitializationGateRule', () => {
  it('emits access.vault-not-initialized when vault is not initialized', () => {
    const ctx = makeContext({ isInitialized: false });
    const result = vaultInitializationGateRule.impl(makeState(ctx), []);
    expect(result.kind).toBe('emit');
    expect(result.facts[0].tag).toBe('access.vault-not-initialized');
  });

  it('returns noop when vault is initialized', () => {
    const ctx = makeContext({ isInitialized: true });
    const result = vaultInitializationGateRule.impl(makeState(ctx), []);
    expect(result.kind).toBe('noop');
  });
});

describe('sessionTimeoutRule', () => {
  it('emits access.session-expired when session has timed out', () => {
    const expiredTime = Date.now() - SESSION_15_MIN - 1000;
    const ctx = makeContext({ lastUnlockTime: expiredTime });
    const result = sessionTimeoutRule.impl(makeState(ctx), []);
    expect(result.kind).toBe('emit');
    expect(result.facts[0].tag).toBe('access.session-expired');
  });

  it('returns noop when session is still active', () => {
    const ctx = makeContext({ lastUnlockTime: Date.now() });
    const result = sessionTimeoutRule.impl(makeState(ctx), []);
    expect(result.kind).toBe('noop');
  });

  it('returns noop when vault is locked (no active session to expire)', () => {
    const expiredTime = Date.now() - SESSION_15_MIN - 1000;
    const ctx = makeContext({ isUnlocked: false, lastUnlockTime: expiredTime });
    const result = sessionTimeoutRule.impl(makeState(ctx), []);
    expect(result.kind).toBe('noop');
  });
});

describe('biometricFallbackRule', () => {
  it('emits access.biometric-failed when biometric is available and failed', () => {
    const ctx = makeContext({ biometricAvailable: true, biometricFailed: true });
    const result = biometricFallbackRule.impl(makeState(ctx), []);
    expect(result.kind).toBe('emit');
    expect(result.facts[0].tag).toBe('access.biometric-failed');
  });

  it('returns noop when biometric is not available', () => {
    const ctx = makeContext({ biometricAvailable: false, biometricFailed: true });
    const result = biometricFallbackRule.impl(makeState(ctx), []);
    expect(result.kind).toBe('noop');
  });

  it('returns noop when biometric succeeded', () => {
    const ctx = makeContext({ biometricAvailable: true, biometricFailed: false });
    const result = biometricFallbackRule.impl(makeState(ctx), []);
    expect(result.kind).toBe('noop');
  });
});

describe('bruteForceProtectionRule', () => {
  it('emits access.locked-out after 5 failed attempts', () => {
    const ctx = makeContext({ failedAttempts: 5 });
    const result = bruteForceProtectionRule.impl(makeState(ctx), []);
    expect(result.kind).toBe('emit');
    expect(result.facts[0].tag).toBe('access.locked-out');
    expect((result.facts[0].payload as { attempts: number }).attempts).toBe(5);
  });

  it('emits access.locked-out for more than 5 attempts', () => {
    const ctx = makeContext({ failedAttempts: 10 });
    const result = bruteForceProtectionRule.impl(makeState(ctx), []);
    expect(result.kind).toBe('emit');
  });

  it('returns noop for fewer than 5 failed attempts', () => {
    const ctx = makeContext({ failedAttempts: 4 });
    const result = bruteForceProtectionRule.impl(makeState(ctx), []);
    expect(result.kind).toBe('noop');
  });
});

describe('vaultMustBeInitializedConstraint', () => {
  it('rejects unlock attempts on uninitialized vault', () => {
    const ctx = makeContext({ isInitialized: false, failedAttempts: 1 });
    const result = vaultMustBeInitializedConstraint.impl(makeConstraintState(ctx));
    expect(typeof result).toBe('string');
  });

  it('allows uninitialized vault when no attempts have been made', () => {
    const ctx = makeContext({ isInitialized: false, failedAttempts: 0 });
    const result = vaultMustBeInitializedConstraint.impl(makeConstraintState(ctx));
    expect(result).toBe(true);
  });
});

describe('sessionActiveConstraint', () => {
  it('rejects expired session', () => {
    const expiredTime = Date.now() - SESSION_15_MIN - 1000;
    const ctx = makeContext({ lastUnlockTime: expiredTime });
    const result = sessionActiveConstraint.impl(makeConstraintState(ctx));
    expect(typeof result).toBe('string');
  });

  it('allows active session', () => {
    const ctx = makeContext({ lastUnlockTime: Date.now() });
    const result = sessionActiveConstraint.impl(makeConstraintState(ctx));
    expect(result).toBe(true);
  });
});
