import {
  defineConstraint,
  defineContract,
  defineModule,
  defineRule,
  fact,
  RuleResult,
} from '@plures/praxis';

// ─── Context ──────────────────────────────────────────────────────────────────

export interface AccessControlContext {
  /** Whether the vault has been initialized (master password set) */
  isInitialized: boolean;
  /** Whether the vault is currently unlocked */
  isUnlocked: boolean;
  /** Epoch ms of the last successful unlock */
  lastUnlockTime: number;
  /** Session timeout in milliseconds (default 15 min) */
  sessionTimeoutMs: number;
  /** Whether a biometric unlock is available on this device */
  biometricAvailable: boolean;
  /** Whether biometric unlock was attempted and failed */
  biometricFailed: boolean;
  /** Number of consecutive failed master-password attempts */
  failedAttempts: number;
}

// ─── Derived helpers ──────────────────────────────────────────────────────────

function isSessionExpired(ctx: AccessControlContext, now: number = Date.now()): boolean {
  if (!ctx.isUnlocked) return false;
  return now - ctx.lastUnlockTime > ctx.sessionTimeoutMs;
}

// ─── Contracts ────────────────────────────────────────────────────────────────

export const vaultInitializationGateContract = defineContract({
  ruleId: 'access-control.vault-initialization-gate',
  behavior: 'Block vault unlock when vault has not been initialized with a master password',
  examples: [
    { given: 'isInitialized is false', when: 'vault unlock is attempted', then: 'access.vault-not-initialized fact is emitted' },
    { given: 'isInitialized is true', when: 'vault unlock is attempted', then: 'noop is returned' },
  ],
  invariants: ['An initialized vault never produces a vault-not-initialized fact'],
});

export const sessionTimeoutContract = defineContract({
  ruleId: 'access-control.session-timeout',
  behavior: 'Lock the vault when idle time exceeds the configured session timeout',
  examples: [
    { given: 'Vault is unlocked and idle time exceeds sessionTimeoutMs', when: 'sessionTimeoutRule evaluates', then: 'access.session-expired fact is emitted with idle and timeout durations' },
    { given: 'Vault is unlocked and session is within timeout', when: 'sessionTimeoutRule evaluates', then: 'noop is returned' },
    { given: 'Vault is locked', when: 'sessionTimeoutRule evaluates', then: 'noop is returned regardless of lastUnlockTime' },
  ],
  invariants: ['A locked vault never produces a session-expired fact', 'An active session within the timeout window never triggers expiration'],
});

export const biometricFallbackContract = defineContract({
  ruleId: 'access-control.biometric-fallback',
  behavior: 'Require master password entry when biometric authentication is available but fails',
  examples: [
    { given: 'biometricAvailable is true and biometricFailed is true', when: 'biometricFallbackRule evaluates', then: 'access.biometric-failed fact is emitted prompting master password' },
    { given: 'biometricAvailable is false', when: 'biometricFallbackRule evaluates', then: 'noop is returned' },
    { given: 'biometricAvailable is true and biometricFailed is false', when: 'biometricFallbackRule evaluates', then: 'noop is returned' },
  ],
  invariants: ['Successful biometric auth never triggers a fallback fact'],
});

export const bruteForceProtectionContract = defineContract({
  ruleId: 'access-control.brute-force-protection',
  behavior: 'Lock access after 5 or more consecutive failed master-password attempts',
  examples: [
    { given: 'failedAttempts is 5', when: 'bruteForceProtectionRule evaluates', then: 'access.locked-out fact is emitted with attempt count' },
    { given: 'failedAttempts is 4', when: 'bruteForceProtectionRule evaluates', then: 'noop is returned' },
  ],
  invariants: ['Fewer than 5 failed attempts never triggers a lockout'],
});

export const vaultMustBeInitializedContract = defineContract({
  ruleId: 'access-control.must-be-initialized',
  behavior: 'Prevent unlock attempts on an uninitialized vault',
  examples: [
    { given: 'isInitialized is false and failedAttempts > 0', when: 'constraint is checked', then: 'An error string is returned' },
    { given: 'isInitialized is false and failedAttempts is 0', when: 'constraint is checked', then: 'true is returned' },
  ],
  invariants: ['An initialized vault always passes this constraint'],
});

export const sessionActiveContract = defineContract({
  ruleId: 'access-control.session-active',
  behavior: 'Require an active non-expired session for vault operations',
  examples: [
    { given: 'Session has expired (idle > timeout)', when: 'constraint is checked', then: 'An error string is returned' },
    { given: 'Session is within the active timeout window', when: 'constraint is checked', then: 'true is returned' },
  ],
  invariants: ['An active session within the timeout window always passes'],
});

// ─── Rules ────────────────────────────────────────────────────────────────────

export const vaultInitializationGateRule = defineRule<AccessControlContext>({
  id: 'access-control.vault-initialization-gate',
  description: 'Vault must be initialized before it can be unlocked',
  contract: vaultInitializationGateContract,
  impl: ({ context }) => {
    if (!context.isInitialized) {
      return RuleResult.emit([
        fact('access.vault-not-initialized', { message: 'Vault requires initial setup' }),
      ]);
    }
    return RuleResult.noop('Vault is initialized');
  },
});

export const sessionTimeoutRule = defineRule<AccessControlContext>({
  id: 'access-control.session-timeout',
  description: 'Lock the vault when the session idle timeout is exceeded',
  contract: sessionTimeoutContract,
  impl: ({ context }) => {
    const now = Date.now();
    if (isSessionExpired(context, now)) {
      return RuleResult.emit([
        fact('access.session-expired', {
          idleMs: now - context.lastUnlockTime,
          timeoutMs: context.sessionTimeoutMs,
        }),
      ]);
    }
    return RuleResult.noop('Session is still active');
  },
});

export const biometricFallbackRule = defineRule<AccessControlContext>({
  id: 'access-control.biometric-fallback',
  description: 'Fall back to master password after biometric failure',
  contract: biometricFallbackContract,
  impl: ({ context }) => {
    if (context.biometricAvailable && context.biometricFailed) {
      return RuleResult.emit([
        fact('access.biometric-failed', { message: 'Biometric auth failed; require master password' }),
      ]);
    }
    return RuleResult.noop('Biometric auth not needed or succeeded');
  },
});

export const bruteForceProtectionRule = defineRule<AccessControlContext>({
  id: 'access-control.brute-force-protection',
  description: 'Lock access after 5 consecutive failed master-password attempts',
  contract: bruteForceProtectionContract,
  impl: ({ context }) => {
    if (context.failedAttempts >= 5) {
      return RuleResult.emit([
        fact('access.locked-out', { attempts: context.failedAttempts }),
      ]);
    }
    return RuleResult.noop('Attempt count within limit');
  },
});

// ─── Constraints ──────────────────────────────────────────────────────────────

export const vaultMustBeInitializedConstraint = defineConstraint<AccessControlContext>({
  id: 'access-control.must-be-initialized',
  description: 'No unlock attempt is allowed on an uninitialized vault',
  contract: vaultMustBeInitializedContract,
  impl: ({ context }) => {
    if (!context.isInitialized && context.failedAttempts > 0) {
      return 'Cannot attempt unlock on an uninitialized vault';
    }
    return true;
  },
});

export const sessionActiveConstraint = defineConstraint<AccessControlContext>({
  id: 'access-control.session-active',
  description: 'Vault operations require an active (non-expired) session',
  contract: sessionActiveContract,
  impl: ({ context }) => {
    if (isSessionExpired(context)) {
      return 'Session has expired; vault must be re-unlocked';
    }
    return true;
  },
});

// ─── Module ───────────────────────────────────────────────────────────────────

export const accessControlModule = defineModule<AccessControlContext>({
  rules: [
    vaultInitializationGateRule,
    sessionTimeoutRule,
    biometricFallbackRule,
    bruteForceProtectionRule,
  ],
  constraints: [vaultMustBeInitializedConstraint, sessionActiveConstraint],
  meta: { version: '1.0.0', domain: 'access-control' },
});
