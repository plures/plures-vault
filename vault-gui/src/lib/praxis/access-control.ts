import {
  defineConstraint,
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

// ─── Rules ────────────────────────────────────────────────────────────────────

export const vaultInitializationGateRule = defineRule<AccessControlContext>({
  id: 'access-control.vault-initialization-gate',
  description: 'Vault must be initialized before it can be unlocked',
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
