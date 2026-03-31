import {
  defineConstraint,
  defineModule,
  defineRule,
  fact,
  RuleResult,
} from '@plures/praxis';

// ─── Context ──────────────────────────────────────────────────────────────────

export interface PasswordPolicyContext {
  password: string;
  /** Entropy bits derived from password character space × length */
  entropyBits: number;
  /** Whether the password was found in a breach database (HIBP-style) */
  isBreached: boolean;
}

// ─── Rules ────────────────────────────────────────────────────────────────────

export const minimumLengthRule = defineRule<PasswordPolicyContext>({
  id: 'password-policy.minimum-length',
  description: 'Password must be at least 12 characters long',
  impl: ({ context }) => {
    if (context.password.length < 12) {
      return RuleResult.emit([
        fact('password.too-short', { length: context.password.length, required: 12 }),
      ]);
    }
    return RuleResult.noop('Password meets minimum length');
  },
});

export const complexityRule = defineRule<PasswordPolicyContext>({
  id: 'password-policy.complexity',
  description: 'Password must contain uppercase, lowercase, digit, and symbol',
  impl: ({ context }) => {
    const { password } = context;
    const missing: string[] = [];

    if (!/[A-Z]/.test(password)) missing.push('uppercase');
    if (!/[a-z]/.test(password)) missing.push('lowercase');
    if (!/[0-9]/.test(password)) missing.push('digit');
    if (!/[^A-Za-z0-9]/.test(password)) missing.push('symbol');

    if (missing.length > 0) {
      return RuleResult.emit([
        fact('password.complexity-failed', { missing }),
      ]);
    }
    return RuleResult.noop('Password meets complexity requirements');
  },
});

export const entropyRule = defineRule<PasswordPolicyContext>({
  id: 'password-policy.entropy',
  description: 'Password must have at least 50 bits of entropy',
  impl: ({ context }) => {
    if (context.entropyBits < 50) {
      return RuleResult.emit([
        fact('password.low-entropy', { bits: context.entropyBits, required: 50 }),
      ]);
    }
    return RuleResult.noop('Password entropy is sufficient');
  },
});

export const breachCheckRule = defineRule<PasswordPolicyContext>({
  id: 'password-policy.breach-check',
  description: 'Password must not appear in known breach databases',
  impl: ({ context }) => {
    if (context.isBreached) {
      return RuleResult.emit([
        fact('password.breached', { message: 'Password found in breach database' }),
      ]);
    }
    return RuleResult.noop('Password not found in breach databases');
  },
});

// ─── Constraints ──────────────────────────────────────────────────────────────

export const noRepeatingCharsConstraint = defineConstraint<PasswordPolicyContext>({
  id: 'password-policy.no-repeating-chars',
  description: 'Password must not contain 4 or more consecutive identical characters',
  impl: ({ context }) => {
    if (/(.)\1{3,}/.test(context.password)) {
      return 'Password contains 4+ consecutive identical characters';
    }
    return true;
  },
});

const COMMON_PATTERNS = ['password', 'qwerty', '123456', 'letmein', 'admin', 'welcome'];

export const noCommonPatternsConstraint = defineConstraint<PasswordPolicyContext>({
  id: 'password-policy.no-common-patterns',
  description: 'Password must not be a common keyboard pattern or dictionary word',
  impl: ({ context }) => {
    const lower = context.password.toLowerCase();
    if (COMMON_PATTERNS.some((p) => lower.includes(p))) {
      return 'Password contains a common pattern or dictionary word';
    }
    return true;
  },
});

// ─── Module ───────────────────────────────────────────────────────────────────

export const passwordPolicyModule = defineModule<PasswordPolicyContext>({
  rules: [minimumLengthRule, complexityRule, entropyRule, breachCheckRule],
  constraints: [noRepeatingCharsConstraint, noCommonPatternsConstraint],
  meta: { version: '1.0.0', domain: 'password-policy' },
});

// ─── Entropy helper ───────────────────────────────────────────────────────────

/**
 * Calculate entropy bits for a password based on character space size.
 * This is a local utility — no external API calls required.
 */
export function calculateEntropy(password: string): number {
  let charSpace = 0;
  if (/[a-z]/.test(password)) charSpace += 26;
  if (/[A-Z]/.test(password)) charSpace += 26;
  if (/[0-9]/.test(password)) charSpace += 10;
  if (/[^A-Za-z0-9]/.test(password)) charSpace += 32;
  if (charSpace === 0) return 0;
  return Math.log2(charSpace) * password.length;
}
