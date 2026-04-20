import {
  defineConstraint,
  defineContract,
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

// ─── Contracts ────────────────────────────────────────────────────────────────

export const minimumLengthContract = defineContract({
  ruleId: 'password-policy.minimum-length',
  behavior: 'Reject passwords shorter than 12 characters and emit a password.too-short fact',
  examples: [
    { given: 'A 7-character password "Short1!"', when: 'minimumLengthRule evaluates', then: 'password.too-short fact is emitted with length 7 and required 12' },
    { given: 'A 15-character password "LongEnough1!abc"', when: 'minimumLengthRule evaluates', then: 'noop is returned' },
  ],
  invariants: ['Passwords of 12 or more characters never produce a password.too-short fact'],
});

export const complexityContract = defineContract({
  ruleId: 'password-policy.complexity',
  behavior: 'Require at least one uppercase, lowercase, digit, and symbol character',
  examples: [
    { given: 'A password missing uppercase "nouppercase1!"', when: 'complexityRule evaluates', then: 'password.complexity-failed fact lists "uppercase" as missing' },
    { given: 'A fully complex password "Correct!Horse9Battery"', when: 'complexityRule evaluates', then: 'noop is returned' },
  ],
  invariants: ['A password with all four character classes never produces a complexity failure'],
});

export const entropyContract = defineContract({
  ruleId: 'password-policy.entropy',
  behavior: 'Reject passwords with fewer than 50 bits of entropy',
  examples: [
    { given: 'A password with 14 bits of entropy', when: 'entropyRule evaluates', then: 'password.low-entropy fact is emitted with bits 14 and required 50' },
    { given: 'A password with 80 bits of entropy', when: 'entropyRule evaluates', then: 'noop is returned' },
  ],
  invariants: ['Passwords with 50 or more entropy bits never produce a low-entropy fact'],
});

export const breachCheckContract = defineContract({
  ruleId: 'password-policy.breach-check',
  behavior: 'Reject passwords found in known breach databases',
  examples: [
    { given: 'isBreached is true', when: 'breachCheckRule evaluates', then: 'password.breached fact is emitted' },
    { given: 'isBreached is false', when: 'breachCheckRule evaluates', then: 'noop is returned' },
  ],
  invariants: ['A non-breached password never produces a password.breached fact'],
});

export const noRepeatingCharsContract = defineContract({
  ruleId: 'password-policy.no-repeating-chars',
  behavior: 'Reject passwords containing 4 or more consecutive identical characters',
  examples: [
    { given: 'A password "aaaa1234!Aa" with 4 consecutive "a"s', when: 'constraint is checked', then: 'An error string is returned' },
    { given: 'A password "aaa1234!Aa" with at most 3 consecutive "a"s', when: 'constraint is checked', then: 'true is returned' },
  ],
  invariants: ['Passwords with fewer than 4 consecutive identical characters always pass'],
});

export const noCommonPatternsContract = defineContract({
  ruleId: 'password-policy.no-common-patterns',
  behavior: 'Reject passwords containing common dictionary words or keyboard patterns',
  examples: [
    { given: 'A password containing "password"', when: 'constraint is checked', then: 'An error string is returned' },
    { given: 'A unique password "Correct!Horse9Battery"', when: 'constraint is checked', then: 'true is returned' },
  ],
  invariants: ['Passwords not containing any common pattern always pass'],
});

// ─── Rules ────────────────────────────────────────────────────────────────────

export const minimumLengthRule = defineRule<PasswordPolicyContext>({
  id: 'password-policy.minimum-length',
  description: 'Password must be at least 12 characters long',
  contract: minimumLengthContract,
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
  contract: complexityContract,
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
  contract: entropyContract,
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
  contract: breachCheckContract,
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
  contract: noRepeatingCharsContract,
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
  contract: noCommonPatternsContract,
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
