import { describe, it, expect } from 'vitest';
import {
  createPraxisEngine,
  PraxisRegistry,
  validateContracts,
} from '@plures/praxis';
import {
  passwordPolicyModule,
  minimumLengthRule,
  complexityRule,
  entropyRule,
  breachCheckRule,
  noRepeatingCharsConstraint,
  noCommonPatternsConstraint,
  minimumLengthContract,
  complexityContract,
  entropyContract,
  breachCheckContract,
  noRepeatingCharsContract,
  noCommonPatternsContract,
  calculateEntropy,
  type PasswordPolicyContext,
} from './password-policy.js';

type PasswordPolicyState = Parameters<typeof minimumLengthRule.impl>[0];
type PasswordPolicyConstraintState = Parameters<typeof noRepeatingCharsConstraint.impl>[0];

function makeContext(overrides: Partial<PasswordPolicyContext> = {}): PasswordPolicyContext {
  return {
    password: 'Correct!Horse9Battery',
    entropyBits: calculateEntropy('Correct!Horse9Battery'),
    isBreached: false,
    ...overrides,
  };
}

function makeState(ctx: PasswordPolicyContext): PasswordPolicyState {
  return { context: ctx, facts: [], meta: {} };
}

function makeConstraintState(ctx: PasswordPolicyContext): PasswordPolicyConstraintState {
  return { context: ctx, facts: [], meta: {} };
}

describe('password-policy module', () => {
  it('registers all rules and constraints', () => {
    const registry = new PraxisRegistry<PasswordPolicyContext>();
    registry.registerModule(passwordPolicyModule);
    expect(registry.getRuleIds()).toContain(minimumLengthRule.id);
    expect(registry.getRuleIds()).toContain(complexityRule.id);
    expect(registry.getRuleIds()).toContain(entropyRule.id);
    expect(registry.getRuleIds()).toContain(breachCheckRule.id);
    expect(registry.getConstraintIds()).toContain(noRepeatingCharsConstraint.id);
    expect(registry.getConstraintIds()).toContain(noCommonPatternsConstraint.id);
  });

  it('engine produces password.too-short fact for a short password', () => {
    const ctx = makeContext({ password: 'Short1!', entropyBits: 20 });
    const registry = new PraxisRegistry<PasswordPolicyContext>();
    registry.registerModule(passwordPolicyModule);
    const engine = createPraxisEngine({ initialContext: ctx, registry });
    engine.step([]);
    const facts = engine.state.facts;
    expect(facts.some((f) => f.tag === 'password.too-short')).toBe(true);
  });
});

describe('calculateEntropy', () => {
  it('returns 0 for empty string', () => {
    expect(calculateEntropy('')).toBe(0);
  });

  it('increases with password length', () => {
    expect(calculateEntropy('aaaa')).toBeLessThan(calculateEntropy('aaaaaaaa'));
  });

  it('increases with character space', () => {
    const lower = calculateEntropy('abcdefgh');
    const mixed = calculateEntropy('Abcdefg1');
    expect(mixed).toBeGreaterThan(lower);
  });
});

describe('minimumLengthRule', () => {
  it('emits password.too-short for short passwords', () => {
    const ctx = makeContext({ password: 'Short1!' });
    const result = minimumLengthRule.impl(makeState(ctx), []);
    expect(result.kind).toBe('emit');
    expect(result.facts[0].tag).toBe('password.too-short');
  });

  it('returns noop for passwords meeting minimum length', () => {
    const ctx = makeContext({ password: 'LongEnough1!abc' });
    const result = minimumLengthRule.impl(makeState(ctx), []);
    expect(result.kind).toBe('noop');
  });
});

describe('complexityRule', () => {
  it('emits password.complexity-failed when missing uppercase', () => {
    const ctx = makeContext({ password: 'nouppercase1!' });
    const result = complexityRule.impl(makeState(ctx), []);
    expect(result.kind).toBe('emit');
    expect(result.facts[0].tag).toBe('password.complexity-failed');
    expect((result.facts[0].payload as { missing: string[] }).missing).toContain('uppercase');
  });

  it('emits password.complexity-failed when missing symbol', () => {
    const ctx = makeContext({ password: 'NoSymbol1234' });
    const result = complexityRule.impl(makeState(ctx), []);
    expect(result.kind).toBe('emit');
    expect((result.facts[0].payload as { missing: string[] }).missing).toContain('symbol');
  });

  it('returns noop for fully complex passwords', () => {
    const ctx = makeContext({ password: 'Correct!Horse9Battery' });
    const result = complexityRule.impl(makeState(ctx), []);
    expect(result.kind).toBe('noop');
  });
});

describe('entropyRule', () => {
  it('emits password.low-entropy when below 50 bits', () => {
    const ctx = makeContext({ password: 'abc', entropyBits: 14 });
    const result = entropyRule.impl(makeState(ctx), []);
    expect(result.kind).toBe('emit');
    expect(result.facts[0].tag).toBe('password.low-entropy');
  });

  it('returns noop when entropy is sufficient', () => {
    const ctx = makeContext({ entropyBits: 80 });
    const result = entropyRule.impl(makeState(ctx), []);
    expect(result.kind).toBe('noop');
  });
});

describe('breachCheckRule', () => {
  it('emits password.breached when isBreached is true', () => {
    const ctx = makeContext({ isBreached: true });
    const result = breachCheckRule.impl(makeState(ctx), []);
    expect(result.kind).toBe('emit');
    expect(result.facts[0].tag).toBe('password.breached');
  });

  it('returns noop when password is clean', () => {
    const ctx = makeContext({ isBreached: false });
    const result = breachCheckRule.impl(makeState(ctx), []);
    expect(result.kind).toBe('noop');
  });
});

describe('noRepeatingCharsConstraint', () => {
  it('rejects passwords with 4+ repeating chars', () => {
    const ctx = makeContext({ password: 'aaaa1234!Aa' });
    const result = noRepeatingCharsConstraint.impl(makeConstraintState(ctx));
    expect(typeof result).toBe('string');
  });

  it('allows passwords with at most 3 repeating chars', () => {
    const ctx = makeContext({ password: 'aaa1234!Aa' });
    const result = noRepeatingCharsConstraint.impl(makeConstraintState(ctx));
    expect(result).toBe(true);
  });
});

describe('noCommonPatternsConstraint', () => {
  it('rejects passwords containing "password"', () => {
    const ctx = makeContext({ password: 'myPassword1!' });
    const result = noCommonPatternsConstraint.impl(makeConstraintState(ctx));
    expect(typeof result).toBe('string');
  });

  it('rejects passwords containing "qwerty"', () => {
    const ctx = makeContext({ password: 'Qwerty123!' });
    const result = noCommonPatternsConstraint.impl(makeConstraintState(ctx));
    expect(typeof result).toBe('string');
  });

  it('allows a strong unique password', () => {
    const ctx = makeContext({ password: 'Correct!Horse9Battery' });
    const result = noCommonPatternsConstraint.impl(makeConstraintState(ctx));
    expect(result).toBe(true);
  });
});

describe('password-policy contracts', () => {
  it('all rules and constraints have contracts with no gaps', () => {
    const registry = new PraxisRegistry<PasswordPolicyContext>();
    registry.registerModule(passwordPolicyModule);
    const report = validateContracts(registry);
    expect(report.missing).toHaveLength(0);
    expect(report.incomplete).toHaveLength(0);
    expect(report.complete.length).toBe(6);
  });

  it('contracts have matching ruleIds', () => {
    expect(minimumLengthContract.ruleId).toBe(minimumLengthRule.id);
    expect(complexityContract.ruleId).toBe(complexityRule.id);
    expect(entropyContract.ruleId).toBe(entropyRule.id);
    expect(breachCheckContract.ruleId).toBe(breachCheckRule.id);
    expect(noRepeatingCharsContract.ruleId).toBe(noRepeatingCharsConstraint.id);
    expect(noCommonPatternsContract.ruleId).toBe(noCommonPatternsConstraint.id);
  });
});
