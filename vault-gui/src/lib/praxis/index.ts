import { createPraxisEngine, PraxisRegistry } from '@plures/praxis';
import { passwordPolicyModule, type PasswordPolicyContext } from './password-policy.js';
import { syncAuthorizationModule, type SyncAuthorizationContext } from './sync-authorization.js';
import { accessControlModule, type AccessControlContext } from './access-control.js';

export type { PasswordPolicyContext } from './password-policy.js';
export type { SyncAuthorizationContext } from './sync-authorization.js';
export type { AccessControlContext } from './access-control.js';

export {
  passwordPolicyModule,
  minimumLengthRule,
  complexityRule,
  entropyRule,
  breachCheckRule,
  noRepeatingCharsConstraint,
  noCommonPatternsConstraint,
  calculateEntropy,
} from './password-policy.js';

export {
  syncAuthorizationModule,
  peerTrustGateRule,
  encryptionRequirementRule,
  signatureVerificationRule,
  conflictResolutionRule,
  encryptionAndSignatureConstraint,
  trustedPeerEncryptionConstraint,
} from './sync-authorization.js';

export {
  accessControlModule,
  vaultInitializationGateRule,
  sessionTimeoutRule,
  biometricFallbackRule,
  bruteForceProtectionRule,
  vaultMustBeInitializedConstraint,
  sessionActiveConstraint,
} from './access-control.js';

export {
  passwordPolicyExpectations,
  syncAuthorizationExpectations,
  accessControlExpectations,
} from './expectations.js';

// ─── Password-policy engine ───────────────────────────────────────────────────

export function createPasswordPolicyEngine(initialContext: PasswordPolicyContext) {
  const registry = new PraxisRegistry<PasswordPolicyContext>();
  registry.registerModule(passwordPolicyModule);
  return createPraxisEngine({ initialContext, registry });
}

// ─── Sync-authorization engine ────────────────────────────────────────────────

export function createSyncAuthorizationEngine(initialContext: SyncAuthorizationContext) {
  const registry = new PraxisRegistry<SyncAuthorizationContext>();
  registry.registerModule(syncAuthorizationModule);
  return createPraxisEngine({ initialContext, registry });
}

// ─── Access-control engine ────────────────────────────────────────────────────

export function createAccessControlEngine(initialContext: AccessControlContext) {
  const registry = new PraxisRegistry<AccessControlContext>();
  registry.registerModule(accessControlModule);
  return createPraxisEngine({ initialContext, registry });
}
