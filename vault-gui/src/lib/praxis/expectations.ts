import { ExpectationSet, expectBehavior } from '@plures/praxis';

// ─── password-policy expectations ────────────────────────────────────────────

export const passwordPolicyExpectations = new ExpectationSet({
  name: 'password-policy',
  description: 'Behavioral expectations for the password-policy PraxisModule',
});

passwordPolicyExpectations
  .add(
    expectBehavior('password.too-short')
      .onlyWhen('password length is less than 12 characters')
      .never('when password is 12 or more characters long')
      .always('includes the actual length and the minimum required length'),
  )
  .add(
    expectBehavior('password.complexity-failed')
      .onlyWhen('password is missing at least one required character class')
      .never('when password contains uppercase, lowercase, digit, and symbol')
      .always('lists which character classes are missing'),
  )
  .add(
    expectBehavior('password.low-entropy')
      .onlyWhen('calculated entropy is below 50 bits')
      .never('when password has 50 or more bits of entropy')
      .always('includes the actual entropy bits and the required minimum'),
  )
  .add(
    expectBehavior('password.breached')
      .onlyWhen('the password appears in a known breach database')
      .never('when isBreached is false')
      .always('emits a human-readable breach warning message'),
  );

// ─── sync-authorization expectations ─────────────────────────────────────────

export const syncAuthorizationExpectations = new ExpectationSet({
  name: 'sync-authorization',
  description: 'Behavioral expectations for the sync-authorization PraxisModule',
});

syncAuthorizationExpectations
  .add(
    expectBehavior('sync.peer-untrusted')
      .onlyWhen('the peer fingerprint is not in the local trust list')
      .never('when isTrustedPeer is true')
      .always('includes the peer fingerprint for operator review'),
  )
  .add(
    expectBehavior('sync.unencrypted-payload')
      .onlyWhen('isEncrypted is false')
      .never('when the payload is encrypted end-to-end')
      .always('identifies the offending peer fingerprint'),
  )
  .add(
    expectBehavior('sync.invalid-signature')
      .onlyWhen('hasValidSignature is false')
      .never('when the HMAC signature verification passes')
      .always('identifies the offending peer fingerprint'),
  )
  .add(
    expectBehavior('sync.unresolved-conflict')
      .onlyWhen('hasConflict is true and conflictResolution is undefined')
      .never('when there is no conflict or a resolution has been selected')
      .always('includes the peer fingerprint involved in the conflict'),
  );

// ─── access-control expectations ─────────────────────────────────────────────

export const accessControlExpectations = new ExpectationSet({
  name: 'access-control',
  description: 'Behavioral expectations for the access-control PraxisModule',
});

accessControlExpectations
  .add(
    expectBehavior('access.vault-not-initialized')
      .onlyWhen('isInitialized is false')
      .never('when the vault has been set up with a master password')
      .always('prompts the user to complete first-time setup'),
  )
  .add(
    expectBehavior('access.session-expired')
      .onlyWhen('time since lastUnlockTime exceeds sessionTimeoutMs')
      .never('when the session is within the active timeout window')
      .always('includes idle time and configured timeout for transparency'),
  )
  .add(
    expectBehavior('access.biometric-failed')
      .onlyWhen('biometricAvailable is true AND biometricFailed is true')
      .never('when biometric auth is unavailable or succeeded')
      .always('prompts for master password as fallback'),
  )
  .add(
    expectBehavior('access.locked-out')
      .onlyWhen('failedAttempts reaches 5 or more')
      .never('when fewer than 5 consecutive failures have occurred')
      .always('includes the failed attempt count for audit purposes'),
  );
