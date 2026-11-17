# MASVS-AUTH playbook

## Controls

- [MASVS-AUTH-1](https://mas.owasp.org/MASVS/controls/MASVS-AUTH-1/): remote authentication and authorization use sound protocols and established practice.
- [MASVS-AUTH-2](https://mas.owasp.org/MASVS/controls/MASVS-AUTH-2/): local authentication (biometrics, device credential) follows platform guidance.
- [MASVS-AUTH-3](https://mas.owasp.org/MASVS/controls/MASVS-AUTH-3/): sensitive operations need an extra authentication step beyond the session.

MASTG candidates: `mastg_tests` in `data/controls.json` (AUTH-3 has none mapped; overlaps with PLATFORM-1 via shared MASWE ids). Test index: https://mas.owasp.org/MASTG/tests/

MASWE weaknesses for this group (requirement, modes, mitigations): `references/maswe.md`, section AUTH; full entries in `data/maswe.json`. Scan matches carry their rule's MASWE ID.

## What to check

There are no static rules for this group: most of it is server behaviour plus how the client binds local auth to secrets. Mark results as **needs manual test** unless you exercised the flow.

- **All stacks (server + client)**
  - Authorization is enforced server-side per request (change an id in a request: IDOR). The client hiding a button is not access control.
  - Access tokens are short-lived; refresh tokens rotate and are revoked on logout, password change and device removal.
  - Logout invalidates the session server-side, not just locally.
  - OAuth/OIDC uses the system browser (ASWebAuthenticationSession / Custom Tabs) with PKCE, not an embedded WebView collecting credentials.
  - OTP / step-up codes: rate-limited, single-use, short expiry, bound to the transaction they approve.
  - Tokens stored per `storage.md`, never in prefs/UserDefaults/AsyncStorage.
- **Flutter**
  - `local_auth.authenticate()` returns a boolean. If a successful result alone unlocks a stored token or approves a payment, a hooking tool can flip it. Check whether a Keystore/Keychain key gates the secret.
  - `biometricOnly` and fallback behaviour match the product's intent.
- **Android**
  - `BiometricPrompt` used with a `CryptoObject` over a Keystore key created with `setUserAuthenticationRequired(true)` (and `setInvalidatedByBiometricEnrollment(true)` where enrollment changes should force re-auth).
  - Deprecated `FingerprintManager`.
- **iOS**
  - `LAContext.evaluatePolicy` alone (boolean) vs a Keychain item with `SecAccessControl` (`.biometryCurrentSet` or `.userPresence`) that the OS releases only after auth.
  - `NSFaceIDUsageDescription` present.
- **React Native**
  - Biometric libraries that only return a boolean vs ones that store/sign with a key gated by biometrics.

Manual tests: replay a logged-out token; call a privileged endpoint with another user's id; hook the biometric callback (Frida/objection) and see whether the protected secret becomes readable.

## Fix patterns

| Issue | Flutter | Android | iOS | React Native |
|---|---|---|---|---|
| Event-bound biometrics | Store the secret behind a biometric-gated key (a plugin that uses Keystore/Keychain access control), or have biometrics unlock a device-bound credential the server verifies (signed challenge or long-lived device token exchanged server-side). **UX change, needs product sign-off** (see below). | `BiometricPrompt` + `CryptoObject` on an auth-bound Keystore key. | Keychain item with `SecAccessControl`; reading it shows the same Face ID prompt. | A library that binds to Keystore/Keychain access control. |
| Local-only logout | Call the revoke endpoint, then clear storage; tolerate offline by clearing locally and revoking on next launch. | same | same | same |
| Embedded login WebView (**UX change**: system browser sheet, and on iOS a consent prompt) | `flutter_appauth` (or equivalent) with PKCE. | AppAuth + Custom Tabs. | `ASWebAuthenticationSession`. | `react-native-app-auth`. |
| No step-up on sensitive actions (**UX change**: adds a prompt) | Reuse the existing PIN/biometric prompt before the action and send proof (signed challenge or fresh short-lived token) the server checks. | same | same | same |

Key-bound biometrics are not UX-neutral:
- A `CryptoObject` requires Class 3 (strong) biometrics. Devices with only Class 2 sensors (many face-unlock phones) lose biometric login.
- Device-credential (PIN/pattern) fallback together with a `CryptoObject` needs API 30+.
- `setInvalidatedByBiometricEnrollment(true)` (Android) and `.biometryCurrentSet` (iOS) invalidate the key when a new fingerprint/face is enrolled, forcing a re-login.
Get product sign-off on these before shipping.

Server fixes (token lifetimes, revocation, IDOR checks, OTP rate limits) need no client release. Prefer them.

## Evidence to show the auditor

- Request/response captures showing a revoked token rejected (401) after logout, and an IDOR attempt rejected (403/404).
- Code snippet of the key creation with user-authentication flags, and of the read that triggers the prompt.
- A hooking attempt that bypasses the callback but still cannot read the secret (state the tool and device).
- Token lifetime config from the server (values, not the secret).

## Common false positives

- "Biometric bypass via Frida" when biometrics only gate a convenience screen and every sensitive action still requires a server-verified credential. Show which actions are server-gated.
- "Session not invalidated" tested by reusing a token within its documented short lifetime when the finding is about logout of a different session. Reproduce exactly before deciding.
- "No certificate-based auth / no MFA" on an app whose threat model and regulator do not require it: answer with the risk acceptance, not a code change. Escalate to the product/compliance owner.
