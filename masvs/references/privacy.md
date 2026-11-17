# MASVS-PRIVACY playbook

## Controls

- [MASVS-PRIVACY-1](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-1/): the app asks only for the data and resources it needs, with informed consent.
- [MASVS-PRIVACY-2](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-2/): the app limits identification of users (anonymization, pseudonymization, unlinkability).
- [MASVS-PRIVACY-3](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-3/): the app is transparent about what it collects, stores and shares.
- [MASVS-PRIVACY-4](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-4/): users can manage, delete and correct their data and privacy settings.

MASTG candidates: `mastg_tests` in `data/controls.json` (PRIVACY-2 and -4 have none mapped). Test index: https://mas.owasp.org/MASTG/tests/

Legal questions (lawful basis, retention periods, regulator-specific duties) go to Legal/Compliance. This playbook covers what the app sends and asks for.

## What to check

- **Flutter**
  - FLT-TELEMETRY-1: Sentry `sendDefaultPii = true` (IP, user, request data to a third party).
  - FLT-TELEMETRY-2: session replay sample rates above 0 (can capture sensitive screens).
  - FLT-TELEMETRY-3: `attachScreenshot = true` on error events.
  - Breadcrumbs and events carrying HTTP bodies, URLs with query params, phone numbers, emails, amounts, payment references or tokens. Look for `beforeSend` / `beforeBreadcrumb`; if present, check it cannot throw.
  - Crashlytics: `setUserIdentifier`, `setCustomKey`, and logged messages containing PII.
  - Analytics events with user properties set to raw identifiers.
- **Android**
  - Merged-manifest permissions (`inspect_apk.py` → `permissions`): each one maps to a feature, including ones added by plugins (location, contacts, phone state, storage).
  - Advertising ID use and the Play Data safety form matching reality.
- **iOS**
  - `PrivacyInfo.xcprivacy` (app and SDKs) and required-reason API declarations; App Store privacy labels.
  - Every `NS*UsageDescription` string is accurate and specific; ATT prompt only if tracking.
- **React Native**
  - Same SDK settings (Sentry RN, Firebase); `console` output shipped to remote logging.
- **All stacks**: account/data deletion path in the app (the stores expect one for apps with account creation); consent before non-essential analytics where required.

Manual tests: proxy traffic to every third-party host during login, payment and profile flows and grep payloads for PII; trigger a test crash and inspect the event in the crash console.

## Fix patterns

| Issue | Flutter | Android | iOS | React Native |
|---|---|---|---|---|
| Sentry over-collection | `sendDefaultPii = false`, `attachScreenshot = false`, replay `sessionSampleRate` and `onErrorSampleRate` = 0, plus `beforeSend` and `beforeBreadcrumb` scrubbers (below). | Same options in `SentryAndroid.init`. | Same options in `SentrySDK.start`. | Same options in `Sentry.init`. |
| Crashlytics PII | `setUserIdentifier(<opaque id>)`; no PII in custom keys/logs. | same | same | same |
| User identity in telemetry | Send an opaque, non-reversible id (random per account or server-issued), never phone/email/name. | same | same | same |
| Unneeded permission from a plugin | Drop the plugin, or remove the permission in the app manifest with `tools:node="remove"` if the feature path is unused. | same | Remove unused usage strings and SDKs. | same |
| Missing transparency | Privacy policy link in settings; accurate store disclosures. | Data safety form. | Privacy manifest + labels. | same |

Scrubber rules (Flutter shown; same idea on every SDK):

```dart
options.beforeSend = (event, hint) {
  try {
    return scrubEvent(event); // redact message, exception values, extras, tags, request
  } catch (_) {
    return null; // drop rather than leak
  }
};
options.beforeBreadcrumb = (crumb, hint) {
  try {
    return scrubCrumb(crumb);
  } catch (_) {
    return null; // drop rather than leak or crash
  }
};
```

- Redact phone numbers, emails, currency amounts, payment/transaction references, bearer tokens, JWTs, and long digit runs. Replace with a fixed marker, not a hash of the value.
- Reduce `event.user` to `{id: <opaque id>}`; drop `ipAddress`, `email`, `username`. Also disable IP address storage in the Sentry project's security/privacy settings, since the server may otherwise derive the IP from the incoming request.
- The scrubber must never throw: depending on SDK and version, an exception there may drop the report, send it unscrubbed, or surface as a new error. Wrap the body and drop the event on failure. Unit-test it with sample payloads.
- Option names vary by SDK version (replay moved between `experimental` and stable namespaces); check the installed version's API.

No UX change: users never see telemetry settings.

## Evidence to show the auditor

- Source scan with zero FLT-TELEMETRY-1/2/3 matches (`python3 scripts/scan_source.py <app>`), plus the init snippet.
- Unit tests for the scrubber (input with PII → output without), including a malformed-event case that exercises the catch path.
- A test crash event from the re-test build as shown in the crash console: no screenshot, no replay, user = opaque id, no PII in breadcrumbs.
- `python3 scripts/inspect_apk.py app.apk` → `permissions`, each mapped to a feature; iOS privacy manifest file.

## Common false positives

- "Sentry/Crashlytics sends user data" when the only identifier is an opaque id and scrubbing is in place. Show a captured event.
- "Excessive permission" for a permission declared by a library but removed with `tools:node="remove"`, or not present in the merged manifest. Check the release APK, not the library manifest.
- "Advertising ID collected" when the SDK's collection is disabled by config; show the setting and a proxy capture without it.
