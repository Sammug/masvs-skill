# MASVS-NETWORK playbook

## Controls

- [MASVS-NETWORK-1](https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/): all traffic is protected in transit (TLS, no cleartext, proper certificate and hostname validation).
- [MASVS-NETWORK-2](https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-2/): the app pins the identity of endpoints it controls instead of trusting every system CA.

MASTG candidates: `mastg_tests` in `data/controls.json` (overlapping lists, mapped via MASWE). Test index: https://mas.owasp.org/MASTG/tests/

## What to check

- **Flutter**
  - FLT-TLS-1: `badCertificateCallback`/`validateCertificate` that returns `true`.
  - Dart's `HttpClient` (and `http`/`dio` on top of it) does its own TLS. It does **not** read Android's network security config. NSC pins protect only platform-side traffic (OkHttp, `HttpURLConnection`, native SDKs). Check pinning in the Dart layer separately.
  - Each flavor/environment has its own pin set and host list; a dev pin set must not ship in prod.
- **Android**
  - AND-NET-1 (`usesCleartextTraffic`), AND-NET-2 (no NSC), AND-NET-3 (NSC permits cleartext). Unresolved placeholders: check `inspect_apk.py` → `uses_cleartext`, `network_security_config`.
  - AND-TLS-1 (trust-all TrustManager), AND-TLS-2 (allow-all HostnameVerifier).
  - NSC `<debug-overrides>` or user CAs (`<certificates src="user"/>`) in the release base config.
  - `scripts/check_pins.py --nsc res/xml/network_security_config.xml` → per domain `pinned_level`, `backup_pin`, `days_left`.
- **iOS**
  - IOS-ATS-1: `NSAllowsArbitraryLoads`. Review each `NSExceptionDomains` entry (`inspect_ipa.py` → `ats`).
  - Pinning via `NSPinnedDomains` (iOS 14+), a URLSession delegate, or a library (TrustKit/Alamofire `ServerTrustManager`).
- **React Native**
  - Cleartext/ATS as for Android/iOS. Pinning via a maintained library that configures OkHttp `CertificatePinner` and the iOS side together.

Manual tests:
- Proxy with a user-installed CA (Burp/mitmproxy): pinned hosts must fail; with a system-trusted interception CA on a rooted test device, still fail.
- Point each environment's build at another environment's host (or a host with a different CA): must reject. Its own host: must accept.
- `scripts/check_pins.py --nsc <file> --host <host>` for each environment; `pinned_level` should be `intermediate`. Servers usually omit the root, and then the last intermediate is reported as `root`. Save the **full chain including the root** to a PEM and pass `--chain` instead (it is applied to every domain in the NSC).
- Cross-check: run `--chain` with another environment's chain; `live_match` must be `false`.

## Fix patterns

Pin policy (all stacks):
- Pin the issuing **intermediate CA** SPKI plus a **backup intermediate from the same CA**. Not the leaf (rotates every renewal, often automated), not the root (it accepts any certificate that root, or any intermediate under it, ever issues).
- Set the NSC `<pin-set expiration>` no later than the earliest pinned intermediate's expiry, so a missed rotation fails open instead of locking users out. Track `days_left`.
- Keep a rotation runbook: when an intermediate has ≤ 60 days left (or the CA announces a change), ship a build adding the new pins while the old ones still validate, then remove old pins in a later release.
- Pins and hosts must be identical in every layer that makes requests (Dart, OkHttp/NSC, URLSession). A mismatch is the usual cause of "works on Android, fails on iOS".

| Issue | Flutter | Android | iOS | React Native |
|---|---|---|---|---|
| Trust-all callback | Delete the callback; default validation is correct. | Delete custom TrustManager/HostnameVerifier. | Remove the `URLSessionDelegate` that calls `.useCredential` unconditionally. | Remove the dev-only override. |
| Cleartext | — | `usesCleartextTraffic="false"`, NSC base config `cleartextTrafficPermitted="false"`; debug exceptions under `<debug-overrides>` only. | Remove `NSAllowsArbitraryLoads`; narrow exceptions per domain. | As native. |
| No pinning | `SecurityContext(withTrustedRoots: false)` trusting only your CA certificates, or a maintained SPKI-pinning plugin; verify with a live accept/reject test per environment. | NSC `<pin-set>` with two intermediate SPKI hashes; OkHttp `CertificatePinner` if a native client needs it. | `NSPinnedDomains` → `NSPinnedCAIdentities` (`SPKI-SHA256-BASE64`) in Info.plist: config, no code. | Pinning library with the same hashes on both platforms. |

No UX change when pins match the live chain. Never add a "disable pinning" toggle reachable in release.

## Evidence to show the auditor

- `python3 scripts/check_pins.py --nsc network_security_config.xml --chain fullchain.pem` per environment (full chain including root): `pinned_level: intermediate`, `backup_pin: true`, positive `days_left`, `live_match: true`.
- A proxy capture showing the TLS handshake failure on pinned hosts (screenshot or log line), from the re-test build.
- `python3 scripts/inspect_apk.py app.apk` → `uses_cleartext` false/absent and `network_security_config` set; `python3 scripts/inspect_ipa.py app.ipa` → `ats` without arbitrary loads.
- The rotation runbook (owner, check date, lead time ≥ 60 days).

## Common false positives

- "No certificate pinning" reported from a proxy test against a host the app does not control (analytics, maps, CDN). Pinning third-party hosts is usually wrong; say so.
- "Pinning bypassed with Frida/objection" on a rooted device: expected for any client-side control. Treat as RESILIENCE (defence in depth), not a NETWORK failure, unless pinning was missing.
- "Cleartext allowed" from a debug-only NSC override or a localhost exception for development. Show the release APK's merged config.
- "Leaf not pinned": pinning the intermediate is the deliberate, documented choice; cite the rotation runbook.
