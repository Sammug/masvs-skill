# MASVS-RESILIENCE playbook

## Controls

- [MASVS-RESILIENCE-1](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-1/): the app checks the integrity of the platform it runs on (root/jailbreak, emulator).
- [MASVS-RESILIENCE-2](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-2/): the app resists tampering and repackaging.
- [MASVS-RESILIENCE-3](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-3/): the app makes static analysis harder (obfuscation, stripped symbols).
- [MASVS-RESILIENCE-4](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-4/): the app resists dynamic analysis (debuggers, hooking, instrumentation).

MASTG candidates: `mastg_tests` in `data/controls.json` (RESILIENCE-1 and -4 overlap). Test index: https://mas.owasp.org/MASTG/tests/

MASWE weaknesses for this group (requirement, modes, mitigations): `references/maswe.md`, section RESILIENCE; full entries in `data/maswe.json`. Scan matches carry their rule's MASWE ID.

Be honest about this group. Every client-side check here can be bypassed by a motivated attacker with a rooted device and Frida. These controls raise cost; they are defence in depth on top of STORAGE, CRYPTO, AUTH and NETWORK, never a substitute. OWASP's MAS testing profiles put this group in the resilience (R) profile, meant for apps whose threat model calls for it (e.g. payments, high-value IP), not for every app.

## What to check

No static rules for this group; use artifact checks and manual tests.

- **Flutter**
  - Release built with `--obfuscate --split-debug-info=<dir>`; symbols uploaded to the crash reporter so stack traces stay readable. Obfuscation renames Dart symbols; string literals remain readable.
  - Root/jailbreak or RASP plugin in use? What does it do on detection, and is detection reported to the server?
- **Android**
  - `inspect_apk.py` → `debuggable: false`.
  - R8 enabled for release (`isMinifyEnabled = true`, `isShrinkResources = true`), mapping file archived.
  - Play Integrity API (server-verified verdicts) for sensitive operations; signature check is meaningful only if verified server-side.
- **iOS**
  - App Attest / DeviceCheck for server-side integrity signals.
  - Release binary stripped (`STRIP_INSTALLED_PRODUCT`, `DEPLOYMENT_POSTPROCESSING`), no `get-task-allow` in the distribution entitlements.
- **React Native**
  - Hermes bytecode vs a plain JS bundle (plain bundles are trivially readable); source maps not shipped in the app.
  - Same integrity APIs via native modules.

Manual tests: install on a rooted/jailbroken device and with Magisk hide/Shamiko; run Frida/objection; repackage with apktool and re-sign; attach a debugger. Record what the app does in each case and what the server sees.

## Fix patterns

Smallest useful change, with UX risk called out.

| Issue | Flutter | Android | iOS | React Native |
|---|---|---|---|---|
| No obfuscation | Add `--obfuscate --split-debug-info` to the release build command; upload symbols. No UX change. | Enable R8 minify/shrink; keep rules for reflection-heavy libs; test the release build. | Strip symbols in Release; upload dSYMs. | Enable Hermes; don't ship source maps. |
| No root/jailbreak signal | A maintained detection/RASP plugin. | Play Integrity verdict checked server-side. | App Attest checked server-side. | A maintained RASP library or native module. |
| No tamper detection | Server-side Play Integrity / App Attest gives a verdict the attacker cannot forge locally. | same | same | same |
| Debuggable release | Fix build type (`flutter build --release`). | `debuggable false` (default for release). | Distribution profile (no `get-task-allow`). | Release variant. |

Fail-closed vs fail-open:
- Blocking the app on a root/jailbreak/emulator signal is a visible UX change and has false positives (custom ROMs, developer-mode devices, some accessibility and enterprise MDM setups, OEM quirks). It also blocks your own QA on emulators.
- Prefer, in order: report the signal to the server and let it step up auth or limit high-risk operations; warn the user; block only the sensitive feature. Full block only with product and support sign-off, plus a kill switch.
- Never let a detection library crash the app or delay startup noticeably; run checks off the main thread.

## Evidence to show the auditor

- Build command / CI step showing `--obfuscate --split-debug-info` (Flutter) or R8 enabled (`mapping.txt` archived per release).
- `python3 scripts/inspect_apk.py app.apk` → `debuggable: false`; `python3 scripts/inspect_ipa.py app.ipa` per binary output.
- A jadx/strings screenshot showing obfuscated class/method names.
- Detection behaviour on a rooted/jailbroken device (screenshot or server log entry), with the policy (warn, limit, block) written down.
- For server-side attestation: the endpoint that verifies the token and what it does on failure.

## Common false positives

- "Root detection bypassed with Frida/Magisk": expected for any client-side check. Respond with the layered controls (server-side authorization, attestation, pinning) and the threat model; don't promise unbypassable detection.
- "Strings readable after obfuscation": Dart/R8 obfuscation renames symbols, not literals. If a literal is a secret, that is a STORAGE/CRYPTO finding (move it server-side), not an obfuscation gap.
- "Flutter app not obfuscated" judged by readable Flutter engine or plugin Java/ObjC symbols: the engine and platform glue are not Dart. Check Dart symbol names in the AOT snapshot instead.
- "No anti-debugging" on an app whose threat model has no resilience requirement: document the risk acceptance with the product owner rather than adding fragile checks.
