# Common false positives

Use these only after reproducing the finding against the build the auditor tested. "False positive" and "already mitigated" both need evidence from the built artifact (APK/IPA), not just source. If the evidence doesn't hold, it's a real finding: fix it.

Commands assume you run from the skill directory (`scripts/...`) with `python3`. Paths like `<app>` and `app.apk` are placeholders.

## Plugin code the app never calls (e.g. getExternalStorageDirectory in path_provider_android)

**Symptom:** "App uses external storage: `getExternalStorageDirectory()` found" (or any risky API) in a decompiled class under a plugin package such as `io.flutter.plugins.pathprovider`.

**Why it's a false positive:** the method lives in a plugin's Android code and is reachable only if Dart code calls the matching plugin API. The app never calls it, holds no storage permission, and stores nothing there. The plugin usually can't simply be removed: it is a transitive dependency (`flutter pub deps` shows the parent, commonly a secure-storage or cache package). Static scanners flag every method in the dex regardless of reachability.

**Evidence:**
- `python3 scripts/scan_source.py <app>`: no AND-STORAGE-1 match with `owner: app`.
- `python3 scripts/scan_source.py ~/.pub-cache --include-deps --stacks android`: the AND-STORAGE-1 match reports `owner: path_provider_android` (filter with `jq '.matches[] | select(.rule=="AND-STORAGE-1") | {file, owner}'`).
- `python3 scripts/inspect_apk.py app-release.apk`: `permissions` has no `READ_EXTERNAL_STORAGE`, `WRITE_EXTERNAL_STORAGE` or `MANAGE_EXTERNAL_STORAGE`.
- `grep -rnE 'getExternalStorageDirectory|getExternalStoragePath' lib android/app/src` returns nothing; `flutter pub deps` shows which package pulls in the plugin.

**Response:** The flagged method is part of a third-party plugin bundled as a transitive dependency; the application never calls it and requests no external storage permission, so no data is written to shared storage. Evidence: merged manifest permissions, source scan attributing the match to the plugin, and the dependency tree. No code change is required.

## ARC disabled in Flutter's App.framework

**Symptom:** "Binary `Frameworks/App.framework/App` is not compiled with ARC" (objc_release / objc_retain not found).

**Why it's a false positive:** `App.framework` holds the app's Dart code compiled ahead-of-time to machine code. It contains no Objective-C, so there is nothing for ARC (an Objective-C memory-management feature) to apply to. Dart memory is managed by the Dart runtime's garbage collector.

**Evidence:**
- `python3 scripts/inspect_ipa.py app.ipa`: the `Frameworks/App.framework/App` entry shows `kind: dart-aot`, `arc: null` and the note about compiled Dart; Objective-C/Swift binaries (Runner, plugin frameworks) show their own `arc` values.
- Optional raw check: `otool -Iv App.framework/App | grep -c _objc_` → 0.

**Response:** App.framework contains ahead-of-time compiled Dart code and no Objective-C, so ARC does not apply to it; Dart memory is managed by its own runtime. All Objective-C/Swift binaries in the bundle use ARC, as shown in the attached binary inspection output.

## Residual legacy cipher class (AES/CBC/PKCS5Padding in flutter_secure_storage)

**Symptom:** "Insecure cipher mode AES/CBC/PKCS5Padding used" in `com.it_nomads.fluttersecurestorage.ciphers.*` (or similar) in the decompiled APK.

**Why it's a false positive:** flutter_secure_storage < 10 uses a legacy AES-CBC scheme on Android for any instance created without `AndroidOptions(encryptedSharedPreferences: true)`. Once every instance sets that option, data is stored with EncryptedSharedPreferences (Keystore-backed, AES-GCM/SIV), and existing values are migrated on first read. The plugin keeps the legacy class in the binary only to read and migrate old data, so the string remains in the dex. If even one instance lacks the option, it is **not** a false positive: fix that instance (users are not logged out).

**Evidence:**
- `python3 scripts/scan_source.py <app>`: zero FLT-STORAGE-2 matches.
- `python3 scripts/scan_source.py <root containing the pub cache> --include-deps --stacks android`: any AND-CRYPTO-2 match has `owner: flutter_secure_storage`, none `owner: app`.
- Snippets of every `FlutterSecureStorage(...)` construction showing the option (including DI/factory code).

**Response:** All secure-storage instances are configured to use the platform's Keystore-backed EncryptedSharedPreferences, and previously stored values are migrated automatically. The AES/CBC class remains in the binary only because the plugin ships it to migrate legacy data; the application does not use it for new storage. Configuration and scan evidence attached.

## StrandHogg 2.0 (CVE-2020-0096) when minSdk is 29 or higher

**Symptom:** "App vulnerable to task hijacking (StrandHogg 2.0)", often based on `taskAffinity` / `launchMode` settings alone.

**Why it's a false positive:** CVE-2020-0096 is an Android OS flaw affecting Android 8.0–9 and fixed in the April 2020 security patch. With minSdk 29 (Android 10) the app cannot be installed on affected versions. `taskAffinity=""` and `singleTop` on the launcher activity are defence in depth, not the primary mitigation.

**Evidence:**
- `python3 scripts/inspect_apk.py app-release.apk`: `min_sdk` ≥ 29.
- `python3 scripts/scan_source.py <app>`: no AND-SDK-1 match (or an unresolved one whose built value the APK confirms).

**Response:** StrandHogg 2.0 (CVE-2020-0096) affects only Android 8.0–9; the application's minimum supported version is Android 10 (API 29), so it cannot run on an affected OS. The launcher activity additionally sets an empty task affinity as defence in depth. Manifest evidence attached.

## Missing stack canaries in Swift or Swift/ObjC-interop frameworks

**Symptom:** "Binary not compiled with stack canaries (`___stack_chk_guard` / `___stack_chk_fail` absent)" for the app executable or Swift pod frameworks.

**Why it's a false positive:** stack canaries are a C/Objective-C mitigation added by Clang. Swift is memory-safe by default and its compiler adds stack protectors only for a narrow set of functions (and only in newer versions), so pure-Swift binaries commonly import neither symbol. Frameworks that mix Swift with Objective-C interop headers may also lack the symbols when they contain no C/ObjC functions that need a canary. Pod C/ObjC code is covered by adding `-fstack-protector-all` to `OTHER_CFLAGS` in the Podfile `post_install`.

**Evidence:**
- `python3 scripts/inspect_ipa.py app.ipa`: Swift-only binaries show `stack_canary: null` with the "pure Swift" note; C/ObjC binaries show `true`.
- For an interop framework reporting `false`: list its sources (`find Pods/<Name> -name '*.m' -o -name '*.mm' -o -name '*.c'`) to show there is no C/ObjC, or show it was rebuilt with the Podfile flag and re-inspected.
- The Podfile `post_install` snippet.

**Response:** The flagged binaries are written in Swift, which relies on memory safety rather than compiler-inserted stack canaries, so the canary symbols are not expected. All C/Objective-C code, including third-party pods, is compiled with `-fstack-protector-all`, and binaries containing such code show canaries in the attached inspection output.

## Certificate pinning bypassed with Frida/objection on a rooted device

**Symptom:** "SSL pinning can be bypassed" after hooking the TLS stack on a rooted or jailbroken device.

**Why it's a false positive:** any client-side check can be disabled by an attacker who controls the device and runtime. The relevant question for MASVS-NETWORK-2 is whether pinning is implemented and enforced on an unmodified device. Resistance to hooking belongs to MASVS-RESILIENCE and is defence in depth. Treat it as a real finding if traffic is interceptable **without** hooking (missing pins, user CAs trusted, a layer that doesn't pin).

**Evidence:**
- `python3 scripts/check_pins.py --nsc network_security_config.xml --chain fullchain.pem`: `pinned_level: intermediate`, `backup_pin: true`, `live_match: true`.
- Proxy capture on an unmodified device showing the handshake rejected for pinned hosts, in every request layer (Dart/OkHttp/URLSession).

**Response:** Certificate pinning is enforced on unmodified devices, as shown by the attached interception test and pin configuration. Bypass through runtime instrumentation on a rooted device is outside what client-side pinning can prevent; it is addressed as defence in depth under our resilience controls and by server-side authorization.
