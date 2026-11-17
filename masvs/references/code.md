# MASVS-CODE playbook

## Controls

- [MASVS-CODE-1](https://mas.owasp.org/MASVS/controls/MASVS-CODE-1/): the app requires a current enough platform version.
- [MASVS-CODE-2](https://mas.owasp.org/MASVS/controls/MASVS-CODE-2/): there is a way to force users onto a fixed version after a critical vulnerability.
- [MASVS-CODE-3](https://mas.owasp.org/MASVS/controls/MASVS-CODE-3/): third-party components have no known vulnerabilities.
- [MASVS-CODE-4](https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/): untrusted input (UI, IPC, network, files) is validated and sanitized. Binary hardening findings (stack canaries, PIE, ARC) are commonly filed here too.

MASTG candidates: `mastg_tests` in `data/controls.json` (CODE-3 and CODE-4 share most entries via MASWE). Test index: https://mas.owasp.org/MASTG/tests/

## What to check

- **Flutter**
  - Dependency tree, not just `pubspec.yaml`: `flutter pub deps` and `pubspec.lock`. Findings often come from transitive packages (e.g. an image-cache package pulling in a SQLite plugin).
  - SCA on the lockfiles: `osv-scanner` (reads `pubspec.lock`, `Podfile.lock`, Gradle lockfiles, `package-lock.json`) or the platform's audit tool. `flutter pub outdated` for stale majors.
  - Raw SQL built by string interpolation (`rawQuery("... $x")`) in app code.
  - Release builds: `--obfuscate --split-debug-info` (see `resilience.md`), `debuggable` false.
- **Android**
  - AND-SDK-1: minSdk < 29, or unresolved (`flutter.minSdkVersion`, `rootProject.ext`). Read the real value from `inspect_apk.py` → `min_sdk`, `target_sdk`.
  - `inspect_apk.py` → `debuggable` must be false in release.
  - `./gradlew :app:dependencies` for transitive native libraries; outdated Play services / OkHttp / WebView-related libs.
  - SQL: `rawQuery`/`execSQL` with concatenation; `ContentProvider` selection args.
- **iOS**
  - IOS-HARDEN-1 (hint only): no `-fstack-protector` in the Podfile. Clang usually enables a stack protector by default; verify the built binaries instead of trusting the hint.
  - `python3 scripts/inspect_ipa.py app.ipa` → per binary `pie`, `stack_canary`, `arc`, `kind`. `None` means not applicable (pure Swift, Dart AOT), not "missing".
  - `Podfile.lock` versions vs advisories.
- **React Native**
  - `npm audit` / `osv-scanner` on the lockfile; native modules' Pods and Gradle deps too.
  - `eval`/`new Function` on server data; WebView `injectedJavaScript` built from input.
- **All stacks (CODE-2)**: a server-driven minimum-version check, or store mechanisms (Play In-App Updates immediate flow). Check it exists and fails safely when the config endpoint is unreachable.

Manual tests: fuzz deep-link and form inputs; inject SQL meta-characters in search fields backed by local DB; feed malformed JSON from a proxy.

## Fix patterns

Prefer removing a dependency over adding one, and config over code.

| Issue | Flutter | Android | iOS | React Native |
|---|---|---|---|---|
| Vulnerable / risky transitive dep | Find the parent with `flutter pub deps`; replace or drop the parent. Example: an image-cache package (`cached_network_image` → `flutter_cache_manager` → `sqflite`) removed, images cached via the framework's in-memory image cache or a small file cache in app-private storage. **UX change** with the in-memory cache only: images are re-downloaded after restart and unavailable offline; add the file cache if that matters. | Bump or exclude the transitive artifact; `dependencyInsight` to find who pulls it. | Bump the pod; drop pods you don't need. | `npm ls <pkg>`; `overrides`/`resolutions` for patched versions. |
| SQL injection | Parameterised `rawQuery('... WHERE id = ?', [id])` or the query builder. | `?` placeholders / Room. | Bound parameters (`sqlite3_bind_*`, GRDB, Core Data predicates). | Parameterised queries in the SQLite library. |
| minSdk | `minSdk = 29` (or the agreed floor) in `android/app/build.gradle`; product sign-off as it drops older devices. | same | Raise `IPHONEOS_DEPLOYMENT_TARGET` to the agreed floor. | same |
| Stack canary flag (iOS pods) | Podfile `post_install` (below). | — | Same Podfile snippet; check app targets' build settings too (Clang usually enables a stack protector by default). | Same Podfile snippet. |
| Forced update | Server-provided `min_version`; compare at launch, show blocking update screen only when below it. | Play In-App Updates (immediate). | Server `min_version` + App Store link. | same as Flutter |

Merge this into the existing `post_install` block (a Podfile allows only one):

```ruby
post_install do |installer|
  installer.pods_project.targets.each do |target|
    flutter_additional_ios_build_settings(target) # Flutter projects only
    target.build_configurations.each do |config|
      config.build_settings['OTHER_CFLAGS'] = '$(inherited) -fstack-protector-all'
    end
  end
end
```

Stack canaries and Swift: Swift relies on memory safety and, unlike Clang for C/ObjC, adds stack protectors only to a narrow set of functions (and only in newer compilers), so the `___stack_chk_*` symbols may be absent from Swift binaries (newer compilers can emit them). `inspect_ipa.py` reports pure Swift as `None` (n/a) with a note. Swift frameworks with ObjC interop can report `False` even though only Swift code is in them; check whether the framework has any C/ObjC sources before treating it as a finding.

## Evidence to show the auditor

- Dependency removal: `grep -c sqflite pubspec.lock` → 0; `flutter pub deps | grep -i sqflite` → nothing; `unzip -l app.ipa | grep -i sqflite` → nothing (no `sqflite.framework`); `unzip -p app.apk 'classes*.dex' | strings | grep -ci sqflite` → 0.
- `python3 scripts/inspect_ipa.py app.ipa`: `pie: true` everywhere; `stack_canary: true` for C/ObjC binaries; `None` with a note for Swift-only/Dart AOT; `kind` per binary.
- `python3 scripts/inspect_apk.py app.apk`: `min_sdk`, `target_sdk`, `debuggable: false`.
- SCA report (tool, version, date) with zero high/critical open, or each remaining one triaged (not reachable / no fix / accepted).
- For forced update: a screen recording of the gate with a raised `min_version` on a test config.

## Common false positives

See `false-positives.md`:
- ARC "disabled" in Flutter's `App.framework` (Dart AOT, no Objective-C).
- Missing stack canaries in Swift / Swift-with-interop frameworks.

Also common: CVEs in a dependency for a code path the app never reaches (state the vulnerable API and show no call); "debuggable" from a debug build handed to the auditor by mistake (re-test with the release artifact).
