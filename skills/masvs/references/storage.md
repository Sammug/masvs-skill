# MASVS-STORAGE playbook

## Controls

- [MASVS-STORAGE-1](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/): sensitive data the app deliberately stores is protected, wherever it lives.
- [MASVS-STORAGE-2](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/): sensitive data does not leak by accident through logs, backups, caches, clipboard or other OS features.

MASTG candidates: `mastg_tests` in `data/controls.json`. That list is mapped through shared MASWE ids, so it overlaps between controls and not every test applies to every app. Test index: https://mas.owasp.org/MASTG/tests/

## What to check

Start with `scripts/scan_source.py <app>` and, when you have a build, `scripts/inspect_apk.py` / `scripts/inspect_ipa.py`. Re-run the scan with `--include-deps` only to attribute a match to a package (`owner`), not to widen the finding list.

- **Flutter**
  - FLT-STORAGE-1: tokens or credentials in `shared_preferences` (a plaintext XML/plist).
  - FLT-STORAGE-2: `FlutterSecureStorage(...)` without `AndroidOptions(encryptedSharedPreferences: true)` on flutter_secure_storage < 10. Every instance counts, including ones built in DI modules, test helpers that ship, and plugins you wrap. One forgotten instance keeps the legacy cipher for its keys.
  - FLT-LOG-1: `print`/`debugPrint` of secrets. Both reach the device log in release builds.
  - FLT-LOG-2: Dio `LogInterceptor` with `requestBody`/`responseBody` true and no `kDebugMode`/`kReleaseMode` guard in the file. Bodies reach the device log in release builds; check how the interceptor is added and whether a redacting wrapper is used.
  - Image/HTTP caches holding sensitive responses (e.g. statements, ID scans) in shared or backed-up locations.
- **Android**
  - AND-BACKUP-1, AND-BACKUP-2: backup enabled or unset. A `${placeholder}` is reported as unresolved; confirm in the merged manifest or APK (`inspect_apk.py` → `allow_backup`).
  - Android 12+ (targetSdk ≥ 31): `allowBackup="false"` stops cloud backup but device-to-device transfer can still copy data unless `dataExtractionRules` excludes it. Check both.
  - AND-STORAGE-1 (external storage), AND-STORAGE-2 (world-readable modes), AND-STORAGE-3 (secrets in plain SharedPreferences), AND-LOG-1.
  - Storage permissions in the merged manifest (`inspect_apk.py` → `permissions`).
- **iOS**
  - IOS-KEYCHAIN-1: `kSecAttrAccessibleAlways*`. Prefer `...WhenUnlockedThisDeviceOnly` (or `AfterFirstUnlockThisDeviceOnly` for background refresh).
  - IOS-STORAGE-1 (secrets in UserDefaults), IOS-PASTE-1 (general pasteboard), IOS-LOG-1 (NSLog).
  - Files with sensitive content: data protection class and `isExcludedFromBackup`.
- **React Native**
  - RN-STORAGE-1: AsyncStorage holding tokens. RN-LOG-1: console logging of secrets.
- **All stacks**: SECRET-AWS-1, SECRET-GITLAB-1, SECRET-GITHUB-1, SECRET-GOOGLE-1, SECRET-SLACK-1, SECRET-JWT-1. These are flagged, not judged: decide whether the value is live, privileged, or a public client key (e.g. a restricted Maps/Firebase key is normal).

Manual tests (needs device):
- Log in, use the sensitive flows, then pull the sandbox (`adb backup`/`bmgr` on a debuggable build, or a jailbroken/rooted test device) and grep for tokens, PII and amounts.
- `adb logcat` / Console.app during login and payment: no tokens, OTPs or full card/phone numbers.
- Background the app and check the clipboard after copying anything sensitive.

## Fix patterns

Smallest change, no user-visible effect. Prefer config over code.

| Issue | Flutter | Android | iOS | React Native |
|---|---|---|---|---|
| Legacy secure-storage cipher | Pass `AndroidOptions(encryptedSharedPreferences: true)` to every instance. The plugin migrates existing values automatically, so users should stay logged in; test the upgrade path from the store build on real devices. Jetpack security-crypto (EncryptedSharedPreferences) is deprecated and flutter_secure_storage ≥ 10 moves away from it, so upgrading to ≥ 10 (following its migration notes) is the forward path; the option is the smallest fix on < 10. | — | — | — |
| Secrets in prefs | Move to flutter_secure_storage; read old key once, write to secure storage, delete old key (silent migration). | EncryptedSharedPreferences or Keystore-wrapped values; same silent migration. | Keychain with `ThisDeviceOnly`; migrate from UserDefaults on launch. | react-native-keychain (or an equivalent Keystore/Keychain wrapper); migrate silently. |
| Backup | Edit `android/app/src/main/AndroidManifest.xml` as in Android column. | `android:allowBackup="false"`, plus `android:fullBackupContent="@xml/backup_rules"` (≤ Android 11) and `android:dataExtractionRules="@xml/data_extraction_rules"` (12+). | Mark sensitive files `isExcludedFromBackup`; Keychain `ThisDeviceOnly` items are not restored to other devices. | As Android/iOS. |
| Logging | Remove, or guard with `kReleaseMode`/`assert`. | Strip `Log.d/v/i` with R8 `-assumenosideeffects`; never log secrets at `w/e`. | `os_log` with `privacy: .private`, or remove. | Guard with `__DEV__` or a console-stripping Babel transform. |
| External storage | Use `getApplicationDocumentsDirectory()`/`getApplicationSupportDirectory()`. | `Context.filesDir`/`cacheDir`. | App container with a data protection class. | App-private paths from your FS library. |

Backup rule files exclude every domain:

```xml
<!-- res/xml/data_extraction_rules.xml (Android 12+) -->
<data-extraction-rules>
  <cloud-backup>
    <exclude domain="root" path="."/>
    <exclude domain="file" path="."/>
    <exclude domain="database" path="."/>
    <exclude domain="sharedpref" path="."/>
    <exclude domain="external" path="."/>
    <exclude domain="device_root" path="."/>
    <exclude domain="device_file" path="."/>
    <exclude domain="device_database" path="."/>
    <exclude domain="device_sharedpref" path="."/>
  </cloud-backup>
  <device-transfer>
    <!-- same nine excludes -->
  </device-transfer>
</data-extraction-rules>
```

`res/xml/backup_rules.xml` is a `<full-backup-content>` element with the same `<exclude>` lines (`device_*` domains are for device-protected storage). UX trade-off: tokens are not affected (a reinstall already requires login), but non-secret local data (settings, drafts, cached content, onboarding state) is also no longer restored on a new device. Confirm with product.

## Evidence to show the auditor

- Release APK: `python3 scripts/inspect_apk.py app-release.apk` → `"allow_backup": false`, no storage permissions in `permissions`. Raw form: `aapt2 dump xmltree --file AndroidManifest.xml app-release.apk | grep -iE 'allowBackup|dataExtractionRules|fullBackupContent'`.
- The two rule XML files, and the manifest diff.
- Source scan with zero FLT-STORAGE-2 / FLT-STORAGE-1 matches owned by `app`, plus the snippet showing the options on each `FlutterSecureStorage` instance.
- Sandbox dump after the fix (file listing, grep for a known test token returning nothing). Label it **verified** only if taken from the re-test build.
- For logging: a logcat/Console capture of the login flow with no secrets.

## Common false positives

See `false-positives.md`:
- `getExternalStorageDirectory` inside path_provider_android (plugin code the app never calls).
- "AES/CBC with PKCS5/PKCS7 padding" in flutter_secure_storage after every instance uses encryptedSharedPreferences.

Also commonly over-reported: a public, restricted client API key flagged by a SECRET-* rule (show the key restrictions in the provider console); `allowBackup` "unset" in a library manifest that the app manifest overrides (check the merged manifest, not the library).
