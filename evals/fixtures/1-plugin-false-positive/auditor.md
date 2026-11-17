# Example App – Mobile VAPT retest sheet (Android, build 1.4.0+42)

| ID | Finding | Affected Asset | Observation | Severity | Recommendation | Status | Remediation / Response |
|---|---|---|---|---|---|---|---|
| F-01 | Insecure data storage on external storage | example_app-release.apk | Decompiled class `io/flutter/plugins/pathprovider/PathProviderPlugin` calls `getExternalStorageDirectory()`. Sensitive data may be written to shared external storage readable by other apps. | Medium | Do not store data on external storage; use internal app storage. | Open | |
| F-02 | Application data can be backed up | example_app-release.apk | `android:allowBackup="true"` in AndroidManifest.xml. App data can be extracted with `adb backup` / cloud backup. | Medium | Set `android:allowBackup="false"` or restrict backup with exclusion rules. | Open | |

Auditor note: findings not explained with evidence at retest stay Open.
