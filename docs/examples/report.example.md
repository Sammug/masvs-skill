# MASVS findings — Example Wallet

Generated: 2026-11-19

## Assets

- Android release APK com.example.wallet 4.2.0 (build 420)
- iOS app com.example.wallet 4.2.0 (source only, no IPA)
- Source repository (Flutter + native Android/iOS)

## Summary

| Severity | Open | Fixed | Already mitigated | False positive | Risk accepted | Not run | Total |
|---|---|---|---|---|---|---|---|
| Critical | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| High | 0 | 1 | 0 | 0 | 0 | 0 | 1 |
| Medium | 2 | 0 | 0 | 0 | 0 | 0 | 2 |
| Low | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Info | 0 | 0 | 0 | 1 | 0 | 2 | 3 |
| Total | 2 | 1 | 0 | 1 | 0 | 2 | 6 |

## Findings

| Finding | Affected Asset | Observation | Impact | Severity | Recommendation | Status | Remediation / Response | Evidence | Re-test Build | Ticket | MASVS Control | MASWE |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Backups enabled | Android release APK com.example.wallet 4.2.0 | android:allowBackup is true in the merged manifest of the release build, and no backup rules exclude the token store. | Anyone with ADB access to an unlocked device can extract app data, including cached session tokens. | Medium | Set android:allowBackup="false", or add dataExtractionRules / fullBackupContent that exclude sensitive files. | Open |  | [verified] inspect_apk.py app-release.apk: allow_backup: true |  | EXW-101 | MASVS-STORAGE-2 | MASWE-0006 (Sensitive Data Not Excluded From Backup) |
| Cleartext only in debug config | android/app/src/debug/AndroidManifest.xml | scan_source.py rule AND-NET-1 matched android:usesCleartextTraffic="true" in the debug source set only. | None for release builds: the debug manifest is not merged into release. | Info | Keep the allowance in src/debug; confirm on the next release APK. | False positive | The match is in the debug source set, which release builds do not include. The release manifest does not set usesCleartextTraffic. To be confirmed with inspect_apk.py on the next release APK (expect uses_cleartext null or false). | [inferred] git ls-files android/app/src: the only usesCleartextTraffic="true" is in src/debug/AndroidManifest.xml; src/main/AndroidManifest.xml has no override |  | EXW-102 | MASVS-NETWORK-1 | MASWE-0026 (Network Traffic Not Encrypted) |
| Certificate pins expired | android/app/src/main/res/xml/network_security_config.xml | The pin-set for api.example.invalid has expiration 2025-06-30 (days_left -507 on 2026-11-19). After that date Android stops enforcing the pins. | The app falls back to ordinary CA validation, so a mis-issued or user-installed CA can intercept API traffic. | Medium | Rotate the pin-set with current leaf/intermediate SPKI hashes plus a backup pin, and set a new expiration. Needs the backend team's certificate plan. | Open | Pin rotation needs the backend team's current and next certificate. Requested; status stays Open until a new build is verified. | [inferred] check_pins.py --nsc network_security_config.xml --today 2026-11-19: expiration 2025-06-30, days_left -507, backup_pin true |  | EXW-103 | MASVS-NETWORK-2 | MASWE-0028 (Insecure Identity Pinning) |
| Exported service without permission | Android release APK com.example.wallet 4.2.1 | com.example.wallet.sync.SyncService was exported with no permission in build 4.2.0. | Any installed app could start the sync service and trigger account sync. | High | Set android:exported="false", or protect the service with a signature-level permission. | Fixed | Set android:exported="false" on SyncService in android/app/src/main/AndroidManifest.xml. Verified on build 4.2.1 (421). | [verified] inspect_apk.py app-release-4.2.1.apk: exported[] no longer lists com.example.wallet.sync.SyncService | 4.2.1 (421) | EXW-104 | MASVS-PLATFORM-1 | MASWE-0018 (Lack of Authentication or Authorization on App Components) |
| Root/jailbreak detection | Android and iOS release builds | Not assessed: needs a rooted/jailbroken test device and a hooking test. No detection library was found in the source scan. | Unknown until tested. | Info | Run the device test during the pentest; decide whether detection is in scope for this app's risk profile. | Not run |  | [manual] no rooted/jailbroken test device: runtime check not run |  |  | MASVS-RESILIENCE-1 | MASWE-0051 (Root/Jailbreak Detection Not Implemented) |
| Binary protections (iOS) | iOS release IPA (not provided) | PIE, ARC and stack canaries can only be checked on the built binaries. No IPA was provided. | Unknown until the IPA is inspected. | Info | Provide a release IPA and run inspect_ipa.py. | Not run |  | [manual] no APK/IPA: inspect_ipa.py not run |  |  | MASVS-CODE-3 | MASWE-0045 (Compiler-Provided Security Features Not Used) |

_Evidence tags: [verified] a script or command showed it; [inferred] reasoned from code or config; [manual] needs manual test_
