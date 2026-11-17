# MASVS-PLATFORM playbook

## Controls

- [MASVS-PLATFORM-1](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/): IPC (intents, components, URL schemes, app links, extensions) is used securely.
- [MASVS-PLATFORM-2](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/): WebViews are configured so they neither leak data nor expose app functionality.
- [MASVS-PLATFORM-3](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-3/): the UI does not expose sensitive data through screenshots, the app switcher, notifications, keyboards and similar channels.

MASTG candidates: `mastg_tests` in `data/controls.json` (overlapping lists via MASWE). Test index: https://mas.owasp.org/MASTG/tests/

MASWE weaknesses for this group (requirement, modes, mitigations): `references/maswe.md`, section PLATFORM; full entries in `data/maswe.json`. Scan matches carry their rule's MASWE ID.

## What to check

- **Flutter**
  - Deep links (`go_router`/`uni_links`/`app_links`) that navigate to sensitive screens or trigger actions without re-checking auth.
  - `webview_flutter` / `flutter_inappwebview`: JavaScript channels exposed to remote content, `file://` access, unrestricted navigation (`NavigationDelegate`).
  - Sensitive `TextField`s: `obscureText`, `enableSuggestions: false`, `autocorrect: false`.
- **Android**
  - AND-IPC-1: exported component without a permission. Confirm with `inspect_apk.py` → `exported` (permission or `"unknown"` per entry). Plugin-contributed components show up only in the merged manifest.
  - Mutable `PendingIntent`s, implicit intents carrying sensitive extras, `FileProvider` paths broader than needed.
  - AND-WEBVIEW-1 (JS bridge), AND-WEBVIEW-2 (JS enabled), AND-WEBVIEW-3 (file/universal access from file URLs).
  - Task hijacking comes in two forms. StrandHogg 2.0 (CVE-2020-0096) is an OS flaw in Android 9 and earlier (fixes for 8.0, 8.1, 9 in the May 2020 bulletin); AND-SDK-1 flags minSdk < 29, check `inspect_apk.py` → `min_sdk`. The original StrandHogg (2019, `taskAffinity` + task reparenting) is not version-bound: check that exported activities set `android:taskAffinity=""` in the release manifest.
  - `FLAG_SECURE` on screens showing card data, balances, OTPs; notification visibility on the lock screen.
- **iOS**
  - Custom URL schemes / universal links handled without validating parameters; `UIPasteboard` (IOS-PASTE-1, see `storage.md`).
  - `WKWebView` with `WKScriptMessageHandler` exposed to remote pages; legacy `UIWebView`.
  - App switcher snapshot of sensitive screens; `isSecureTextEntry` on secrets; keyboard caching (`autocorrectionType`).
- **React Native**
  - RN-WEBVIEW-1: `originWhitelist={['*']}`. `injectedJavaScript` / `onMessage` handlers trusting any origin.
  - Linking handlers that act on parameters without validation.

Manual tests: `adb shell am start -n <pkg>/<exported activity>` with crafted extras; open deep links with tampered params; take a screenshot and open the app switcher on sensitive screens; check lock-screen notifications.

## Fix patterns

| Issue | Flutter | Android | iOS | React Native |
|---|---|---|---|---|
| Exported component | Fix in `android/app/src/main/AndroidManifest.xml` (Android column); for a plugin's component, redeclare it with `android:exported="false"` and `tools:replace="android:exported"`, only if the feature doesn't need outside callers. | `android:exported="false"`, or protect with a `signature` permission; validate all extras. | — | As Android. |
| Deep link to sensitive action | Route through the same auth guard as in-app navigation; never auto-execute actions from link params. | Same in the handling activity. | Same in `scene(_:openURLContexts:)` / `application(_:continue:)`. | Same in the Linking handler. |
| WebView | Load only your origins; restrict `NavigationDelegate`; expose minimal JS channels and validate the calling URL. | `setAllowFileAccess(false)`, no universal file access, `addJavascriptInterface` only for trusted content. | `WKWebView` only; check `message.frameInfo.securityOrigin` in handlers. | Explicit `originWhitelist`; validate `onMessage` origin. |
| StrandHogg 2.0 | `minSdk 29` in `android/app/build.gradle` | `minSdk 29` rules out 2.0; `launchMode="singleTop"` is defence in depth. Raising minSdk drops Android 9-and-earlier users: confirm with product first. | — | As Android. |
| StrandHogg (original, taskAffinity) | Android column, in `android/app/src/main/AndroidManifest.xml`. | `android:taskAffinity=""` on exported activities; verify in the release APK. minSdk does not fix this one. | — | As Android. |
| Screenshots / app switcher | Apply `FLAG_SECURE` per sensitive route via a platform channel or plugin. | `window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)` on sensitive screens only. | Cover the window with a blur/placeholder view on `sceneWillResignActive`, remove on `sceneDidBecomeActive`. | A maintained privacy-screen library. |
| Keyboard caching | `enableSuggestions: false`, `autocorrect: false` on sensitive fields. | `inputType` with `textNoSuggestions` / password types. | `autocorrectionType = .no`, `isSecureTextEntry` for secrets. | `autoCorrect={false}`, `secureTextEntry`. |

UX note: app-wide `FLAG_SECURE` blocks user screenshots everywhere and is visible; scope it to sensitive screens, and get product sign-off. An app-switcher blur is invisible in normal use.

## Evidence to show the auditor

- `python3 scripts/inspect_apk.py app-release.apk` → `exported` list where each entry has a permission or is the launcher; `min_sdk` ≥ 29 for StrandHogg 2.0; `taskAffinity=""` on exported activities (aapt2 xmltree) for the original StrandHogg.
- Manifest diff for `exported`/`taskAffinity`/`launchMode`.
- Screenshots: app switcher showing the blur; a black capture (or "can't take screenshot" toast) on a `FLAG_SECURE` screen.
- `adb shell am start ...` output showing the call rejected (SecurityException or redirect to login).

## Common false positives

See `false-positives.md` for StrandHogg 2.0 when minSdk ≥ 29 (not the original, taskAffinity-based StrandHogg).

Also common:
- Exported launcher activity, or components exported by Firebase/Play services that are protected by a signature or system permission. Check the `exported` entry's permission field before accepting the finding.
- "JavaScript enabled in WebView" for a WebView that only loads bundled or first-party content with no JS bridge. Show the URL allow-list.
- "Screenshot allowed" on screens with no sensitive data (onboarding, marketing). Ask the auditor which screen.
