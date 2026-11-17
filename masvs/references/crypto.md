# MASVS-CRYPTO playbook

## Controls

- [MASVS-CRYPTO-1](https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-1/): current, strong algorithms, used the way they are meant to be used (modes, IVs, randomness).
- [MASVS-CRYPTO-2](https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-2/): keys are generated, stored, used and retired safely.

MASTG candidates: `mastg_tests` in `data/controls.json` (mapped through shared MASWE ids, so they overlap with STORAGE). Test index: https://mas.owasp.org/MASTG/tests/

## What to check

- **Flutter**
  - FLT-CRYPTO-1: `AESMode.ecb` (package `encrypt` or similar).
  - Hard-coded keys/IVs in Dart (`Key.fromUtf8('...')`, `IV.fromLength(16)` with a zero IV, a constant IV reused for every message).
  - `Random()` instead of `Random.secure()` for anything security-relevant.
  - FLT-STORAGE-2 (see `storage.md`): the secure-storage plugin's legacy Android cipher is a CRYPTO finding as often as a STORAGE one.
- **Android**
  - AND-CRYPTO-1: ECB, DES/3DES, RC4, Blowfish, or bare `"AES"` (provider default is ECB).
  - AND-CRYPTO-2: AES-CBC without a MAC. Decide whether the code is the app's or a dependency's (`owner` from `scan_source.py --include-deps`).
  - AND-CRYPTO-3: MD5/SHA-1. Fine for cache keys and checksums; a finding only for passwords, signatures or integrity.
  - Keys created in code instead of `AndroidKeyStore`; `java.util.Random` for tokens/nonces.
- **iOS**
  - IOS-CRYPTO-1: `CC_MD5`, `CC_SHA1`, `Insecure.MD5`, DES/3DES/RC4, `kCCOptionECBMode`.
  - Static keys in source; keys stored in UserDefaults or files instead of the Keychain / Secure Enclave.
- **React Native**
  - JS crypto libraries with hard-coded keys, `Math.random()` for secrets, crypto-js in ECB/CBC without integrity.
- **All stacks**
  - SECRET-PEM-1: a private key in the repo or bundle. Treat as compromised until shown otherwise (test fixture, revoked, or public demo key).
  - Encryption whose key ships in the binary is obfuscation, not protection. Say so in the response instead of claiming the data is encrypted.

Manual tests: decompile the release build (jadx, or `strings` on the iOS binary) and search for key material and cipher strings; confirm whether each hit is reachable from app code.

## Fix patterns

| Issue | Flutter | Android | iOS | React Native |
|---|---|---|---|---|
| Secure-storage legacy cipher | `AndroidOptions(encryptedSharedPreferences: true)` on every instance; existing data migrates on first read, no forced logout. | — | — | — |
| Weak mode / no integrity | AES-GCM via `cryptography` or platform channel to Keystore/Keychain. | `AES/GCM/NoPadding` with a 12-byte random IV per message; key in `AndroidKeyStore`. | CryptoKit `AES.GCM` (or `ChaChaPoly`); key in Keychain/Secure Enclave. | Native module wrapping the platform APIs, or a maintained library using AES-GCM. |
| Weak hash for security | `crypto` package SHA-256; HMAC-SHA256 for integrity. | `SHA-256`; `Mac.getInstance("HmacSHA256")`. | CryptoKit `SHA256` / `HMAC<SHA256>`. | Same, via a native-backed library. |
| Insecure RNG | `Random.secure()`. | `SecureRandom`. | `SecRandomCopyBytes` / CryptoKit. | `crypto.getRandomValues` (with a native polyfill). |
| Hard-coded key | Move the secret server-side, or derive per-install keys in Keystore/Keychain. | Keystore-generated key, non-exportable. | Keychain / Secure Enclave key. | Native keystore wrapper. |

Migrating stored ciphertext to a new algorithm: decrypt with the old scheme on first read, re-encrypt with the new one, delete the old blob. No prompt, no logout. Keep the old decrypt path for at least one release cycle.

Do not swap a working platform keystore for hand-rolled crypto to satisfy a scanner. Changing algorithms in a dependency you don't own is rarely the smallest fix; configuring it usually is.

## Evidence to show the auditor

- The config snippet on every `FlutterSecureStorage(...)` instance, and `scripts/scan_source.py <app>` showing zero FLT-STORAGE-2 matches.
- `scripts/scan_source.py <app> --include-deps` output where any remaining AND-CRYPTO-2 hit has `owner` set to a package, not `app`.
- For hashes: the call site showing the non-security use (cache key, file checksum).
- For a found PEM key: what it is and proof it is not a live production key (revocation, or the matching public key is not trusted anywhere).

## Common false positives

See `false-positives.md`:
- "AES/CBC/PKCS5Padding" in flutter_secure_storage: the plugin keeps its legacy class to migrate old data. Residual once every instance is configured.

Also common: MD5/SHA-1 used for non-security checksums or cache keys; CBC findings inside a well-maintained TLS or database library the app does not call directly (attribute with `owner`, then decide).
