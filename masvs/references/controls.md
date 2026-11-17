# MASVS controls

OWASP MASVS v2.1.0 (https://mas.owasp.org/MASVS/), CC BY-SA 4.0, paraphrased.

| Control | Summary | MASWE | MASTG tests |
|---|---|---|---|
| [MASVS-STORAGE-1](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/) | Sensitive data the app intentionally stores must be protected, whether the location is private or public. | MASWE-0001, MASWE-0002, MASWE-0003, MASWE-0004 | - |
| [MASVS-STORAGE-2](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/) | Sensitive data must not leak unintentionally through side effects of APIs, logs, backups, caches or system features. | MASWE-0001, MASWE-0002, MASWE-0005, MASWE-0006, MASWE-0018, MASWE-0029, MASWE-0030, MASWE-0031, MASWE-0032, MASWE-0033, MASWE-0034, MASWE-0036, MASWE-0037, MASWE-0038, MASWE-0040 | - |
| [MASVS-CRYPTO-1](https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-1/) | Use current, strong cryptographic algorithms and apply them following accepted best practices. | MASWE-0007, MASWE-0008, MASWE-0009, MASWE-0010, MASWE-0011, MASWE-0012, MASWE-0047 | - |
| [MASVS-CRYPTO-2](https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-2/) | Manage cryptographic keys properly across their whole lifecycle, from generation and storage to use and retirement. | MASWE-0001, MASWE-0003, MASWE-0007, MASWE-0009, MASWE-0010, MASWE-0013, MASWE-0014, MASWE-0015, MASWE-0016, MASWE-0017, MASWE-0020, MASWE-0022, MASWE-0046 | - |
| [MASVS-AUTH-1](https://mas.owasp.org/MASVS/controls/MASVS-AUTH-1/) | Remote authentication and authorization use secure protocols and follow established best practices. | MASWE-0018, MASWE-0019, MASWE-0047 | - |
| [MASVS-AUTH-2](https://mas.owasp.org/MASVS/controls/MASVS-AUTH-2/) | Local authentication, such as biometrics or a device PIN, is implemented securely per platform guidance. | MASWE-0016, MASWE-0020, MASWE-0021, MASWE-0022 | - |
| [MASVS-AUTH-3](https://mas.owasp.org/MASVS/controls/MASVS-AUTH-3/) | Sensitive operations require an extra authentication step beyond the normal session. | MASWE-0016, MASWE-0019, MASWE-0023, MASWE-0024, MASWE-0025 | - |
| [MASVS-NETWORK-1](https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/) | All network traffic is protected in transit following current best practices. | MASWE-0026, MASWE-0027, MASWE-0047, MASWE-0062 | - |
| [MASVS-NETWORK-2](https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-2/) | The app pins the identity of remote endpoints it controls rather than trusting every default root CA. | MASWE-0028 | - |
| [MASVS-PLATFORM-1](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/) | Inter-process communication mechanisms are used securely when exposing data or functionality. | MASWE-0018, MASWE-0029, MASWE-0030, MASWE-0031, MASWE-0032 | - |
| [MASVS-PLATFORM-2](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/) | WebViews are configured securely so they do not leak data or expose app functionality. | MASWE-0033, MASWE-0034, MASWE-0035, MASWE-0063 | - |
| [MASVS-PLATFORM-3](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-3/) | Sensitive data shown in the UI is not exposed through screenshots, notifications, keyboards or similar channels. | MASWE-0023, MASWE-0036, MASWE-0037, MASWE-0038, MASWE-0039, MASWE-0040 | - |
| [MASVS-CODE-1](https://mas.owasp.org/MASVS/controls/MASVS-CODE-1/) | The app requires an up-to-date minimum platform version so known OS-level threats are not inherited. | MASWE-0039, MASWE-0041, MASWE-0042 | - |
| [MASVS-CODE-2](https://mas.owasp.org/MASVS/controls/MASVS-CODE-2/) | A mechanism exists to force users onto a fixed version when a critical vulnerability is found. | MASWE-0043 | - |
| [MASVS-CODE-3](https://mas.owasp.org/MASVS/controls/MASVS-CODE-3/) | Third-party components and libraries in use have no known vulnerabilities. | MASWE-0044, MASWE-0045, MASWE-0046, MASWE-0047, MASWE-0048 | - |
| [MASVS-CODE-4](https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/) | All untrusted input, from UI, IPC, network or files, is validated and sanitized. | MASWE-0029, MASWE-0034, MASWE-0035, MASWE-0045, MASWE-0049, MASWE-0050, MASWE-0057 | - |
| [MASVS-RESILIENCE-1](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-1/) | The app checks the integrity of the platform it runs on, such as rooted or jailbroken devices. | MASWE-0051, MASWE-0052, MASWE-0053, MASWE-0054 | - |
| [MASVS-RESILIENCE-2](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-2/) | The app resists tampering and repackaging with anti-tampering mechanisms. | MASWE-0055, MASWE-0056, MASWE-0057, MASWE-0058 | - |
| [MASVS-RESILIENCE-3](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-3/) | The app makes static analysis and reverse engineering harder, for example through obfuscation. | MASWE-0059, MASWE-0060, MASWE-0061, MASWE-0062 | - |
| [MASVS-RESILIENCE-4](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-4/) | The app resists dynamic analysis, such as debugging, hooking and instrumentation. | MASWE-0051, MASWE-0053, MASWE-0063, MASWE-0064, MASWE-0065 | - |
| [MASVS-PRIVACY-1](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-1/) | The app requests only the data and resources it needs, with informed user consent. | MASWE-0066, MASWE-0073 | - |
| [MASVS-PRIVACY-2](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-2/) | The app prevents users from being identified, using anonymization, pseudonymization and unlinkability. | MASWE-0067, MASWE-0068, MASWE-0069, MASWE-0070, MASWE-0071 | - |
| [MASVS-PRIVACY-3](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-3/) | The app is transparent about what data it collects, stores and shares. | MASWE-0072, MASWE-0073, MASWE-0074, MASWE-0075 | - |
| [MASVS-PRIVACY-4](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-4/) | Users can manage, delete and modify their data and change their privacy settings. | MASWE-0076, MASWE-0077, MASWE-0078 | - |
