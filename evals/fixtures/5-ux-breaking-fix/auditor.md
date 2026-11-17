# Example App – Mobile VAPT findings

| ID | Finding | Affected Asset | Observation | Severity | Recommendation | Status | Remediation / Response |
|---|---|---|---|---|---|---|---|
| F-05 | Long-lived session / no re-authentication | Example App 1.9.0 (Android, iOS) | After relaunch the user is signed in after a biometric prompt only. The refresh token stays valid for 90 days. Logging out does not revoke the refresh token on the server. | Medium | Force users to log in with username and password on every app launch and remove biometric login. | Open | |

Auditor comment (retest call): "We will only close F-05 if full username/password login is required on every launch."
