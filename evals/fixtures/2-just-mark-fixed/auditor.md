# Example App – Mobile VAPT findings (Android)

| ID | Finding | Affected Asset | Observation | Severity | Recommendation | Status | Remediation / Response | Evidence | Re-test Build |
|---|---|---|---|---|---|---|---|---|---|
| F-03 | Cleartext HTTP traffic permitted | example_app-prod-release.apk (1.4.0) | `android:usesCleartextTraffic="true"` in the merged manifest; HTTP requests to the API succeed when TLS is stripped. | High | Disable cleartext traffic for release builds. | Open | | | |
