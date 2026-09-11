# Assessment, Remediation, and Validation Methodology

## 1. Scope and authorization

Use this project only with synthetic data or configuration exported from systems you are explicitly authorized to assess. The tool does not connect to endpoints.

## 2. Evidence collection

Export or copy the relevant global `sshd_config` directives into a review artifact. Preserve change-ticket or asset context separately. Do not place credentials, private keys, production secrets, or sensitive host inventories in the repository.

## 3. Control assessment

The engine evaluates explicit controls for root login, password authentication, public-key authentication, empty passwords, X11 forwarding, TCP forwarding, authentication retries, principal restriction, and optional listener-network alignment.

A missing security-sensitive directive is reported instead of silently assuming a platform default. This makes the assessment conservative and avoids false assurance across distributions with different defaults.

## 4. Prioritization

Severity is assigned by control impact and a bounded aggregate score supports triage. The score is deliberately simple and transparent. It should be combined with asset criticality, exposure, business purpose, compensating controls, authentication telemetry, and operational constraints in a real program.

## 5. MITRE ATT&CK context

Mappings provide defensive threat context:

- **T1021.004 — SSH**: abuse of remote services for lateral movement or administration.
- **T1078 — Valid Accounts**: authentication controls that reduce misuse of legitimate credentials.
- **T1110 — Brute Force**: authentication retry restrictions and monitoring.
- **T1133 — External Remote Services**: unnecessary or poorly constrained remote-service exposure.

The presence of a mapped finding does not mean the ATT&CK technique occurred.

## 6. Remediation workflow

1. Assign each finding to an accountable system or platform owner.
2. Confirm service dependencies before modifying authentication or forwarding behavior.
3. Test proposed changes in a representative non-production environment.
4. Apply approved configuration using normal change control.
5. Validate syntax and effective daemon configuration with platform-native tooling.
6. Re-run this offline assessment against the post-change export.
7. Confirm approved administrative access still works and unapproved paths are denied.
8. Review authentication and service telemetry for expected behavior after change.
9. Close the finding only when evidence demonstrates the control state changed and the intended security outcome is effective.

## 7. Closure evidence

Strong closure evidence includes the approved change record, before/after configuration excerpts, effective-configuration output, successful approved-path access validation, denied unapproved-path validation where appropriate, and relevant authentication logs. Screenshots alone should not replace machine-readable evidence when stronger evidence is available.

## 8. Exception handling

If a directive cannot be remediated immediately, document the business justification, accountable owner, expiration date, compensating controls, monitoring requirement, and retest date. Exceptions should be time-bounded and reviewed rather than treated as permanent closure.
