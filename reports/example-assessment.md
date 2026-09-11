# Example SSH Hardening Assessment — `lab-admin-01`

> Synthetic portfolio example. No live system was assessed.

## Executive summary

The fictional configuration contains multiple hardening gaps that increase the likelihood or impact of unauthorized SSH access. The most material issues are direct root login and password-based authentication, followed by permissive forwarding, excessive authentication retries, and X11 forwarding.

**Illustrative risk classification:** High

## Prioritized findings

| Priority | Control | Observation | Risk | Recommended action |
|---|---|---|---|---|
| 1 | PermitRootLogin | `yes` | High | Disable direct root SSH access and require accountable named administration. |
| 2 | PasswordAuthentication | `yes` | High | Move to approved key/certificate-backed authentication after dependency review. |
| 3 | AllowTcpForwarding | `yes` | Medium | Restrict forwarding to required use cases only. |
| 4 | MaxAuthTries | `6` | Medium | Reduce retry allowance and verify failed-authentication monitoring. |
| 5 | X11Forwarding | `yes` | Low | Disable unless there is an approved operational requirement. |

## ATT&CK defensive context

- **T1021.004 — SSH**
- **T1078 — Valid Accounts**
- **T1110 — Brute Force**
- **T1133 — External Remote Services**

These mappings describe why the controls matter defensively; they are not evidence that an intrusion occurred.

## Remediation sequence

1. Validate administrative dependencies and emergency-access requirements.
2. Establish approved non-root administrative identities and public-key/certificate authentication.
3. Test configuration changes in a representative environment.
4. Disable direct root and password authentication under change control.
5. Restrict forwarding and authentication retry behavior.
6. Re-export effective configuration and rerun the assessment.
7. Confirm expected approved access, denied unapproved access, and healthy authentication telemetry.

## Closure criteria

A finding is considered remediated only when the effective post-change configuration is evidenced and the intended access-control outcome is validated. A ticket state or configuration change alone is not sufficient proof of effectiveness.
