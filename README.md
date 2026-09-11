# SSH Hardening Lab

Defensive security-engineering project for assessing exported OpenSSH server configuration against an explicit hardening policy, prioritizing control gaps, mapping relevant findings to MITRE ATT&CK, and documenting remediation plus post-change validation.

This repository is intentionally **offline and non-invasive**. It does not scan hosts, authenticate to systems, execute shell commands, restart services, or modify configuration.

## Problem statement

SSH remains a common administrative control plane. Weak configuration can increase the likelihood or impact of credential misuse, brute-force activity, uncontrolled forwarding, excessive privileged access, or unnecessary remote-service exposure. A useful security review needs more than a checklist: it should produce repeatable evidence, explain prioritization, preserve limitations, and define how remediation is proven effective.

This lab demonstrates that workflow using synthetic evidence and auditable Python code.

## Architecture

```text
Synthetic/exported sshd_config
            |
            v
     strict offline parser
            |
            v
   deterministic policy engine
      /        |         \
     v         v          v
 findings   ATT&CK     risk score
     \         |          /
      +--------+---------+
               v
        metrics + reporting
               |
               v
        Markdown assessment
               |
               v
 remediation -> validation -> closure evidence
```

See [`docs/architecture.md`](docs/architecture.md) for trust boundaries and design decisions.

## Controls assessed

The current engine evaluates:

- direct root login;
- password authentication;
- public-key authentication;
- empty-password allowance;
- X11 forwarding;
- TCP forwarding;
- authentication retry limits;
- explicit administrative principal restrictions;
- optional listener alignment to approved management CIDRs.

Missing security-sensitive directives are reported rather than silently inheriting assumed platform defaults.

## MITRE ATT&CK context

| Technique | Defensive relevance |
|---|---|
| **T1021.004 — SSH** | Hardening remote administration and reducing lateral-movement opportunity. |
| **T1078 — Valid Accounts** | Reducing misuse of legitimate privileged or administrative credentials. |
| **T1110 — Brute Force** | Limiting authentication retries and emphasizing failed-authentication telemetry. |
| **T1133 — External Remote Services** | Constraining unnecessary or poorly governed remote-service exposure. |

Mappings are threat-model context only. A finding does **not** prove that the mapped technique occurred.

## Repository structure

```text
.github/workflows/ci.yml        Least-privilege CI
src/ssh_audit.py                Parser, policy engine, findings, scoring
src/reporting.py                Metrics and Markdown report generation
src/cli.py                      Offline command-line workflow
data/sshd_config.synthetic      Fictional input fixture
tests/test_ssh_audit.py         Unit tests
docs/architecture.md            Architecture and trust boundaries
docs/methodology.md             Assessment/remediation methodology
reports/example-assessment.md   Recruiter-facing synthetic report
```

## Usage

Requires Python 3.11+ and only the standard library.

```bash
PYTHONPATH=src python src/cli.py data/sshd_config.synthetic \
  --target lab-admin-01 \
  --admin-cidr 10.50.0.0/16 \
  --output reports/generated-assessment.md
```

Run tests locally:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

The target name is a display label only; the CLI never resolves or contacts it.

## Risk model

The engine uses transparent severity weights:

- Critical: 35
- High: 22
- Medium: 10
- Low: 4

The aggregate score is capped at **100**. It is a prioritization aid for this lab, not a substitute for asset criticality, exposure, compensating controls, business requirements, authentication telemetry, or organization-specific risk methodology.

## Deterministic findings

Each finding receives a SHA-derived stable identifier based on control, severity, title, and evidence. This supports before/after comparison without inventing operational ticket IDs or assessment history.

## Remediation and validation workflow

A configuration change is not considered proof of remediation by itself. The methodology requires:

1. accountable ownership and impact review;
2. representative pre-production testing;
3. approved change implementation;
4. syntax/effective-configuration validation using platform-native tooling;
5. re-export and repeat offline assessment;
6. positive validation of approved administrative access;
7. negative validation of disallowed access paths where appropriate;
8. authentication/service telemetry review;
9. evidence-backed closure or a time-bounded exception.

See [`docs/methodology.md`](docs/methodology.md).

## Synthetic example

The fictional fixture intentionally includes:

- `PermitRootLogin yes`;
- `PasswordAuthentication yes`;
- `MaxAuthTries 6`;
- `X11Forwarding yes`;
- unrestricted TCP forwarding.

The example report demonstrates how those observations are prioritized and translated into a defensible remediation sequence without claiming a real-world compromise or production assessment.

## Testing

The unit suite currently exercises:

- a secure baseline;
- root-login severity;
- empty-password severity;
- fail-closed missing directives;
- unsupported `Match` blocks;
- invalid retry values;
- administrative principal restrictions;
- deterministic finding IDs;
- bounded risk scoring;
- management-network alignment;
- metrics consistency;
- report validation guidance.

CI is configured to compile the source, run the unit tests, generate a report from the synthetic fixture, and verify that the report is non-empty. The workflow uses `contents: read` only.

## Security design principles

- **Offline by default:** no host connection or active probing.
- **Fail closed:** unsupported `Match` semantics are rejected rather than guessed.
- **Explicit policy:** reviewers can see exactly which directives are evaluated.
- **Evidence-oriented:** findings record the observed configuration state.
- **Deterministic:** repeated identical evidence produces stable identifiers.
- **Non-destructive:** there is no remediation execution logic.
- **No sensitive data:** repository fixtures are fictional and contain no credentials or private keys.

## Limitations

This is a portfolio lab, not a complete OpenSSH compliance scanner. It does not:

- expand `Include` directives;
- evaluate `Match` blocks;
- call `sshd -T` or inspect effective runtime configuration;
- inspect PAM, sudoers, firewall, EDR, SIEM, or identity-provider configuration;
- evaluate negotiated cryptographic algorithms;
- prove that configuration was deployed successfully;
- establish exploitability or compromise.

A production implementation should integrate effective-configuration evidence, platform baselines, asset metadata, exception governance, and controlled validation procedures.

## Skills demonstrated

- Python security automation
- defensive configuration analysis
- secure parser design
- fail-closed validation
- deterministic security findings
- risk prioritization
- MITRE ATT&CK contextualization
- remediation governance
- validation and closure criteria
- unit testing
- CI/CD security controls
- technical security documentation
- recruiter-facing risk communication

## Roadmap

Planned safe extensions include:

- configurable policy profiles for different administrative tiers;
- machine-readable JSON report output;
- configuration-diff support for pre/post-remediation comparison;
- cryptographic-policy evaluation from supplied effective configuration;
- exception-register schema with expiry validation;
- baseline mappings to recognized SSH hardening guidance;
- signed assessment artifacts for change-control traceability.

## Ethics and scope

Use this project only with synthetic data or configuration from systems you are authorized to assess. Do not commit credentials, private keys, confidential inventories, employer/client evidence, or production secrets.
