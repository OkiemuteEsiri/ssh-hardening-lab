# Architecture

## Purpose

This project demonstrates defensive SSH configuration assessment using exported configuration only. It is intentionally offline: there is no network scanner, credential use, shell execution, host mutation, or service restart logic.

## Components

```text
exported sshd_config
        |
        v
+-------------------+
| strict parser     |
| src/ssh_audit.py  |
+---------+---------+
          |
          v
+-------------------+
| policy evaluator  |
| deterministic IDs |
| ATT&CK context    |
+---------+---------+
          |
          +--------------------+
          |                    |
          v                    v
+------------------+   +------------------+
| risk prioritizer |   | metrics/reporting|
+---------+--------+   +---------+--------+
          |                      |
          +----------+-----------+
                     v
              Markdown report
```

## Trust boundaries

1. **Evidence boundary** — input must be an intentionally exported text configuration. The tool does not retrieve files from endpoints.
2. **Parser boundary** — unsupported `Match` blocks fail closed rather than being interpreted incorrectly.
3. **Policy boundary** — controls are explicit and deterministic; findings do not claim exploitation or compromise.
4. **Reporting boundary** — target labels are display metadata only and are never resolved or contacted.

## Design choices

- Python standard library only to keep the lab auditable and portable.
- Immutable findings to prevent accidental mutation during reporting.
- Deterministic SHA-derived finding IDs so repeated assessments can be compared safely.
- Bounded risk scoring for prioritization, with severities remaining visible independently of the aggregate score.
- ATT&CK mappings are threat-model context only.

## Limitations

The parser evaluates global directives only and deliberately rejects `Match` blocks. It does not expand `Include` directives, query `sshd -T`, validate PAM configuration, inspect firewall state, assess cryptographic algorithm negotiation, or prove effective runtime configuration. Production validation should use platform-native effective-configuration checks and change-control processes.
