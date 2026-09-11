"""Markdown reporting for SSH posture assessments."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Iterable

from ssh_audit import Finding, risk_score


def metrics(findings: Iterable[Finding]) -> dict[str, int]:
    items = list(findings)
    counts = Counter(f.severity for f in items)
    return {
        "total": len(items),
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"],
        "risk_score": risk_score(items),
    }


def render_markdown(target: str, findings: Iterable[Finding]) -> str:
    items = list(findings)
    m = metrics(items)
    lines = [
        f"# SSH Hardening Assessment — {target}",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        "",
        "## Executive summary",
        "",
        f"- Findings: **{m['total']}**",
        f"- Risk score: **{m['risk_score']}/100**",
        f"- Critical / High / Medium / Low: **{m['critical']} / {m['high']} / {m['medium']} / {m['low']}**",
        "",
        "Risk scoring is a transparent lab prioritization aid, not a substitute for environment-specific threat modeling.",
        "",
        "## Findings",
        "",
    ]
    for finding in items:
        lines.extend([
            f"### {finding.finding_id} — {finding.title}",
            "",
            f"- **Severity:** {finding.severity.title()}",
            f"- **Control:** `{finding.control}`",
            f"- **Evidence:** `{finding.evidence}`",
            f"- **MITRE ATT&CK context:** {', '.join(finding.mitre)}",
            f"- **Remediation:** {finding.recommendation}",
            "",
        ])
    lines.extend([
        "## Validation expectations",
        "",
        "After remediation, re-export the effective SSH configuration, rerun the assessment, confirm the intended directive values, and validate authentication telemetry plus administrative access from approved management paths.",
        "",
    ])
    return "\n".join(lines)
