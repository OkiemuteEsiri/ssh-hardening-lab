"""Offline SSH configuration posture assessment.

This module parses synthetic or exported sshd_config text and evaluates a
small, explicit defensive policy. It never connects to hosts and never changes
configuration.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from ipaddress import ip_network
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class Finding:
    control: str
    severity: str
    title: str
    evidence: str
    recommendation: str
    mitre: tuple[str, ...]

    @property
    def finding_id(self) -> str:
        material = f"{self.control}|{self.severity}|{self.title}|{self.evidence}"
        return "SSH-" + sha256(material.encode()).hexdigest()[:12].upper()


DEFAULT_POLICY = {
    "PermitRootLogin": {"allowed": {"no"}, "severity": "high"},
    "PasswordAuthentication": {"allowed": {"no"}, "severity": "high"},
    "PubkeyAuthentication": {"allowed": {"yes"}, "severity": "medium"},
    "PermitEmptyPasswords": {"allowed": {"no"}, "severity": "critical"},
    "X11Forwarding": {"allowed": {"no"}, "severity": "low"},
    "AllowTcpForwarding": {"allowed": {"no", "local"}, "severity": "medium"},
}


def parse_config(text: str) -> dict[str, str]:
    """Parse global sshd_config directives.

    Match blocks are rejected because inheriting Match semantics incorrectly
    would create false assurance. Duplicate global directives use the last
    value, matching common OpenSSH configuration behavior.
    """
    config: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, *rest = line.split()
        if key.lower() == "match":
            raise ValueError("Match blocks are not supported by this offline parser")
        if not rest:
            raise ValueError(f"directive has no value: {key}")
        config[key] = " ".join(rest)
    return config


def _finding(control: str, severity: str, title: str, evidence: str, recommendation: str, mitre: tuple[str, ...]) -> Finding:
    return Finding(control, severity, title, evidence, recommendation, mitre)


def assess(config: dict[str, str], approved_admin_cidrs: Iterable[str] = ()) -> list[Finding]:
    findings: list[Finding] = []
    for directive, rule in DEFAULT_POLICY.items():
        value = config.get(directive)
        if value is None:
            findings.append(_finding(
                directive, "medium", f"{directive} is not explicitly defined",
                "directive absent from supplied configuration",
                f"Set {directive} explicitly to an approved value: {', '.join(sorted(rule['allowed']))}.",
                ("T1021.004",),
            ))
            continue
        if value.lower() not in rule["allowed"]:
            mitre = ("T1078", "T1021.004") if directive in {"PermitRootLogin", "PasswordAuthentication", "PermitEmptyPasswords"} else ("T1021.004",)
            findings.append(_finding(
                directive, str(rule["severity"]), f"Insecure {directive} value",
                f"{directive} {value}",
                f"Change {directive} to one of: {', '.join(sorted(rule['allowed']))} after compatibility testing.",
                mitre,
            ))

    max_auth = config.get("MaxAuthTries")
    if max_auth is None:
        findings.append(_finding("MaxAuthTries", "medium", "Authentication retry limit not explicit", "MaxAuthTries absent", "Set MaxAuthTries to 4 or fewer and validate operational impact.", ("T1110",)))
    else:
        try:
            if int(max_auth) > 4:
                findings.append(_finding("MaxAuthTries", "medium", "Excessive authentication retries allowed", f"MaxAuthTries {max_auth}", "Reduce MaxAuthTries to 4 or fewer and monitor failed authentication telemetry.", ("T1110",)))
        except ValueError as exc:
            raise ValueError("MaxAuthTries must be an integer") from exc

    allow_users = config.get("AllowUsers")
    allow_groups = config.get("AllowGroups")
    if not allow_users and not allow_groups:
        findings.append(_finding("PrincipalRestriction", "medium", "No explicit SSH principal restriction", "AllowUsers/AllowGroups absent", "Restrict interactive SSH to approved administrative groups or principals.", ("T1078", "T1021.004")))

    listen = config.get("ListenAddress")
    if approved_admin_cidrs and listen:
        try:
            listen_ip = listen.split("%")[0]
            if not any(ip_network(c, strict=False).supernet_of(ip_network(f"{listen_ip}/32", strict=False)) or ip_network(c, strict=False) == ip_network(f"{listen_ip}/32", strict=False) for c in approved_admin_cidrs):
                findings.append(_finding("ListenAddress", "high", "SSH listener outside approved administrative ranges", f"ListenAddress {listen}", "Bind SSH only to approved management interfaces or enforce equivalent network policy.", ("T1133", "T1021.004")))
        except ValueError as exc:
            raise ValueError("invalid ListenAddress or approved CIDR") from exc

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(findings, key=lambda f: (severity_order[f.severity], f.control, f.finding_id))


def risk_score(findings: Iterable[Finding]) -> int:
    weights = {"critical": 35, "high": 22, "medium": 10, "low": 4}
    return min(100, sum(weights[f.severity] for f in findings))


def load_and_assess(path: str | Path, approved_admin_cidrs: Iterable[str] = ()) -> tuple[dict[str, str], list[Finding]]:
    config = parse_config(Path(path).read_text(encoding="utf-8"))
    return config, assess(config, approved_admin_cidrs)
