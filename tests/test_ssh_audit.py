import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ssh_audit import assess, parse_config, risk_score
from reporting import metrics, render_markdown


class SSHHardeningTests(unittest.TestCase):
    def test_secure_baseline_has_no_policy_findings(self):
        cfg = parse_config("""
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
AllowTcpForwarding local
MaxAuthTries 3
AllowGroups ssh-admins
""")
        self.assertEqual(assess(cfg), [])

    def test_root_login_is_high(self):
        findings = assess(parse_config("PermitRootLogin yes\nPasswordAuthentication no\nPubkeyAuthentication yes\nPermitEmptyPasswords no\nX11Forwarding no\nAllowTcpForwarding no\nMaxAuthTries 3\nAllowGroups admins"))
        root = next(f for f in findings if f.control == "PermitRootLogin")
        self.assertEqual(root.severity, "high")
        self.assertIn("T1078", root.mitre)

    def test_empty_passwords_are_critical(self):
        cfg = parse_config("PermitRootLogin no\nPasswordAuthentication no\nPubkeyAuthentication yes\nPermitEmptyPasswords yes\nX11Forwarding no\nAllowTcpForwarding no\nMaxAuthTries 3\nAllowGroups admins")
        finding = next(f for f in assess(cfg) if f.control == "PermitEmptyPasswords")
        self.assertEqual(finding.severity, "critical")

    def test_missing_directive_fails_closed_as_finding(self):
        findings = assess({"MaxAuthTries": "3", "AllowGroups": "admins"})
        self.assertTrue(any(f.control == "PasswordAuthentication" for f in findings))

    def test_match_blocks_are_rejected(self):
        with self.assertRaises(ValueError):
            parse_config("Match User alice\nPasswordAuthentication yes")

    def test_invalid_max_auth_tries_is_rejected(self):
        with self.assertRaises(ValueError):
            assess({"MaxAuthTries": "many"})

    def test_principal_restriction_is_required(self):
        findings = assess(parse_config("PermitRootLogin no\nPasswordAuthentication no\nPubkeyAuthentication yes\nPermitEmptyPasswords no\nX11Forwarding no\nAllowTcpForwarding no\nMaxAuthTries 3"))
        self.assertTrue(any(f.control == "PrincipalRestriction" for f in findings))

    def test_finding_ids_are_deterministic(self):
        cfg = parse_config("PermitRootLogin yes\nPasswordAuthentication no\nPubkeyAuthentication yes\nPermitEmptyPasswords no\nX11Forwarding no\nAllowTcpForwarding no\nMaxAuthTries 3\nAllowGroups admins")
        first = assess(cfg)[0].finding_id
        second = assess(cfg)[0].finding_id
        self.assertEqual(first, second)

    def test_risk_score_is_bounded(self):
        cfg = {}
        self.assertLessEqual(risk_score(assess(cfg)), 100)

    def test_listener_outside_admin_range_is_high(self):
        cfg = parse_config("PermitRootLogin no\nPasswordAuthentication no\nPubkeyAuthentication yes\nPermitEmptyPasswords no\nX11Forwarding no\nAllowTcpForwarding no\nMaxAuthTries 3\nAllowGroups admins\nListenAddress 10.1.2.3")
        findings = assess(cfg, ["10.50.0.0/16"])
        listener = next(f for f in findings if f.control == "ListenAddress")
        self.assertEqual(listener.severity, "high")

    def test_metrics_are_consistent(self):
        findings = assess({})
        m = metrics(findings)
        self.assertEqual(m["total"], len(findings))
        self.assertEqual(m["risk_score"], risk_score(findings))

    def test_report_contains_validation_guidance(self):
        report = render_markdown("lab-host", assess({}))
        self.assertIn("Validation expectations", report)
        self.assertIn("lab-host", report)


if __name__ == "__main__":
    unittest.main()
