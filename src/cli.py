"""Command-line interface for offline SSH hardening assessment."""
from __future__ import annotations

import argparse
from pathlib import Path

from reporting import render_markdown
from ssh_audit import load_and_assess


def main() -> int:
    parser = argparse.ArgumentParser(description="Assess an exported sshd_config without connecting to a host.")
    parser.add_argument("config", help="Path to sshd_config text")
    parser.add_argument("--target", default="synthetic-host", help="Display label only")
    parser.add_argument("--admin-cidr", action="append", default=[], help="Approved management CIDR; may be repeated")
    parser.add_argument("--output", help="Write Markdown report to this path")
    args = parser.parse_args()

    _, findings = load_and_assess(args.config, args.admin_cidr)
    report = render_markdown(args.target, findings)
    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report, encoding="utf-8")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
