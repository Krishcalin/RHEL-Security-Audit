#!/usr/bin/env python3
"""
RHEL 8 Offline Security Audit Scanner
======================================
Offline analyzer for the bundle produced by collector/collect_rhel8.sh.

Usage:
    # Audit a bundle (tar.gz produced by the collector)
    python rhel8_scanner.py --bundle rhel8-audit-host-2026.tar.gz --output report.html

    # Audit a directory (unpacked bundle, useful for development)
    python rhel8_scanner.py --bundle ./unpacked/ --output report.html

    # Subset of modules
    python rhel8_scanner.py --bundle b.tar.gz --modules ssh selinux cve

    # Severity floor
    python rhel8_scanner.py --bundle b.tar.gz --severity HIGH

Exit codes:
    0  - no CRITICAL or HIGH findings
    1  - one or more CRITICAL/HIGH findings (suitable for CI gating)
    2  - usage error / bundle not found

Python 3.8+ stdlib only — no third-party dependencies.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List

# Reconfigure stdout/stderr to UTF-8 with errors='replace' so the banner's
# unicode characters and any non-ASCII finding text don't crash on Windows
# cp1252 consoles when run from the audit workstation.
for _stream in (sys.stdout, sys.stderr):
    _reconfigure = getattr(_stream, "reconfigure", None)
    if callable(_reconfigure):
        try:
            _reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass

from core import __version__
from core.bundle import Bundle
from core.report import ReportGenerator
from modules.ssh import SshAuditor
from modules.selinux import SelinuxAuditor
from modules.audit import AuditAuditor
from modules.pam import PamAuditor
from modules.sysctl import SysctlAuditor
from modules.firewall import FirewallAuditor
from modules.services import ServiceAuditor
from modules.filesystem import FilesystemAuditor
from modules.sudo_cron import SudoCronAuditor
from modules.accounts import AccountsAuditor
from modules.cve import CveAuditor


MODULE_MAP = {
    "ssh":        ("SSH Daemon", SshAuditor),
    "selinux":    ("SELinux", SelinuxAuditor),
    "audit":      ("Audit Subsystem", AuditAuditor),
    "pam":        ("PAM / Authentication", PamAuditor),
    "sysctl":     ("Kernel / Network Parameters", SysctlAuditor),
    "firewall":   ("Firewall / Exposure", FirewallAuditor),
    "services":   ("Services", ServiceAuditor),
    "filesystem": ("Filesystem", FilesystemAuditor),
    "sudo":       ("Sudo / Cron", SudoCronAuditor),
    "accounts":   ("Accounts", AccountsAuditor),
    "cve":        ("CVE Detection", CveAuditor),
}


def banner():
    print(f"""
  ===============================================================
    RHEL 8 Offline Security Audit Scanner v{__version__}
    CIS RHEL 8 Benchmark + DISA STIG + Red Hat PSIRT CVEs
  ===============================================================
""")


def main(argv=None) -> int:
    banner()

    p = argparse.ArgumentParser(
        description=f"Offline RHEL 8 security audit scanner v{__version__}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python rhel8_scanner.py --bundle host.tar.gz --output report.html
  python rhel8_scanner.py --bundle ./sample_bundle/ --modules ssh cve
  python rhel8_scanner.py --bundle b.tar.gz --severity HIGH --output ci.html
""",
    )
    p.add_argument("--bundle", required=True,
                   help="Path to a collector bundle (.tar.gz) or unpacked directory")
    p.add_argument("--output", default="rhel8_security_report.html",
                   help="HTML report output path (default: rhel8_security_report.html)")
    p.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "ALL"],
                   default="ALL", help="Minimum severity to include (default: ALL)")
    p.add_argument("--modules", nargs="+",
                   choices=list(MODULE_MAP.keys()) + ["all"], default=["all"],
                   help="Modules to run (default: all)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)

    bundle_path = Path(args.bundle)
    if not bundle_path.exists():
        print(f"[ERROR] Bundle not found: {bundle_path}", file=sys.stderr)
        return 2

    print(f"[*] Loading bundle: {bundle_path}")
    try:
        bundle = Bundle.open(bundle_path)
    except Exception as exc:
        print(f"[ERROR] Failed to read bundle: {exc}", file=sys.stderr)
        return 2

    print(f"[*] Host: {bundle.hostname}  RHEL: {bundle.rhel_version or 'unknown'}  "
          f"Files: {len(bundle._files)}  Source: {bundle.source}")

    selected = list(MODULE_MAP.keys()) if "all" in args.modules else args.modules
    print(f"[*] Running modules: {', '.join(selected)}\n")

    all_findings: List[Dict[str, Any]] = []
    for key in selected:
        label, cls = MODULE_MAP[key]
        try:
            auditor = cls(bundle)
            findings = auditor.run_all_checks()
            for f in findings:
                f["device"] = bundle.hostname
                f["module"] = key
            all_findings.extend(findings)
            print(f"  [{key:11}] {label:32} {len(findings):>4} finding(s)")
        except Exception as exc:
            print(f"  [{key:11}] {label:32} FAILED: {exc}")

    # Severity filter
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    if args.severity != "ALL":
        floor = sev_order[args.severity]
        all_findings = [f for f in all_findings if sev_order.get(f["severity"], 4) <= floor]

    # Summary counts
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in all_findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    # Report
    meta = {
        "hostname": bundle.hostname,
        "rhel_version": bundle.rhel_version,
        "kernel": bundle.meta.get("kernel", ""),
        "collected_at": bundle.meta.get("collected_at", ""),
        "bundle_source": str(bundle.source),
        "modules_run": selected,
    }
    print(f"\n[*] Writing report: {args.output}")
    ReportGenerator(all_findings, meta).generate(args.output)

    print(f"""
  ===============================================================
    SCAN COMPLETE
    Total findings : {len(all_findings)}
    CRITICAL : {counts['CRITICAL']}    HIGH : {counts['HIGH']}    MEDIUM : {counts['MEDIUM']}
    LOW      : {counts['LOW']}         INFO : {counts['INFO']}
    Report   : {args.output}
  ===============================================================
""")

    return 1 if (counts["CRITICAL"] or counts["HIGH"]) else 0


if __name__ == "__main__":
    sys.exit(main())
