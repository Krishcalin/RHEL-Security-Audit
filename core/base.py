"""
Base auditor pattern for the RHEL 8 offline scanner.

Every module subclasses BaseAuditor, declares its SUPPORTED_RHEL_MAJORS, and
implements run_all_checks(). Findings carry the same schema as the Cisco /
Fortinet sister tools so the report generator and any future export sink
(JSON, CSV, SARIF) reads from a single shape.
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional, Set

from .bundle import Bundle


class BaseAuditor:
    SEVERITY_CRITICAL = "CRITICAL"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_LOW = "LOW"
    SEVERITY_INFO = "INFO"

    # Set on subclasses if the module is RHEL-major-specific. None means run on
    # any detected major (or when the bundle's RHEL version can't be parsed).
    # Today this scanner is targeted at RHEL 8; the field is here so adding
    # RHEL 9 / RHEL 10 modules later doesn't require touching the runner.
    SUPPORTED_RHEL_MAJORS: Optional[Set[int]] = None

    def __init__(self, bundle: Bundle, baseline: Optional[Dict[str, Any]] = None):
        self.bundle = bundle
        self.baseline = baseline or {}
        self.findings: List[Dict[str, Any]] = []

    # ---------------------------------------------------------------- emit
    def finding(
        self,
        check_id: str,
        title: str,
        severity: str,
        category: str,
        description: str,
        affected_items: Optional[List[str]] = None,
        remediation: str = "",
        references: Optional[List[str]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        f = {
            "check_id": check_id,
            "title": title,
            "severity": severity,
            "category": category,
            "description": description,
            "affected_items": affected_items or [],
            "affected_count": len(affected_items) if affected_items else 0,
            "remediation": remediation,
            "references": references or [],
            "details": details or {},
            "timestamp": datetime.datetime.now().isoformat(),
        }
        self.findings.append(f)
        return f

    # ---------------------------------------------------------------- guards
    def supports_rhel(self) -> bool:
        """Return False if SUPPORTED_RHEL_MAJORS excludes the detected major."""
        if self.SUPPORTED_RHEL_MAJORS is None:
            return True
        major = self.bundle.rhel_major
        if major is None:
            # Be permissive: if we can't detect the version, run the checks
            # rather than silently skip. The operator still gets results.
            return True
        return major in self.SUPPORTED_RHEL_MAJORS

    def _emit_skip_notice(self, category: str) -> List[Dict[str, Any]]:
        majors = sorted(self.SUPPORTED_RHEL_MAJORS) if self.SUPPORTED_RHEL_MAJORS else "any"
        self.finding(
            check_id=f"{category.split()[0].upper()}-META-001",
            title=f"{category} checks skipped — RHEL major mismatch",
            severity=self.SEVERITY_INFO,
            category=category,
            description=(
                f"This module targets RHEL major version(s) {majors}. The "
                f"bundle reports RHEL {self.bundle.rhel_version}, so these "
                f"checks were skipped."
            ),
            remediation="Use a scanner module targeted at the bundle's RHEL major.",
        )
        return self.findings

    # ---------------------------------------------------------------- subclass
    def run_all_checks(self) -> List[Dict[str, Any]]:
        raise NotImplementedError

    # ---------------------------------------------------------------- baseline
    def get_baseline(self, key: str, default: Any) -> Any:
        return self.baseline.get(key, default)


# ---------------------------------------------------------------------------
# Small text-parsing helpers shared by hardening modules
# ---------------------------------------------------------------------------

def parse_keyvalue_config(text: str, separator: Optional[str] = None) -> Dict[str, str]:
    """Parse a typical Linux 'key value' config file (sshd_config, login.defs,
    sysctl.conf, etc.) into a dict of the last value seen per key.

    Treats lines starting with '#' or ';' as comments, strips inline trailing
    comments after the value, and lowercases the key for case-insensitive
    lookups (Linux config files are mostly case-insensitive on keys).
    """
    result: Dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        # Strip trailing comments (' # ...' or tab '#')
        # but NOT '#' inside quoted strings — config files rarely use them.
        if "#" in line:
            line = line.split("#", 1)[0].rstrip()
            if not line:
                continue
        if separator:
            if separator not in line:
                continue
            key, _, value = line.partition(separator)
        else:
            parts = line.split(None, 1)
            if len(parts) < 2:
                # Treat a bare key (no value) as empty string
                key, value = parts[0], ""
            else:
                key, value = parts[0], parts[1]
        result[key.strip().lower()] = value.strip()
    return result


def parse_sysctl_runtime(text: str) -> Dict[str, str]:
    """Parse `sysctl -a` output into {key: value}. Lines look like:
        net.ipv4.ip_forward = 0
    """
    result: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        result[key.strip()] = value.strip()
    return result
