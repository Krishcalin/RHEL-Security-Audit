"""
SELinux Hardening (CIS RHEL 8 Section 1.6, STIG SELinux controls)

Audits /etc/selinux/config plus the runtime sestatus / getenforce captures
to confirm SELinux is installed, enabled at boot, and in enforcing mode.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from core.base import BaseAuditor, parse_keyvalue_config


class SelinuxAuditor(BaseAuditor):
    SUPPORTED_RHEL_MAJORS = {8, 9}
    CATEGORY = "SELinux"

    def run_all_checks(self) -> List[Dict[str, Any]]:
        if not self.supports_rhel():
            return self._emit_skip_notice(self.CATEGORY)

        self._check_grub_selinux_disabled()
        self._check_config_file()
        self._check_runtime_state()
        self._check_policy()
        return self.findings

    def _check_grub_selinux_disabled(self):
        cmdline = self.bundle.read_command("boot_cmdline")
        if re.search(r"\bselinux=0\b", cmdline) or re.search(r"\benforcing=0\b", cmdline):
            self.finding(
                "SEL-001", "SELinux disabled on kernel command line",
                self.SEVERITY_CRITICAL, self.CATEGORY,
                "The kernel was booted with selinux=0 or enforcing=0, completely disabling the "
                "mandatory access control layer. SELinux is the primary RHEL exploit-mitigation "
                "for service compromise.",
                affected_items=[cmdline.strip()],
                remediation="Edit /etc/default/grub, remove 'selinux=0'/'enforcing=0' from GRUB_CMDLINE_LINUX, regenerate grub.cfg, and reboot.",
                references=["CIS RHEL 8 1.6.1.1", "STIG RHEL-08-010170"],
            )

    def _check_config_file(self):
        text = self.bundle.read_etc_file("/etc/selinux/config")
        if not text:
            self.finding(
                "SEL-META-001", "/etc/selinux/config missing from bundle",
                self.SEVERITY_INFO, self.CATEGORY,
                "SELinux state at boot cannot be evaluated without /etc/selinux/config.",
                remediation="Re-run the collector as root.",
            )
            return
        cfg = parse_keyvalue_config(text, separator="=")
        state = cfg.get("selinux", "").lower()
        if state in ("disabled", "permissive"):
            sev = self.SEVERITY_CRITICAL if state == "disabled" else self.SEVERITY_HIGH
            self.finding(
                "SEL-002", f"SELinux state in /etc/selinux/config is '{state}'",
                sev, self.CATEGORY,
                f"SELINUX={state} means the system will boot {'without SELinux at all' if state == 'disabled' else 'with policy logged but not enforced'}.",
                remediation="Set 'SELINUX=enforcing' in /etc/selinux/config.",
                references=["CIS RHEL 8 1.6.1.3", "STIG RHEL-08-010171"],
            )
        policy = cfg.get("selinuxtype", "").lower()
        if policy and policy not in ("targeted", "mls"):
            self.finding(
                "SEL-003", f"Non-standard SELinux policy type '{policy}'",
                self.SEVERITY_MEDIUM, self.CATEGORY,
                f"SELINUXTYPE={policy} is not a Red Hat-supplied policy.",
                remediation="Set 'SELINUXTYPE=targeted' unless an MLS deployment is required.",
                references=["CIS RHEL 8 1.6.1.4"],
            )

    def _check_runtime_state(self):
        if not self.bundle.has_command("getenforce"):
            return
        mode = self.bundle.read_command("getenforce").strip().splitlines()
        mode_str = mode[-1].strip().lower() if mode else ""
        if mode_str == "disabled":
            self.finding(
                "SEL-004", "Runtime SELinux mode is Disabled",
                self.SEVERITY_CRITICAL, self.CATEGORY,
                "getenforce reports 'Disabled' — SELinux is not active on the running system.",
                remediation="setenforce 1; ensure /etc/selinux/config has SELINUX=enforcing and reboot.",
                references=["CIS RHEL 8 1.6.1.5"],
            )
        elif mode_str == "permissive":
            self.finding(
                "SEL-005", "Runtime SELinux mode is Permissive",
                self.SEVERITY_HIGH, self.CATEGORY,
                "SELinux is logging policy violations but not enforcing them.",
                remediation="Run 'setenforce 1' and fix /etc/selinux/config to make it persistent.",
                references=["CIS RHEL 8 1.6.1.5"],
            )

    def _check_policy(self):
        sestatus = self.bundle.read_command("sestatus")
        if "Loaded policy name:" in sestatus:
            m = re.search(r"Loaded policy name:\s*(\S+)", sestatus)
            if m and m.group(1).lower() not in ("targeted", "mls"):
                self.finding(
                    "SEL-006", f"Loaded SELinux policy is '{m.group(1)}'",
                    self.SEVERITY_MEDIUM, self.CATEGORY,
                    "The loaded policy is non-standard for RHEL.",
                    remediation="Switch to the 'targeted' policy unless MLS is required.",
                    references=["CIS RHEL 8 1.6.1.4"],
                )
