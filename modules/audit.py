"""
Audit Subsystem (CIS RHEL 8 Section 4.1, STIG audit controls)

Confirms auditd is installed, enabled, and configured to log the events
required by CIS / STIG (time-change, identity, login, perm-changes,
mounts, deletions, sudo, kernel modules, etc.).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from core.base import BaseAuditor, parse_keyvalue_config


# CIS-required audit rules. Each entry is (id, title, severity, regex-on-rules)
# The regex is matched against the concatenated 'auditctl -l' output.
_REQUIRED_RULES = [
    ("AUD-010", "time-change events not audited",
     "HIGH", r"-a always,exit -F arch=b64 -S (adjtimex|settimeofday|clock_settime)"),
    ("AUD-011", "user/group identity changes not audited (/etc/passwd, /etc/shadow, /etc/group)",
     "HIGH", r"-w /etc/(passwd|shadow|group)\b"),
    ("AUD-012", "login/logout audit not configured (/var/log/wtmp, btmp, lastlog)",
     "HIGH", r"-w /var/log/(wtmp|btmp|lastlog)\b"),
    ("AUD-013", "session-initiation events not audited",
     "MEDIUM", r"-w /var/(run|log)/utmp\b"),
    ("AUD-014", "DAC permission-change syscalls not audited (chmod/chown family)",
     "HIGH", r"-S\s+(chmod|fchmod|fchmodat|chown|fchown|fchownat|lchown)"),
    ("AUD-015", "unsuccessful file-access attempts not audited (EACCES, EPERM)",
     "MEDIUM", r"-F\s+exit=-EACCES|-F\s+exit=-EPERM"),
    ("AUD-016", "use of privileged commands not audited",
     "MEDIUM", r"-F\s+path=/usr/bin/sudo|-F\s+path=/usr/sbin/usermod"),
    ("AUD-017", "successful filesystem mounts not audited",
     "LOW", r"-S\s+mount\b"),
    ("AUD-018", "file deletions not audited (unlink/rename family)",
     "MEDIUM", r"-S\s+(unlink|unlinkat|rename|renameat)"),
    ("AUD-019", "sudoers / sudoers.d changes not audited",
     "HIGH", r"-w /etc/sudoers"),
    ("AUD-020", "kernel module load/unload not audited",
     "HIGH", r"-w /sbin/insmod|-w /sbin/modprobe|-S\s+(init_module|finit_module|delete_module)"),
    ("AUD-021", "audit configuration itself not made immutable (-e 2)",
     "MEDIUM", r"-e\s+2\b"),
]


class AuditAuditor(BaseAuditor):
    SUPPORTED_RHEL_MAJORS = {8, 9}
    CATEGORY = "Audit"

    def run_all_checks(self) -> List[Dict[str, Any]]:
        if not self.supports_rhel():
            return self._emit_skip_notice(self.CATEGORY)

        self._check_auditd_installed()
        self._check_auditd_running()
        self._check_log_storage()
        self._check_max_log_file()
        self._check_required_rules()
        return self.findings

    def _check_auditd_installed(self):
        rpm = self.bundle.read_command("rpm_qa")
        if not re.search(r"^audit\|", rpm, re.MULTILINE) and "audit-" not in rpm:
            self.finding(
                "AUD-001", "audit package not installed",
                self.SEVERITY_CRITICAL, self.CATEGORY,
                "The 'audit' RPM provides the kernel audit framework userspace. Without it, "
                "no audit events can be captured at all.",
                remediation="dnf install -y audit && systemctl enable --now auditd",
                references=["CIS RHEL 8 4.1.1.1"],
            )

    def _check_auditd_running(self):
        units = self.bundle.read_command("systemctl_unit_files")
        running = self.bundle.read_command("systemctl_running")
        if "auditd.service" not in units:
            return  # already covered by AUD-001
        if not re.search(r"^auditd\.service\s+enabled", units, re.MULTILINE):
            self.finding(
                "AUD-002", "auditd.service is not enabled at boot",
                self.SEVERITY_HIGH, self.CATEGORY,
                "auditd must be enabled so that audit events are captured from system boot, "
                "before any post-boot tampering.",
                remediation="systemctl enable auditd",
                references=["CIS RHEL 8 4.1.1.2"],
            )
        if "auditd.service" not in running:
            self.finding(
                "AUD-003", "auditd.service is not currently running",
                self.SEVERITY_HIGH, self.CATEGORY,
                "auditd is enabled but the service was not in the running unit list at collection time.",
                remediation="systemctl start auditd && journalctl -u auditd",
                references=["CIS RHEL 8 4.1.1.2"],
            )

    def _check_log_storage(self):
        text = self.bundle.read_etc_file("/etc/audit/auditd.conf")
        if not text:
            return
        cfg = parse_keyvalue_config(text, separator="=")
        action = cfg.get("space_left_action", "").lower()
        if action not in ("email", "exec", "single", "halt"):
            self.finding(
                "AUD-004", f"space_left_action is '{action}' (should alert / single-user)",
                self.SEVERITY_MEDIUM, self.CATEGORY,
                "When audit log space runs low, auditd should escalate (email, single-user, halt) "
                "rather than silently drop events.",
                remediation="Set 'space_left_action = email' (and configure action_mail_acct).",
                references=["CIS RHEL 8 4.1.2.3"],
            )
        admin_action = cfg.get("admin_space_left_action", "").lower()
        if admin_action not in ("single", "halt"):
            self.finding(
                "AUD-005", f"admin_space_left_action is '{admin_action}' (should be single/halt)",
                self.SEVERITY_HIGH, self.CATEGORY,
                "When admin_space_left is exhausted, auditd MUST stop or halt the system; otherwise "
                "audit events are silently lost.",
                remediation="Set 'admin_space_left_action = single' (or 'halt' for high-assurance).",
                references=["CIS RHEL 8 4.1.2.3"],
            )

    def _check_max_log_file(self):
        text = self.bundle.read_etc_file("/etc/audit/auditd.conf")
        if not text:
            return
        cfg = parse_keyvalue_config(text, separator="=")
        max_log = cfg.get("max_log_file", "")
        try:
            n = int(max_log)
            if n < 8:
                self.finding(
                    "AUD-006", f"max_log_file is {n} MB (recommended ≥ 8 MB)",
                    self.SEVERITY_LOW, self.CATEGORY,
                    "Very small audit log files rotate too quickly and can hide attacker activity.",
                    remediation="Set 'max_log_file = 8' (or higher) in /etc/audit/auditd.conf.",
                    references=["CIS RHEL 8 4.1.2.1"],
                )
        except ValueError:
            pass

    def _check_required_rules(self):
        rules = self.bundle.read_command("auditctl_rules")
        if not rules.strip():
            self.finding(
                "AUD-007", "auditctl -l returned no rules",
                self.SEVERITY_HIGH, self.CATEGORY,
                "No audit rules are loaded in the running kernel. /etc/audit/rules.d may exist but "
                "augenrules has not been run since boot.",
                remediation="augenrules --load && systemctl restart auditd",
                references=["CIS RHEL 8 4.1.3"],
            )
            return
        for cid, title, sev_str, pattern in _REQUIRED_RULES:
            if not re.search(pattern, rules):
                sev_map = {"CRITICAL": self.SEVERITY_CRITICAL, "HIGH": self.SEVERITY_HIGH,
                           "MEDIUM": self.SEVERITY_MEDIUM, "LOW": self.SEVERITY_LOW}
                self.finding(
                    cid, f"Required audit rule missing: {title}",
                    sev_map.get(sev_str, self.SEVERITY_MEDIUM), self.CATEGORY,
                    f"CIS / STIG requires audit rules matching pattern: {pattern}. "
                    "This event class is not currently being recorded.",
                    remediation=f"Add the appropriate rule to /etc/audit/rules.d/*.rules and reload with 'augenrules --load'.",
                    references=["CIS RHEL 8 4.1.3", "STIG RHEL-08-030xxx"],
                )
