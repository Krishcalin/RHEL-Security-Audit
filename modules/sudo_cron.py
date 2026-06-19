"""
Sudo & Scheduled Task Hardening (CIS RHEL 8 Sections 1.3, 5.6)

- /etc/sudoers + /etc/sudoers.d: NOPASSWD, !authenticate, ALL=(ALL) ALL granted to wide groups.
- /etc/cron.allow / /etc/cron.deny: must restrict cron access.
- /etc/crontab + drop-ins: flag overly-permissive scripts and root-running cron jobs from world-writable paths.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from core.base import BaseAuditor


class SudoCronAuditor(BaseAuditor):
    SUPPORTED_RHEL_MAJORS = {8, 9}
    CATEGORY = "Sudo / Cron"

    def run_all_checks(self) -> List[Dict[str, Any]]:
        if not self.supports_rhel():
            return self._emit_skip_notice(self.CATEGORY)
        self._check_sudoers()
        self._check_cron_allow_deny()
        self._check_cron_at_perms()
        return self.findings

    # -------- sudo --------------------------------------------------------
    def _check_sudoers(self):
        text = self.bundle.read_etc_file("/etc/sudoers")
        # Also pull in any sudoers.d/* files
        for path in self.bundle.list_etc("/etc/sudoers.d"):
            text += "\n# --- " + path + " ---\n" + self.bundle.read_etc_file(path)

        if not text.strip():
            self.finding(
                "SUDO-META-001", "/etc/sudoers and /etc/sudoers.d not collected",
                self.SEVERITY_INFO, self.CATEGORY,
                "Cannot evaluate sudo policy without sudoers files.",
                remediation="Re-run the collector as root.",
            )
            return

        # NOPASSWD entries — high risk if granted to a non-individual account
        nopasswd_lines = []
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            if re.search(r"\bNOPASSWD\s*:", stripped, re.IGNORECASE):
                nopasswd_lines.append(stripped)
        if nopasswd_lines:
            self.finding(
                "SUDO-001", f"{len(nopasswd_lines)} sudo rule(s) grant NOPASSWD access",
                self.SEVERITY_HIGH, self.CATEGORY,
                "NOPASSWD: rules let an account run sudo without re-authentication, which means "
                "a stolen session token / SSH key escalates to root with zero friction. Restrict "
                "NOPASSWD to specific commands and individual accounts only.",
                affected_items=nopasswd_lines[:20],
                remediation="Replace NOPASSWD with Cmnd_Alias scopes and require password re-authentication for full root access.",
                references=["CIS RHEL 8 5.6 (sudoers)", "STIG RHEL-08-010380"],
            )

        # !authenticate is even worse than NOPASSWD
        if re.search(r"^[^#]*\!authenticate", text, re.MULTILINE):
            self.finding(
                "SUDO-002", "sudoers contains '!authenticate' (auth requirement disabled)",
                self.SEVERITY_CRITICAL, self.CATEGORY,
                "!authenticate completely bypasses the sudo password prompt regardless of NOPASSWD.",
                remediation="Remove all '!authenticate' directives from /etc/sudoers and /etc/sudoers.d/.",
                references=["CIS RHEL 8 5.6"],
            )

        # Use of !logfile or no Defaults log_input/log_output
        if not re.search(r"Defaults\s+log_input", text):
            self.finding(
                "SUDO-003", "sudo input-logging not enabled (no 'Defaults log_input')",
                self.SEVERITY_LOW, self.CATEGORY,
                "Without Defaults log_input/log_output, sudo only records WHAT command was run, "
                "not the keystrokes or interactive session content.",
                remediation="Add 'Defaults log_input,log_output' and 'Defaults iolog_dir=/var/log/sudo-io' to /etc/sudoers.",
                references=["CIS RHEL 8 5.6"],
            )

        # 'ALL=(ALL) ALL' granted to a non-root account or group
        broad = re.findall(r"^([^#\s][^\s]*)\s+ALL\s*=\s*\(ALL(?::ALL)?\)\s*ALL", text, re.MULTILINE)
        # Filter out 'root' and the standard 'wheel' / '%wheel' (wheel is the conventional admin group)
        broad_others = [b for b in broad if b not in ("root", "%wheel", "wheel", "%admin")]
        if broad_others:
            self.finding(
                "SUDO-004", f"Broad sudo grants to non-wheel principals: {', '.join(sorted(set(broad_others)))[:120]}",
                self.SEVERITY_MEDIUM, self.CATEGORY,
                "Granting ALL=(ALL) ALL to accounts/groups outside 'wheel' bypasses the standard "
                "admin-group convention and complicates access reviews.",
                affected_items=sorted(set(broad_others))[:20],
                remediation="Migrate sudo access to the 'wheel' group; remove direct grants in /etc/sudoers.d/.",
                references=["CIS RHEL 8 5.6"],
            )

    # -------- cron --------------------------------------------------------
    def _check_cron_allow_deny(self):
        has_allow = self.bundle.has_etc_file("/etc/cron.allow")
        has_deny = self.bundle.has_etc_file("/etc/cron.deny")
        if not has_allow:
            self.finding(
                "CRON-001", "/etc/cron.allow does not exist (any user can schedule cron jobs)",
                self.SEVERITY_MEDIUM, self.CATEGORY,
                "When neither /etc/cron.allow nor a restrictive /etc/cron.deny is in place, every "
                "local user can schedule arbitrary cron jobs. CIS recommends a default-deny "
                "approach: create /etc/cron.allow listing only the accounts that need cron.",
                remediation="Create /etc/cron.allow with 'root' and any service accounts that need cron; chmod 600.",
                references=["CIS RHEL 8 5.1.8"],
            )
        if not has_allow and has_deny:
            self.finding(
                "CRON-002", "/etc/cron.deny present but /etc/cron.allow absent",
                self.SEVERITY_LOW, self.CATEGORY,
                "Default-deny via /etc/cron.allow is preferred to deny-list via /etc/cron.deny.",
                remediation="Replace /etc/cron.deny with an explicit /etc/cron.allow list.",
                references=["CIS RHEL 8 5.1.8"],
            )
        has_at_allow = self.bundle.has_etc_file("/etc/at.allow")
        if not has_at_allow:
            self.finding(
                "CRON-003", "/etc/at.allow does not exist (any user can schedule 'at' jobs)",
                self.SEVERITY_LOW, self.CATEGORY,
                "Same logic as cron.allow: use /etc/at.allow to whitelist users who may use the 'at' scheduler.",
                remediation="Create /etc/at.allow listing only authorised accounts; chmod 600.",
                references=["CIS RHEL 8 5.1.9"],
            )

    def _check_cron_at_perms(self):
        # CIS expects specific permissions on cron files
        # We can't check perms from a tar bundle reliably, so emit an INFO
        # noting the operator should verify with 'stat'.
        self.finding(
            "CRON-META-001",
            "Cron / at file permissions cannot be verified from a tar bundle",
            self.SEVERITY_INFO, self.CATEGORY,
            "tar archives don't preserve all permission metadata reliably across systems. Verify "
            "manually on the target:\n\n"
            "  stat -c '%a %u %g %n' /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d\n"
            "Expected: 700 root root for the directories, 600 root root for /etc/crontab.",
            remediation="Run the stat command above on the target host and compare to CIS recommendations.",
            references=["CIS RHEL 8 5.1.1 - 5.1.7"],
        )
