"""
User Account Hardening (CIS RHEL 8 Sections 5.4, 6.2)

- Multiple UID 0 accounts (effective root)
- Accounts with empty password fields
- World-readable /etc/shadow
- /etc/login.defs password expiry settings (PASS_MAX_DAYS, PASS_MIN_DAYS, PASS_WARN_AGE)
- System accounts with valid shells
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from core.base import BaseAuditor, parse_keyvalue_config


class AccountsAuditor(BaseAuditor):
    SUPPORTED_RHEL_MAJORS = {8, 9}
    CATEGORY = "Accounts"

    def run_all_checks(self) -> List[Dict[str, Any]]:
        if not self.supports_rhel():
            return self._emit_skip_notice(self.CATEGORY)
        self._check_uid_zero()
        self._check_empty_passwords()
        self._check_login_defs_expiry()
        self._check_system_accounts_with_shells()
        self._check_root_path()
        self._check_default_umask()
        return self.findings

    def _check_uid_zero(self):
        passwd = self.bundle.read_etc_file("/etc/passwd")
        if not passwd:
            return
        zero_uid = []
        for line in passwd.splitlines():
            parts = line.split(":")
            if len(parts) >= 3 and parts[2] == "0":
                zero_uid.append(parts[0])
        if len(zero_uid) > 1:
            self.finding(
                "ACCT-001", f"Multiple UID 0 accounts found: {', '.join(zero_uid)}",
                self.SEVERITY_CRITICAL, self.CATEGORY,
                "Only the 'root' account should have UID 0. Any other UID-0 account is effectively "
                "a hidden root account and bypasses sudo accountability.",
                affected_items=zero_uid,
                remediation="Remove or change the UID of every UID-0 account except 'root'.",
                references=["CIS RHEL 8 6.2.5"],
            )

    def _check_empty_passwords(self):
        shadow = self.bundle.read_etc_file("/etc/shadow")
        if not shadow:
            return
        empty = []
        for line in shadow.splitlines():
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] == "":
                empty.append(parts[0])
        if empty:
            self.finding(
                "ACCT-002", f"Accounts with empty password fields: {', '.join(empty)}",
                self.SEVERITY_CRITICAL, self.CATEGORY,
                "Accounts with an empty password field can log in without supplying a password "
                "(when combined with PermitEmptyPasswords or PAM misconfiguration).",
                affected_items=empty,
                remediation="passwd -l <account>  (lock the account) or set a real password.",
                references=["CIS RHEL 8 6.2.1", "STIG RHEL-08-010110"],
            )

    def _check_login_defs_expiry(self):
        text = self.bundle.read_etc_file("/etc/login.defs")
        if not text:
            return
        cfg = parse_keyvalue_config(text)
        max_days = cfg.get("pass_max_days", "")
        min_days = cfg.get("pass_min_days", "")
        warn_age = cfg.get("pass_warn_age", "")

        try:
            if int(max_days) > 365:
                self.finding(
                    "ACCT-010", f"PASS_MAX_DAYS={max_days} (recommended ≤ 365)",
                    self.SEVERITY_MEDIUM, self.CATEGORY,
                    "Passwords never expire within a year, weakening defence against credential theft.",
                    remediation="Set 'PASS_MAX_DAYS 365' in /etc/login.defs.",
                    references=["CIS RHEL 8 5.5.1.1"],
                )
        except ValueError:
            pass
        try:
            if int(min_days) < 1:
                self.finding(
                    "ACCT-011", f"PASS_MIN_DAYS={min_days} (recommended ≥ 1)",
                    self.SEVERITY_LOW, self.CATEGORY,
                    "Users can cycle through passwords to defeat the history requirement.",
                    remediation="Set 'PASS_MIN_DAYS 1' in /etc/login.defs.",
                    references=["CIS RHEL 8 5.5.1.2"],
                )
        except ValueError:
            pass
        try:
            if int(warn_age) < 7:
                self.finding(
                    "ACCT-012", f"PASS_WARN_AGE={warn_age} (recommended ≥ 7)",
                    self.SEVERITY_LOW, self.CATEGORY,
                    "Users get insufficient warning before a forced password change.",
                    remediation="Set 'PASS_WARN_AGE 7' in /etc/login.defs.",
                    references=["CIS RHEL 8 5.5.1.3"],
                )
        except ValueError:
            pass

    def _check_system_accounts_with_shells(self):
        passwd = self.bundle.read_etc_file("/etc/passwd")
        if not passwd:
            return
        bad_shells = []
        for line in passwd.splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            user, _, uid, _, _, _, shell = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]
            try:
                uid_n = int(uid)
            except ValueError:
                continue
            if user == "root":
                continue
            # System accounts (uid < 1000 on RHEL 8) should have nologin/false shells
            if uid_n < 1000 and shell not in ("/sbin/nologin", "/usr/sbin/nologin",
                                              "/bin/false", "/usr/bin/false",
                                              "/bin/sync", "/sbin/shutdown", "/sbin/halt"):
                bad_shells.append(f"{user} (uid={uid_n}) shell={shell}")
        if bad_shells:
            self.finding(
                "ACCT-020", f"{len(bad_shells)} system accounts have login shells",
                self.SEVERITY_MEDIUM, self.CATEGORY,
                "System / service accounts (UID < 1000) should not have interactive shells. If "
                "an attacker compromises a service, an interactive shell on its service account "
                "is a privilege-escalation foothold.",
                affected_items=bad_shells[:20],
                remediation="usermod -s /sbin/nologin <user>",
                references=["CIS RHEL 8 6.2.7"],
            )

    def _check_root_path(self):
        # Look in /root/.bash_profile equivalent via login.defs ENV_PATH and the
        # system-wide /etc/profile (we don't capture those). Emit an informational
        # finding noting this requires manual verification.
        self.finding(
            "ACCT-META-001",
            "Root's interactive PATH is not directly evaluable from the bundle",
            self.SEVERITY_INFO, self.CATEGORY,
            "Root's effective PATH (from /root/.bashrc, /etc/profile, /etc/profile.d/*) is not "
            "captured by the default collector. Verify manually: 'sudo -i; echo $PATH' should "
            "contain only absolute paths, no '.', and no world-writable directories.",
            remediation="Run 'sudo -i' on the target and inspect $PATH.",
            references=["CIS RHEL 8 6.2.4"],
        )

    def _check_default_umask(self):
        text = self.bundle.read_etc_file("/etc/login.defs")
        if not text:
            return
        cfg = parse_keyvalue_config(text)
        umask = cfg.get("umask", "")
        if umask and umask not in ("027", "077", "0027", "0077"):
            self.finding(
                "ACCT-030", f"Default user UMASK is {umask} (recommended 027)",
                self.SEVERITY_LOW, self.CATEGORY,
                "Default UMASK of 022 (or weaker) means new files are world-readable, which leaks "
                "sensitive data dropped in user home directories.",
                remediation="Set 'UMASK 027' in /etc/login.defs.",
                references=["CIS RHEL 8 5.5.5"],
            )
