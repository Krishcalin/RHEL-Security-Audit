"""
PAM / Authentication (CIS RHEL 8 Section 5.3 - 5.4, STIG PAM controls)

Audits /etc/pam.d/* and /etc/security/pwquality.conf for password quality,
lockout, password reuse, and authentication-related settings.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from core.base import BaseAuditor, parse_keyvalue_config


class PamAuditor(BaseAuditor):
    SUPPORTED_RHEL_MAJORS = {8, 9}
    CATEGORY = "PAM / Authentication"

    def run_all_checks(self) -> List[Dict[str, Any]]:
        if not self.supports_rhel():
            return self._emit_skip_notice(self.CATEGORY)
        self._check_pwquality()
        self._check_pwhistory()
        self._check_faillock()
        self._check_password_hash_algo()
        self._check_su_pam_wheel()
        return self.findings

    def _check_pwquality(self):
        text = self.bundle.read_etc_file("/etc/security/pwquality.conf")
        if not text:
            self.finding(
                "PAM-META-001", "/etc/security/pwquality.conf missing",
                self.SEVERITY_INFO, self.CATEGORY,
                "Cannot evaluate password complexity policy.",
            )
            return
        cfg = parse_keyvalue_config(text, separator="=")
        rules = [
            ("minlen",  14, "minimum password length",                 "PAM-001"),
            ("dcredit", -1, "at least one digit required (dcredit ≤ -1)", "PAM-002"),
            ("ucredit", -1, "at least one uppercase required (ucredit ≤ -1)", "PAM-003"),
            ("lcredit", -1, "at least one lowercase required (lcredit ≤ -1)", "PAM-004"),
            ("ocredit", -1, "at least one special required (ocredit ≤ -1)", "PAM-005"),
        ]
        for key, threshold, desc, cid in rules:
            v = cfg.get(key, "")
            try:
                n = int(v)
            except ValueError:
                n = None
            if n is None or (key == "minlen" and n < threshold) or (key != "minlen" and n > threshold):
                self.finding(
                    cid, f"Password quality: {desc}",
                    self.SEVERITY_HIGH, self.CATEGORY,
                    f"pwquality.conf does not enforce {desc}. Currently: {key}={v or '(unset)'}.",
                    remediation=f"Set '{key} = {threshold}' in /etc/security/pwquality.conf.",
                    references=["CIS RHEL 8 5.4.1", "STIG RHEL-08-020110"],
                )

    def _check_pwhistory(self):
        # Check system-auth and password-auth for pam_pwhistory remember=5+
        for fname in ("system-auth", "password-auth"):
            path = f"/etc/pam.d/{fname}"
            text = self.bundle.read_etc_file(path)
            if not text:
                continue
            m = re.search(r"pam_pwhistory\.so.*remember=(\d+)", text)
            if not m:
                self.finding(
                    f"PAM-010-{fname}", f"Password reuse history not configured in {path}",
                    self.SEVERITY_MEDIUM, self.CATEGORY,
                    "pam_pwhistory should prevent the last N passwords from being reused.",
                    remediation=f"Add 'password requisite pam_pwhistory.so remember=5 use_authtok' to {path}.",
                    references=["CIS RHEL 8 5.4.3", "STIG RHEL-08-020220"],
                )
            elif int(m.group(1)) < 5:
                self.finding(
                    f"PAM-011-{fname}", f"Password history depth too small in {path} (remember={m.group(1)})",
                    self.SEVERITY_LOW, self.CATEGORY,
                    "Passwords are only being remembered for fewer than 5 cycles.",
                    remediation=f"Set 'remember=5' (or higher) on the pam_pwhistory.so line in {path}.",
                    references=["CIS RHEL 8 5.4.3"],
                )

    def _check_faillock(self):
        for fname in ("system-auth", "password-auth"):
            text = self.bundle.read_etc_file(f"/etc/pam.d/{fname}")
            if not text:
                continue
            if "pam_faillock.so" not in text:
                self.finding(
                    f"PAM-020-{fname}", f"pam_faillock not configured in /etc/pam.d/{fname}",
                    self.SEVERITY_HIGH, self.CATEGORY,
                    "Account lockout after repeated failed authentications is not enforced.",
                    remediation="Run 'authselect select sssd with-faillock' or manually add pam_faillock.so to auth and account stacks.",
                    references=["CIS RHEL 8 5.4.2", "STIG RHEL-08-020010"],
                )
        # Also check /etc/security/faillock.conf if present
        text = self.bundle.read_etc_file("/etc/security/faillock.conf")
        if text:
            cfg = parse_keyvalue_config(text, separator="=")
            deny = cfg.get("deny", "")
            try:
                if int(deny) > 5:
                    self.finding(
                        "PAM-021", f"faillock 'deny' threshold is {deny} (recommended ≤ 5)",
                        self.SEVERITY_MEDIUM, self.CATEGORY,
                        "High deny threshold gives attackers more attempts before lockout.",
                        remediation="Set 'deny = 5' (or lower) in /etc/security/faillock.conf.",
                        references=["CIS RHEL 8 5.4.2"],
                    )
            except ValueError:
                pass
            unlock = cfg.get("unlock_time", "")
            try:
                if int(unlock) < 900:
                    self.finding(
                        "PAM-022", f"faillock 'unlock_time' is {unlock} (recommended ≥ 900s)",
                        self.SEVERITY_LOW, self.CATEGORY,
                        "Lockouts unlock too quickly, weakening the brute-force throttle.",
                        remediation="Set 'unlock_time = 900' in /etc/security/faillock.conf.",
                        references=["CIS RHEL 8 5.4.2"],
                    )
            except ValueError:
                pass

    def _check_password_hash_algo(self):
        text = self.bundle.read_etc_file("/etc/login.defs")
        if not text:
            return
        cfg = parse_keyvalue_config(text)
        encrypt = cfg.get("encrypt_method", "").upper()
        if encrypt and encrypt not in ("SHA512", "YESCRYPT"):
            self.finding(
                "PAM-030", f"Weak password hashing algorithm: {encrypt}",
                self.SEVERITY_HIGH, self.CATEGORY,
                f"ENCRYPT_METHOD={encrypt} in /etc/login.defs configures weak password hashing. "
                "RHEL 8 should use SHA512 or YESCRYPT.",
                remediation="Set 'ENCRYPT_METHOD SHA512' (or YESCRYPT on RHEL 9+) in /etc/login.defs.",
                references=["CIS RHEL 8 5.4.4", "STIG RHEL-08-010120"],
            )

    def _check_su_pam_wheel(self):
        text = self.bundle.read_etc_file("/etc/pam.d/su")
        if not text:
            return
        if not re.search(r"^\s*auth\s+\S+\s+pam_wheel\.so.*use_uid", text, re.MULTILINE):
            self.finding(
                "PAM-040", "/etc/pam.d/su does not require wheel group membership",
                self.SEVERITY_MEDIUM, self.CATEGORY,
                "Without pam_wheel.so, any user can attempt to 'su' to root. Restricting su to "
                "the wheel group narrows the attack surface against root.",
                remediation="Uncomment 'auth required pam_wheel.so use_uid' in /etc/pam.d/su and ensure approved admins are in 'wheel'.",
                references=["CIS RHEL 8 5.6", "STIG RHEL-08-010380"],
            )
