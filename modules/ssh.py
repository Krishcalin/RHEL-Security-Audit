"""
SSH Daemon Hardening (CIS RHEL 8 Benchmark Section 5.2, DISA STIG SSH)

Audits /etc/ssh/sshd_config (and any sshd_config.d/*.conf overrides) for the
standard SSH hardening controls.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List

from core.base import BaseAuditor, parse_keyvalue_config


class SshAuditor(BaseAuditor):
    SUPPORTED_RHEL_MAJORS = {8, 9}

    CATEGORY = "SSH"

    def run_all_checks(self) -> List[Dict[str, Any]]:
        if not self.supports_rhel():
            return self._emit_skip_notice(self.CATEGORY)

        if not self.bundle.has_etc_file("/etc/ssh/sshd_config"):
            self.finding(
                "SSH-META-002",
                "/etc/ssh/sshd_config not present in bundle",
                self.SEVERITY_INFO,
                self.CATEGORY,
                "SSH hardening cannot be evaluated because sshd_config is missing from the collected bundle.",
                remediation="Re-run the collector as root to ensure /etc/ssh/sshd_config is captured.",
            )
            return self.findings

        cfg = self._merged_config()

        self._check_protocol_2(cfg)
        self._check_permit_root_login(cfg)
        self._check_password_auth(cfg)
        self._check_empty_passwords(cfg)
        self._check_x11_forwarding(cfg)
        self._check_max_auth_tries(cfg)
        self._check_idle_timeout(cfg)
        self._check_login_grace_time(cfg)
        self._check_strong_macs(cfg)
        self._check_strong_ciphers(cfg)
        self._check_strong_kex(cfg)
        self._check_log_level(cfg)
        self._check_banner(cfg)
        self._check_host_based_auth(cfg)
        self._check_gss_api(cfg)
        self._check_compression(cfg)
        self._check_allow_tcp_forwarding(cfg)
        self._check_ignore_rhosts(cfg)
        self._check_strict_modes(cfg)
        self._check_use_pam(cfg)

        return self.findings

    # ---------------------------------------------------------------- helpers
    def _merged_config(self) -> Dict[str, str]:
        """Merge sshd_config with any sshd_config.d/*.conf overrides.

        sshd applies the *first* matching directive in the file order; the
        canonical setup is to read 50-redhat.conf and friends first, then the
        main sshd_config. We approximate that by parsing main first, then
        letting overlays *override* (since 'override' here means the value
        that ends up effective). For audit purposes seeing the most-recently
        set value is the right thing.
        """
        base = parse_keyvalue_config(self.bundle.read_etc_file("/etc/ssh/sshd_config"))
        for path in self.bundle.list_etc("/etc/ssh/sshd_config.d"):
            if path.endswith(".conf"):
                base.update(parse_keyvalue_config(self.bundle.read_etc_file(path)))
        return base

    def _val(self, cfg: Dict[str, str], key: str, default: str = "") -> str:
        return cfg.get(key.lower(), default)

    # ---------------------------------------------------------------- checks
    def _check_protocol_2(self, cfg):
        proto = self._val(cfg, "Protocol")
        if proto and proto != "2":
            self.finding(
                "SSH-001", "SSH Protocol 1 is enabled",
                self.SEVERITY_CRITICAL, self.CATEGORY,
                "SSH Protocol 1 has known cryptographic weaknesses (CRC32 compensation attack, "
                "MITM) and must not be used. RHEL 8's sshd only supports Protocol 2; explicitly "
                "setting Protocol 1 indicates a misconfigured baseline.",
                affected_items=[f"Protocol {proto}"],
                remediation="Remove the 'Protocol' directive or set 'Protocol 2'.",
                references=["CIS RHEL 8 5.2.4", "RFC 4253"],
            )

    def _check_permit_root_login(self, cfg):
        v = self._val(cfg, "PermitRootLogin", "yes").lower()
        if v not in ("no", "prohibit-password"):
            self.finding(
                "SSH-002", f"Root login over SSH is permitted (PermitRootLogin {v or 'unset/yes'})",
                self.SEVERITY_HIGH, self.CATEGORY,
                "Direct root SSH login bypasses sudo accountability and broadens the brute-force "
                "attack surface against a known account name.",
                affected_items=[f"PermitRootLogin {v or '(unset, default yes)'}"],
                remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd.",
                references=["CIS RHEL 8 5.2.10", "STIG RHEL-08-010550"],
            )

    def _check_password_auth(self, cfg):
        # Default is 'yes' if unspecified
        v = self._val(cfg, "PasswordAuthentication", "yes").lower()
        if v != "no":
            self.finding(
                "SSH-003", "Password authentication enabled (key-based auth preferred)",
                self.SEVERITY_MEDIUM, self.CATEGORY,
                "Password authentication is susceptible to brute-force and credential-stuffing "
                "attacks. Public-key authentication is strongly preferred.",
                remediation="Set 'PasswordAuthentication no' and distribute SSH keys for all admins.",
                references=["CIS RHEL 8 5.2.11", "NIST SP 800-63B"],
            )

    def _check_empty_passwords(self, cfg):
        v = self._val(cfg, "PermitEmptyPasswords", "no").lower()
        if v == "yes":
            self.finding(
                "SSH-004", "PermitEmptyPasswords allows accounts with blank passwords",
                self.SEVERITY_CRITICAL, self.CATEGORY,
                "Allowing empty passwords means any account configured with no password can log "
                "in over SSH unauthenticated.",
                remediation="Set 'PermitEmptyPasswords no'.",
                references=["CIS RHEL 8 5.2.9", "STIG RHEL-08-010830"],
            )

    def _check_x11_forwarding(self, cfg):
        v = self._val(cfg, "X11Forwarding", "no").lower()
        if v == "yes":
            self.finding(
                "SSH-005", "X11 forwarding enabled over SSH",
                self.SEVERITY_LOW, self.CATEGORY,
                "X11 forwarding exposes the client's display to the server side and increases the "
                "attack surface. Disable unless explicitly required.",
                remediation="Set 'X11Forwarding no'.",
                references=["CIS RHEL 8 5.2.6"],
            )

    def _check_max_auth_tries(self, cfg):
        v = self._val(cfg, "MaxAuthTries", "6")
        try:
            n = int(v)
        except ValueError:
            return
        if n > 4:
            self.finding(
                "SSH-006", f"MaxAuthTries is {n} (recommended: ≤4)",
                self.SEVERITY_MEDIUM, self.CATEGORY,
                f"Allowing {n} authentication attempts per connection makes brute-forcing easier.",
                remediation="Set 'MaxAuthTries 4'.",
                references=["CIS RHEL 8 5.2.7"],
            )

    def _check_idle_timeout(self, cfg):
        ci = self._val(cfg, "ClientAliveInterval", "0")
        cm = self._val(cfg, "ClientAliveCountMax", "3")
        try:
            ci_n, cm_n = int(ci), int(cm)
        except ValueError:
            return
        if ci_n == 0 or ci_n > 300:
            self.finding(
                "SSH-007", f"SSH idle timeout too lenient (ClientAliveInterval={ci_n})",
                self.SEVERITY_LOW, self.CATEGORY,
                "Long-running idle SSH sessions can be hijacked from a left-unlocked workstation "
                "and skip session-timeout policies enforced elsewhere.",
                remediation="Set 'ClientAliveInterval 300' and 'ClientAliveCountMax 0' (or 1).",
                references=["CIS RHEL 8 5.2.16", "STIG RHEL-08-010200"],
            )
        if cm_n > 3:
            self.finding(
                "SSH-008", f"SSH ClientAliveCountMax is {cm_n} (recommended: ≤3)",
                self.SEVERITY_LOW, self.CATEGORY,
                "High ClientAliveCountMax extends the effective timeout window.",
                remediation="Set 'ClientAliveCountMax 0' or '1'.",
                references=["CIS RHEL 8 5.2.16"],
            )

    def _check_login_grace_time(self, cfg):
        v = self._val(cfg, "LoginGraceTime", "120")
        # Strip 's', 'm' suffixes — sshd accepts time-spec
        m = re.match(r"^(\d+)([smh]?)$", v)
        if not m:
            return
        n = int(m.group(1))
        if m.group(2) == "m":
            n *= 60
        elif m.group(2) == "h":
            n *= 3600
        if n > 60:
            self.finding(
                "SSH-009", f"LoginGraceTime is {v} (>60s)",
                self.SEVERITY_LOW, self.CATEGORY,
                "Long LoginGraceTime gives attackers more time per attempted brute-force connection.",
                remediation="Set 'LoginGraceTime 60'.",
                references=["CIS RHEL 8 5.2.17"],
            )

    def _check_strong_macs(self, cfg):
        macs = self._val(cfg, "MACs")
        if not macs:
            return  # crypto policy controls it
        weak = {"hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96",
                "hmac-md5-etm@openssh.com", "hmac-sha1-etm@openssh.com"}
        configured = {m.strip().lower() for m in macs.split(",")}
        found = sorted(configured & weak)
        if found:
            self.finding(
                "SSH-010", f"Weak SSH MACs configured: {', '.join(found)}",
                self.SEVERITY_HIGH, self.CATEGORY,
                "MD5- and SHA-1-based MAC algorithms have known collision weaknesses and must not "
                "be used for SSH integrity protection.",
                affected_items=[f"MACs {macs}"],
                remediation="Set 'MACs hmac-sha2-256,hmac-sha2-512,umac-128@openssh.com' or rely on the system-wide crypto policy.",
                references=["CIS RHEL 8 5.2.14", "STIG RHEL-08-040030"],
            )

    def _check_strong_ciphers(self, cfg):
        ciph = self._val(cfg, "Ciphers")
        if not ciph:
            return
        weak = {"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc",
                "arcfour", "arcfour128", "arcfour256", "blowfish-cbc",
                "cast128-cbc"}
        configured = {c.strip().lower() for c in ciph.split(",")}
        found = sorted(configured & weak)
        if found:
            self.finding(
                "SSH-011", f"Weak / deprecated SSH ciphers configured: {', '.join(found)}",
                self.SEVERITY_HIGH, self.CATEGORY,
                "CBC-mode and arcfour SSH ciphers are vulnerable to plaintext-recovery and "
                "biased-keystream attacks. Use AES-GCM or ChaCha20-Poly1305 only.",
                affected_items=[f"Ciphers {ciph}"],
                remediation="Set 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr'.",
                references=["CIS RHEL 8 5.2.13", "STIG RHEL-08-040020"],
            )

    def _check_strong_kex(self, cfg):
        kex = self._val(cfg, "KexAlgorithms")
        if not kex:
            return
        weak = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
                "diffie-hellman-group-exchange-sha1"}
        configured = {k.strip().lower() for k in kex.split(",")}
        found = sorted(configured & weak)
        if found:
            self.finding(
                "SSH-012", f"Weak SSH key-exchange algorithms configured: {', '.join(found)}",
                self.SEVERITY_HIGH, self.CATEGORY,
                "SHA-1-based and group-1 (1024-bit) DH key exchange are deprecated due to LOGJAM "
                "and SHA-1 collision risk.",
                affected_items=[f"KexAlgorithms {kex}"],
                remediation="Use only curve25519-sha256, ecdh-sha2-nistp{256,384,521}, and diffie-hellman-group16-sha512+ kex algorithms.",
                references=["CIS RHEL 8 5.2.15"],
            )

    def _check_log_level(self, cfg):
        v = self._val(cfg, "LogLevel", "INFO").upper()
        if v not in ("VERBOSE", "DEBUG", "DEBUG2", "DEBUG3"):
            # INFO is the default but CIS requires VERBOSE for key-fingerprint logging
            self.finding(
                "SSH-013", f"SSH LogLevel is {v} (should be VERBOSE)",
                self.SEVERITY_LOW, self.CATEGORY,
                "LogLevel VERBOSE makes sshd log the SSH key fingerprint used at login, which is "
                "required by several CIS / STIG controls for forensic traceability.",
                remediation="Set 'LogLevel VERBOSE'.",
                references=["CIS RHEL 8 5.2.5", "STIG RHEL-08-010040"],
            )

    def _check_banner(self, cfg):
        b = self._val(cfg, "Banner")
        if not b or b.lower() == "none":
            self.finding(
                "SSH-014", "No SSH login banner configured",
                self.SEVERITY_LOW, self.CATEGORY,
                "A pre-authentication banner is required by many compliance frameworks (legal "
                "warning, system classification).",
                remediation="Set 'Banner /etc/issue.net' and populate /etc/issue.net with an approved warning.",
                references=["CIS RHEL 8 5.2.18", "DoD CCI-002314"],
            )

    def _check_host_based_auth(self, cfg):
        v = self._val(cfg, "HostbasedAuthentication", "no").lower()
        if v == "yes":
            self.finding(
                "SSH-015", "HostbasedAuthentication enabled",
                self.SEVERITY_MEDIUM, self.CATEGORY,
                "HostbasedAuthentication trusts entire hosts to vouch for users, undermining "
                "per-user accountability.",
                remediation="Set 'HostbasedAuthentication no'.",
                references=["CIS RHEL 8 5.2.8"],
            )

    def _check_gss_api(self, cfg):
        v = self._val(cfg, "GSSAPIAuthentication", "yes").lower()
        if v == "yes":
            self.finding(
                "SSH-016", "GSSAPIAuthentication enabled (Kerberos)",
                self.SEVERITY_LOW, self.CATEGORY,
                "GSSAPI auth is rarely used and adds attack surface unless Kerberos SSO is in use.",
                remediation="Set 'GSSAPIAuthentication no' unless Kerberos auth is required.",
                references=["CIS RHEL 8 5.2.19"],
            )

    def _check_compression(self, cfg):
        v = self._val(cfg, "Compression", "delayed").lower()
        if v == "yes":
            self.finding(
                "SSH-017", "SSH Compression always-on (history of compression-based exploits)",
                self.SEVERITY_LOW, self.CATEGORY,
                "Pre-authentication compression has historically been a source of vulnerabilities "
                "(CVE-2016-0777 client side; CRIME-style attacks). 'delayed' is safer.",
                remediation="Set 'Compression delayed' (the OpenSSH default).",
                references=["CIS RHEL 8 5.2.20"],
            )

    def _check_allow_tcp_forwarding(self, cfg):
        v = self._val(cfg, "AllowTcpForwarding", "yes").lower()
        if v == "yes":
            self.finding(
                "SSH-018", "TCP forwarding enabled (SSH can be used as a tunnel)",
                self.SEVERITY_LOW, self.CATEGORY,
                "AllowTcpForwarding=yes lets authenticated users pivot through the SSH server to "
                "reach internal hosts. Disable unless your operations require it.",
                remediation="Set 'AllowTcpForwarding no' unless explicitly required.",
                references=["CIS RHEL 8 5.2.21"],
            )

    def _check_ignore_rhosts(self, cfg):
        v = self._val(cfg, "IgnoreRhosts", "yes").lower()
        if v != "yes":
            self.finding(
                "SSH-019", "IgnoreRhosts disabled (legacy .rhosts trust honoured)",
                self.SEVERITY_MEDIUM, self.CATEGORY,
                "Honouring legacy .rhosts files allows host-based trust relationships that bypass "
                "per-user authentication.",
                remediation="Set 'IgnoreRhosts yes'.",
                references=["CIS RHEL 8 5.2.22"],
            )

    def _check_strict_modes(self, cfg):
        v = self._val(cfg, "StrictModes", "yes").lower()
        if v == "no":
            self.finding(
                "SSH-020", "StrictModes disabled (sshd ignores key/file permission errors)",
                self.SEVERITY_MEDIUM, self.CATEGORY,
                "Without StrictModes, sshd will accept private keys with overly permissive file "
                "permissions, making credential theft easier.",
                remediation="Set 'StrictModes yes'.",
                references=["CIS RHEL 8 5.2.23"],
            )

    def _check_use_pam(self, cfg):
        v = self._val(cfg, "UsePAM", "yes").lower()
        if v != "yes":
            self.finding(
                "SSH-021", "UsePAM disabled — bypasses PAM account/session policies",
                self.SEVERITY_HIGH, self.CATEGORY,
                "Disabling PAM bypasses account lockout, time-of-day restrictions, MFA, and "
                "the system-wide auth policy. UsePAM should always be 'yes' on RHEL.",
                remediation="Set 'UsePAM yes'.",
                references=["CIS RHEL 8 5.2.24", "STIG RHEL-08-010380"],
            )
