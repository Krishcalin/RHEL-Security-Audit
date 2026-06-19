"""
Service Hardening (CIS RHEL 8 Section 2.1)

Flags legacy / insecure services that should not be enabled on a hardened
RHEL 8 baseline (telnet, rsh, rlogin, tftp, ftp, NIS, talk, etc.).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from core.base import BaseAuditor


# Unit name -> (title, severity, why-this-is-bad)
_BAD_SERVICES = {
    "telnet.socket":        ("Telnet daemon enabled",
                              "CRITICAL", "Telnet transmits credentials and data in plaintext."),
    "telnet.service":       ("Telnet daemon enabled",
                              "CRITICAL", "Telnet transmits credentials and data in plaintext."),
    "rsh.socket":           ("rsh enabled",
                              "CRITICAL", "rsh transmits credentials and data in plaintext."),
    "rsh.service":          ("rsh enabled",
                              "CRITICAL", "rsh transmits credentials and data in plaintext."),
    "rlogin.socket":        ("rlogin enabled",
                              "CRITICAL", "rlogin transmits credentials in plaintext."),
    "rlogin.service":       ("rlogin enabled",
                              "CRITICAL", "rlogin transmits credentials in plaintext."),
    "rexec.socket":         ("rexec enabled",
                              "CRITICAL", "rexec transmits credentials in plaintext."),
    "tftp.socket":          ("TFTP daemon enabled",
                              "HIGH",     "TFTP has no authentication."),
    "tftp.service":         ("TFTP daemon enabled",
                              "HIGH",     "TFTP has no authentication."),
    "vsftpd.service":       ("vsftpd (FTP) enabled",
                              "MEDIUM",   "FTP transmits credentials in plaintext unless tunnelled."),
    "ypserv.service":       ("NIS server enabled",
                              "HIGH",     "NIS exposes user database with weak auth; deprecated by Red Hat."),
    "ypbind.service":       ("NIS client enabled",
                              "MEDIUM",   "NIS client is deprecated; migrate to SSSD."),
    "talk.service":         ("talk daemon enabled",
                              "LOW",      "Legacy chat service, unauthenticated."),
    "ntalk.service":        ("ntalk daemon enabled",
                              "LOW",      "Legacy chat service, unauthenticated."),
    "chargen-dgram.socket": ("chargen service enabled",
                              "MEDIUM",   "Character generator service used for DDoS amplification."),
    "chargen-stream.socket":("chargen service enabled",
                              "MEDIUM",   "Character generator service used for DDoS amplification."),
    "echo-dgram.socket":    ("echo service enabled",
                              "MEDIUM",   "echo service used for DDoS amplification."),
    "discard-dgram.socket": ("discard service enabled",
                              "LOW",      "Legacy diagnostic service, unnecessary."),
    "daytime-dgram.socket": ("daytime service enabled",
                              "LOW",      "Legacy time service, unnecessary (use chronyd)."),
    "time-dgram.socket":    ("time service enabled",
                              "LOW",      "Legacy time service, unnecessary (use chronyd)."),
    "xinetd.service":       ("xinetd enabled",
                              "MEDIUM",   "xinetd is deprecated on RHEL 8; legacy services should be removed entirely."),
    "avahi-daemon.service": ("Avahi (mDNS) enabled",
                              "LOW",      "Avahi broadcasts host presence on the LAN; usually unnecessary on servers."),
    "cups.service":         ("CUPS print server enabled",
                              "LOW",      "Print server with historical CVEs; unnecessary on most servers."),
    "dhcpd.service":        ("DHCP server enabled",
                              "MEDIUM",   "Servers should generally not run DHCP — flag for review."),
    "slapd.service":        ("OpenLDAP server enabled",
                              "MEDIUM",   "LDAP server — confirm it is intentional and TLS-only."),
    "named.service":        ("BIND DNS server enabled",
                              "MEDIUM",   "Authoritative/recursive DNS server — confirm intent and patch level."),
    "smb.service":          ("Samba/SMB server enabled",
                              "MEDIUM",   "SMB has historical RCEs (EternalBlue, etc.); confirm intent and patch level."),
    "snmpd.service":        ("SNMP daemon enabled",
                              "MEDIUM",   "SNMPv1/v2c use plaintext community strings; ensure SNMPv3-only or disable."),
}


class ServiceAuditor(BaseAuditor):
    SUPPORTED_RHEL_MAJORS = {8, 9}
    CATEGORY = "Services"

    def run_all_checks(self) -> List[Dict[str, Any]]:
        if not self.supports_rhel():
            return self._emit_skip_notice(self.CATEGORY)
        self._check_bad_services()
        self._check_failed_units()
        return self.findings

    def _check_bad_services(self):
        units_text = self.bundle.read_command("systemctl_unit_files")
        if not units_text:
            self.finding(
                "SVC-META-001", "systemctl_unit_files not in bundle",
                self.SEVERITY_INFO, self.CATEGORY,
                "Cannot evaluate service hardening without the systemd unit file inventory.",
                remediation="Re-run the collector.",
            )
            return
        sev_map = {
            "CRITICAL": self.SEVERITY_CRITICAL, "HIGH": self.SEVERITY_HIGH,
            "MEDIUM": self.SEVERITY_MEDIUM, "LOW": self.SEVERITY_LOW,
        }
        for unit, (title, sev, why) in _BAD_SERVICES.items():
            # systemd lists are 'name<spaces>state<spaces>vendor-preset'
            pattern = rf"^{re.escape(unit)}\s+(enabled|alias)\b"
            if re.search(pattern, units_text, re.MULTILINE):
                self.finding(
                    f"SVC-{unit.replace('.', '-')}", title,
                    sev_map[sev], self.CATEGORY,
                    f"{unit} is enabled. {why}",
                    affected_items=[unit],
                    remediation=f"systemctl disable --now {unit}; dnf remove -y <package>",
                    references=["CIS RHEL 8 Section 2.1"],
                )

    def _check_failed_units(self):
        failed = self.bundle.read_command("systemctl_failed")
        units = []
        for line in failed.splitlines():
            line = line.strip()
            if not line or line.lower().startswith("unit"):
                continue
            parts = line.split()
            if parts and parts[0].endswith(".service"):
                units.append(parts[0])
        if units:
            self.finding(
                "SVC-FAILED", f"{len(units)} systemd unit(s) in failed state",
                self.SEVERITY_LOW, self.CATEGORY,
                "Failed units may indicate broken security features (auditd, firewalld, AIDE timer, etc.).",
                affected_items=units[:20],
                remediation="systemctl status <unit> and journalctl -u <unit> to investigate.",
                references=["Operational hygiene"],
            )
