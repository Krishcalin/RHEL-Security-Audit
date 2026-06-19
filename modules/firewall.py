"""
Firewall posture (CIS RHEL 8 Section 3.4)

Confirms a firewall is installed and active (firewalld, nftables, or iptables),
no unexpected services are exposed, and the default zone is sensible.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from core.base import BaseAuditor


# Ports a typical hardened host should NOT listen on externally
_HIGH_RISK_PORTS = {
    "21":   ("FTP",       "FTP transmits credentials in plaintext"),
    "23":   ("Telnet",    "Telnet transmits credentials in plaintext"),
    "25":   ("SMTP",      "Open SMTP relay risk if not explicitly intended"),
    "69":   ("TFTP",      "TFTP has no authentication"),
    "111":  ("rpcbind",   "RPC portmapper is rarely needed and exposes other RPC services"),
    "139":  ("NetBIOS",   "Legacy SMB; should be firewalled to internal management only"),
    "445":  ("SMB",       "SMB exposure has been the vector for ransomware (WannaCry, NotPetya)"),
    "513":  ("rlogin",    "rlogin transmits credentials in plaintext"),
    "514":  ("rsh",       "rsh transmits credentials in plaintext"),
    "515":  ("LPD",       "Legacy printer protocol with weak auth"),
    "873":  ("rsync",     "rsync daemon without auth"),
    "2049": ("NFS",       "NFS without Kerberos is essentially world-readable"),
    "3306": ("MySQL",     "Databases should never be exposed on management/public interfaces"),
    "5432": ("PostgreSQL","Databases should never be exposed on management/public interfaces"),
    "6379": ("Redis",     "Default Redis has no auth; trivial RCE on exposed instances"),
    "11211":("memcached", "memcached UDP has been used for amplification DDoS"),
    "27017":("MongoDB",   "Default MongoDB has no auth; large breaches via exposure"),
}


class FirewallAuditor(BaseAuditor):
    SUPPORTED_RHEL_MAJORS = {8, 9}
    CATEGORY = "Firewall / Exposure"

    def run_all_checks(self) -> List[Dict[str, Any]]:
        if not self.supports_rhel():
            return self._emit_skip_notice(self.CATEGORY)

        self._check_firewall_installed()
        self._check_firewall_running()
        self._check_default_zone()
        self._check_listening_ports()
        self._check_hosts_files()
        return self.findings

    def _check_firewall_installed(self):
        rpm = self.bundle.read_command("rpm_qa")
        has_firewalld = "firewalld|" in rpm
        has_nft = "nftables|" in rpm
        has_iptables = "iptables|" in rpm
        if not (has_firewalld or has_nft or has_iptables):
            self.finding(
                "FW-001", "No host firewall installed (firewalld / nftables / iptables)",
                self.SEVERITY_CRITICAL, self.CATEGORY,
                "No firewall package is installed. Any services bound to 0.0.0.0 are reachable "
                "from any network the host is connected to.",
                remediation="dnf install -y firewalld && systemctl enable --now firewalld",
                references=["CIS RHEL 8 3.4.1.1"],
            )

    def _check_firewall_running(self):
        units = self.bundle.read_command("systemctl_unit_files")
        running = self.bundle.read_command("systemctl_running")
        if "firewalld.service" in units:
            if not re.search(r"^firewalld\.service\s+enabled", units, re.MULTILINE):
                self.finding(
                    "FW-002", "firewalld is installed but not enabled at boot",
                    self.SEVERITY_HIGH, self.CATEGORY,
                    "firewalld will not start automatically after a reboot, leaving the host without firewall enforcement.",
                    remediation="systemctl enable --now firewalld",
                    references=["CIS RHEL 8 3.4.1.1"],
                )
            if "firewalld.service" not in running:
                self.finding(
                    "FW-003", "firewalld is not currently running",
                    self.SEVERITY_HIGH, self.CATEGORY,
                    "firewalld service was not in the running unit list at collection time.",
                    remediation="systemctl start firewalld; check journalctl -u firewalld",
                    references=["CIS RHEL 8 3.4.1.1"],
                )

    def _check_default_zone(self):
        text = self.bundle.read_command("firewall_cmd_list")
        if not text:
            return
        # The default zone block starts with "zone <name> (default, active)"
        m = re.search(r"^([A-Za-z0-9_-]+)\s+\(default[^)]*\)", text, re.MULTILINE)
        if m:
            zone = m.group(1).lower()
            if zone == "public":
                # Public is fine for an internet host; trusted is the dangerous one
                pass
            elif zone == "trusted":
                self.finding(
                    "FW-010", "firewalld default zone is 'trusted' (allows all traffic)",
                    self.SEVERITY_CRITICAL, self.CATEGORY,
                    "The 'trusted' zone accepts all inbound traffic and is intended only for "
                    "loopback / management interfaces.",
                    remediation="firewall-cmd --set-default-zone=public",
                    references=["CIS RHEL 8 3.4.1.2"],
                )

    def _check_listening_ports(self):
        text = self.bundle.read_command("ss_listen")
        if not text:
            return
        listening = []
        # ss -tulnp output: Netid State Recv-Q Send-Q Local Address:Port Peer ...
        for line in text.splitlines():
            line = line.strip()
            if not line or line.lower().startswith("netid"):
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            local = parts[4]
            # Extract port (everything after the last :)
            if ":" not in local:
                continue
            addr, _, port = local.rpartition(":")
            # Only flag wildcard listens (0.0.0.0 / *) — loopback-only is fine
            if addr not in ("0.0.0.0", "*", "[::]", "::", ""):
                continue
            listening.append(port)

        listening_set = set(listening)
        risky = [p for p in listening_set if p in _HIGH_RISK_PORTS]
        for p in sorted(risky, key=int):
            name, why = _HIGH_RISK_PORTS[p]
            self.finding(
                f"FW-100-{p}", f"High-risk service listening on 0.0.0.0:{p} ({name})",
                self.SEVERITY_HIGH, self.CATEGORY,
                f"{name} (port {p}) is bound to all interfaces. {why}",
                affected_items=[f"0.0.0.0:{p}"],
                remediation=f"Either disable the service, bind it to localhost/management network, or restrict it via firewall-cmd --remove-port={p}/tcp.",
                references=["CIS RHEL 8 3.4 (firewall rules)", "OWASP Top 10 — Misconfiguration"],
            )

    def _check_hosts_files(self):
        # /etc/hosts.allow + /etc/hosts.deny — should ideally not exist on RHEL 8
        # (tcp_wrappers was removed), but if present should not be 'ALL: ALL'
        allow = self.bundle.read_etc_file("/etc/hosts.allow")
        if "ALL" in allow.upper() and re.search(r"^\s*ALL\s*:\s*ALL", allow, re.MULTILINE):
            self.finding(
                "FW-020", "/etc/hosts.allow contains 'ALL: ALL' rule",
                self.SEVERITY_MEDIUM, self.CATEGORY,
                "An 'ALL: ALL' rule in /etc/hosts.allow grants TCP-Wrappers access to every "
                "service from every host (defeats the purpose of the file).",
                remediation="Remove the 'ALL: ALL' rule and rely on firewalld for access control.",
                references=["CIS RHEL 8 3.4.4"],
            )
