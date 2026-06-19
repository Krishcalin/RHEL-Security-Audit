"""
Kernel parameter hardening (CIS RHEL 8 Section 3.2 / 3.3, STIG sysctl controls)

Audits the runtime 'sysctl -a' output for network and kernel parameters that
CIS / STIG require for a hardened RHEL 8 baseline.
"""

from __future__ import annotations

from typing import Any, Dict, List

from core.base import BaseAuditor, parse_sysctl_runtime


# Each entry: (id, key, expected, severity, title, remediation, references)
# 'expected' is a string the runtime value must equal exactly (after str()).
_RULES = [
    # Network — disable forwarding unless this is a router
    ("SCTL-001", "net.ipv4.ip_forward", "0", "MEDIUM",
     "IPv4 forwarding enabled (host acting as router)",
     "Set 'net.ipv4.ip_forward = 0' (in /etc/sysctl.d/) unless this host is intentionally routing.",
     "CIS RHEL 8 3.2.2"),
    ("SCTL-002", "net.ipv6.conf.all.forwarding", "0", "MEDIUM",
     "IPv6 forwarding enabled",
     "Set 'net.ipv6.conf.all.forwarding = 0' unless routing IPv6.",
     "CIS RHEL 8 3.2.2"),

    # Source routing / redirects / martians
    ("SCTL-010", "net.ipv4.conf.all.accept_source_route", "0", "HIGH",
     "Source-routed packets accepted (IPv4 all)",
     "Set 'net.ipv4.conf.all.accept_source_route = 0' and the same for 'default'.",
     "CIS RHEL 8 3.3.1"),
    ("SCTL-011", "net.ipv4.conf.default.accept_source_route", "0", "HIGH",
     "Source-routed packets accepted (IPv4 default)",
     "Set 'net.ipv4.conf.default.accept_source_route = 0'.",
     "CIS RHEL 8 3.3.1"),
    ("SCTL-012", "net.ipv4.conf.all.accept_redirects", "0", "MEDIUM",
     "ICMP redirects accepted (IPv4 all)",
     "Set 'net.ipv4.conf.all.accept_redirects = 0'.",
     "CIS RHEL 8 3.3.2"),
    ("SCTL-013", "net.ipv4.conf.all.secure_redirects", "0", "MEDIUM",
     "Secure ICMP redirects accepted (IPv4 all)",
     "Set 'net.ipv4.conf.all.secure_redirects = 0'.",
     "CIS RHEL 8 3.3.3"),
    ("SCTL-014", "net.ipv4.conf.all.log_martians", "1", "LOW",
     "Martian packet logging not enabled",
     "Set 'net.ipv4.conf.all.log_martians = 1' for visibility of spoofed traffic.",
     "CIS RHEL 8 3.3.4"),
    ("SCTL-015", "net.ipv4.icmp_echo_ignore_broadcasts", "1", "MEDIUM",
     "Broadcast ICMP echo not ignored (Smurf attack vector)",
     "Set 'net.ipv4.icmp_echo_ignore_broadcasts = 1'.",
     "CIS RHEL 8 3.3.5"),
    ("SCTL-016", "net.ipv4.icmp_ignore_bogus_error_responses", "1", "LOW",
     "Bogus ICMP error responses not ignored",
     "Set 'net.ipv4.icmp_ignore_bogus_error_responses = 1'.",
     "CIS RHEL 8 3.3.6"),
    ("SCTL-017", "net.ipv4.conf.all.rp_filter", "1", "HIGH",
     "Reverse path filtering not strict (anti-spoofing)",
     "Set 'net.ipv4.conf.all.rp_filter = 1' (and same for 'default').",
     "CIS RHEL 8 3.3.7"),
    ("SCTL-018", "net.ipv4.tcp_syncookies", "1", "HIGH",
     "TCP SYN cookies disabled (SYN flood mitigation)",
     "Set 'net.ipv4.tcp_syncookies = 1'.",
     "CIS RHEL 8 3.3.8"),

    # IPv6 RA / redirects
    ("SCTL-020", "net.ipv6.conf.all.accept_ra", "0", "MEDIUM",
     "IPv6 router advertisements accepted (all)",
     "Set 'net.ipv6.conf.all.accept_ra = 0' (router announces are an injection vector).",
     "CIS RHEL 8 3.3.9"),
    ("SCTL-021", "net.ipv6.conf.all.accept_redirects", "0", "MEDIUM",
     "IPv6 ICMP redirects accepted (all)",
     "Set 'net.ipv6.conf.all.accept_redirects = 0'.",
     "CIS RHEL 8 3.3.2"),

    # Kernel hardening
    ("SCTL-030", "kernel.randomize_va_space", "2", "HIGH",
     "ASLR not fully enabled (kernel.randomize_va_space)",
     "Set 'kernel.randomize_va_space = 2'.",
     "CIS RHEL 8 1.5.3"),
    ("SCTL-031", "fs.suid_dumpable", "0", "MEDIUM",
     "SUID-binaries can produce core dumps (fs.suid_dumpable)",
     "Set 'fs.suid_dumpable = 0'.",
     "CIS RHEL 8 1.5.1"),
    ("SCTL-032", "kernel.kptr_restrict", "1", "MEDIUM",
     "Kernel pointer addresses exposed (kernel.kptr_restrict)",
     "Set 'kernel.kptr_restrict = 1' (or 2 for stricter).",
     "CIS RHEL 8 1.5.4"),
    ("SCTL-033", "kernel.yama.ptrace_scope", "1", "MEDIUM",
     "ptrace-based debugging is unrestricted (yama.ptrace_scope = 0)",
     "Set 'kernel.yama.ptrace_scope = 1' to require parent or CAP_SYS_PTRACE.",
     "CIS RHEL 8 1.5.5"),
    ("SCTL-034", "kernel.dmesg_restrict", "1", "LOW",
     "Unprivileged users can read kernel ring buffer (dmesg_restrict)",
     "Set 'kernel.dmesg_restrict = 1'.",
     "STIG RHEL-08-010375"),
    ("SCTL-035", "kernel.unprivileged_bpf_disabled", "1", "MEDIUM",
     "Unprivileged BPF enabled (kernel attack surface)",
     "Set 'kernel.unprivileged_bpf_disabled = 1'.",
     "STIG RHEL-08-040282"),
]


class SysctlAuditor(BaseAuditor):
    SUPPORTED_RHEL_MAJORS = {8, 9}
    CATEGORY = "Kernel / Network Parameters"

    def run_all_checks(self) -> List[Dict[str, Any]]:
        if not self.supports_rhel():
            return self._emit_skip_notice(self.CATEGORY)

        if not self.bundle.has_command("sysctl_a"):
            self.finding(
                "SCTL-META-001", "sysctl_a not captured in bundle",
                self.SEVERITY_INFO, self.CATEGORY,
                "Cannot evaluate kernel parameters without the runtime sysctl output.",
                remediation="Re-run the collector — 'sysctl -a' must be captured.",
            )
            return self.findings

        runtime = parse_sysctl_runtime(self.bundle.read_command("sysctl_a"))
        sev_map = {
            "CRITICAL": self.SEVERITY_CRITICAL, "HIGH": self.SEVERITY_HIGH,
            "MEDIUM": self.SEVERITY_MEDIUM, "LOW": self.SEVERITY_LOW,
        }
        for cid, key, expected, sev_str, title, fix, ref in _RULES:
            actual = runtime.get(key)
            if actual is None:
                # Some keys (e.g. ipv6 ones) may not exist if module unloaded —
                # skip silently rather than spam findings.
                continue
            if actual != expected:
                self.finding(
                    cid, f"{title} (currently {key} = {actual}, expected {expected})",
                    sev_map.get(sev_str, self.SEVERITY_MEDIUM), self.CATEGORY,
                    f"Runtime kernel parameter {key} is set to {actual}; CIS/STIG expects {expected}.",
                    affected_items=[f"{key} = {actual}"],
                    remediation=fix,
                    references=[ref],
                )
        return self.findings
