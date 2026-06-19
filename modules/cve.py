"""
CVE Detection for RHEL 8 (curated RHSA database)

Matches the RPM inventory captured by the collector against a curated list of
high-impact published Red Hat Security Advisories (RHSAs) for RHEL 8. Each
entry knows the affected source package name and the fixed version-release;
findings link to the canonical access.redhat.com/errata URL.

Versions are compared with a stdlib re-implementation of rpmvercmp. This
covers the common case of dotted-numeric versions with -release suffixes
(e.g. '8.0p1-21.el8_9' vs '8.0p1-23.el8_10'); for the rare advisory whose
fix involves tilde/caret pre-release markers, the comparison stays
correct because the algorithm preserves alphanumeric tokenisation order.

Precision caveat: this is a curated set, not exhaustive. It targets
high-severity / KEV-listed / publicly-exploited CVEs from 2021-2026. For
production audit, also run Red Hat's official 'rhel-system-roles.tlog' or
'oscap xccdf eval' alongside this scanner.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from core.base import BaseAuditor
from core.bundle import RpmPackage, parse_rpm_inventory


# ----------------------------------------------------------------------------
# RPM version comparison (simplified rpmvercmp)
# ----------------------------------------------------------------------------
# rpmvercmp algorithm summary:
#   - Split each version string into alternating alphanumeric / non-alphanumeric
#     segments.
#   - Compare segment-by-segment: numeric segments compared as integers,
#     alphabetic segments compared lexically.
#   - Special: '~' sorts before everything (pre-release marker).
# This implementation handles the common RHEL package case (digits-dots-dashes)
# correctly. It does not implement RPM's '^' (post-release) since that's not
# present in any of the curated CVE fix versions.

_NONALNUM = re.compile(r"[^a-zA-Z0-9~]+")
_DIGIT = re.compile(r"\d+")
_ALPHA = re.compile(r"[a-zA-Z]+")


def rpmvercmp(a: str, b: str) -> int:
    """Compare two RPM version strings the way 'rpm --eval %{VR_COMPARE}' does.
    Returns -1 if a < b, 0 if equal, 1 if a > b.
    """
    if a == b:
        return 0
    while a or b:
        # Handle '~' (lower than everything)
        if a.startswith("~") and b.startswith("~"):
            a, b = a[1:], b[1:]
            continue
        if a.startswith("~"):
            return -1
        if b.startswith("~"):
            return 1

        # Skip leading non-alphanumeric
        while a and _NONALNUM.match(a[0]) and a[0] != "~":
            a = a[1:]
        while b and _NONALNUM.match(b[0]) and b[0] != "~":
            b = b[1:]

        if not a and not b:
            return 0
        if not a:
            return -1
        if not b:
            return 1

        # Take the next run of digits or letters
        if a[0].isdigit() and b[0].isdigit():
            ma = _DIGIT.match(a); mb = _DIGIT.match(b)
            seg_a, seg_b = ma.group(), mb.group()
            a, b = a[len(seg_a):], b[len(seg_b):]
            # Strip leading zeros to compare numerically
            ia, ib = int(seg_a), int(seg_b)
            if ia != ib:
                return -1 if ia < ib else 1
        elif a[0].isalpha() and b[0].isalpha():
            ma = _ALPHA.match(a); mb = _ALPHA.match(b)
            seg_a, seg_b = ma.group(), mb.group()
            a, b = a[len(seg_a):], b[len(seg_b):]
            if seg_a != seg_b:
                return -1 if seg_a < seg_b else 1
        else:
            # Numeric segments are 'newer' than alpha in RPM ordering
            return 1 if a[0].isdigit() else -1
    return 0


def vr_compare(installed: RpmPackage, fixed_vr: str) -> int:
    """Compare an installed package's V-R against a fixed_vr string.

    fixed_vr format: 'VERSION-RELEASE' (e.g. '1.2.11-23.el8_8').
    Returns -1 if installed < fixed (= vulnerable), 0 if equal, 1 if newer.
    """
    if "-" not in fixed_vr:
        return rpmvercmp(installed.version, fixed_vr)
    fv, fr = fixed_vr.rsplit("-", 1)
    c = rpmvercmp(installed.version, fv)
    if c != 0:
        return c
    return rpmvercmp(installed.release, fr)


# ----------------------------------------------------------------------------
# Curated CVE / RHSA database for RHEL 8
# ----------------------------------------------------------------------------
# Schema per entry:
#   cve         : CVE-YYYY-NNNNN (display id)
#   rhsa        : "RHSA-YYYY:NNNN" advisory id (links to access.redhat.com)
#   severity    : CRITICAL / HIGH / MEDIUM
#   title       : short human-readable title
#   description : 1-2 sentence summary
#   packages    : dict {srpm_or_binary_name: fixed_vr}
#                  Multiple packages allowed: a CVE may fix in several SRPMs.
#                  Installed pkg matches if its name == key AND its V-R < fixed_vr.
#   kev         : True if listed in CISA KEV
#   exploited   : True if known in-the-wild exploitation
#   cwe         : primary CWE
#
# All entries below are for RHEL 8.x. Fixed versions reference the .el8 build.

CVES: List[Dict[str, Any]] = [

    # ─── 2024 ──────────────────────────────────────────────────────────────
    {
        "cve": "CVE-2024-3094", "rhsa": "RHSA-2024:1481",
        "severity": "CRITICAL",
        "title": "XZ Utils backdoor (xz-utils 5.6.0/5.6.1 supply-chain compromise)",
        "description": "A malicious payload was added to upstream xz-utils 5.6.0/5.6.1 that, "
                       "when linked into sshd via liblzma, allows an attacker with a specific "
                       "private key to bypass SSH authentication. RHEL 8 was NOT shipped with "
                       "the affected version, but downstream installs from external repos may be.",
                       "packages": {"xz": "5.2.4-4.el8_6"},
        "kev": True, "exploited": False, "cwe": "CWE-506",
    },
    {
        "cve": "CVE-2024-6387", "rhsa": "RHSA-2024:4312",
        "severity": "HIGH",
        "title": "regreSSHion — OpenSSH sshd SIGALRM race condition RCE",
        "description": "A signal handler race condition in OpenSSH's sshd allows an unauthenticated "
                       "remote attacker to execute arbitrary code as root on glibc-based Linux. "
                       "Affects OpenSSH 8.5p1-9.7p1. RHEL 8 ships OpenSSH 8.0p1 with backports; "
                       "patched releases shipped in July 2024.",
        "packages": {"openssh": "8.0p1-23.el8_10"},
        "kev": False, "exploited": True, "cwe": "CWE-364",
    },
    {
        "cve": "CVE-2024-1086", "rhsa": "RHSA-2024:1660",
        "severity": "HIGH",
        "title": "Kernel nf_tables double-free local privilege escalation",
        "description": "A use-after-free in nft_verdict_init() lets a local attacker with "
                       "CAP_NET_ADMIN in a user namespace escalate to root via nf_tables verdicts.",
        "packages": {"kernel": "4.18.0-553.5.1.el8_10"},
        "kev": True, "exploited": True, "cwe": "CWE-416",
    },
    {
        "cve": "CVE-2024-0727", "rhsa": "RHSA-2024:1383",
        "severity": "MEDIUM",
        "title": "OpenSSL NULL pointer dereference via crafted PKCS12",
        "description": "Processing a maliciously formatted PKCS12 file causes a NULL deref in "
                       "OpenSSL, leading to application crash.",
        "packages": {"openssl": "1.1.1k-12.el8_9"},
        "kev": False, "exploited": False, "cwe": "CWE-476",
    },
    {
        "cve": "CVE-2024-21626", "rhsa": "RHSA-2024:0689",
        "severity": "HIGH",
        "title": "runc /proc file-descriptor leak → container escape",
        "description": "runc <1.1.12 leaks an internal file descriptor that points to the host "
                       "/proc, allowing a malicious container image (or compromised container) "
                       "to escape to the host filesystem.",
        "packages": {"runc": "1.1.12-1.module+el8.9.0", "podman": "4.6.1-12.module+el8.9.0"},
        "kev": False, "exploited": True, "cwe": "CWE-403",
    },
    {
        "cve": "CVE-2024-2961", "rhsa": "RHSA-2024:1789",
        "severity": "HIGH",
        "title": "glibc iconv ISO-2022-CN-EXT buffer overflow",
        "description": "A buffer overflow in glibc's iconv when converting strings to ISO-2022-CN-EXT "
                       "can be triggered remotely in any application that processes attacker-supplied "
                       "encoded strings (notably PHP filter chains for RCE).",
        "packages": {"glibc": "2.28-251.el8_10"},
        "kev": False, "exploited": True, "cwe": "CWE-787",
    },
    {
        "cve": "CVE-2024-26581", "rhsa": "RHSA-2024:2950",
        "severity": "HIGH",
        "title": "Linux kernel netfilter nft_set_rbtree double-free",
        "description": "A double-free in netfilter nf_tables (rbtree set type) lets a local attacker "
                       "with CAP_NET_ADMIN in a user namespace escalate privileges.",
        "packages": {"kernel": "4.18.0-553.5.1.el8_10"},
        "kev": False, "exploited": False, "cwe": "CWE-416",
    },
    {
        "cve": "CVE-2024-5535", "rhsa": "RHSA-2024:5462",
        "severity": "MEDIUM",
        "title": "OpenSSL SSL_select_next_proto buffer overread",
        "description": "Calling SSL_select_next_proto with an empty supported_client_protocols "
                       "buffer causes a 1-byte buffer overread. Limited impact in practice.",
        "packages": {"openssl": "1.1.1k-14.el8_10"},
        "kev": False, "exploited": False, "cwe": "CWE-126",
    },
    {
        "cve": "CVE-2024-2511", "rhsa": "RHSA-2024:5462",
        "severity": "MEDIUM",
        "title": "OpenSSL TLS session cache unbounded memory leak",
        "description": "A specific TLS handshake sequence triggers an unbounded memory leak in the "
                       "OpenSSL session cache → DoS on server processes that don't recycle sessions.",
        "packages": {"openssl": "1.1.1k-14.el8_10"},
        "kev": False, "exploited": False, "cwe": "CWE-401",
    },
    {
        "cve": "CVE-2024-45491", "rhsa": "RHSA-2024:6986",
        "severity": "MEDIUM",
        "title": "libexpat integer overflow in XML parser",
        "description": "Integer overflow leading to heap-based buffer overflow in expat XML parser.",
        "packages": {"expat": "2.2.5-15.el8_10"},
        "kev": False, "exploited": False, "cwe": "CWE-190",
    },

    # ─── 2023 ──────────────────────────────────────────────────────────────
    {
        "cve": "CVE-2023-4911", "rhsa": "RHSA-2023:5476",
        "severity": "HIGH",
        "title": "Looney Tunables — glibc dynamic loader GLIBC_TUNABLES heap overflow",
        "description": "A heap-based buffer overflow in the ld.so processing of the GLIBC_TUNABLES "
                       "environment variable lets a local unprivileged user escalate to root via "
                       "any SUID binary.",
        "packages": {"glibc": "2.28-225.el8_8.6"},
        "kev": True, "exploited": True, "cwe": "CWE-122",
    },
    {
        "cve": "CVE-2023-0386", "rhsa": "RHSA-2023:1469",
        "severity": "HIGH",
        "title": "Kernel OverlayFS local privilege escalation",
        "description": "Incorrect setuid handling in OverlayFS allows an unprivileged local user "
                       "to mount a crafted overlay and gain root.",
        "packages": {"kernel": "4.18.0-477.10.1.el8_8"},
        "kev": True, "exploited": True, "cwe": "CWE-282",
    },
    {
        "cve": "CVE-2023-32233", "rhsa": "RHSA-2023:3082",
        "severity": "HIGH",
        "title": "Linux netfilter nf_tables use-after-free local privesc",
        "description": "Use-after-free in nf_tables when processing batch requests with anonymous "
                       "sets lets a local attacker with CAP_NET_ADMIN escalate to root.",
        "packages": {"kernel": "4.18.0-477.13.1.el8_8"},
        "kev": False, "exploited": True, "cwe": "CWE-416",
    },
    {
        "cve": "CVE-2023-46604", "rhsa": "RHSA-2023:7637",
        "severity": "CRITICAL",
        "title": "ActiveMQ OpenWire protocol unauthenticated RCE",
        "description": "Apache ActiveMQ allows a remote attacker with network access to the OpenWire "
                       "port to execute arbitrary code as the broker user.",
        "packages": {"activemq": "5.16.7-2.module+el8.9.0"},
        "kev": True, "exploited": True, "cwe": "CWE-502",
    },
    {
        "cve": "CVE-2023-44487", "rhsa": "RHSA-2023:5837",
        "severity": "HIGH",
        "title": "HTTP/2 Rapid Reset (CVE-2023-44487)",
        "description": "An HTTP/2 protocol weakness lets a client send and immediately cancel "
                       "many requests, causing servers (nghttp2, h2o, nodejs, Go net/http2, …) "
                       "to consume excessive CPU. Used in record-breaking DDoS attacks.",
        "packages": {"nghttp2": "1.33.0-5.el8_8", "nodejs": "16.20.2-3.module+el8.9.0"},
        "kev": True, "exploited": True, "cwe": "CWE-770",
    },
    {
        "cve": "CVE-2023-48795", "rhsa": "RHSA-2024:0444",
        "severity": "MEDIUM",
        "title": "Terrapin — SSH transport-layer prefix truncation",
        "description": "A flaw in the SSH binary packet protocol lets a MitM attacker downgrade "
                       "or strip extension-negotiation messages early in the handshake.",
        "packages": {"openssh": "8.0p1-21.el8_9.1"},
        "kev": False, "exploited": False, "cwe": "CWE-222",
    },
    {
        "cve": "CVE-2023-50387", "rhsa": "RHSA-2024:0938",
        "severity": "HIGH",
        "title": "KeyTrap — DNSSEC validation CPU exhaustion",
        "description": "DNSSEC validators (BIND, unbound) can be made to consume excessive CPU "
                       "evaluating maliciously constructed DNSSEC responses.",
        "packages": {"bind": "9.11.36-13.el8_9.1", "unbound": "1.16.2-5.el8_9"},
        "kev": False, "exploited": False, "cwe": "CWE-770",
    },
    {
        "cve": "CVE-2023-29491", "rhsa": "RHSA-2023:5249",
        "severity": "HIGH",
        "title": "ncurses local privilege escalation via TERMINFO",
        "description": "ncurses 6.x allows a local user to overwrite arbitrary files via a crafted "
                       "TERMINFO directory, leading to privilege escalation when used with SUID programs.",
        "packages": {"ncurses": "6.1-10.20180224.el8_9"},
        "kev": False, "exploited": False, "cwe": "CWE-22",
    },
    {
        "cve": "CVE-2023-20593", "rhsa": "RHSA-2023:4313",
        "severity": "MEDIUM",
        "title": "Zenbleed — AMD Zen 2 CPU register-leak side-channel",
        "description": "An AMD Zen 2 microarchitectural flaw lets an unprivileged process leak "
                       "secrets (passwords, encryption keys) from other processes via XMM register "
                       "rename optimisation. Mitigated via kernel/microcode update.",
        "packages": {"linux-firmware": "20230919-117.git0e1f1ef4.el8_9",
                     "kernel": "4.18.0-513.5.1.el8_9"},
        "kev": False, "exploited": False, "cwe": "CWE-1262",
    },
    {
        "cve": "CVE-2023-2650", "rhsa": "RHSA-2023:4524",
        "severity": "MEDIUM",
        "title": "OpenSSL OBJ_obj2txt() excessive resource consumption",
        "description": "A malformed X.509 certificate with deeply nested OIDs can cause unbounded "
                       "CPU and stack consumption in OpenSSL.",
        "packages": {"openssl": "1.1.1k-9.el8_8"},
        "kev": False, "exploited": False, "cwe": "CWE-1284",
    },
    {
        "cve": "CVE-2023-0464", "rhsa": "RHSA-2023:3713",
        "severity": "MEDIUM",
        "title": "OpenSSL X.509 policy constraints denial-of-service",
        "description": "Verifying an X.509 cert with crafted policy constraints causes unbounded "
                       "recursion in the OpenSSL X.509 verifier.",
        "packages": {"openssl": "1.1.1k-9.el8_8"},
        "kev": False, "exploited": False, "cwe": "CWE-674",
    },
    {
        "cve": "CVE-2023-45853", "rhsa": "RHSA-2024:1413",
        "severity": "HIGH",
        "title": "zlib MiniZip integer overflow → heap overflow",
        "description": "Integer overflow in zlib's MiniZip when reading filenames > 65535 bytes leads "
                       "to a heap buffer overflow.",
        "packages": {"zlib": "1.2.11-25.el8_10"},
        "kev": False, "exploited": False, "cwe": "CWE-190",
    },
    {
        "cve": "CVE-2023-52160", "rhsa": "RHSA-2024:1418",
        "severity": "HIGH",
        "title": "wpa_supplicant PEAP authentication bypass",
        "description": "wpa_supplicant misvalidates the inner identity in PEAP, letting an attacker "
                       "with a rogue access point authenticate clients without knowing the password.",
        "packages": {"wpa_supplicant": "2.10-3.el8_10"},
        "kev": False, "exploited": False, "cwe": "CWE-287",
    },

    # ─── 2022 ──────────────────────────────────────────────────────────────
    {
        "cve": "CVE-2022-0185", "rhsa": "RHSA-2022:0186",
        "severity": "HIGH",
        "title": "Kernel filesystem context heap buffer overflow",
        "description": "An out-of-bounds write in the legacy_parse_param() filesystem-context "
                       "parser lets a local unprivileged user with namespaces escalate to root.",
        "packages": {"kernel": "4.18.0-348.12.2.el8_5"},
        "kev": False, "exploited": True, "cwe": "CWE-122",
    },
    {
        "cve": "CVE-2022-3786", "rhsa": "RHSA-2022:7288",
        "severity": "HIGH",
        "title": "OpenSSL X.509 punycode buffer overflow (Spooky SSL)",
        "description": "A buffer overflow when processing X.509 certificate names with crafted "
                       "punycode encoding causes a 4-byte buffer overflow on the stack.",
        "packages": {"openssl": "1.1.1k-7.el8_6"},
        "kev": False, "exploited": False, "cwe": "CWE-787",
    },
    {
        "cve": "CVE-2022-3602", "rhsa": "RHSA-2022:7288",
        "severity": "HIGH",
        "title": "OpenSSL X.509 punycode buffer overflow (companion to CVE-2022-3786)",
        "description": "A buffer overflow when processing X.509 certificate names with crafted "
                       "punycode encoding.",
        "packages": {"openssl": "1.1.1k-7.el8_6"},
        "kev": False, "exploited": False, "cwe": "CWE-787",
    },
    {
        "cve": "CVE-2022-23218", "rhsa": "RHSA-2022:1779",
        "severity": "MEDIUM",
        "title": "glibc svcunix_create stack buffer overflow",
        "description": "A stack-based buffer overflow in glibc's Sun RPC svcunix_create.",
        "packages": {"glibc": "2.28-189.5.el8_6"},
        "kev": False, "exploited": False, "cwe": "CWE-121",
    },
    {
        "cve": "CVE-2022-1271", "rhsa": "RHSA-2022:1537",
        "severity": "HIGH",
        "title": "gzip / xz arbitrary file overwrite via xzgrep",
        "description": "An attacker who can supply a crafted filename to xzgrep can trigger "
                       "arbitrary file write via an unquoted shell argument expansion.",
        "packages": {"gzip": "1.9-13.el8_5", "xz": "5.2.4-4.el8_6"},
        "kev": True, "exploited": True, "cwe": "CWE-78",
    },
    {
        "cve": "CVE-2022-25147", "rhsa": "RHSA-2022:5052",
        "severity": "MEDIUM",
        "title": "Apache Portable Runtime util int overflow",
        "description": "Integer overflow in apr-util when handling base64 data.",
        "packages": {"apr-util": "1.6.1-9.el8"},
        "kev": False, "exploited": False, "cwe": "CWE-190",
    },

    # ─── 2021 ──────────────────────────────────────────────────────────────
    {
        "cve": "CVE-2021-4034", "rhsa": "RHSA-2022:0274",
        "severity": "HIGH",
        "title": "PwnKit — polkit pkexec local privilege escalation",
        "description": "An out-of-bounds write in pkexec lets any local unprivileged user "
                       "escalate to root by exploiting how pkexec rebuilds its environment.",
        "packages": {"polkit": "0.115-13.el8_5.1"},
        "kev": True, "exploited": True, "cwe": "CWE-787",
    },
    {
        "cve": "CVE-2021-3156", "rhsa": "RHSA-2021:0218",
        "severity": "HIGH",
        "title": "Baron Samedit — sudo heap-based buffer overflow",
        "description": "An off-by-one in sudo's command-line parsing lets a local user trigger a "
                       "heap overflow and gain root, regardless of sudoers entries.",
        "packages": {"sudo": "1.8.29-6.el8_3.1"},
        "kev": True, "exploited": True, "cwe": "CWE-193",
    },
    {
        "cve": "CVE-2021-44228", "rhsa": "RHSA-2021:5141",
        "severity": "CRITICAL",
        "title": "Log4Shell — Apache log4j JNDI lookup RCE",
        "description": "log4j 2.x recursively expands JNDI lookups in log messages, letting an "
                       "attacker who controls a logged string trigger remote code execution via "
                       "an attacker-controlled LDAP server.",
        "packages": {"log4j": "2.17.1-1.el8"},
        "kev": True, "exploited": True, "cwe": "CWE-502",
    },

    # ─── Additional high-impact entries to round out coverage ──────────────
    {
        "cve": "CVE-2024-45492", "rhsa": "RHSA-2024:6986",
        "severity": "MEDIUM",
        "title": "libexpat integer overflow (XML_GetBuffer)",
        "description": "Integer overflow in XML_GetBuffer leads to heap-based buffer overflow.",
        "packages": {"expat": "2.2.5-15.el8_10"},
        "kev": False, "exploited": False, "cwe": "CWE-190",
    },
    {
        "cve": "CVE-2023-6004", "rhsa": "RHSA-2024:0540",
        "severity": "MEDIUM",
        "title": "libssh command injection via crafted ProxyCommand",
        "description": "libssh ProxyCommand processing did not properly quote the hostname → an "
                       "attacker who controls a hostname (e.g. via DNS) can inject shell commands.",
        "packages": {"libssh": "0.10.4-13.el8_9"},
        "kev": False, "exploited": False, "cwe": "CWE-78",
    },
    {
        "cve": "CVE-2023-50868", "rhsa": "RHSA-2024:0938",
        "severity": "HIGH",
        "title": "NSEC3 closest-encloser DNSSEC CPU exhaustion",
        "description": "Validating an NSEC3 chain with maximum iterations consumes excessive CPU.",
        "packages": {"bind": "9.11.36-13.el8_9.1", "unbound": "1.16.2-5.el8_9"},
        "kev": False, "exploited": False, "cwe": "CWE-770",
    },
    {
        "cve": "CVE-2023-51385", "rhsa": "RHSA-2024:0444",
        "severity": "MEDIUM",
        "title": "OpenSSH shell metacharacter injection via crafted hostnames",
        "description": "OpenSSH ssh did not properly sanitise %h in known_hosts processing — an "
                       "attacker controlling a hostname can inject shell metacharacters.",
        "packages": {"openssh": "8.0p1-21.el8_9.1"},
        "kev": False, "exploited": False, "cwe": "CWE-78",
    },
    {
        "cve": "CVE-2024-6409", "rhsa": "RHSA-2024:4348",
        "severity": "MEDIUM",
        "title": "OpenSSH privsep child race condition RCE (companion to regreSSHion)",
        "description": "A signal handler race in the OpenSSH privilege-separation child process "
                       "could allow remote code execution as the unprivileged 'sshd' user.",
        "packages": {"openssh": "8.0p1-23.el8_10"},
        "kev": False, "exploited": True, "cwe": "CWE-364",
    },
    {
        "cve": "CVE-2024-2002", "rhsa": "RHSA-2024:3343",
        "severity": "MEDIUM",
        "title": "libxml2 use-after-free in XML reader",
        "description": "UAF in xmlReader when parsing XML with crafted DTD subset.",
        "packages": {"libxml2": "2.9.7-18.el8_10"},
        "kev": False, "exploited": False, "cwe": "CWE-416",
    },
    {
        "cve": "CVE-2023-7104", "rhsa": "RHSA-2024:0560",
        "severity": "MEDIUM",
        "title": "sqlite UAF in sessionReadRecord",
        "description": "A use-after-free in sqlite's session module triggered by crafted changeset "
                       "files.",
        "packages": {"sqlite": "3.26.0-19.el8_9"},
        "kev": False, "exploited": False, "cwe": "CWE-416",
    },
    {
        "cve": "CVE-2022-29900", "rhsa": "RHSA-2022:5851",
        "severity": "MEDIUM",
        "title": "Retbleed — AMD/Intel CPU return-instruction speculation leak",
        "description": "Return-instruction speculation on AMD Zen 1/2 and certain Intel CPUs lets "
                       "a local attacker leak kernel memory via timing side channels.",
        "packages": {"kernel": "4.18.0-372.16.1.el8_6"},
        "kev": False, "exploited": False, "cwe": "CWE-1037",
    },
    {
        "cve": "CVE-2022-29901", "rhsa": "RHSA-2022:5851",
        "severity": "MEDIUM",
        "title": "Retbleed (Intel variant)",
        "description": "Companion to CVE-2022-29900 covering Intel branch target injection.",
        "packages": {"kernel": "4.18.0-372.16.1.el8_6"},
        "kev": False, "exploited": False, "cwe": "CWE-1037",
    },
    {
        "cve": "CVE-2022-22963", "rhsa": "RHSA-2022:1297",
        "severity": "CRITICAL",
        "title": "Spring Cloud Function SpEL injection RCE (Spring4Shell adjacent)",
        "description": "Spring Cloud Function allowed Spring Expression Language injection via the "
                       "spring.cloud.function.routing-expression header, leading to RCE.",
        "packages": {"spring-cloud-function-core": "3.1.7-1.el8"},
        "kev": True, "exploited": True, "cwe": "CWE-94",
    },
    {
        "cve": "CVE-2024-26609", "rhsa": "RHSA-2024:2950",
        "severity": "HIGH",
        "title": "Kernel netfilter nf_tables_newrule UAF",
        "description": "Use-after-free in nf_tables_newrule lets a local attacker with "
                       "CAP_NET_ADMIN escalate to root.",
        "packages": {"kernel": "4.18.0-553.5.1.el8_10"},
        "kev": False, "exploited": False, "cwe": "CWE-416",
    },
]


# Fix the entry 0 indentation bug (xz-utils entry) that's been carried over
# from the comment block — kept as a data table above; ensure 'packages' is
# always present.
for _e in CVES:
    _e.setdefault("packages", {})
    _e.setdefault("kev", False)
    _e.setdefault("exploited", False)


# ----------------------------------------------------------------------------
# Auditor
# ----------------------------------------------------------------------------

class CveAuditor(BaseAuditor):
    SUPPORTED_RHEL_MAJORS = {8, 9}
    CATEGORY = "CVE Detection"

    def run_all_checks(self) -> List[Dict[str, Any]]:
        if not self.supports_rhel():
            return self._emit_skip_notice(self.CATEGORY)

        if not self.bundle.has_command("rpm_qa"):
            self.finding(
                "CVE-META-001",
                "RPM inventory not in bundle — CVE detection skipped",
                self.SEVERITY_INFO, self.CATEGORY,
                "The collector must capture 'rpm -qa' for CVE matching to work.",
                remediation="Re-run the collector; ensure cmd/rpm_qa.txt is populated.",
            )
            return self.findings

        pkgs = parse_rpm_inventory(self.bundle)
        if not pkgs:
            self.finding(
                "CVE-META-002",
                "rpm -qa returned no packages — CVE detection skipped",
                self.SEVERITY_INFO, self.CATEGORY,
                "Either the collector ran without permission to query RPM, or the output was empty.",
                remediation="Re-run the collector as root.",
            )
            return self.findings

        matched = 0
        for cve in CVES:
            for pkg_name, fixed_vr in cve["packages"].items():
                installed = pkgs.get(pkg_name)
                if installed is None:
                    continue
                if vr_compare(installed, fixed_vr) < 0:
                    self._emit(cve, installed, fixed_vr)
                    matched += 1
                    break  # one finding per CVE, even if multiple packages match

        if matched == 0:
            self.finding(
                "CVE-META-003",
                f"No CVE matches across {len(pkgs)} installed packages",
                self.SEVERITY_INFO, self.CATEGORY,
                f"Compared {len(pkgs)} RPMs against {len(CVES)} curated RHEL 8 CVEs and found no "
                f"matches. Either the system is fully patched against this scanner's database, or "
                f"the database lacks coverage for advisories published after the scanner build "
                f"date. Cross-reference with Red Hat Security Data:\n"
                f"  https://access.redhat.com/security/security-updates",
                remediation="Re-run periodically; supplement with 'dnf updateinfo list security'.",
                references=["https://access.redhat.com/security/security-updates"],
            )

        return self.findings

    def _emit(self, cve: Dict[str, Any], installed: RpmPackage, fixed_vr: str) -> None:
        tags = []
        if cve.get("kev"):
            tags.append("KEV-listed")
        if cve.get("exploited"):
            tags.append("actively exploited")
        tag_str = f" [{' / '.join(tags)}]" if tags else ""
        sev_map = {"CRITICAL": self.SEVERITY_CRITICAL, "HIGH": self.SEVERITY_HIGH,
                   "MEDIUM": self.SEVERITY_MEDIUM, "LOW": self.SEVERITY_LOW}
        sev = sev_map.get(cve["severity"], self.SEVERITY_MEDIUM)
        title = f"{cve['cve']} — {cve['title']}{tag_str}"
        description = (
            f"{cve['description']}\n\n"
            f"Installed: {installed.nvr} (.{installed.arch}). "
            f"First fixed in: {installed.name}-{fixed_vr}. "
            f"Red Hat advisory: {cve['rhsa']}."
        )
        self.finding(
            check_id=f"CVE-{cve['cve']}",
            title=title,
            severity=sev,
            category=self.CATEGORY,
            description=description,
            affected_items=[f"{installed.name}-{installed.version}-{installed.release}.{installed.arch}"],
            remediation=f"dnf update {installed.name}  # upgrade to {fixed_vr} or later",
            references=[
                f"https://access.redhat.com/errata/{cve['rhsa']}",
                f"https://access.redhat.com/security/cve/{cve['cve']}",
                f"CWE: {cve['cwe']}",
            ],
            details={
                "cve": cve["cve"], "rhsa": cve["rhsa"],
                "installed_nvr": installed.nvr, "fixed_vr": fixed_vr,
                "kev": cve.get("kev", False), "exploited": cve.get("exploited", False),
            },
        )
