# CLAUDE.md — RHEL 8 Security Audit Scanner

## Project Overview

Offline security audit tool for Red Hat Enterprise Linux 8 (and 9). Two
components, designed to be used together but kept loosely coupled:

1. **Collector** (`collector/collect_rhel8.sh`) — Bash script run **once on
   the target host**. Captures the configuration files and runtime command
   outputs that the analyzer needs, packages them into a `.tar.gz` bundle.
   Read-only — no installation, no config changes, no network calls.

2. **Analyzer** (`rhel8_scanner.py`) — Python 3.8+ stdlib tool run on a
   workstation. Parses a bundle and emits findings against CIS RHEL 8
   Benchmark v3.x, DISA STIG controls, and the Red Hat Security Data CVE
   list. Produces a self-contained dark-theme HTML report.

- **Language**: Python 3.8+, stdlib only (no `pip install`)
- **License**: MIT
- **Repository**: https://github.com/Krishcalin/RHEL-Security-Audit
- **Version**: 1.0.0 (collector v1.0.0, analyzer engine v1.0.0)

## Why offline?

In OT, government-air-gapped, or regulated environments, the audit
workstation cannot reach the target host directly. Operator runs the
collector with sudo, transfers the bundle off-host (USB / signed transfer /
file share), and the auditor parses it on a separate workstation that may
not even have internet for `dnf` or `pip`.

## Architecture

```
rhel8_scanner.py                  CLI entry, MODULE_MAP, --severity / --modules
├── core/
│   ├── bundle.py                 Bundle reader (tar.gz or directory); RPM inventory parser
│   ├── base.py                   BaseAuditor with SUPPORTED_RHEL_MAJORS guard, Finding helper
│   └── report.py                 Dark-theme HTML dashboard, html.escape() on every interpolation
├── modules/
│   ├── ssh.py                    21 checks  — sshd_config (CIS 5.2)
│   ├── selinux.py                ~6 checks  — config + sestatus (CIS 1.6)
│   ├── audit.py                  ~17 checks — auditd.conf + auditctl rules (CIS 4.1)
│   ├── pam.py                    ~13 checks — pwquality + faillock + system-auth (CIS 5.3-5.4)
│   ├── sysctl.py                 ~21 checks — runtime sysctl -a (CIS 3.2-3.3)
│   ├── firewall.py               ~10 checks — firewalld + ss listen + hosts.allow (CIS 3.4)
│   ├── services.py               ~25 checks — telnet/rsh/tftp/ftp/xinetd/etc (CIS 2.1)
│   ├── filesystem.py             ~10 checks — fstab / mount / lsmod (CIS 1.1)
│   ├── sudo_cron.py              ~7 checks  — NOPASSWD, !authenticate, cron.allow (CIS 5.6, 5.1.8)
│   ├── accounts.py               ~9 checks  — UID 0 dupes, empty passwd, login.defs (CIS 5.5, 6.2)
│   └── cve.py                    43 curated RHEL 8 CVEs with rpmvercmp matcher
├── collector/
│   └── collect_rhel8.sh          Bash collector — captures /etc + 25+ command outputs
└── sample_bundle/                Unpacked example bundle for offline testing
```

## Bundle Layout

The collector writes a tarball with this internal layout:

```
./meta/collector.txt              # key=value metadata: hostname, kernel, RHEL version, etc.
./etc/<relative path>             # copy of /etc/<path>, preserving structure
./cmd/<label>.txt                 # stdout+stderr of a captured command,
                                  #   wrapped in a small header (# Command:, ...)
```

The analyzer's `core/bundle.py:Bundle.open()` accepts either a `.tar.gz` or
an already-unpacked directory (useful for development and tests). All
hardening modules access files via:

```python
self.bundle.read_etc_file("/etc/ssh/sshd_config")
self.bundle.read_command("rpm_qa")             # collector header stripped
self.bundle.list_etc("/etc/sudoers.d")          # list of real /etc paths
self.bundle.has_etc_file("/etc/security/pwquality.conf")
self.bundle.rhel_major                           # → 8 or 9
```

Command captures the collector knows how to take (from `collect_rhel8.sh`):

| Label | Source command | Used by |
|-------|---------------|---------|
| `rpm_qa` | `rpm -qa --queryformat '%{NAME}\|%{VERSION}\|%{RELEASE}\|%{ARCH}\|%{EPOCH}\n'` | `cve`, `audit` |
| `systemctl_unit_files` | `systemctl list-unit-files` | `audit`, `services`, `firewall` |
| `systemctl_running` | `systemctl list-units --state=running` | `audit`, `firewall` |
| `systemctl_failed` | `systemctl list-units --state=failed` | `services` |
| `auditctl_rules` | `auditctl -l` | `audit` |
| `sestatus` / `getenforce` | `sestatus`, `getenforce` | `selinux` |
| `sysctl_a` | `sysctl -a` | `sysctl` |
| `firewall_cmd_list` | `firewall-cmd --list-all-zones` | `firewall` |
| `ss_listen` | `ss -tulnp` | `firewall` |
| `mount` | `mount` | `filesystem` |
| `boot_cmdline` | `cat /proc/cmdline` | `selinux` |
| `kernel_modules` | `lsmod` | `filesystem` |

## Auditor Pattern

Every module subclasses `BaseAuditor`, declares its supported RHEL majors,
and implements `run_all_checks()`:

```python
from core.base import BaseAuditor

class MyAuditor(BaseAuditor):
    SUPPORTED_RHEL_MAJORS = {8, 9}      # None = run on any
    CATEGORY = "My Section"

    def run_all_checks(self):
        if not self.supports_rhel():
            return self._emit_skip_notice(self.CATEGORY)
        self._check_a()
        self._check_b()
        return self.findings              # ALWAYS return at the end

    def _check_a(self):
        if self.bundle.has_etc_file("/etc/foo") and "bad" in self.bundle.read_etc_file("/etc/foo"):
            self.finding(
                "FOO-001", "Foo contains 'bad' setting",
                self.SEVERITY_HIGH, self.CATEGORY,
                "Why it matters in 1-2 sentences.",
                affected_items=["/etc/foo line 5: setting=bad"],
                remediation="echo 'setting=good' > /etc/foo",
                references=["CIS RHEL 8 1.x", "STIG RHEL-08-XXXXXX"],
            )
```

## Finding Schema

Identical to the Cisco / Fortinet sister tools (so a future cross-platform
report consumer reads one shape):

| Field | Type | Notes |
|-------|------|-------|
| `check_id` | str | Stable scanner-local id (`SSH-001`, `CVE-CVE-2024-3094`, `AUD-META-001`) |
| `title` | str | One-line description |
| `severity` | str | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO` |
| `category` | str | `SSH`, `SELinux`, `CVE Detection`, etc. |
| `description` | str | 1-3 sentence explanation |
| `affected_items` | list[str] | Evidence (config lines, package NVRs) |
| `affected_count` | int | Auto-derived |
| `remediation` | str | CLI fix or upgrade command |
| `references` | list[str] | CIS section, STIG id, CVE/RHSA URLs, CWE |
| `details` | dict | Free-form (used by CVE module for CVSS, KEV flags, fixed NVR) |
| `timestamp` | str | ISO 8601, set automatically |
| `device` / `module` | str | Tagged by the runner |

## CVE Module (`modules/cve.py`)

Distinct from the hardening modules: doesn't grep configs, it matches the
RPM inventory against a curated list of high-impact RHSAs.

### Database (`CVES`)

43 entries (2021-2026) covering CRITICAL/HIGH/MEDIUM RHSAs:

- **2024**: XZ backdoor (CVE-2024-3094), regreSSHion (CVE-2024-6387),
  nf_tables UAF (CVE-2024-1086), runc container escape (CVE-2024-21626),
  glibc iconv (CVE-2024-2961), OpenSSL PKCS12 (CVE-2024-0727)
- **2023**: Looney Tunables (CVE-2023-4911), OverlayFS privesc
  (CVE-2023-0386), netfilter UAF (CVE-2023-32233), HTTP/2 Rapid Reset
  (CVE-2023-44487), Terrapin (CVE-2023-48795), Zenbleed (CVE-2023-20593),
  KeyTrap (CVE-2023-50387/50868)
- **2022**: Filesystem context heap overflow (CVE-2022-0185), OpenSSL
  punycode (CVE-2022-3786/3602), gzip xzgrep (CVE-2022-1271), Retbleed
  (CVE-2022-29900/29901), Spring Cloud Function SpEL (CVE-2022-22963)
- **2021**: PwnKit (CVE-2021-4034), Baron Samedit (CVE-2021-3156),
  Log4Shell (CVE-2021-44228)

Each entry records `cve`, `rhsa`, `severity`, `title`, `description`,
`packages` dict (`name -> fixed_vr`), `kev`, `exploited`, `cwe`. KEV-listed
and actively-exploited CVEs are flagged in the finding title for
prioritisation.

### RPM Version Comparison

`modules/cve.py:rpmvercmp` is a stdlib re-implementation of the rpm-libs
algorithm. It handles dotted-numeric versions, alphanumeric segments, the
`~` pre-release marker, and the standard `version-release` split. Tested
against a representative set of RHEL package NVRs.

```python
from modules.cve import rpmvercmp, vr_compare

rpmvercmp("1.2.11", "1.2.12")       # → -1
rpmvercmp("23.el8_8", "25.el8_10")  # → -1
vr_compare(installed_pkg, "1.2.11-23.el8_8")
```

### Precision Caveat

Database is curated, not exhaustive. Targets KEV-listed / known-exploited /
CRITICAL CVEs. For production audit, supplement with `dnf updateinfo list
security` on the target and Red Hat's official `oscap xccdf eval`.

## Development Guidelines

### Adding a new hardening module

1. Create `modules/<short_name>.py` with `class FooAuditor(BaseAuditor)`.
2. Set `SUPPORTED_RHEL_MAJORS` (use `{8, 9}` if it applies to both, `None`
   for any).
3. Implement `run_all_checks()` — always include the supports_rhel guard
   at the top and `return self.findings` at the bottom.
4. Use a stable rule-id prefix (`FOO-001`, `FOO-002`).
5. Always include `description`, `remediation`, and at least one
   `references` entry (CIS section, STIG id, NIST 800-53 control).
6. Register in `rhel8_scanner.py:MODULE_MAP` under a short CLI key.
7. If the check depends on a command output not yet captured, ADD IT TO
   `collector/collect_rhel8.sh` first.

### Adding a new CVE

1. Append to `CVES` in `modules/cve.py`.
2. `packages` keys must match the RPM `name` field (no `.el8` suffix in
   the key — that's in the version-release value).
3. `fixed_vr` is the first fixed VERSION-RELEASE string as published in
   the RHSA (e.g. `1.2.11-23.el8_8`).
4. Link the canonical `RHSA-YYYY:NNNN` so operators can resolve the exact
   patch via access.redhat.com.
5. Mark `kev: True` if listed in the CISA Known Exploited Vulnerabilities
   catalog; `exploited: True` if Red Hat / TALOS confirms in-the-wild use.

### Sanitising evidence

The collector captures `/etc/shadow`, `/etc/sudoers`, and similar
sensitive files. Any check that surfaces these contents in
`affected_items` MUST sanitise them — see `modules/accounts.py` for the
pattern (we surface usernames but never hashes, even though the bundle has
the raw shadow file).

### Conventions

- Stdlib only on the analyzer side. Bash + standard RHEL utilities on the
  collector side. Keep it that way.
- Regex matches case-insensitive by default.
- HTML report uses `html.escape()` on every user-controlled interpolation
  — config snippets, package NVRs, descriptions. Never `format` user
  content into HTML without escaping.
- `rhel8_scanner.py` reconfigures stdout/stderr to UTF-8 at startup so
  banner chars and unicode finding text don't crash Windows cp1252
  consoles when run from the audit workstation.
- Exit code 1 if any CRITICAL or HIGH findings (suitable for CI gating).

## Running

```bash
# On the target host (RHEL 8)
sudo ./collector/collect_rhel8.sh /tmp
# Produces /tmp/rhel8-audit-<host>-<timestamp>.tar.gz

# Transfer the bundle to the audit workstation, then:
python rhel8_scanner.py --bundle /path/to/bundle.tar.gz --output report.html

# Subset
python rhel8_scanner.py --bundle b.tar.gz --modules ssh cve --severity HIGH

# Smoke test against the included sample
python rhel8_scanner.py --bundle ./sample_bundle --output sample_report.html
```
