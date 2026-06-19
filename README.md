<h1 align="center">RHEL 8 Security Audit Scanner</h1>

<p align="center">
  <strong>Offline configuration, hardening, and CVE assessment for Red Hat Enterprise Linux 8</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue?style=flat-square" alt="Version"/>
  <img src="https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/dependencies-zero-brightgreen?style=flat-square" alt="Dependencies"/>
  <img src="https://img.shields.io/badge/RHEL-8%20%7C%209-red?style=flat-square" alt="RHEL"/>
  <img src="https://img.shields.io/badge/checks-130%2B-orange?style=flat-square" alt="Checks"/>
  <img src="https://img.shields.io/badge/CVEs-43-critical?style=flat-square" alt="CVEs"/>
  <img src="https://img.shields.io/badge/CIS-RHEL%208%20v3.x-blueviolet?style=flat-square" alt="CIS"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"/>
</p>

---

## Overview

The **RHEL 8 Security Audit Scanner** is a two-piece offline tool:

1. A small **Bash collector** (`collect_rhel8.sh`) you run **once on the target host**. It captures `/etc` configuration files plus the runtime command outputs (RPM inventory, audit rules, SELinux state, sysctl, firewall, listening ports, mount table, etc.) into a single `.tar.gz` bundle.
2. A **Python analyzer** (`rhel8_scanner.py`) that runs on a separate workstation, parses the bundle, and produces an interactive HTML security dashboard.

Designed for **OT, air-gapped, and regulated environments** where the audit workstation cannot reach the target host directly — and where `pip install` may not be possible on either side.

### Key features

| Capability | Details |
|-----------|---------|
| **Two-step offline workflow** | Bash collector → tar.gz bundle → Python analyzer. No network access between collector and analyzer required. |
| **Zero third-party dependencies** | Python 3.8+ stdlib only on the analyzer; standard RHEL utilities only in the collector. |
| **CIS RHEL 8 Benchmark v3.x aligned** | 130+ checks across SSH, SELinux, audit, PAM, sysctl, firewall, services, filesystem, sudo, cron, accounts. |
| **DISA STIG cross-references** | Each finding links to the relevant STIG ID where one exists. |
| **43 curated RHEL 8 CVEs** | RPM-based version matching against Red Hat PSIRT advisories (RHSA-YYYY:NNNN). Includes KEV-listed and actively-exploited tagging. |
| **rpmvercmp implementation** | Stdlib re-implementation of the RPM version-comparison algorithm — handles dotted-numeric, alphanumeric, and pre-release markers correctly. |
| **Interactive HTML report** | Dark-theme dashboard with severity filter, weighted risk score, and per-finding expansion. All user content `html.escape()`-d. |
| **CI/CD ready** | Exit code 1 when CRITICAL/HIGH findings are present, suitable for pipeline gating. |

---

## Audit Modules (11)

| Module | Key | Focus | Checks |
|--------|-----|-------|:------:|
| **SSH Daemon** | `ssh` | sshd_config: protocol, root login, weak ciphers / MACs / kex, MaxAuthTries, banner, PAM | 21 |
| **SELinux** | `selinux` | /etc/selinux/config + sestatus + getenforce + boot cmdline | ~6 |
| **Audit Subsystem** | `audit` | auditd.conf + auditctl rule coverage (CIS 4.1 required rules) | ~17 |
| **PAM / Authentication** | `pam` | pwquality, faillock, pwhistory, su pam_wheel, hashing algorithm | ~13 |
| **Kernel / Network Parameters** | `sysctl` | runtime sysctl -a: forwarding, source routes, redirects, ASLR, ptrace, BPF | ~21 |
| **Firewall / Exposure** | `firewall` | firewalld installed/enabled/running, default zone, listening ports | ~10 |
| **Services** | `services` | Legacy services enabled (telnet, rsh, tftp, ftp, xinetd, NIS) + failed units | ~25 |
| **Filesystem** | `filesystem` | /etc/fstab + mount options on /tmp, /dev/shm, /var, /home; risky kernel modules | ~10 |
| **Sudo / Cron** | `sudo` | NOPASSWD, !authenticate, broad sudo grants, cron.allow, at.allow | ~7 |
| **Accounts** | `accounts` | Multiple UID 0, empty passwords, login.defs expiry, system shells, UMASK | ~9 |
| **CVE Detection** | `cve` | 43 curated RHEL 8 RHSAs matched against RPM inventory | 43 |

---

## Bundle Layout

The collector produces a tarball with this layout:

```
./meta/collector.txt              hostname, kernel, RHEL version, collector metadata
./etc/<relative path>             copy of /etc/<path>, preserving structure
./cmd/<label>.txt                 stdout+stderr of a captured command, wrapped in a small header
```

Captured commands include `rpm_qa`, `sysctl_a`, `auditctl_rules`, `sestatus`, `getenforce`, `firewall_cmd_list`, `ss_listen`, `mount`, `systemctl_unit_files`, `systemctl_running`, `systemctl_failed`, `boot_cmdline`, `kernel_modules`, and more.

---

## Quick Start

### 1. Collect on the target RHEL 8 host

```bash
# Copy collector to the target (USB / scp / file share)
sudo bash collect_rhel8.sh /tmp

# Output:
# [*] Bundle: rhel8-audit-prod-web-01-20260619T100000Z
# ...
# /tmp/rhel8-audit-prod-web-01-20260619T100000Z.tar.gz
```

The collector is read-only — it does not install packages, change config, or make network calls. Safe to run on production.

### 2. Transfer the bundle to your audit workstation

Use whatever transport your security policy allows: signed USB, internal file share, scp.

### 3. Analyze

```bash
python rhel8_scanner.py --bundle rhel8-audit-prod-web-01-20260619T100000Z.tar.gz \
                       --output prod-web-01-report.html
```

Open the HTML report in any browser. No JavaScript dependencies, fully self-contained.

### 4. Selective scans

```bash
# Only SSH and CVE modules
python rhel8_scanner.py --bundle b.tar.gz --modules ssh cve

# Only HIGH+ findings (good for CI gating)
python rhel8_scanner.py --bundle b.tar.gz --severity HIGH --output ci-report.html
echo "exit: $?"   # 1 if CRITICAL/HIGH present

# Smoke test against the included sample bundle
python rhel8_scanner.py --bundle ./sample_bundle --output sample_report.html
```

---

## Sample Output

Running against the included sample bundle (`./sample_bundle/`, intentionally insecure RHEL 8.8 host):

```
  ===============================================================
    RHEL 8 Offline Security Audit Scanner v1.0.0
  ===============================================================
[*] Loading bundle: ./sample_bundle
[*] Host: rhel8-demo  RHEL: 8.8  Files: 26
[*] Running modules: ssh, selinux, audit, pam, sysctl, firewall,
                     services, filesystem, sudo, accounts, cve

  [ssh        ] SSH Daemon                         16 finding(s)
  [selinux    ] SELinux                             2 finding(s)
  [audit      ] Audit Subsystem                    15 finding(s)
  [pam        ] PAM / Authentication               12 finding(s)
  [sysctl     ] Kernel / Network Parameters        14 finding(s)
  [firewall   ] Firewall / Exposure                 7 finding(s)
  [services   ] Services                            6 finding(s)
  [filesystem ] Filesystem                          9 finding(s)
  [sudo       ] Sudo / Cron                         7 finding(s)
  [accounts   ] Accounts                            8 finding(s)
  [cve        ] CVE Detection                      35 finding(s)

  ===============================================================
    SCAN COMPLETE
    Total findings : 131
    CRITICAL : 8    HIGH : 48    MEDIUM : 49
    LOW      : 23   INFO : 3
  ===============================================================
```

Headline CVEs the sample triggers: XZ backdoor, regreSSHion, PwnKit, Baron Samedit, Looney Tunables, Log4Shell, runc container escape.

---

## CLI Reference

```
usage: rhel8_scanner.py [-h] --bundle BUNDLE [--output OUTPUT]
                        [--severity {CRITICAL,HIGH,MEDIUM,LOW,INFO,ALL}]
                        [--modules {ssh,selinux,audit,pam,sysctl,firewall,
                                    services,filesystem,sudo,accounts,cve,all} ...]
                        [--version]

  --bundle BUNDLE         Path to collector bundle (.tar.gz) or unpacked directory
  --output OUTPUT         HTML report path (default: rhel8_security_report.html)
  --severity LEVEL        Minimum severity to include
  --modules KEY [KEY ...] Subset of modules to run (default: all)
```

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | No CRITICAL or HIGH findings |
| `1` | One or more CRITICAL/HIGH findings |
| `2` | Bundle not found / usage error |

---

## Security Considerations

- **Bundle is sensitive.** It contains `/etc/shadow`, `/etc/sudoers`, the full RPM inventory, audit rules, and SELinux policy state. Treat the `.tar.gz` with the same controls you apply to the host itself: encrypted transport, restricted storage, deletion after audit.
- **Run collector as root.** Without root, key files (`/etc/shadow`, audit rules, firewalld zones) won't be readable, and many checks will degrade to INFO meta-findings.
- **Verify CVE matches.** The CVE database is curated, not exhaustive. For production audit, supplement with `dnf updateinfo list security` on the target and Red Hat's `oscap xccdf eval` with the official SCAP content.
- **Report contains sanitised evidence.** Where modules surface evidence from sensitive files (sudoers NOPASSWD lines, /etc/passwd UID-0 accounts), the report shows usernames and rule shapes — never password hashes.

---

## References

- [CIS Red Hat Enterprise Linux 8 Benchmark](https://www.cisecurity.org/benchmark/red_hat_linux)
- [DISA STIG Red Hat Enterprise Linux 8](https://public.cyber.mil/stigs/downloads/)
- [Red Hat Security Data](https://access.redhat.com/security/data/)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Red Hat Errata Search](https://access.redhat.com/security/security-updates/)

---

## License

MIT License — see [LICENSE](LICENSE).
