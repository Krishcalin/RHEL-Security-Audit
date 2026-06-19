"""
Filesystem Hardening (CIS RHEL 8 Section 1.1)

Audits /etc/fstab and mount output for separate partition coverage and
required mount options (nodev, nosuid, noexec) on the standard mount points.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Set

from core.base import BaseAuditor


# Mount points that CIS expects to be separate filesystems with hardened options
_EXPECTED_PARTITIONS = {
    "/tmp":             ("MEDIUM", {"nodev", "nosuid", "noexec"}),
    "/dev/shm":         ("MEDIUM", {"nodev", "nosuid", "noexec"}),
    "/var":             ("LOW",    set()),
    "/var/tmp":         ("MEDIUM", {"nodev", "nosuid", "noexec"}),
    "/var/log":         ("LOW",    set()),
    "/var/log/audit":   ("MEDIUM", set()),
    "/home":            ("LOW",    {"nodev"}),
}


def _parse_mounts(text: str) -> Dict[str, Dict[str, object]]:
    """Parse 'mount' output into {mountpoint: {fs, opts: set()}}."""
    mounts: Dict[str, Dict[str, object]] = {}
    # Lines look like: tmpfs on /run type tmpfs (rw,nosuid,nodev,seclabel,size=...)
    rx = re.compile(r"^(\S+)\s+on\s+(\S+)\s+type\s+(\S+)\s+\(([^)]+)\)")
    for line in text.splitlines():
        m = rx.match(line.strip())
        if not m:
            continue
        _dev, mp, fs, opts = m.groups()
        mounts[mp] = {"fs": fs, "opts": set(o.strip() for o in opts.split(","))}
    return mounts


class FilesystemAuditor(BaseAuditor):
    SUPPORTED_RHEL_MAJORS = {8, 9}
    CATEGORY = "Filesystem"

    def run_all_checks(self) -> List[Dict[str, Any]]:
        if not self.supports_rhel():
            return self._emit_skip_notice(self.CATEGORY)

        mount_text = self.bundle.read_command("mount")
        mounts = _parse_mounts(mount_text) if mount_text else {}
        sev_map = {
            "CRITICAL": self.SEVERITY_CRITICAL, "HIGH": self.SEVERITY_HIGH,
            "MEDIUM": self.SEVERITY_MEDIUM, "LOW": self.SEVERITY_LOW,
        }
        for mp, (sev, required_opts) in _EXPECTED_PARTITIONS.items():
            if mp not in mounts:
                self.finding(
                    f"FS-{mp.replace('/', '-')}-A",
                    f"{mp} is not a separate filesystem",
                    sev_map[sev], self.CATEGORY,
                    f"CIS recommends {mp} be on its own filesystem so it can be sized, monitored "
                    f"for fill, and hardened with mount options independently of /.",
                    remediation=f"Create a dedicated partition / logical volume for {mp} and update /etc/fstab.",
                    references=[f"CIS RHEL 8 1.1.x ({mp})"],
                )
                continue
            opts = mounts[mp]["opts"]
            missing = required_opts - opts
            if missing:
                self.finding(
                    f"FS-{mp.replace('/', '-')}-B",
                    f"{mp} missing required mount options: {', '.join(sorted(missing))}",
                    sev_map[sev], self.CATEGORY,
                    f"{mp} is mounted but without {', '.join(sorted(missing))}. CIS requires these "
                    f"options on world-writable / user-writable mount points to prevent privilege "
                    f"escalation via setuid binaries dropped there.",
                    affected_items=[f"{mp} → {','.join(sorted(opts))}"],
                    remediation=f"Edit /etc/fstab to add {','.join(sorted(missing))} to the {mp} entry and remount.",
                    references=[f"CIS RHEL 8 1.1.x ({mp})"],
                )

        self._check_kernel_modules_filesystems()
        self._check_world_writable_dirs_in_path()
        return self.findings

    def _check_kernel_modules_filesystems(self):
        """CIS expects unused filesystem kernel modules to be disabled."""
        mods = self.bundle.read_command("kernel_modules")
        # 'lsmod' format: Module<spc>Size<spc>Used-by
        loaded = set()
        for line in mods.splitlines():
            parts = line.split()
            if parts and parts[0] and not parts[0].lower().startswith("module"):
                loaded.add(parts[0])
        risky_fs = {"cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "squashfs", "udf"}
        loaded_risky = sorted(loaded & risky_fs)
        if loaded_risky:
            self.finding(
                "FS-MOD-001", f"Unnecessary filesystem kernel modules loaded: {', '.join(loaded_risky)}",
                self.SEVERITY_LOW, self.CATEGORY,
                "CIS recommends blacklisting filesystem modules not required by the workload — "
                "each loaded module is part of the kernel attack surface.",
                affected_items=loaded_risky,
                remediation="Add 'install <mod> /bin/true' lines under /etc/modprobe.d/ and reboot.",
                references=["CIS RHEL 8 1.1.1"],
            )

    def _check_world_writable_dirs_in_path(self):
        # The collector doesn't capture a 'find / -perm -0002' result by
        # default (would balloon the bundle size on large hosts). Emit a META
        # finding so operators know this check is not performed and can opt-in.
        self.finding(
            "FS-META-001",
            "World-writable directory scan not part of default collection",
            self.SEVERITY_INFO, self.CATEGORY,
            "World-writable directory enumeration ('find / -perm -0002 -type d') and SUID "
            "binary enumeration ('find / -perm -4000') are not captured by the default "
            "collector to keep bundle size small. Run these manually on the target host:\n\n"
            "  find / -xdev -type d -perm -0002 ! -perm -1000 -print 2>/dev/null\n"
            "  find / -xdev -type f -perm -4000 -print 2>/dev/null",
            remediation="Append the find outputs to the bundle's cmd/ directory if you need these checks.",
        )
