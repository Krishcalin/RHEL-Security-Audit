"""
Bundle reader for the RHEL 8 audit collector output.

The collector script produces a tar.gz with this layout:
    ./meta/collector.txt           key=value metadata about the collection
    ./etc/<relative path>          copy of /etc/<path>, preserving structure
    ./cmd/<label>.txt              stdout+stderr of a captured command,
                                   wrapped in a small header (# Command:, ...)

This module hides those mechanics behind a small class that auditors use:

    bundle = Bundle.open("rhel8-audit-host-2026....tar.gz")
    sshd_cfg = bundle.read_etc_file("/etc/ssh/sshd_config")
    rpm_qa = bundle.read_command("rpm_qa")
    hostname = bundle.meta.get("hostname")

Also handles ingesting a plain directory (e.g. an unpacked bundle) so the
test suite and interactive debugging don't need to repeatedly tar/untar.
"""

from __future__ import annotations

import io
import re
import tarfile
from pathlib import Path
from typing import Dict, Iterable, List, Optional


# Lines emitted by the collector that wrap real command output. Stripped when
# read_command() is called so auditors see only the actual command stdout.
_COMMAND_HEADER_PATTERNS = (
    re.compile(r"^# Command: "),
    re.compile(r"^# Captured: "),
    re.compile(r"^# Host: "),
    re.compile(r"^# Exit: "),
    re.compile(r"^---\s*$"),
)


def _strip_command_wrapper(text: str) -> str:
    """Drop the collector's header/footer lines, return just the command output."""
    lines = text.splitlines()
    out: List[str] = []
    for line in lines:
        if any(rx.match(line) for rx in _COMMAND_HEADER_PATTERNS):
            continue
        out.append(line)
    return "\n".join(out)


class Bundle:
    """Read-only view of a collector bundle (tar.gz or directory)."""

    def __init__(self, files: Dict[str, str], source: str):
        # Keyed by the path inside the bundle (e.g. "etc/ssh/sshd_config",
        # "cmd/rpm_qa.txt", "meta/collector.txt"). Values are decoded text.
        self._files = files
        self.source = source
        self.meta = self._parse_meta()

    # ---------------------------------------------------------------- factory
    @classmethod
    def open(cls, path: str | Path) -> "Bundle":
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Bundle not found: {p}")
        if p.is_dir():
            return cls._open_dir(p)
        return cls._open_tar(p)

    @classmethod
    def _open_tar(cls, p: Path) -> "Bundle":
        files: Dict[str, str] = {}
        with tarfile.open(p, "r:*") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                # Normalise leading "./" and any absolute prefixes
                name = member.name.lstrip("./")
                f = tf.extractfile(member)
                if f is None:
                    continue
                try:
                    raw = f.read()
                except Exception:
                    continue
                try:
                    text = raw.decode("utf-8", errors="replace")
                except Exception:
                    text = ""
                files[name] = text
        return cls(files, source=str(p))

    @classmethod
    def _open_dir(cls, root: Path) -> "Bundle":
        files: Dict[str, str] = {}
        for f in root.rglob("*"):
            if not f.is_file():
                continue
            rel = f.relative_to(root).as_posix()
            try:
                files[rel] = f.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
        return cls(files, source=str(root))

    # ---------------------------------------------------------------- meta
    def _parse_meta(self) -> Dict[str, str]:
        """Parse ./meta/collector.txt key=value lines into a dict."""
        meta: Dict[str, str] = {}
        text = self._files.get("meta/collector.txt", "")
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, _, v = line.partition("=")
                meta[k.strip()] = v.strip().strip('"')
        return meta

    # ---------------------------------------------------------------- access
    def has_etc_file(self, etc_path: str) -> bool:
        return self._etc_key(etc_path) in self._files

    def read_etc_file(self, etc_path: str, default: str = "") -> str:
        """Return the text of an /etc file captured by the collector.

        etc_path is given in its real on-disk form ('/etc/ssh/sshd_config').
        """
        return self._files.get(self._etc_key(etc_path), default)

    def list_etc(self, prefix: str = "/etc") -> List[str]:
        """Return real /etc paths that exist in the bundle under prefix."""
        if not prefix.startswith("/etc"):
            return []
        # Convert "/etc/pam.d" -> "etc/pam.d/"
        key_prefix = "etc" + prefix[len("/etc"):].rstrip("/") + "/"
        return sorted(
            "/etc" + k[len("etc"):]
            for k in self._files
            if k.startswith(key_prefix)
        )

    def has_command(self, label: str) -> bool:
        return f"cmd/{label}.txt" in self._files

    def read_command(self, label: str, default: str = "") -> str:
        """Return the raw command stdout (collector header stripped)."""
        raw = self._files.get(f"cmd/{label}.txt")
        if raw is None:
            return default
        return _strip_command_wrapper(raw)

    def iter_command_lines(self, label: str) -> Iterable[str]:
        """Yield each non-empty line of the captured command output."""
        text = self.read_command(label)
        for line in text.splitlines():
            stripped = line.strip()
            if stripped:
                yield stripped

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _etc_key(etc_path: str) -> str:
        # "/etc/ssh/sshd_config" -> "etc/ssh/sshd_config"
        if not etc_path.startswith("/etc"):
            etc_path = "/etc" + etc_path.lstrip("/")
        return "etc" + etc_path[len("/etc"):]

    # ---------------------------------------------------------------- summary
    @property
    def hostname(self) -> str:
        return self.meta.get("hostname", "unknown")

    @property
    def rhel_version(self) -> Optional[str]:
        """Return the RHEL version as 'X.Y' if detectable from os-release."""
        # os-release lines like: VERSION_ID="8.10"
        text = self._files.get("meta/collector.txt", "")
        m = re.search(r'VERSION_ID="?(\d+(?:\.\d+)?)', text)
        if m:
            return m.group(1)
        # Fallback: parse /etc/redhat-release if present
        m = re.search(r"release\s+(\d+(?:\.\d+)?)", text)
        return m.group(1) if m else None

    @property
    def rhel_major(self) -> Optional[int]:
        v = self.rhel_version
        if not v:
            return None
        try:
            return int(v.split(".")[0])
        except ValueError:
            return None

    def __repr__(self) -> str:
        return (
            f"<Bundle source={self.source!r} hostname={self.hostname!r} "
            f"rhel={self.rhel_version!r} files={len(self._files)}>"
        )


# ---------------------------------------------------------------------------
# RPM inventory helpers — used by the CVE module
# ---------------------------------------------------------------------------

class RpmPackage:
    """A single line of `rpm -qa --queryformat '%{NAME}|%{VERSION}|%{RELEASE}|%{ARCH}|%{EPOCH}'`."""

    __slots__ = ("name", "version", "release", "arch", "epoch")

    def __init__(self, name: str, version: str, release: str, arch: str, epoch: str):
        self.name = name
        self.version = version
        self.release = release
        self.arch = arch
        self.epoch = "" if epoch in ("(none)", "") else epoch

    @property
    def nvr(self) -> str:
        return f"{self.name}-{self.version}-{self.release}"

    @property
    def nevra(self) -> str:
        epoch = f"{self.epoch}:" if self.epoch else ""
        return f"{self.name}-{epoch}{self.version}-{self.release}.{self.arch}"

    def __repr__(self) -> str:
        return f"<RpmPackage {self.nevra}>"


def parse_rpm_inventory(bundle: Bundle) -> Dict[str, RpmPackage]:
    """Parse the rpm_qa command output into a {name: RpmPackage} map.

    If the same name appears multiple times (multi-arch packages: glibc.x86_64
    and glibc.i686), the later entry wins. The CVE module only needs the
    version-release for matching, so this is fine.
    """
    pkgs: Dict[str, RpmPackage] = {}
    for line in bundle.iter_command_lines("rpm_qa"):
        parts = line.split("|")
        if len(parts) < 4:
            continue
        name, version, release, arch = parts[0], parts[1], parts[2], parts[3]
        epoch = parts[4] if len(parts) >= 5 else ""
        if not name:
            continue
        pkgs[name] = RpmPackage(name, version, release, arch, epoch)
    return pkgs
