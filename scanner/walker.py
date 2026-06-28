from __future__ import annotations

import fnmatch
import hashlib
from dataclasses import dataclass
from pathlib import Path

from .config import Config

MANIFEST_NAMES = {"fxmanifest.lua", "__resource.lua"}


@dataclass
class WalkedFile:
    path: Path
    resource: str
    allowlisted: bool
    suspicious_location: bool = False
    location_reason: str = ""


def _norm(path: Path) -> str:
    return str(path).replace("\\", "/")


def _matches_any(path: Path, globs: list[str]) -> bool:
    s = _norm(path)
    return any(fnmatch.fnmatch(s, g) or fnmatch.fnmatch(path.name, g) for g in globs)


def _find_resource_dirs(root: Path) -> set[Path]:
    dirs: set[Path] = set()
    for name in MANIFEST_NAMES:
        for manifest in root.rglob(name):
            dirs.add(manifest.parent)
    return dirs


def _owning_resource(path: Path, resource_dirs: set[Path], root: Path) -> Path | None:
    best: Path | None = None
    for d in resource_dirs:
        try:
            path.relative_to(d)
        except ValueError:
            continue
        if best is None or len(d.parts) > len(best.parts):
            best = d
    return best


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def walk(root: Path, config: Config):
    root = Path(root)
    resource_dirs = _find_resource_dirs(root)

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if _matches_any(path, config.ignore_globs):
            continue

        ext = path.suffix.lower()
        owner = _owning_resource(path, resource_dirs, root)
        resource = owner.name if owner else "(no resource)"
        allowlisted = _matches_any(path, config.allowlist_globs)

        if ext in config.suspicious_in_resource_exts and owner is not None:
            yield WalkedFile(
                path=path,
                resource=resource,
                allowlisted=allowlisted,
                suspicious_location=True,
                location_reason=f"executable/binary file ({ext}) inside a resource",
            )
            continue

        if ext not in config.scannable_exts:
            continue

        loose = owner is None and ext in {".lua", ".js", ".py"}
        yield WalkedFile(
            path=path,
            resource=resource,
            allowlisted=allowlisted,
            suspicious_location=loose,
            location_reason="script file outside any resource" if loose else "",
        )
