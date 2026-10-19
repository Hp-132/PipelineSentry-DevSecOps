from pathlib import Path

from detection.alerts import PermanentError
from shared import config


class UnsafePathError(PermanentError):
    pass


def scan_root() -> Path:
    return Path(config.SCAN_ROOT).resolve()


def resolve_scan_path(relative: str, must_be_file: bool = False) -> Path:
    """Resolve a user-supplied path, refusing anything outside SCAN_ROOT (incl. via .. or symlinks)."""
    root = scan_root()
    candidate = Path(relative)
    if candidate.is_absolute():
        raise UnsafePathError("absolute paths are not allowed; give a path relative to the scan root")
    resolved = (root / candidate).resolve()
    if not resolved.is_relative_to(root):
        raise UnsafePathError("path escapes the configured scan root")
    if not resolved.exists():
        raise UnsafePathError(f"path not found under scan root: {relative}")
    if must_be_file and not resolved.is_file():
        raise UnsafePathError(f"not a file: {relative}")
    return resolved
