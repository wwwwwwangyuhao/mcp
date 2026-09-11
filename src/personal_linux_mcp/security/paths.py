from __future__ import annotations

import posixpath


class PathSecurityError(ValueError):
    pass


def require_absolute_posix(path: str) -> str:
    if not path or "\x00" in path:
        raise PathSecurityError("path is empty or contains a NUL byte")
    if not path.startswith("/"):
        raise PathSecurityError("remote filesystem paths must be absolute")
    normalized = posixpath.normpath(path)
    if not normalized.startswith("/"):
        raise PathSecurityError("invalid absolute path")
    return normalized


def is_within(path: str, root: str) -> bool:
    path = posixpath.normpath(path)
    root = posixpath.normpath(root)
    try:
        return posixpath.commonpath([path, root]) == root
    except ValueError:
        return False


def ensure_within_any(path: str, roots: list[str]) -> str:
    if not any(is_within(path, root) for root in roots):
        raise PathSecurityError(
            f"path escapes configured allowed roots: {path!r}"
        )
    return path
