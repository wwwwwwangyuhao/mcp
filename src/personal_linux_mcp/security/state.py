from __future__ import annotations

import os
import stat
from pathlib import Path


def prepare_state_dir(state_dir: str) -> Path:
    """Create a private state directory without mutating unrelated paths."""
    path = Path(state_dir)
    if path.is_symlink():
        raise RuntimeError("state_dir must not be a symbolic link")
    if path.exists():
        if not path.is_dir():
            raise RuntimeError("state_dir exists but is not a directory")
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode != 0o700:
            raise PermissionError(
                f"existing state_dir must already be mode 0700; found {mode:04o}"
            )
        return path

    if not path.parent.exists() or not path.parent.is_dir():
        raise RuntimeError("state_dir parent directory must already exist")
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)
    return path


def state_database_path(state_dir: str) -> Path:
    """Return the gateway DB path, rejecting pre-existing symlinks/non-files."""
    state = prepare_state_dir(state_dir)
    path = state / "gateway.sqlite3"
    if path.is_symlink():
        raise RuntimeError("gateway state database must not be a symbolic link")
    if path.exists() and not path.is_file():
        raise RuntimeError("gateway state database path is not a regular file")
    return path


def harden_state_file(path: str | Path) -> None:
    """Restrict a gateway-owned regular state file to the gateway account."""
    target = Path(path)
    if target.is_symlink() or not target.is_file():
        raise RuntimeError("refusing to chmod non-regular gateway state file")
    os.chmod(target, 0o600)
