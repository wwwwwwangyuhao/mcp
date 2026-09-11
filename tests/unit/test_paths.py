import pytest

from personal_linux_mcp.security.paths import PathSecurityError, ensure_within_any, is_within, require_absolute_posix


def test_path_prefix_does_not_escape_root():
    assert is_within("/home/user/project/file.py", "/home/user/project")
    assert not is_within("/home/user/project-evil/file.py", "/home/user/project")


def test_absolute_path_required_and_nul_rejected():
    with pytest.raises(PathSecurityError):
        require_absolute_posix("../etc/passwd")
    with pytest.raises(PathSecurityError):
        require_absolute_posix("/ok\x00bad")


def test_ensure_within_any_rejects_escape():
    with pytest.raises(PathSecurityError):
        ensure_within_any("/etc/passwd", ["/home/user"])
