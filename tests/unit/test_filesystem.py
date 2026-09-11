from contextlib import asynccontextmanager
from types import SimpleNamespace

import asyncssh
import pytest

from personal_linux_mcp.config import Settings
from personal_linux_mcp.security.paths import PathSecurityError
from personal_linux_mcp.security.remote_paths import RemotePathAuthorizer
from personal_linux_mcp.tools.filesystem import FilesystemService


class Handle:
    def __init__(self, fs, path, mode):
        self.fs = fs
        self.path = path
        self.mode = mode
        self.buffer = bytearray(fs.files.get(path, b"")) if "r" in mode else bytearray()

    async def read(self, n=-1, offset=0):
        data = self.fs.files.get(self.path, b"")
        return data[offset:] if n < 0 else data[offset : offset + n]

    async def write(self, data):
        if self.fs.fail_temp_write and ".plmcp-" in self.path:
            raise OSError("simulated write failure")
        raw = data if isinstance(data, bytes) else data.encode()
        self.buffer.extend(raw)
        self.fs.files[self.path] = bytes(self.buffer)

    def close(self):
        pass


class FakeSFTP:
    def __init__(self):
        self.files = {"/work/text.txt": "AéB".encode(), "/work/patch.txt": b"one two"}
        self.modes = {"/work/text.txt": 0o100644, "/work/patch.txt": 0o100640}
        self.fail_temp_write = False
        self.entries = [
            SimpleNamespace(filename=f"f{i}.txt", attrs=SimpleNamespace(permissions=0o100644, size=i, mtime=i))
            for i in range(4)
        ]

    async def realpath(self, path):
        if path == "/work":
            return "/work"
        if path.startswith("/work/link"):
            return path.replace("/work/link", "/etc", 1)
        if path in self.files:
            return path
        raise asyncssh.SFTPNoSuchFile("missing")

    async def stat(self, path):
        if path not in self.files:
            raise asyncssh.SFTPNoSuchFile("missing")
        return SimpleNamespace(
            size=len(self.files[path]), mtime=1, permissions=self.modes.get(path, 0o100600)
        )

    async def open(self, path, mode):
        if "x" in mode and path in self.files:
            raise FileExistsError(path)
        if "r" in mode and path not in self.files:
            raise asyncssh.SFTPNoSuchFile("missing")
        return Handle(self, path, mode)

    async def chmod(self, path, mode):
        current_type = self.modes.get(path, 0o100000) & 0o170000
        self.modes[path] = current_type | mode

    async def rename(self, old, new, flags=0):
        if new in self.files:
            raise FileExistsError(new)
        self.files[new] = self.files.pop(old)
        self.modes[new] = self.modes.pop(old, 0o100600)

    async def posix_rename(self, old, new):
        self.files[new] = self.files.pop(old)
        self.modes[new] = self.modes.pop(old, 0o100600)

    async def remove(self, path):
        self.files.pop(path, None)
        self.modes.pop(path, None)

    async def scandir(self, _path):
        for entry in self.entries:
            yield entry


class FakeSSH:
    def __init__(self, settings, sftp):
        self.settings = settings
        self.client = sftp

    def server(self, alias):
        return self.settings.servers[alias]

    @asynccontextmanager
    async def sftp(self, _alias):
        yield self.client


def cfg(tmp_path=None):
    return Settings.model_validate(
        {
            "servers": {
                "a": {
                    "host": "a",
                    "allowed_roots": ["/work"],
                    "permissions": {"read": True, "write": True},
                }
            }
        }
    )


@pytest.mark.asyncio
async def test_symlink_escape_is_rejected():
    settings = cfg()
    fake = FakeSFTP()
    auth = RemotePathAuthorizer(FakeSSH(settings, fake))
    with pytest.raises(PathSecurityError):
        await auth.canonicalize("a", "/work/link/passwd")


@pytest.mark.asyncio
async def test_utf8_pagination_never_splits_codepoint():
    settings = cfg()
    fake = FakeSFTP()
    service = FilesystemService(settings, FakeSSH(settings, fake))
    first = await service.file_read("a", "/work/text.txt", length=2)
    assert first.content == "A"
    assert first.next_offset == 1
    second = await service.file_read("a", "/work/text.txt", offset=1, length=2)
    assert second.content == "é"
    assert second.next_offset == 3
    with pytest.raises(ValueError):
        await service.file_read("a", "/work/text.txt", offset=2, length=2)


@pytest.mark.asyncio
async def test_patch_ambiguity_performs_no_write():
    settings = cfg()
    fake = FakeSFTP()
    fake.files["/work/patch.txt"] = b"x x"
    service = FilesystemService(settings, FakeSSH(settings, fake))
    with pytest.raises(ValueError):
        await service.file_patch("a", "/work/patch.txt", "x", "y", expected_replacements=1)
    assert fake.files["/work/patch.txt"] == b"x x"


@pytest.mark.asyncio
async def test_atomic_patch_failure_preserves_original():
    settings = cfg()
    fake = FakeSFTP()
    fake.fail_temp_write = True
    service = FilesystemService(settings, FakeSSH(settings, fake))
    before = fake.files["/work/patch.txt"]
    with pytest.raises(OSError):
        await service.file_patch("a", "/work/patch.txt", "one", "ONE")
    assert fake.files["/work/patch.txt"] == before


@pytest.mark.asyncio
async def test_atomic_patch_preserves_mode():
    settings = cfg()
    fake = FakeSFTP()
    service = FilesystemService(settings, FakeSSH(settings, fake))
    await service.file_patch("a", "/work/patch.txt", "one", "ONE")
    assert fake.files["/work/patch.txt"] == b"ONE two"
    assert fake.modes["/work/patch.txt"] & 0o7777 == 0o640


@pytest.mark.asyncio
async def test_file_write_limit_is_enforced_before_remote_open():
    settings = Settings.model_validate({
        "limits": {"file_write_max_bytes": 1024},
        "servers": {
            "a": {
                "host": "a",
                "allowed_roots": ["/work"],
                "permissions": {"read": True, "write": True},
            }
        },
    })
    fake = FakeSFTP()
    service = FilesystemService(settings, FakeSSH(settings, fake))
    with pytest.raises(ValueError, match="file_write_max_bytes"):
        await service.file_write("a", "/work/new.txt", "x" * 1025)
    assert "/work/new.txt" not in fake.files


@pytest.mark.asyncio
async def test_directory_list_is_bounded_and_paginated():
    settings = cfg()
    fake = FakeSFTP()
    service = FilesystemService(settings, FakeSSH(settings, fake))
    page = await service.directory_list("a", "/work", offset=1, limit=2)
    assert [row["name"] for row in page["entries"]] == ["f1.txt", "f2.txt"]
    assert page["next_offset"] == 3
    assert page["truncated"] is True


@pytest.mark.asyncio
async def test_create_refuses_existing_and_overwrite_refuses_missing():
    settings = cfg()
    fake = FakeSFTP()
    service = FilesystemService(settings, FakeSSH(settings, fake))
    with pytest.raises(FileExistsError):
        await service.file_write("a", "/work/text.txt", "new", mode="create")
    with pytest.raises(FileNotFoundError):
        await service.file_write("a", "/work/missing.txt", "new", mode="overwrite")


@pytest.mark.asyncio
async def test_missing_write_under_symlinked_parent_is_rejected():
    settings = cfg()
    fake = FakeSFTP()
    service = FilesystemService(settings, FakeSSH(settings, fake))
    with pytest.raises(PathSecurityError):
        await service.file_write("a", "/work/link/new.txt", "x", mode="create")
