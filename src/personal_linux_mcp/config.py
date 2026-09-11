from __future__ import annotations

import os
import posixpath
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Permissions(StrictModel):
    read: bool = True
    write: bool = False
    shell: bool = False
    jobs: bool = False


class ServerConfig(StrictModel):
    host: str
    port: int | None = Field(default=None, ge=1, le=65535)
    user: str | None = None
    ssh_config: str | None = None
    identity_file: str | None = None
    known_hosts: str | None = None
    allowed_roots: list[str] = Field(default_factory=list)
    job_root: str | None = None
    max_concurrent_channels: int = Field(default=8, ge=1, le=128)
    connect_timeout_seconds: float = Field(default=15.0, gt=0, le=120)
    permissions: Permissions = Field(default_factory=Permissions)

    @field_validator("allowed_roots")
    @classmethod
    def validate_roots(cls, roots: list[str]) -> list[str]:
        if not roots:
            raise ValueError("allowed_roots must contain at least one absolute POSIX path")
        cleaned = []
        for root in roots:
            if "\x00" in root or not root.startswith("/"):
                raise ValueError(f"allowed root must be an absolute POSIX path: {root!r}")
            cleaned.append(posixpath.normpath(root))
        return cleaned

    @model_validator(mode="after")
    def validate_job_root(self) -> "ServerConfig":
        if self.permissions.jobs and self.job_root is None:
            self.job_root = posixpath.join(self.allowed_roots[0], ".personal-linux-mcp", "jobs")
        if self.job_root is not None:
            if "\x00" in self.job_root or not self.job_root.startswith("/"):
                raise ValueError("job_root must be an absolute POSIX path")
            self.job_root = posixpath.normpath(self.job_root)
            if not any(
                posixpath.commonpath([self.job_root, root]) == root
                for root in self.allowed_roots
            ):
                raise ValueError("job_root must be contained in an allowed_root")
        return self


class Limits(StrictModel):
    file_read_max_bytes: int = Field(default=256 * 1024, ge=1024, le=4 * 1024 * 1024)
    file_write_max_bytes: int = Field(default=2 * 1024 * 1024, ge=1024, le=16 * 1024 * 1024)
    patch_max_bytes: int = Field(default=2 * 1024 * 1024, ge=1024, le=16 * 1024 * 1024)
    directory_list_max_entries: int = Field(default=500, ge=1, le=5000)
    shell_output_max_bytes: int = Field(default=256 * 1024, ge=1024, le=4 * 1024 * 1024)
    command_max_bytes: int = Field(default=64 * 1024, ge=256, le=1024 * 1024)
    job_log_read_max_bytes: int = Field(default=256 * 1024, ge=1024, le=4 * 1024 * 1024)
    job_log_max_lines: int = Field(default=500, ge=1, le=5000)
    job_stdin_max_bytes: int = Field(default=64 * 1024, ge=1, le=1024 * 1024)
    search_max_results: int = Field(default=200, ge=1, le=5000)


class JobsConfig(StrictModel):
    launch_timeout_seconds: float = Field(default=5.0, gt=0, le=60)
    status_timeout_seconds: float = Field(default=5.0, gt=0, le=60)
    terminate_grace_seconds: float = Field(default=2.0, gt=0, le=30)


class HttpConfig(StrictModel):
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)
    path: str = "/mcp"
    public_url: str = "http://127.0.0.1:8000"
    bearer_token_env: str = "PERSONAL_LINUX_MCP_TOKEN"

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("http.path must start with '/'")
        return value


class Settings(StrictModel):
    servers: dict[str, ServerConfig]
    limits: Limits = Field(default_factory=Limits)
    jobs: JobsConfig = Field(default_factory=JobsConfig)
    http: HttpConfig = Field(default_factory=HttpConfig)
    state_dir: str = ".state"
    audit_commands: bool = False

    @model_validator(mode="after")
    def validate_aliases(self) -> "Settings":
        if not self.servers:
            raise ValueError("at least one server must be configured")
        for alias in self.servers:
            if not alias or any(c.isspace() for c in alias):
                raise ValueError(f"invalid server alias: {alias!r}")
        return self

    @classmethod
    def from_yaml(cls, path: str | os.PathLike[str]) -> "Settings":
        config_path = Path(path).expanduser().resolve()
        raw: dict[str, Any] = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        settings = cls.model_validate(raw)
        state = Path(settings.state_dir).expanduser()
        if not state.is_absolute():
            state = config_path.parent / state
        settings.state_dir = str(state.resolve())
        return settings


def config_path_from_env(default: str = "config.yaml") -> str:
    return os.environ.get("PERSONAL_LINUX_MCP_CONFIG", default)
