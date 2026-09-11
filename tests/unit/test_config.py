from pathlib import Path

import pytest

from personal_linux_mcp.config import Settings


def test_config_requires_absolute_roots():
    with pytest.raises(ValueError):
        Settings.model_validate(
            {
                "servers": {
                    "a": {
                        "host": "example",
                        "user": "u",
                        "allowed_roots": ["relative/path"],
                    }
                }
            }
        )


def test_relative_state_dir_is_resolved_next_to_config(tmp_path: Path):
    config = tmp_path / "config.yaml"
    config.write_text(
        "servers:\n  a:\n    host: x\n    user: u\n    allowed_roots: [/work]\n",
        encoding="utf-8",
    )
    settings = Settings.from_yaml(config)
    assert settings.state_dir == str((tmp_path / ".state").resolve())


def test_jobs_default_to_private_root_under_first_allowed_root():
    settings = Settings.model_validate(
        {
            "servers": {
                "a": {
                    "host": "ssh-alias",
                    "allowed_roots": ["/work"],
                    "permissions": {"jobs": True},
                }
            }
        }
    )
    assert settings.servers["a"].job_root == "/work/.personal-linux-mcp/jobs"
    assert settings.servers["a"].user is None
    assert settings.servers["a"].port is None


def test_job_root_cannot_escape_allowed_roots():
    with pytest.raises(ValueError):
        Settings.model_validate(
            {
                "servers": {
                    "a": {
                        "host": "x",
                        "allowed_roots": ["/work"],
                        "job_root": "/tmp/jobs",
                        "permissions": {"jobs": True},
                    }
                }
            }
        )


def test_checked_in_example_config_is_valid():
    example = Path(__file__).resolve().parents[2] / "config.example.yaml"
    settings = Settings.from_yaml(example)
    assert "server_a" in settings.servers
    assert settings.servers["server_a"].permissions.jobs is True
    assert settings.limits.file_write_max_bytes == 2097152
