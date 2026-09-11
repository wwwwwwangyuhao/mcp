from personal_linux_mcp.config import Settings
from personal_linux_mcp.server import build_server


def test_server_registers_v1_tools(tmp_path):
    settings = Settings.model_validate(
        {
            "state_dir": str(tmp_path / "state"),
            "servers": {
                "fake": {
                    "host": "127.0.0.1",
                    "user": "fake",
                    "allowed_roots": ["/work"],
                    "permissions": {"read": True, "write": True, "shell": True, "jobs": True},
                }
            },
        }
    )
    server = build_server(settings)
    names = {tool.name for tool in server._tool_manager.list_tools()}
    expected = {
        "servers_list", "server_info", "directory_list", "file_stat", "file_read",
        "file_write", "file_patch", "file_search", "shell_exec", "job_start",
        "job_status", "job_logs", "job_stdin", "job_terminate", "process_list",
        "system_status",
    }
    assert expected <= names
