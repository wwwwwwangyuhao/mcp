# Personal Linux Remote MCP Gateway

A personal, Linux-only MCP gateway for managing multiple SSH servers from ChatGPT, Claude, Codex, or another standards-compatible MCP client.

V1 exposes structured server status, bounded filesystem operations, short foreground shell commands, durable long-running jobs, process listing, and CPU/RAM/disk/GPU status. Git, tmux, pytest, conda and CodeBuddy remain ordinary shell commands rather than separate MCP tools.

## Safety properties

- Explicit server aliases, capabilities and canonical filesystem roots.
- Verified SSH host keys by default; no normal insecure host-key bypass.
- No automatic command/job replay after dispatch may have begun.
- Shared bounded-memory stdout/stderr collection for foreground commands.
- Symlink-aware SFTP path authorization for structured filesystem tools.
- Explicit create/overwrite semantics and exact-count atomic text patching.
- Durable remote job metadata/logs survive MCP-client and gateway restarts.
- PID + `/proc` start-tick verification before job termination.
- HTTP mode requires an environment-backed bearer token.
- Audit omits command text by default; local SQLite state is owner-only.

`allowed_roots` is a structured-filesystem guardrail, not a sandbox for arbitrary shell commands. Use a dedicated least-privileged SSH account for real isolation.

See `docs/phase-b-architecture-freeze.md`, `docs/architecture.md`, `docs/security.md`, and `docs/deployment.md`.

## Development

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest
```

The implementation is independently written for this narrow multi-server Linux/SSH use case. Phase A reviewed DesktopCommanderMCP, mcp-ssh-multi, remote-ssh-mcp and ssh-mcp as architecture references; upstream source code is not copied into this project.

`allowed_roots` protects the structured filesystem tools; it is **not** a
sandbox for arbitrary shell commands. The target SSH account and its Unix
permissions/ACLs remain the security boundary when `shell` or `jobs` is enabled.

## Job durability

`job_start` creates a private remote control directory beneath `job_root`, then
launches a detached Linux session. SQLite stores only control metadata, not the
command text. `job_status` and `job_logs` can reconcile the remote job after the
MCP client disconnects or the gateway process is recreated. Uncertain states are
reported as `unknown` or `orphaned`; the gateway never resolves uncertainty by
launching the command again.

## Development

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest
```

Copy `config.example.yaml` to a private `config.yaml` for actual use. Do not
commit tokens, passwords, private keys, or private deployment configuration.

See `docs/architecture.md`, `docs/security.md`, `docs/deployment.md`, and the
historical `docs/phase-b-architecture-freeze.md`.
