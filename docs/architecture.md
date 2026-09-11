# Architecture

Personal Linux MCP is a standard MCP gateway which maps every tool call to a
configured Linux server alias. It does not install a persistent agent on target
servers.

```text
MCP client
   |
stdio or Streamable HTTP
   |
Personal Linux MCP Gateway
   |-- bearer auth + audit
   |-- per-server capability gate
   |-- filesystem service
   |-- bounded foreground shell
   |-- durable job service
   `-- AsyncSSH/SFTP connection pool
             |
          Linux SSH hosts
```

## SSH transport

The gateway keeps at most one reusable verified AsyncSSH transport per alias and
opens bounded channels for individual operations. OpenSSH client configuration
may provide user, port, ProxyJump, identity-agent, and known-hosts behavior when
not explicitly overridden.

A closed transport detected **before** dispatch may be recreated. Once a
command-carrying channel call is attempted, any transport ambiguity is treated
as non-retryable. The gateway never automatically replays that command.

## Filesystem

Structured filesystem tools use SFTP. Existing paths are authorized after
remote `realpath`; a missing write target is authorized by resolving its deepest
existing ancestor and rebuilding the unresolved suffix. Canonical paths must
remain inside a canonical configured `allowed_root`.

Reads, directory listings, writes, patches, searches, and returned outputs are
bounded. UTF-8 file reads use byte cursors that end on codepoint boundaries.
Create does not overwrite, overwrite does not create, and patch replacement
counts must match exactly before any write. Replacement uses a same-directory
temporary file and atomic rename when supported by the SFTP server.

## Foreground shell

`shell_exec` is for bounded foreground work. Stdout and stderr are consumed
concurrently under one shared memory budget. Timeout or output-limit cleanup is
best-effort TERM/KILL; side effects or descendants may already exist, so the
command is never replayed automatically.

## Durable jobs

Each job gets a UUID and a private directory beneath the configured `job_root`.
The detached runner stores status, PID, `/proc` start ticks, exit code, a bounded
cursor-readable log file, and an stdin FIFO. Local SQLite stores only control
metadata.

After a gateway restart, `job_status` reloads SQLite metadata and reconciles the
remote marker files. PID identity requires both PID and start ticks, preventing
a stale job record from signaling an unrelated process which reused the PID.
States are `running`, `completed`, `failed`, `terminated`, `unknown`, and
`orphaned`. No state transition automatically restarts a job.

## MCP transports

Stdio is intended for local clients. Streamable HTTP uses ordinary
`Authorization: Bearer <token>` authentication, with the token sourced only
from an environment variable. The application binds to loopback by default;
TLS termination belongs at a trusted reverse proxy/private ingress layer.

## Open-source review

The implementation is independently built for this narrow topology. Phase A
reviewed DesktopCommanderMCP, mcp-ssh-multi, remote-ssh-mcp, and ssh-mcp for
bounded-output, SSH trust, session, policy, and no-replay design lessons. The
formal build-vs-fork decision and frozen invariants are recorded in
`phase-b-architecture-freeze.md`.
