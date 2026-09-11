# Phase B Architecture Freeze

Status: **FROZEN for Phase C implementation**

This document is the canonical V1 architecture decision after the Phase A open-source audit.
It supersedes conflicting implementation details in the current uncommitted draft, but does
not itself authorize commit, push, merge, deployment, or operations on any server other than
the task-scoped development host.

## 1. Phase A decision carried forward

Decision: **BUILD a narrow personal Linux MCP gateway** rather than USE or FORK an upstream
project. The design may reuse proven concepts, but upstream source is not copied.

Reference lessons retained:
- DesktopCommanderMCP: bounded output, exact patch semantics, symlink-aware path checks.
- mcp-ssh-multi: Python/AsyncSSH multi-host shape, but not its disabled host-key checking or
  automatic command replay after connection loss.
- remote-ssh-mcp: persistent/recoverable command semantics and strict SSH trust behavior.
- ssh-mcp: fail-closed thinking, connection pooling, audit discipline, and at-most-once
  command dispatch across reconnect boundaries.

## 2. Non-negotiable V1 invariants

1. SSH host-key verification is enabled by default and has no normal config switch to disable it.
2. A transport reconnect must never automatically replay a command or job launch.
3. Output limits must bound memory while data is being read, not only truncate after collection.
4. Structured filesystem tools must authorize canonical remote paths, including symlink resolution.
5. Arbitrary shell is explicitly outside the `allowed_roots` sandbox claim; Unix account/ACLs are
   the final boundary for shell commands.6. Long jobs must survive MCP-client disconnects and gateway-process restarts without being restarted.
7. Unknown job state is reported as unknown/orphaned; uncertainty is never resolved by re-execution.
8. HTTP mode requires application-layer bearer authentication; secrets come from environment only.
9. Audit command text is disabled by default; secrets must not be persisted by normal operation.
10. V1 remains Linux-only and installs no persistent agent on target servers.

## 3. Frozen high-level architecture

```text
ChatGPT / Claude / Codex / standard MCP client
                  |
          stdio or Streamable HTTP
                  |
                  v
        Personal Linux MCP Gateway
        +---------------------------+
        | MCP tool layer            |
        | bearer auth + audit       |
        | per-host capability gate  |
        | filesystem service        |
        | short-shell service       |
        | durable job service       |
        | SSH/SFTP connection pool  |
        +-------------+-------------+
                      |
                   AsyncSSH
                      |
               Linux SSH hosts
```

The gateway keeps at most one reusable SSH transport per configured alias and opens bounded
channels for individual operations. SFTP and command channels share this transport model.## 4. Frozen V1 MCP surface

No Git/tmux/pytest/conda/CodeBuddy-specific tool is added in V1. Those remain shell commands.

- `servers_list`
- `server_info`
- `directory_list`
- `file_stat`
- `file_read`
- `file_write`
- `file_patch`
- `file_search`
- `shell_exec`
- `job_start`
- `job_status`
- `job_logs`
- `job_stdin`
- `job_terminate`
- `process_list`
- `system_status`

Existing names are retained to avoid needless API churn. Optional pagination/cursor parameters may
be refined in Phase C, but no new top-level tool is required for V1.

## 5. Current draft disposition

| Area | Decision | Phase C action |
|---|---|---|
| package layout / Python stack | KEEP | retain Python, MCP 2.x, AsyncSSH, Pydantic, SQLite |
| `auth.py` static bearer verifier | KEEP/HARDEN | keep env-only + constant-time comparison; integration-test HTTP 401/success |
| strict Pydantic config | KEEP/EXTEND | add job control root and allow OpenSSH config fallbacks |
| `security/paths.py` | KEEP | retain absolute path + commonpath primitives |
| redaction concept | KEEP/HARDEN | keep command logging off by default; expand tests/patterns |
| SQLite audit concept | KEEP/REWRITE | owner-only state permissions; audit every tool consistently |
| AsyncSSH connection pool | KEEP/REWRITE | retain per-alias pool; formalize dispatch boundary and bounded channel use |
| current `SSHConnectionManager.run()` | REWRITE | stream output while bounded; explicit timeout/output-limit cleanup |
| current live-channel `JobManager` | REWRITE COMPLETELY | replace with detached remote job-control protocol |
| in-memory `LogBuffer` for jobs | REMOVE FROM CORE | logs live remotely and are cursor-read through SFTP |
| filesystem canonicalization | KEEP | it is the strongest part of the draft |
| direct overwrite/patch writes | REWRITE | same-directory temp file + atomic replacement where applicable || `server.py` monolithic registration | KEEP/REFACTOR | preserve tool surface; move service logic out of handlers |
| current docs saying jobs die with gateway | REMOVE/UPDATE | V1 target is durable reattachment, not in-memory-only jobs |

## 6. SSH connection and dispatch semantics

AsyncSSH remains the V1 SSH library. On the audited a10 environment, AsyncSSH 2.24 supports
OpenSSH client config and includes `ProxyJump`, `UserKnownHostsFile`, `IdentityAgent`, and
`ForwardAgent` handling, so V1 does not need an OpenSSH subprocess layer merely for these features.

Configuration should allow `host` to be an SSH alias. `port` and `user` become optional so that,
when omitted, OpenSSH config values can apply. An optional explicit SSH config path may be supplied;
when omitted, AsyncSSH's normal user config behavior is used. Explicit identity and known-hosts paths
remain supported.

Host-key policy:
- omitted `known_hosts` means normal verified known-hosts behavior;
- an explicit known-hosts path narrows verification to that configured source;
- V1 does not expose `known_hosts=None`/`StrictHostKeyChecking=no` behavior as a user feature.

Dispatch boundary:
1. A closed transport detected before an operation may be recreated.
2. Once a command-carrying AsyncSSH API is invoked, any resulting transport/channel uncertainty is
   treated as non-retryable by the gateway.
3. No exception path recursively calls the same shell command or job launch.
4. Reads may be manually retried by the client because their semantics are idempotent; the gateway
   itself still does not silently replay them across an ambiguous transport failure.

## 7. Short shell semantics

`shell_exec` is for bounded foreground commands, not multi-hour training.
The current `conn.run()` implementation is rejected because it can accumulate complete output before
post-hoc truncation.

Phase C must use a streaming process channel with a shared byte budget across stdout/stderr. When the
budget is exhausted, the command is stopped rather than letting memory grow without bound. Timeout
and output-limit termination are best-effort remote process cleanup; the result must state that remote
side effects or descendants may remain and must never cause an automatic retry.## 8. Structured filesystem semantics

The current SFTP `realpath` design is retained:
- existing targets are resolved with remote `realpath`;
- for a non-existing write target, the deepest existing ancestor is resolved first and the unresolved
  suffix is rebuilt below that canonical ancestor;
- configured roots are themselves canonicalized remotely;
- authorization uses component-aware path containment, not string-prefix matching.

This is an accidental-escape guardrail, not a transactional filesystem sandbox. A remote filesystem
can still change between validation and use; V1 documents this TOCTOU residual rather than claiming a
stronger security property.

`directory_list` gains bounded pagination (`offset`/`limit` or equivalent next cursor) rather than
returning an unbounded directory.

`file_read` keeps byte cursors but must become UTF-8 boundary safe: a gateway-issued `next_offset`
must never skip or duplicate bytes, trailing partial code points are held for the next page, and an
arbitrary offset in the middle of a UTF-8 sequence is rejected rather than silently replacing bytes.

`file_write` keeps explicit `mode=create|overwrite`; implicit overwrite remains forbidden. Create
must use exclusive-create semantics where AsyncSSH/SFTP supports them. Overwrite writes a temporary
file in the same directory and replaces the target only after the complete payload is written.

`file_patch` retains exact `old_string` matching plus `expected_replacements`. Ambiguous counts fail
before any write. Optional expected hash/version guards remain available. The new contents are written
to a same-directory temporary file and atomically renamed where the remote SFTP server supports that
operation. Existing mode bits should be preserved on replacement when practical.

`file_search` remains a structured read operation. Fixed internal `find`/`grep` commands are allowed
even when arbitrary shell permission is disabled, but every caller-controlled path/pattern must be
validated/quoted and recursive content search must not intentionally follow symlinks out of the root.

A new `file_write_max_bytes` limit is added so file writes and patch payloads are bounded at the MCP
boundary as well as during remote I/O.## 9. Durable job protocol

The current job design is rejected because the remote process is owned by an in-memory SSH channel.
V1 instead uses a small per-job control directory on the remote Linux host. This is not a persistent
remote agent; it is job metadata and files created for the lifetime of that job.

Each job-capable server has an explicit absolute `job_root`. `job_start` allocates a gateway UUID and
a directory such as `<job_root>/<job_id>/` with owner-only permissions. The control directory contains
at least:
- `job.log`: combined stdout/stderr in natural descriptor order;
- `status`: running/completed/failed/terminated when known;
- `exit_code`: written only after normal command completion;
- `pid`: detached process-group/session leader PID;
- `start_ticks`: `/proc/<pid>/stat` start-time identity used to detect PID reuse;
- `stdin.fifo`: named pipe used only while a job is running;
- a temporary command payload/runner, permission 0600/0700, removed when no longer needed.

The remote runner is detached from the initiating SSH channel using Linux session-detach primitives
(`setsid`/`nohup` or an equivalent audited wrapper). Its command runs in a child shell so an `exit` or
`exec` inside the user's command cannot prevent the wrapper from recording final state.

The local SQLite jobs table stores only control metadata: job id, server alias, cwd, remote control
path, PID identity, timestamps, last-known status, and exit code. It does **not** store command text.

Public job states are frozen as:
`running`, `completed`, `failed`, `terminated`, `unknown`, `orphaned`.

`unknown` means dispatch/transport uncertainty prevents the gateway from proving whether launch or a
later state transition happened. `orphaned` means a job was previously believed running, no final
marker exists, and the stored PID identity no longer matches a live remote process. Neither state may
trigger automatic restart.`job_status` must work after gateway restart by loading SQLite metadata and reconciling remote marker
files plus PID/start-tick identity. If the remote host is unreachable, the tool returns the local
last-known state plus an explicit reachability/uncertainty indication rather than mutating the job.

`job_logs` reads `job.log` directly through SFTP with a monotonic byte cursor and a bounded response.
Logs are therefore not lost merely because the gateway process restarted. If a caller supplies a
cursor beyond the current file size, the request fails explicitly rather than silently wrapping.

`job_stdin` writes only to a verified-running job's FIFO through a bounded short-lived SSH operation.
The write has a timeout so a missing reader cannot block the gateway indefinitely. Binary/NUL-rich
interactive protocols are out of scope; V1 stdin is text/bytes suitable for ordinary CLI input.

`job_terminate` first verifies both PID and `/proc` start ticks before signaling the process group.
It sends TERM, waits a bounded grace period, then may escalate to KILL. PID mismatch produces
`orphaned`/refusal rather than killing an unrelated process.

`job_start` allocates and persists `job_id` **before** remote dispatch. If transport failure occurs
after launch may have been sent but before acknowledgement, the call returns/reports that job id with
`unknown` state so it can be reconciled. The gateway does not send the launch command a second time.

## 10. Capability model

Per-server V1 permissions remain deliberately small:
- `read`: structured filesystem reads plus fixed read-only server/process/system probes;
- `write`: structured file create/overwrite/patch;
- `shell`: arbitrary short `shell_exec`;
- `jobs`: arbitrary durable background jobs and their control operations.

`allowed_roots` constrains structured filesystem operations and the optional cwd accepted by shell/job
tools. It does not constrain arbitrary paths subsequently referenced inside an enabled shell command.
The dedicated SSH Unix account and its ACLs remain the true shell security boundary.

Complex Claude/Codex-specific PreToolUse policy gates are intentionally **not** part of V1. Policy
must live inside the standard MCP gateway and remain client-independent. More detailed command policy
can be added later only if a concrete need appears.## 11. HTTP authentication and deployment

Stdio remains available for local clients. Streamable HTTP remains the remote transport.

The current environment-backed static bearer verifier is retained conceptually:
- token is read from a named environment variable, never YAML/Git;
- comparison is constant-time;
- HTTP mode refuses to start if the configured token environment variable is empty;
- the token is not written to audit or job state.

Phase D must prove both an unauthenticated/incorrect-token rejection and a successful authorized MCP
initialize/tool-discovery request. If MCP SDK metadata requirements make the static-token path
misleading or brittle, Phase C may place a minimal Authorization middleware in front of the MCP ASGI
route, but the external contract remains ordinary `Authorization: Bearer <token>`.

TLS is not implemented inside the gateway. Remote deployment must terminate HTTPS at a reverse proxy,
private ingress, or equivalent trusted network layer. The default bind remains loopback.

## 12. Local state and audit

`state_dir` remains local to the gateway and contains SQLite state only. Phase C hardens it to owner-only
permissions (`0700` directory and `0600` database where the platform permits).

Audit coverage must include all V1 tools, including `job_status`, `job_logs`, `job_stdin`,
`job_terminate`, `process_list`, and `system_status`, not only mutating calls.

Minimum audit fields remain: UTC timestamp, request id, tool, server alias, target/control id,
duration, status, exit code when meaningful, and returned-byte count. Command text remains absent by
default. If `audit_commands=true` is explicitly enabled, redaction is best-effort and documentation
must not claim that arbitrary embedded secrets can always be detected.

## 13. Configuration changes frozen for Phase C

`ServerConfig` keeps explicit aliases but changes connection overrides to optional fields so OpenSSH
config can participate naturally:
- `host`: required alias/hostname passed to AsyncSSH;
- `port`: optional override;
- `user`: optional override;
- `ssh_config`: optional explicit local config path;
- `identity_file`: optional explicit key override;
- `known_hosts`: optional explicit known-hosts path; omission still verifies using defaults;
- `allowed_roots`: one or more absolute remote roots;
- `job_root`: required absolute remote path when `permissions.jobs=true`;
- bounded channel/connect limits and the existing permission block.Global limits add or retain explicit caps for file read, file write, patch size, shell output,
job log page size/lines, search results, command length, SSH connect timeout, and termination grace.

No password field is added to YAML. Agent/key authentication remains the intended deployment model.

## 14. Phase C implementation order

1. Extend config/models first; no behavior changes hidden in unrelated patches.
2. Rewrite SSH foreground execution with bounded streaming and no replay.
3. Refactor path authorization away from read-permission checks so cwd authorization is reusable.
4. Harden filesystem write/patch and directory/read pagination semantics.
5. Replace the current job subsystem with the durable remote control protocol and migration-safe SQLite schema.
6. Refactor MCP handlers so every tool has consistent capability checks and audit coverage.
7. Update README/security/deployment docs only after implementation matches the frozen design.
8. Add/expand unit and integration tests before any commit or push.

## 15. Mandatory acceptance tests for Phase C/D

SSH:
- default host-key verification is not disabled;
- existing live connection is reused;
- a connection detected closed before dispatch reconnects;
- an error after command dispatch does not cause automatic replay;
- short command timeout and output cap clean up the channel and bound retained memory;
- server aliases remain isolated under concurrent access.

Filesystem:
- root-prefix confusion (`/root/a` vs `/root/abc`) is rejected;
- existing symlink escape is rejected;
- non-existing target under a symlinked parent is rejected;
- directory pagination is bounded;
- UTF-8 paged reads neither lose nor duplicate bytes;
- create refuses existing targets;
- overwrite refuses missing targets;
- ambiguous patch count performs no write;
- interrupted/failed replacement does not truncate the original target.

Jobs:
- job survives MCP client disconnect;
- job remains discoverable after recreating the gateway service object/process state;
- cursor log reads are incremental and bounded;
- stdin reaches a verified-running FIFO and times out safely when unavailable;
- terminate validates PID start ticks and cannot kill a reused PID;
- simulated SSH loss never launches the command a second time;
- ambiguous launch becomes `unknown`, not a retry;
- missing process without final marker becomes `orphaned`.HTTP/auth/audit:
- HTTP refuses startup with missing token env;
- missing/wrong bearer token is rejected;
- correct token can initialize MCP and discover tools;
- audit rows are emitted for read-only and mutating tools;
- command text is absent by default and configured state files are owner-only.

## 16. Explicitly out of scope for V1

- Windows/macOS target support;
- Kubernetes/container orchestration abstractions;
- remote resident agents;
- browser/GUI/Office/PDF features;
- automatic command or job replay;
- full OAuth multi-user authorization;
- automatic SSH host enrollment or disabling trust checks;
- a claim that `allowed_roots` sandboxes arbitrary shell;
- bespoke Git/tmux/pytest/conda/CodeBuddy MCP tools;
- general binary terminal/PTY emulation.

## 17. Phase B exit decision

The frozen draft is **not discarded**. Its configuration skeleton, auth verifier, path security,
filesystem canonicalization, MCP surface, and SQLite/audit direction are useful and should be evolved.
However, the current foreground shell implementation is only a prototype and the current live-channel
job implementation must not ship as V1.

Phase B is complete when this document exists, source code remains otherwise frozen, and no commit or
push has occurred. Phase C may now implement this design in small auditable changes.