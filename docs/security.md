# Security model

This gateway is a privileged automation surface. If arbitrary `shell` or `jobs`
is enabled, the effective security boundary is the target SSH account and its
Unix permissions/ACLs. `allowed_roots` is a guardrail for structured filesystem
operations and accepted working directories; it is not claimed to sandbox shell
commands.

## SSH trust and dispatch

Host-key verification remains enabled. Omitting `known_hosts` uses AsyncSSH's
normal verified known-hosts behavior; configuration does not expose a normal
`known_hosts=None` / `StrictHostKeyChecking=no` mode.

A transport may reconnect before command dispatch. After a command-carrying SSH
API is attempted, failure is treated as execution uncertainty and the gateway
does not replay the command. This prevents duplicate experiment launches and
other repeated side effects.

## Filesystem guardrails

Remote paths must be absolute. Existing paths and configured roots are resolved
through SFTP `realpath`; missing write targets resolve their deepest existing
ancestor first. Component-aware containment prevents ordinary prefix and
symlink escapes. A remote filesystem can still change between authorization and
use, so this is not presented as a transactional sandbox.

Structured overwrite/patch operations write a temporary file in the target
directory and replace only after the payload is complete. Create and overwrite
semantics are explicit. Exact patch replacement counts prevent ambiguous edits.

## Durable job safety

Long jobs are detached from the initiating SSH channel. Reconciliation uses
remote marker files plus PID and `/proc/<pid>/stat` start ticks. Termination
signals a process group only after that identity matches; PID reuse therefore
causes refusal/orphaning rather than signaling an unrelated process.

If launch or control dispatch becomes ambiguous, the gateway reports
`unknown`; it does not resend the operation. If a previously running process no
longer matches and no final marker exists, the job becomes `orphaned`.

## HTTP and local state

Streamable HTTP requires a high-entropy bearer token from an environment
variable. The default bind is loopback. Use HTTPS at a trusted reverse proxy or
private ingress before remote exposure.

The local state directory is mode `0700` and the SQLite database is `0600` on
Linux. For safety, an existing state directory with broader permissions is
rejected rather than silently chmodded, and symbolic links are rejected for both
the state directory and database path. Job command text is not stored in SQLite.
Audit command text is off by default; when explicitly enabled, secret redaction
is best-effort and must not be treated as a guarantee.
