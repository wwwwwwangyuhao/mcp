# Deployment

This document describes intended deployment; Phase C development/testing does
not itself deploy the gateway to any target server.

1. Create a dedicated Python 3.11+ virtual environment for the gateway.
2. Install the project into that environment.
3. Copy `config.example.yaml` to a private `config.yaml` and configure aliases,
   capabilities, `allowed_roots`, and `job_root`.
4. Use SSH-agent/key authentication. Do not place passwords or private key
   contents in YAML.
5. Verify target host keys out of band before first use. Do not disable host-key
   verification to make a connection succeed.
6. Prefer a dedicated target SSH account with no sudo and only the Unix
   permissions/ACLs required for the intended project directories.

For local stdio clients:

```bash
personal-linux-mcp --config /private/path/config.yaml --transport stdio
```

No HTTP token is required when only stdio is used.

For Streamable HTTP:

1. Set a high-entropy secret in the environment variable named by
   `http.bearer_token_env`.
2. Keep the application listener on loopback or a private interface.
3. Terminate HTTPS at a trusted reverse proxy/private ingress.
4. Set `http.enabled: true` and configure `public_url` to match the externally
   protected MCP resource URL.
5. Run:

```bash
personal-linux-mcp --config /private/path/config.yaml --transport streamable-http
```

HTTP mode refuses to construct the MCP server when the configured token
environment variable is missing or empty.

## Durable jobs

When `permissions.jobs: true`, each server needs a writable `job_root` beneath
an allowed root. If omitted, V1 derives a private default below the first
`allowed_root`. Jobs create owner-only control directories containing status,
PID identity, log, exit-code, and stdin FIFO files. No persistent remote agent
is installed.

A gateway restart does not restart a remote job. The new gateway process reads
SQLite metadata and reconciles the remote control directory. Unreachable or
ambiguous state is surfaced instead of being resolved by automatic replay.
