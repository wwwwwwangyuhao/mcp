from __future__ import annotations

import argparse
import asyncio

from .config import Settings, config_path_from_env
from .server import build_server


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Personal Linux Remote MCP Gateway")
    p.add_argument("--config", default=config_path_from_env())
    p.add_argument("--transport", choices=("stdio", "streamable-http"), default="stdio")
    return p


async def _run(args: argparse.Namespace) -> None:
    settings = Settings.from_yaml(args.config)
    server = build_server(settings)
    services = server._personal_linux_services  # type: ignore[attr-defined]
    try:
        if args.transport == "stdio":
            await server.run_stdio_async()
        else:
            if not settings.http.enabled:
                raise RuntimeError("streamable-http transport requested but http.enabled=false")
            await server.run_streamable_http_async(
                host=settings.http.host,
                port=settings.http.port,
                streamable_http_path=settings.http.path,
                stateless_http=True,
            )
    finally:
        await services.ssh.close()


def main() -> None:
    args = parser().parse_args()
    asyncio.run(_run(args))


if __name__ == "__main__":
    main()
