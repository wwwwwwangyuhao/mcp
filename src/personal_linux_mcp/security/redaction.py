from __future__ import annotations

import re

_PATTERNS = [
    re.compile(r"(?i)\b(authorization:\s*bearer\s+)([^\s]+)"),
    re.compile(r"(?i)\b(token|password|passwd|secret|api[_-]?key)\s*=\s*([^\s;&]+)"),
]


def redact(text: str) -> str:
    out = text
    for pattern in _PATTERNS:
        if pattern.groups >= 2:
            out = pattern.sub(lambda m: f"{m.group(1)}[REDACTED]", out)
        else:
            out = pattern.sub("[REDACTED]", out)
    return out
