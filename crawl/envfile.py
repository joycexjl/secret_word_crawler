"""Minimal .env loader — no dependency.

Reads KEY=VALUE lines from a .env file into os.environ without overwriting
variables already set in the environment (real env wins, so you can always
override per-command). Credentials stay out of the code and out of git
(.env is gitignored; ADR 0001's "never hardcoded" holds — the file is the
local secret store, the repo only ever sees the variable *names*).
"""

from __future__ import annotations

import os
from pathlib import Path


def load_dotenv(path: str | Path = ".env") -> dict[str, str]:
    """Load KEY=VALUE pairs from path into os.environ (no clobber). Returns
    the dict of what was loaded. Missing file is fine — returns {}."""
    p = Path(path)
    loaded: dict[str, str] = {}
    if not p.exists():
        return loaded
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if not key:
            continue
        loaded[key] = value
        os.environ.setdefault(key, value)  # real environment takes precedence
    return loaded
