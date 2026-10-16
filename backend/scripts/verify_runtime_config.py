"""Validate effective AEGISAI runtime settings without printing secrets."""

from __future__ import annotations

import sys
from pathlib import Path

# Invoking this file by path puts /app/scripts on sys.path. Add /app so the
# sibling app package is importable in the production container.
BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.core.config import get_settings


def main() -> None:
    settings = get_settings()
    database_engine = settings.database_url.split(":", 1)[0] or "not configured"
    print("AEGISAI runtime configuration is valid.")
    print(f"Environment: {settings.environment}")
    print(f"Authentication required: {settings.auth_required}")
    print(f"Database engine: {database_engine}")
    print(f"Async campaigns: {settings.async_campaigns}")
    print(f"API documentation exposed: {settings.api_docs_enabled}")


if __name__ == "__main__":
    main()
