"""Apply AEGISAI database migrations.

Run from the repository root:

    python backend/scripts/init_db.py
"""

import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402


def main() -> None:
    command.upgrade(Config(str(BACKEND_DIR / "alembic.ini")), "head")
    print("AEGISAI database migrations are up to date.")


if __name__ == "__main__":
    main()
