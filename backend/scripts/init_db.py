"""Initialize AEGISAI database tables.

Run from the repository root:

    python backend/scripts/init_db.py
"""

import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app.core.database import Base, engine  # noqa: E402
from app.db import models  # noqa: F401, E402


def main() -> None:
    Base.metadata.create_all(bind=engine)
    print("AEGISAI database tables are ready.")


if __name__ == "__main__":
    main()
