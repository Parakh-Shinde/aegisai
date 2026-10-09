"""Validate the committed evaluation policy and write a CI integrity report."""

# ruff: noqa: E402

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.services.release_policy import ReleasePolicyError, validate_release_policy


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--policy",
        type=Path,
        default=Path("release/evaluation-policy.json"),
        help="Path to the committed release policy.",
    )
    parser.add_argument(
        "--corpus-dir",
        type=Path,
        default=Path("app/corpus"),
        help="Directory containing versioned corpus JSON files.",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=Path("build/release-integrity.json"),
        help="Output path for the generated integrity report.",
    )
    parser.add_argument(
        "--source-revision",
        default=os.getenv("GITHUB_SHA", "local"),
        help="Immutable source revision recorded in the report.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        report = validate_release_policy(
            policy_path=args.policy,
            corpus_dir=args.corpus_dir,
            source_revision=args.source_revision,
        )
    except ReleasePolicyError as exc:
        print(f"Release gate failed: {exc}", file=sys.stderr)
        return 1

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Release gate passed. Report written to {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
