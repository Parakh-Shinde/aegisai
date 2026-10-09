"""Deterministic CI release-policy validation for evaluation assets."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


class ReleasePolicyError(RuntimeError):
    """Raised when a committed evaluation asset violates the approved policy."""


def _load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleasePolicyError(f"Cannot read JSON file: {path}") from exc

    if not isinstance(data, dict):
        raise ReleasePolicyError(f"Expected a JSON object: {path}")
    return data


def _required_string(data: dict[str, Any], key: str, source: Path) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ReleasePolicyError(f"{source} must define a non-empty {key}.")
    return value


def validate_release_policy(
    *,
    policy_path: Path,
    corpus_dir: Path,
    source_revision: str,
) -> dict[str, Any]:
    """Validate locked evaluation inputs and return a reproducible report."""

    policy = _load_json(policy_path)
    if policy.get("schema_version") != "1.0":
        raise ReleasePolicyError("Unsupported release policy schema version.")

    locked_corpora = policy.get("required_corpora")
    if not isinstance(locked_corpora, list) or not locked_corpora:
        raise ReleasePolicyError("Release policy must define required_corpora.")

    expected_files: set[str] = set()
    report_corpora: list[dict[str, Any]] = []
    for item in locked_corpora:
        if not isinstance(item, dict):
            raise ReleasePolicyError(
                "Each required corpus policy entry must be an object."
            )

        filename = item.get("file")
        if not isinstance(filename, str) or Path(filename).name != filename:
            raise ReleasePolicyError(
                "Corpus policy file names must be simple file names."
            )
        if filename in expected_files:
            raise ReleasePolicyError(f"Duplicate corpus policy entry: {filename}")
        expected_files.add(filename)

        minimum_tests = item.get("minimum_tests")
        if not isinstance(minimum_tests, int) or minimum_tests < 1:
            raise ReleasePolicyError(
                f"Corpus policy minimum_tests is invalid: {filename}"
            )

        corpus_path = corpus_dir / filename
        if not corpus_path.is_file():
            raise ReleasePolicyError(f"Required corpus is missing: {filename}")
        try:
            raw_corpus = corpus_path.read_bytes()
        except OSError as exc:
            raise ReleasePolicyError(
                f"Cannot read required corpus: {filename}"
            ) from exc
        try:
            corpus_data = json.loads(raw_corpus)
        except json.JSONDecodeError as exc:
            raise ReleasePolicyError(f"Corpus is not valid JSON: {filename}") from exc
        if not isinstance(corpus_data, dict):
            raise ReleasePolicyError(
                f"Corpus must be a versioned JSON object: {filename}"
            )

        tests = corpus_data.get("tests")
        if not isinstance(tests, list) or len(tests) < minimum_tests:
            raise ReleasePolicyError(
                f"Corpus has fewer than {minimum_tests} tests: {filename}"
            )

        actual = {
            "suite_name": _required_string(corpus_data, "suite_name", corpus_path),
            "version": _required_string(corpus_data, "version", corpus_path),
            "scoring_rule_version": _required_string(
                corpus_data,
                "scoring_rule_version",
                corpus_path,
            ),
            "sha256": hashlib.sha256(raw_corpus).hexdigest(),
        }
        expected = {
            key: item.get(key)
            for key in ("suite_name", "version", "scoring_rule_version", "sha256")
        }
        if actual != expected:
            raise ReleasePolicyError(
                f"Corpus provenance does not match the approved policy: {filename}"
            )
        report_corpora.append(
            {
                "file": filename,
                "minimum_tests": minimum_tests,
                "test_count": len(tests),
                **actual,
            }
        )

    discovered_files = {path.name for path in corpus_dir.glob("*.json")}
    if discovered_files != expected_files:
        raise ReleasePolicyError(
            "Committed corpus files and release-policy entries must match exactly."
        )

    requirements = policy.get("release_requirements")
    if not isinstance(requirements, dict):
        raise ReleasePolicyError("Release policy must define release_requirements.")

    canonical_policy = json.dumps(
        policy,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "report_schema_version": "1.0",
        "decision": "pass",
        "source_revision": source_revision,
        "policy_sha256": hashlib.sha256(canonical_policy).hexdigest(),
        "release_requirements": requirements,
        "corpora": sorted(report_corpora, key=lambda corpus: corpus["file"]),
    }
