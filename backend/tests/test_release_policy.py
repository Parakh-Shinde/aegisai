import json
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from app.services.release_policy import ReleasePolicyError, validate_release_policy

BACKEND_ROOT = Path(__file__).resolve().parents[1]


def test_approved_release_policy_passes_for_committed_corpora() -> None:
    report = validate_release_policy(
        policy_path=BACKEND_ROOT / "release" / "evaluation-policy.json",
        corpus_dir=BACKEND_ROOT / "app" / "corpus",
        source_revision="test-revision",
    )

    assert report["decision"] == "pass"
    assert report["source_revision"] == "test-revision"
    assert [corpus["test_count"] for corpus in report["corpora"]] == [8, 5, 10, 6, 5]


def test_modified_corpus_fails_the_release_policy(tmp_path: Path) -> None:
    corpus_dir = tmp_path / "corpus"
    shutil.copytree(BACKEND_ROOT / "app" / "corpus", corpus_dir)
    basic_corpus = corpus_dir / "basic_safety_suite.json"
    basic_corpus.write_text(
        basic_corpus.read_text(encoding="utf-8").replace(
            '"version": "1.0.0"',
            '"version": "1.0.1"',
        ),
        encoding="utf-8",
    )

    with pytest.raises(ReleasePolicyError, match="provenance"):
        validate_release_policy(
            policy_path=BACKEND_ROOT / "release" / "evaluation-policy.json",
            corpus_dir=corpus_dir,
            source_revision="test-revision",
        )



def _write_policy_copy(
    tmp_path: Path,
    mutate: Callable[[dict[str, Any]], object],
) -> Path:
    source = BACKEND_ROOT / "release" / "evaluation-policy.json"
    policy = json.loads(source.read_text(encoding="utf-8"))
    mutate(policy)
    destination = tmp_path / "evaluation-policy.json"
    destination.write_text(json.dumps(policy), encoding="utf-8")
    return destination


def test_release_policy_rejects_missing_requirement(tmp_path: Path) -> None:
    policy_path = _write_policy_copy(
        tmp_path,
        lambda policy: policy["release_requirements"].pop("block_new_leaks"),
    )

    with pytest.raises(ReleasePolicyError, match="exactly"):
        validate_release_policy(
            policy_path=policy_path,
            corpus_dir=BACKEND_ROOT / "app" / "corpus",
            source_revision="test-revision",
        )


def test_release_policy_rejects_boolean_campaign_minimum(tmp_path: Path) -> None:
    policy_path = _write_policy_copy(
        tmp_path,
        lambda policy: policy["release_requirements"].update(
            {"minimum_campaign_tests": True}
        ),
    )

    with pytest.raises(ReleasePolicyError, match="positive integer"):
        validate_release_policy(
            policy_path=policy_path,
            corpus_dir=BACKEND_ROOT / "app" / "corpus",
            source_revision="test-revision",
        )


def test_release_policy_requires_exact_corpus_matching(tmp_path: Path) -> None:
    policy_path = _write_policy_copy(
        tmp_path,
        lambda policy: policy["release_requirements"].update(
            {"require_exact_corpus_match": False}
        ),
    )

    with pytest.raises(ReleasePolicyError, match="safety requirements"):
        validate_release_policy(
            policy_path=policy_path,
            corpus_dir=BACKEND_ROOT / "app" / "corpus",
            source_revision="test-revision",
        )



@pytest.mark.parametrize(
    "requirement",
    [
        "require_human_review",
        "block_new_leaks",
        "block_new_high_risk_findings",
        "require_exact_corpus_match",
    ],
)
def test_release_policy_rejects_disabled_safety_requirement(
    tmp_path: Path,
    requirement: str,
) -> None:
    def disable_requirement(policy: dict[str, Any]) -> None:
        policy["release_requirements"][requirement] = False

    policy_path = _write_policy_copy(tmp_path, disable_requirement)

    with pytest.raises(ReleasePolicyError, match="safety requirements"):
        validate_release_policy(
            policy_path=policy_path,
            corpus_dir=BACKEND_ROOT / "app" / "corpus",
            source_revision="test-revision",
        )



def test_release_policy_rejects_runtime_minimum_mismatch(tmp_path: Path) -> None:
    policy_path = _write_policy_copy(
        tmp_path,
        lambda policy: policy["release_requirements"].update(
            {"minimum_campaign_tests": 11}
        ),
    )

    with pytest.raises(ReleasePolicyError, match="match the runtime minimum"):
        validate_release_policy(
            policy_path=policy_path,
            corpus_dir=BACKEND_ROOT / "app" / "corpus",
            source_revision="test-revision",
        )
