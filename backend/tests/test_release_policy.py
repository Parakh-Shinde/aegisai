import shutil
from pathlib import Path

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
    assert [corpus["test_count"] for corpus in report["corpora"]] == [5, 10, 5]


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
