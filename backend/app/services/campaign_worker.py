from sqlalchemy.orm import Session

from app.api.security_tests import load_corpus_suite, run_single_security_test
from app.core.auth import ACTOR_SESSION_KEY, Actor
from app.core.database import SessionLocal
from app.db.models import UserRole


def run_basic_suite_job(payload: dict) -> None:
    actor_data = payload["actor"]
    actor = Actor(
        user_id=actor_data["user_id"],
        organization_id=actor_data["organization_id"],
        role=UserRole(actor_data["role"]),
        email=actor_data["email"],
    )
    db: Session = SessionLocal()
    try:
        db.info[ACTOR_SESSION_KEY] = actor
        corpus = load_corpus_suite(payload["suite_name"])
        expected_digest = payload.get("corpus_digest")
        if expected_digest and expected_digest != corpus.digest:
            raise RuntimeError("Corpus changed after the campaign was queued.")
        for test in corpus.tests:
            run_single_security_test(
                db=db,
                model=payload["model"],
                test_type=test.test_type,
                test_category=test.test_category,
                instruction=test.instruction,
                user_prompt=test.user_prompt,
                campaign_id=payload["campaign_id"],
                corpus=corpus,
            )
        # Evidence belongs in PostgreSQL, where field encryption and tenant access
        # controls apply. Do not copy prompts or model output into Redis job results.
        return None
    finally:
        db.close()
