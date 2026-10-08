from app.core.config import get_settings
from app.core.database import SessionLocal
from app.core.evidence import ENCRYPTED_EVIDENCE_PREFIX, protect_evidence
from app.db.models import SecurityTestResultRecord
from sqlalchemy import select


def main() -> None:
    if not get_settings().evidence_encryption_key:
        raise RuntimeError("AEGISAI_EVIDENCE_ENCRYPTION_KEY must be configured first.")

    with SessionLocal() as db:
        records = db.scalars(select(SecurityTestResultRecord)).all()
        migrated = 0
        for record in records:
            if not record.prompt_sent.startswith(ENCRYPTED_EVIDENCE_PREFIX):
                record.prompt_sent = protect_evidence(record.prompt_sent)
                migrated += 1
            if not record.model_response.startswith(ENCRYPTED_EVIDENCE_PREFIX):
                record.model_response = protect_evidence(record.model_response)
                migrated += 1
        db.commit()

    print(f"Encrypted {migrated} legacy evidence fields.")


if __name__ == "__main__":
    main()
