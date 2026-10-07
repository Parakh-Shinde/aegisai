from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings

ENCRYPTED_EVIDENCE_PREFIX = "fernet:v1:"


def _fernet() -> Fernet | None:
    encryption_key = get_settings().evidence_encryption_key
    return Fernet(encryption_key.encode("ascii")) if encryption_key else None


def protect_evidence(value: str) -> str:
    """Encrypt evidence when a key is configured; local development stays readable."""
    fernet = _fernet()
    if fernet is None:
        return value
    encrypted = fernet.encrypt(value.encode("utf-8")).decode("ascii")
    return f"{ENCRYPTED_EVIDENCE_PREFIX}{encrypted}"


def reveal_evidence(value: str) -> str:
    """Decrypt current evidence and preserve legacy development records safely."""
    if not value.startswith(ENCRYPTED_EVIDENCE_PREFIX):
        return value

    fernet = _fernet()
    if fernet is None:
        raise RuntimeError(
            "Encrypted evidence cannot be read without AEGISAI_EVIDENCE_ENCRYPTION_KEY."
        )
    try:
        encrypted_value = value.removeprefix(ENCRYPTED_EVIDENCE_PREFIX)
        return fernet.decrypt(encrypted_value).decode("utf-8")
    except InvalidToken as exc:
        raise RuntimeError(
            "Stored evidence could not be decrypted with the configured key."
        ) from exc
