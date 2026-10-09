import uuid
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy import (
    Enum as SqlEnum,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


def new_id() -> str:
    return str(uuid.uuid4())


def utc_now() -> datetime:
    return datetime.now(UTC)


class UserRole(StrEnum):
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    VIEWER = "viewer"


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    slug: Mapped[str] = mapped_column(
        String(80), unique=True, index=True, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    email: Mapped[str] = mapped_column(
        String(320), unique=True, index=True, nullable=False
    )
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        SqlEnum(UserRole, name="user_role", native_enum=False),
        default=UserRole.VIEWER,
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RegisteredModelRecord(Base):
    __tablename__ = "registered_models"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "model_id", name="uq_registered_models_org_model"
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    model_id: Mapped[str] = mapped_column(String(256), nullable=False)
    provider: Mapped[str] = mapped_column(String(80), nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    version: Mapped[str] = mapped_column(String(120), nullable=False)
    endpoint: Mapped[str] = mapped_column(String(512), nullable=False)
    deployment_type: Mapped[str] = mapped_column(String(80), nullable=False)
    capabilities: Mapped[dict[str, bool]] = mapped_column(
        JSON, default=dict, nullable=False
    )
    authentication: Mapped[str] = mapped_column(String(80), nullable=False)
    created_by_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )


class SecurityTestResultRecord(Base):
    __tablename__ = "security_test_results"

    test_id: Mapped[str] = mapped_column(primary_key=True, index=True)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    created_by_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    test_type: Mapped[str] = mapped_column(index=True)
    test_category: Mapped[str] = mapped_column(index=True)
    model: Mapped[str] = mapped_column(index=True)
    risk_status: Mapped[str] = mapped_column(index=True)
    severity: Mapped[str] = mapped_column(index=True)
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    recommendation: Mapped[str] = mapped_column(Text)
    finding: Mapped[str] = mapped_column(Text)
    prompt_sent: Mapped[str] = mapped_column(Text)
    model_response: Mapped[str] = mapped_column(Text)
    campaign_id: Mapped[str | None] = mapped_column(index=True, nullable=True)
    corpus_suite_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    corpus_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    corpus_digest: Mapped[str | None] = mapped_column(
        String(64),
        index=True,
        nullable=True,
    )
    scoring_rule_version: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    review_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="unreviewed",
        index=True,
    )
    review_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reviewed_by_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    triage_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="open",
        index=True,
    )
    assigned_to_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    sla_due_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )
    resolution_notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class EvaluationBaseline(Base):
    __tablename__ = "evaluation_baselines"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "name",
            name="uq_evaluation_baselines_org_name",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    created_by_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    source_campaign_id: Mapped[str] = mapped_column(String(128), nullable=False)
    model: Mapped[str] = mapped_column(String(256), nullable=False)
    corpus_suite_name: Mapped[str] = mapped_column(String(120), nullable=False)
    corpus_version: Mapped[str] = mapped_column(String(64), nullable=False)
    corpus_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    scoring_rule_version: Mapped[str] = mapped_column(String(64), nullable=False)
    total_tests: Mapped[int] = mapped_column(Integer, nullable=False)
    safety_score: Mapped[int] = mapped_column(Integer, nullable=False)
    leaked_tests: Mapped[int] = mapped_column(Integer, nullable=False)
    uncertain_tests: Mapped[int] = mapped_column(Integer, nullable=False)
    high_risk_tests: Mapped[int] = mapped_column(Integer, nullable=False)
    evidence_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    actor_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    action: Mapped[str] = mapped_column(String(120), index=True, nullable=False)
    resource_type: Mapped[str] = mapped_column(String(120), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    details: Mapped[dict[str, str | int | bool | None]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )
    previous_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    entry_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
