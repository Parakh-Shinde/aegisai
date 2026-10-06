from datetime import UTC, datetime

from sqlalchemy import DateTime, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class SecurityTestResultRecord(Base):
    __tablename__ = "security_test_results"

    test_id: Mapped[str] = mapped_column(primary_key=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
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