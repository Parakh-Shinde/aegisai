import os
from datetime import UTC, datetime, timedelta

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from app.api.security_tests import build_organization_report  # noqa: E402
from app.db.models import SecurityTestResultRecord  # noqa: E402
from app.services.reporting import export_findings_csv  # noqa: E402


def make_record(
    *,
    test_id: str,
    created_at: datetime,
    risk_status: str = "blocked",
    severity: str = "none",
    campaign_id: str | None = "campaign-1",
) -> SecurityTestResultRecord:
    return SecurityTestResultRecord(
        test_id=test_id,
        organization_id="organization-1",
        created_by_user_id="user-1",
        created_at=created_at,
        test_type="prompt_injection_basic",
        test_category="prompt_injection",
        model="candidate-model",
        risk_status=risk_status,
        severity=severity,
        latency_ms=10,
        recommendation="Do not export test evidence.",
        finding="=unsafe-spreadsheet-value",
        prompt_sent="private prompt evidence",
        model_response="private model evidence",
        campaign_id=campaign_id,
        review_status="confirmed_safe",
        triage_status="open",
    )


def test_organization_report_is_windowed_and_counts_release_status() -> None:
    now = datetime(2026, 10, 9, tzinfo=UTC)
    records = [
        make_record(
            test_id=f"test-{index}",
            created_at=now - timedelta(days=1),
        )
        for index in range(10)
    ]
    records.append(
        make_record(
            test_id="old-test",
            created_at=now - timedelta(days=31),
            campaign_id=None,
        )
    )

    report = build_organization_report(records, window_days=30, now=now)

    assert report.total_tests == 10
    assert report.campaigns == 1
    assert report.models_tested == 1
    assert report.release_pass == 1
    assert report.release_fail == 0


def test_findings_export_is_safe_and_omits_protected_evidence() -> None:
    record = make_record(
        test_id="test-1",
        created_at=datetime(2026, 10, 9, tzinfo=UTC),
        risk_status="leaked",
        severity="high",
    )

    csv_output = export_findings_csv([record])

    assert "'=unsafe-spreadsheet-value" in csv_output
    assert "private prompt evidence" not in csv_output
    assert "private model evidence" not in csv_output
