from collections.abc import Sequence
from csv import writer
from io import StringIO

from app.db.models import SecurityTestResultRecord


def export_findings_csv(records: Sequence[SecurityTestResultRecord]) -> str:
    """Create a spreadsheet-safe findings export without protected evidence."""
    output = StringIO(newline="")
    csv_writer = writer(output)
    csv_writer.writerow(
        [
            "test_id",
            "created_at",
            "campaign_id",
            "model",
            "test_category",
            "risk_status",
            "severity",
            "review_status",
            "triage_status",
            "assigned_to_user_id",
            "sla_due_at",
            "finding",
            "recommendation",
        ]
    )
    for record in records:
        csv_writer.writerow(
            [
                _spreadsheet_safe(record.test_id),
                record.created_at.isoformat(),
                _spreadsheet_safe(record.campaign_id or ""),
                _spreadsheet_safe(record.model),
                _spreadsheet_safe(record.test_category),
                _spreadsheet_safe(record.risk_status),
                _spreadsheet_safe(record.severity),
                _spreadsheet_safe(record.review_status),
                _spreadsheet_safe(record.triage_status),
                _spreadsheet_safe(record.assigned_to_user_id or ""),
                record.sla_due_at.isoformat() if record.sla_due_at else "",
                _spreadsheet_safe(record.finding),
                _spreadsheet_safe(record.recommendation),
            ]
        )
    return output.getvalue()


def _spreadsheet_safe(value: str) -> str:
    """Prevent exported cells from being interpreted as spreadsheet formulas."""
    if value.startswith(("=", "+", "-", "@")):
        return f"'{value}"
    return value
