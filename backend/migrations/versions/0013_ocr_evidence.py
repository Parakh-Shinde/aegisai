"""Persist evidence and decisions from the isolated OCR stage.

Revision ID: 0013_ocr_evidence
Revises: 0012_model_gateway_eval
Create Date: 2026-10-10
"""

import sqlalchemy as sa
from alembic import op

revision = "0013_ocr_evidence"
down_revision = "0012_model_gateway_eval"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "file_security_scans",
        sa.Column("ocr_status", sa.String(length=24), nullable=True),
    )
    op.add_column(
        "file_security_scans",
        sa.Column("ocr_text_evidence", sa.Text(), nullable=True),
    )
    op.add_column(
        "file_security_scans",
        sa.Column("ocr_text_sha256", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "file_security_scans",
        sa.Column("ocr_text_characters", sa.Integer(), nullable=True),
    )
    op.add_column(
        "file_security_scans",
        sa.Column("ocr_signals", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("file_security_scans", "ocr_signals")
    op.drop_column("file_security_scans", "ocr_text_characters")
    op.drop_column("file_security_scans", "ocr_text_sha256")
    op.drop_column("file_security_scans", "ocr_text_evidence")
    op.drop_column("file_security_scans", "ocr_status")
