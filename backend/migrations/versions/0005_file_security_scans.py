"""Add static file security scan records.

Revision ID: 0005_file_security_scans
Revises: 0004_ai_system_profiles
Create Date: 2026-10-10
"""

import sqlalchemy as sa
from alembic import op

revision = "0005_file_security_scans"
down_revision = "0004_ai_system_profiles"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "file_security_scans",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("system_id", sa.String(length=36), nullable=True),
        sa.Column("created_by_user_id", sa.String(length=36), nullable=True),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("declared_content_type", sa.String(length=255), nullable=True),
        sa.Column("detected_type", sa.String(length=32), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("file_size_bytes", sa.Integer(), nullable=False),
        sa.Column("verdict", sa.String(length=24), nullable=False),
        sa.Column("signals", sa.JSON(), nullable=False),
        sa.Column("recommendation", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["system_id"], ["ai_system_profiles.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
    )
    op.create_index(
        "ix_file_security_scans_organization_id",
        "file_security_scans",
        ["organization_id"],
    )
    op.create_index(
        "ix_file_security_scans_system_id",
        "file_security_scans",
        ["system_id"],
    )
    op.create_index(
        "ix_file_security_scans_sha256",
        "file_security_scans",
        ["sha256"],
    )
    op.create_index(
        "ix_file_security_scans_verdict",
        "file_security_scans",
        ["verdict"],
    )


def downgrade() -> None:
    op.drop_index("ix_file_security_scans_verdict", table_name="file_security_scans")
    op.drop_index("ix_file_security_scans_sha256", table_name="file_security_scans")
    op.drop_index("ix_file_security_scans_system_id", table_name="file_security_scans")
    op.drop_index(
        "ix_file_security_scans_organization_id",
        table_name="file_security_scans",
    )
    op.drop_table("file_security_scans")
