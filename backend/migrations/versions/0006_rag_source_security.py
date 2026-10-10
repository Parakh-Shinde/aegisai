"""Add RAG source security records.

Revision ID: 0006_rag_source_security
Revises: 0005_file_security_scans
Create Date: 2026-10-10
"""

import sqlalchemy as sa
from alembic import op

revision = "0006_rag_source_security"
down_revision = "0005_file_security_scans"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "rag_sources",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("system_id", sa.String(length=36), nullable=False),
        sa.Column("created_by_user_id", sa.String(length=36), nullable=True),
        sa.Column("reviewed_by_user_id", sa.String(length=36), nullable=True),
        sa.Column("source_name", sa.String(length=255), nullable=False),
        sa.Column("source_kind", sa.String(length=40), nullable=False),
        sa.Column("source_reference", sa.String(length=512), nullable=True),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("content_characters", sa.Integer(), nullable=False),
        sa.Column("verdict", sa.String(length=24), nullable=False),
        sa.Column("signals", sa.JSON(), nullable=False),
        sa.Column("recommendation", sa.Text(), nullable=False),
        sa.Column("review_state", sa.String(length=32), nullable=False),
        sa.Column("review_notes", sa.Text(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["system_id"], ["ai_system_profiles.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["reviewed_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
    )
    op.create_index(
        "ix_rag_sources_organization_id",
        "rag_sources",
        ["organization_id"],
    )
    op.create_index("ix_rag_sources_system_id", "rag_sources", ["system_id"])
    op.create_index("ix_rag_sources_content_sha256", "rag_sources", ["content_sha256"])
    op.create_index("ix_rag_sources_verdict", "rag_sources", ["verdict"])
    op.create_index("ix_rag_sources_review_state", "rag_sources", ["review_state"])


def downgrade() -> None:
    op.drop_index("ix_rag_sources_review_state", table_name="rag_sources")
    op.drop_index("ix_rag_sources_verdict", table_name="rag_sources")
    op.drop_index("ix_rag_sources_content_sha256", table_name="rag_sources")
    op.drop_index("ix_rag_sources_system_id", table_name="rag_sources")
    op.drop_index("ix_rag_sources_organization_id", table_name="rag_sources")
    op.drop_table("rag_sources")
