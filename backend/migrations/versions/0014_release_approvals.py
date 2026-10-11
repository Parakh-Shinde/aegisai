"""Persist immutable release-evidence snapshots and approval decisions.

Revision ID: 0014_release_approvals
Revises: 0013_ocr_evidence
Create Date: 2026-10-11
"""

import sqlalchemy as sa
from alembic import op

revision = "0014_release_approvals"
down_revision = "0013_ocr_evidence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "release_approvals",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("system_id", sa.String(length=36), nullable=False),
        sa.Column("profile_version", sa.Integer(), nullable=False),
        sa.Column("release_decision", sa.String(length=32), nullable=False),
        sa.Column("decision_digest", sa.String(length=64), nullable=False),
        sa.Column("decision_snapshot", sa.JSON(), nullable=False),
        sa.Column("request_notes", sa.Text(), nullable=False),
        sa.Column("requested_by_user_id", sa.String(length=36), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approval_status", sa.String(length=24), nullable=False),
        sa.Column("decided_by_user_id", sa.String(length=36), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_notes", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["system_id"], ["ai_system_profiles.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["decided_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_release_approvals_organization_id",
        "release_approvals",
        ["organization_id"],
    )
    op.create_index(
        "ix_release_approvals_system_id",
        "release_approvals",
        ["system_id"],
    )
    op.create_index(
        "ix_release_approvals_approval_status",
        "release_approvals",
        ["approval_status"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_release_approvals_approval_status",
        table_name="release_approvals",
    )
    op.drop_index("ix_release_approvals_system_id", table_name="release_approvals")
    op.drop_index(
        "ix_release_approvals_organization_id",
        table_name="release_approvals",
    )
    op.drop_table("release_approvals")
