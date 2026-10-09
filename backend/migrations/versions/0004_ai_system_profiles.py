"""Add AI system profiles for adaptive security coverage.

Revision ID: 0004_ai_system_profiles
Revises: 0003_finding_triage
Create Date: 2026-10-10
"""

import sqlalchemy as sa
from alembic import op

revision = "0004_ai_system_profiles"
down_revision = "0003_finding_triage"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_system_profiles",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("created_by_user_id", sa.String(length=36), nullable=True),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("system_type", sa.String(length=48), nullable=False),
        sa.Column("deployment_exposure", sa.String(length=24), nullable=False),
        sa.Column("data_classification", sa.String(length=24), nullable=False),
        sa.Column("input_modalities", sa.JSON(), nullable=False),
        sa.Column("capabilities", sa.JSON(), nullable=False),
        sa.Column("profile_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.UniqueConstraint(
            "organization_id",
            "name",
            name="uq_ai_system_profiles_org_name",
        ),
    )
    op.create_index(
        "ix_ai_system_profiles_organization_id",
        "ai_system_profiles",
        ["organization_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_ai_system_profiles_organization_id",
        table_name="ai_system_profiles",
    )
    op.drop_table("ai_system_profiles")
