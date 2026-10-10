"""Add agent action security inspection records.

Revision ID: 0007_agent_action_security
Revises: 0006_rag_source_security
Create Date: 2026-10-10
"""

import sqlalchemy as sa
from alembic import op

revision = "0007_agent_action_security"
down_revision = "0006_rag_source_security"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_action_inspections",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("system_id", sa.String(length=36), nullable=False),
        sa.Column("created_by_user_id", sa.String(length=36), nullable=True),
        sa.Column("reviewed_by_user_id", sa.String(length=36), nullable=True),
        sa.Column("action_type", sa.String(length=40), nullable=False),
        sa.Column("tool_name", sa.String(length=120), nullable=False),
        sa.Column("target", sa.String(length=512), nullable=True),
        sa.Column("request_sha256", sa.String(length=64), nullable=False),
        sa.Column("request_characters", sa.Integer(), nullable=False),
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
        "ix_agent_action_inspections_organization_id",
        "agent_action_inspections",
        ["organization_id"],
    )
    op.create_index(
        "ix_agent_action_inspections_system_id",
        "agent_action_inspections",
        ["system_id"],
    )
    op.create_index(
        "ix_agent_action_inspections_request_sha256",
        "agent_action_inspections",
        ["request_sha256"],
    )
    op.create_index(
        "ix_agent_action_inspections_verdict",
        "agent_action_inspections",
        ["verdict"],
    )
    op.create_index(
        "ix_agent_action_inspections_review_state",
        "agent_action_inspections",
        ["review_state"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_agent_action_inspections_review_state",
        table_name="agent_action_inspections",
    )
    op.drop_index(
        "ix_agent_action_inspections_verdict",
        table_name="agent_action_inspections",
    )
    op.drop_index(
        "ix_agent_action_inspections_request_sha256",
        table_name="agent_action_inspections",
    )
    op.drop_index(
        "ix_agent_action_inspections_system_id",
        table_name="agent_action_inspections",
    )
    op.drop_index(
        "ix_agent_action_inspections_organization_id",
        table_name="agent_action_inspections",
    )
    op.drop_table("agent_action_inspections")
