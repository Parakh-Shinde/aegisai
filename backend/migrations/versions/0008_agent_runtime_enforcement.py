"""Add agent runtime enforcement metadata.

Revision ID: 0008_agent_runtime_enforcement
Revises: 0007_agent_action_security
Create Date: 2026-10-10
"""

import sqlalchemy as sa
from alembic import op

revision = "0008_agent_runtime_enforcement"
down_revision = "0007_agent_action_security"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "agent_action_inspections",
        sa.Column(
            "decision_source",
            sa.String(length=24),
            nullable=False,
            server_default="inspection",
        ),
    )
    op.add_column(
        "agent_action_inspections",
        sa.Column("idempotency_key", sa.String(length=128), nullable=True),
    )
    op.create_index(
        "uq_agent_actions_org_system_idempotency",
        "agent_action_inspections",
        ["organization_id", "system_id", "idempotency_key"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(
        "uq_agent_actions_org_system_idempotency",
        table_name="agent_action_inspections",
    )
    op.drop_column("agent_action_inspections", "idempotency_key")
    op.drop_column("agent_action_inspections", "decision_source")
