"""Add runtime evaluation identifiers to agent action evidence.

Revision ID: 0009_agent_runtime_evaluation
Revises: 0008_agent_runtime_enforcement
Create Date: 2026-10-10
"""

import sqlalchemy as sa
from alembic import op

revision = "0009_agent_runtime_evaluation"
down_revision = "0008_agent_runtime_enforcement"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "agent_action_inspections",
        sa.Column("evaluation_run_id", sa.String(length=36), nullable=True),
    )
    op.add_column(
        "agent_action_inspections",
        sa.Column("evaluation_case_id", sa.String(length=96), nullable=True),
    )
    op.create_index(
        "ix_agent_action_inspections_evaluation_run_id",
        "agent_action_inspections",
        ["evaluation_run_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_agent_action_inspections_evaluation_run_id",
        table_name="agent_action_inspections",
    )
    op.drop_column("agent_action_inspections", "evaluation_case_id")
    op.drop_column("agent_action_inspections", "evaluation_run_id")
