"""Persist evidence for model-to-gateway runtime evaluations.

Revision ID: 0012_model_agent_gateway_evaluation
Revises: 0011_promptfoo_tool_runner
Create Date: 2026-10-10
"""

import sqlalchemy as sa
from alembic import op

revision = "0012_model_agent_gateway_evaluation"
down_revision = "0011_promptfoo_tool_runner"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "agent_action_inspections",
        sa.Column("model_response_evidence", sa.Text(), nullable=True),
    )
    op.add_column(
        "agent_action_inspections",
        sa.Column("proposal_evidence", sa.Text(), nullable=True),
    )
    op.add_column(
        "agent_runtime_assessments",
        sa.Column("target_id", sa.String(length=36), nullable=True),
    )
    op.add_column(
        "agent_runtime_assessments",
        sa.Column("model_name", sa.String(length=120), nullable=True),
    )
    op.add_column(
        "agent_runtime_assessments",
        sa.Column("execution_mode", sa.String(length=40), nullable=True),
    )
    op.create_foreign_key(
        "fk_agent_runtime_assessments_target_id",
        "agent_runtime_assessments",
        "tool_evaluation_targets",
        ["target_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_agent_runtime_assessments_target_id",
        "agent_runtime_assessments",
        ["target_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_agent_runtime_assessments_target_id",
        table_name="agent_runtime_assessments",
    )
    op.drop_constraint(
        "fk_agent_runtime_assessments_target_id",
        "agent_runtime_assessments",
        type_="foreignkey",
    )
    op.drop_column("agent_runtime_assessments", "execution_mode")
    op.drop_column("agent_runtime_assessments", "model_name")
    op.drop_column("agent_runtime_assessments", "target_id")
    op.drop_column("agent_action_inspections", "proposal_evidence")
    op.drop_column("agent_action_inspections", "model_response_evidence")
