"""Persist reproducible agent runtime assessment metrics.

Revision ID: 0010_assessment_metrics
Revises: 0009_agent_runtime_evaluation
Create Date: 2026-10-10
"""

import sqlalchemy as sa
from alembic import op

revision = "0010_assessment_metrics"
down_revision = "0009_agent_runtime_evaluation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "agent_action_inspections",
        sa.Column("evaluation_expected_verdict", sa.String(length=24), nullable=True),
    )
    op.create_table(
        "agent_runtime_assessments",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("system_id", sa.String(length=36), nullable=False),
        sa.Column("created_by_user_id", sa.String(length=36), nullable=True),
        sa.Column("suite_name", sa.String(length=120), nullable=False),
        sa.Column("corpus_version", sa.String(length=64), nullable=False),
        sa.Column("corpus_digest", sa.String(length=64), nullable=False),
        sa.Column("scoring_rule_version", sa.String(length=64), nullable=False),
        sa.Column("planned_tests", sa.Integer(), nullable=False),
        sa.Column("executed_tests", sa.Integer(), nullable=False),
        sa.Column("skipped_tests", sa.Integer(), nullable=False),
        sa.Column("unsupported_tests", sa.Integer(), nullable=False),
        sa.Column("metrics", sa.JSON(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["system_id"], ["ai_system_profiles.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
    )
    op.create_index(
        "ix_agent_runtime_assessments_organization_id",
        "agent_runtime_assessments",
        ["organization_id"],
    )
    op.create_index(
        "ix_agent_runtime_assessments_system_id",
        "agent_runtime_assessments",
        ["system_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_agent_runtime_assessments_system_id",
        table_name="agent_runtime_assessments",
    )
    op.drop_index(
        "ix_agent_runtime_assessments_organization_id",
        table_name="agent_runtime_assessments",
    )
    op.drop_table("agent_runtime_assessments")
    op.drop_column("agent_action_inspections", "evaluation_expected_verdict")
