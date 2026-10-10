"""Add approved targets and evidence for isolated Promptfoo evaluations.

Revision ID: 0011_promptfoo_tool_runner
Revises: 0010_assessment_metrics
Create Date: 2026-10-10
"""

import sqlalchemy as sa
from alembic import op

revision = "0011_promptfoo_tool_runner"
down_revision = "0010_assessment_metrics"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tool_evaluation_targets",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("system_id", sa.String(length=36), nullable=False),
        sa.Column("created_by_user_id", sa.String(length=36), nullable=True),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("endpoint", sa.String(length=512), nullable=False),
        sa.Column("model_name", sa.String(length=120), nullable=False),
        sa.Column("authorization_confirmed", sa.Boolean(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["system_id"], ["ai_system_profiles.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("organization_id", "name", name="uq_tool_evaluation_targets_org_name"),
    )
    op.create_index(
        "ix_tool_evaluation_targets_organization_id",
        "tool_evaluation_targets",
        ["organization_id"],
    )
    op.create_index(
        "ix_tool_evaluation_targets_system_id",
        "tool_evaluation_targets",
        ["system_id"],
    )
    op.create_table(
        "tool_evaluation_runs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("system_id", sa.String(length=36), nullable=False),
        sa.Column("target_id", sa.String(length=36), nullable=False),
        sa.Column("created_by_user_id", sa.String(length=36), nullable=True),
        sa.Column("tool_name", sa.String(length=64), nullable=False),
        sa.Column("tool_version", sa.String(length=80), nullable=False),
        sa.Column("suite_name", sa.String(length=120), nullable=False),
        sa.Column("config_digest", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("planned_tests", sa.Integer(), nullable=False),
        sa.Column("executed_tests", sa.Integer(), nullable=False),
        sa.Column("passed_tests", sa.Integer(), nullable=False),
        sa.Column("failed_tests", sa.Integer(), nullable=False),
        sa.Column("skipped_tests", sa.Integer(), nullable=False),
        sa.Column("report_digest", sa.String(length=64), nullable=True),
        sa.Column("error_summary", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["system_id"], ["ai_system_profiles.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["target_id"], ["tool_evaluation_targets.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
    )
    for column in ("organization_id", "system_id", "target_id", "status"):
        op.create_index(
            f"ix_tool_evaluation_runs_{column}", "tool_evaluation_runs", [column]
        )
    op.create_table(
        "tool_evaluation_cases",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("external_case_id", sa.String(length=160), nullable=False),
        sa.Column("outcome", sa.String(length=24), nullable=False),
        sa.Column("score", sa.Float(), nullable=True),
        sa.Column("prompt_evidence", sa.Text(), nullable=True),
        sa.Column("response_evidence", sa.Text(), nullable=True),
        sa.Column("assertions", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["run_id"], ["tool_evaluation_runs.id"], ondelete="CASCADE"
        ),
        sa.UniqueConstraint(
            "run_id",
            "external_case_id",
            name="uq_tool_evaluation_cases_run_external_case",
        ),
    )
    for column in ("organization_id", "run_id", "outcome"):
        op.create_index(
            f"ix_tool_evaluation_cases_{column}", "tool_evaluation_cases", [column]
        )


def downgrade() -> None:
    for column in ("outcome", "run_id", "organization_id"):
        op.drop_index(f"ix_tool_evaluation_cases_{column}", table_name="tool_evaluation_cases")
    op.drop_table("tool_evaluation_cases")
    for column in ("status", "target_id", "system_id", "organization_id"):
        op.drop_index(f"ix_tool_evaluation_runs_{column}", table_name="tool_evaluation_runs")
    op.drop_table("tool_evaluation_runs")
    op.drop_index(
        "ix_tool_evaluation_targets_system_id", table_name="tool_evaluation_targets"
    )
    op.drop_index(
        "ix_tool_evaluation_targets_organization_id",
        table_name="tool_evaluation_targets",
    )
    op.drop_table("tool_evaluation_targets")
