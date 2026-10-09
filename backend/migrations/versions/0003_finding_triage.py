"""Add analyst triage ownership and SLA metadata.

Revision ID: 0003_finding_triage
Revises: 0002_evaluation_integrity
Create Date: 2026-10-09
"""

import sqlalchemy as sa
from alembic import op

revision = "0003_finding_triage"
down_revision = "0002_evaluation_integrity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "security_test_results",
        sa.Column(
            "triage_status",
            sa.String(length=32),
            nullable=False,
            server_default="open",
        ),
    )
    op.add_column(
        "security_test_results",
        sa.Column("assigned_to_user_id", sa.String(length=36), nullable=True),
    )
    op.add_column(
        "security_test_results",
        sa.Column("sla_due_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "security_test_results",
        sa.Column("resolution_notes", sa.Text(), nullable=True),
    )
    op.create_foreign_key(
        "fk_security_test_results_assigned_to_user",
        "security_test_results",
        "users",
        ["assigned_to_user_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_security_test_results_triage_status",
        "security_test_results",
        ["triage_status"],
    )
    op.create_index(
        "ix_security_test_results_assigned_to_user_id",
        "security_test_results",
        ["assigned_to_user_id"],
    )
    op.create_index(
        "ix_security_test_results_sla_due_at",
        "security_test_results",
        ["sla_due_at"],
    )
    op.alter_column("security_test_results", "triage_status", server_default=None)


def downgrade() -> None:
    op.drop_index(
        "ix_security_test_results_sla_due_at",
        table_name="security_test_results",
    )
    op.drop_index(
        "ix_security_test_results_assigned_to_user_id",
        table_name="security_test_results",
    )
    op.drop_index(
        "ix_security_test_results_triage_status",
        table_name="security_test_results",
    )
    op.drop_constraint(
        "fk_security_test_results_assigned_to_user",
        "security_test_results",
        type_="foreignkey",
    )
    op.drop_column("security_test_results", "resolution_notes")
    op.drop_column("security_test_results", "sla_due_at")
    op.drop_column("security_test_results", "assigned_to_user_id")
    op.drop_column("security_test_results", "triage_status")
